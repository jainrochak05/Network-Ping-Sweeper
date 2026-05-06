from flask import Flask, request, jsonify, send_from_directory
import subprocess
import ipaddress
import platform
import concurrent.futures
import socket
import re
import json
import os
import threading
import time
from datetime import datetime, timezone

app = Flask(__name__, static_folder='static')

SCAN_LOG_FILE = 'scan_results.json'
_log_lock = threading.Lock()

# Common ports scanned by default when port scan is enabled
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]

PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 135: "MSRPC", 139: "NetBIOS", 5900: "VNC",
    6379: "Redis", 27017: "MongoDB",
}


def icmp_ping(ip):
    """ICMP ping via system ping command. Returns (is_up, latency_ms)."""
    system = platform.system().lower()
    count_param = '-n' if system == 'windows' else '-c'
    timeout_param = '-w' if system == 'windows' else '-W'
    timeout_val = '1000' if system == 'windows' else '1'
    command = ['ping', count_param, '1', timeout_param, timeout_val, str(ip)]
    try:
        output = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if output.returncode == 0:
            rtt_match = re.search(r'[=<]\s*([\d.]+)\s*ms', output.stdout)
            latency = round(float(rtt_match.group(1)), 2) if rtt_match else None
            return True, latency
        return False, None
    except Exception:
        return False, None


def tcp_ping(ip, timeout=1):
    """TCP connect probe to detect host liveness. Returns (is_up, latency_ms).
    Tries ports 80, 443, 22, 8080 in sequence; a successful connect or an
    ECONNREFUSED (port closed but host up) counts as 'Up'."""
    # errno values for connection-refused across platforms
    _conn_refused = {111, 61, 10061}
    test_ports = [80, 443, 22, 8080, 21, 25]
    for port in test_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            t0 = time.time()
            result = sock.connect_ex((str(ip), port))
            latency = round((time.time() - t0) * 1000, 2)
            sock.close()
            if result == 0 or result in _conn_refused:
                return True, latency
        except Exception:
            pass
    return False, None


def udp_ping(ip, timeout=1):
    """UDP probe to detect host liveness. Returns (is_up, latency_ms).
    Sends a minimal datagram to well-known UDP ports; an ICMP 'port unreachable'
    response (surfaced as ConnectionRefusedError) means the host is alive."""
    test_ports = [53, 137, 161, 123]
    per_port_timeout = max(0.3, timeout / len(test_ports))
    for port in test_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(per_port_timeout)
            t0 = time.time()
            sock.sendto(b'\x00' * 8, (str(ip), port))
            try:
                sock.recv(1024)
                latency = round((time.time() - t0) * 1000, 2)
                sock.close()
                return True, latency  # received UDP reply
            except socket.timeout:
                sock.close()
            except ConnectionRefusedError:
                latency = round((time.time() - t0) * 1000, 2)
                sock.close()
                return True, latency  # ICMP port unreachable → host is up
        except Exception:
            pass
    return False, None


def scan_ports(ip, ports, timeout=0.5):
    """TCP port scan. Returns a list of open-port dicts."""
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((str(ip), port))
            sock.close()
            if result == 0:
                open_ports.append({
                    "port": port,
                    "service": PORT_NAMES.get(port, "unknown"),
                    "state": "open",
                })
        except Exception:
            pass
    return open_ports


def scan_host(ip, mode="icmp", ports_to_scan=None):
    """Comprehensive per-host scan: ping + optional port scan."""
    host_info = {
        "ip": str(ip),
        "hostname": None,
        "status": "Down",
        "latency_ms": None,
        "scan_method": mode.upper(),
        "open_ports": [],
        "port_scan_performed": ports_to_scan is not None,
    }

    # Reverse DNS lookup
    try:
        host_info["hostname"] = socket.gethostbyaddr(str(ip))[0]
    except (socket.herror, socket.gaierror):
        pass

    # Ping based on selected mode
    if mode == "icmp":
        is_up, latency = icmp_ping(ip)
    elif mode == "tcp":
        is_up, latency = tcp_ping(str(ip))
    elif mode == "udp":
        is_up, latency = udp_ping(str(ip))
    else:
        is_up, latency = icmp_ping(ip)

    host_info["status"] = "Up" if is_up else "Down"
    host_info["latency_ms"] = latency

    # Port scan (run for every host when enabled, regardless of ping result)
    if ports_to_scan:
        host_info["open_ports"] = scan_ports(str(ip), ports_to_scan)

    return host_info


def append_scan_log(entry):
    """Appends a scan entry to the local JSON log file without overwriting previous entries."""
    with _log_lock:
        log = []
        if os.path.exists(SCAN_LOG_FILE):
            try:
                with open(SCAN_LOG_FILE, 'r') as f:
                    log = json.load(f)
            except (json.JSONDecodeError, IOError):
                log = []
        log.append(entry)
        with open(SCAN_LOG_FILE, 'w') as f:
            json.dump(log, f, indent=2)


@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


@app.route('/api/sweep', methods=['POST'])
def sweep():
    data = request.json or {}
    target_network = data.get('network')
    mode = (data.get('mode') or 'icmp').lower()
    port_scan = bool(data.get('port_scan', False))
    custom_ports = data.get('ports')  # comma-separated string or None

    if mode not in ('icmp', 'tcp', 'udp'):
        mode = 'icmp'

    if not target_network:
        return jsonify({"error": "Network is required (CIDR format)."}), 400

    try:
        network = ipaddress.ip_network(target_network, strict=False)
        hosts = list(network.hosts())
    except ValueError:
        return jsonify({"error": "Invalid CIDR network format."}), 400

    # Resolve which ports to scan
    ports_to_scan = None
    if port_scan:
        if custom_ports:
            try:
                parsed = [int(p.strip()) for p in str(custom_ports).split(',') if p.strip()]
                ports_to_scan = [p for p in parsed if 1 <= p <= 65535] or COMMON_PORTS
            except ValueError:
                ports_to_scan = COMMON_PORTS
        else:
            ports_to_scan = COMMON_PORTS

    results = []
    max_workers = min(100, max(10, len(hosts)))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {
            executor.submit(scan_host, ip, mode, ports_to_scan): ip for ip in hosts
        }
        for future in concurrent.futures.as_completed(future_to_ip):
            results.append(future.result())

    results = sorted(results, key=lambda x: ipaddress.IPv4Address(x['ip']))

    scan_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "network": target_network,
        "mode": mode,
        "port_scan": port_scan,
        "results": results,
    }
    append_scan_log(scan_entry)

    return jsonify({"network": target_network, "mode": mode, "results": results})


if __name__ == '__main__':
    app.run(debug=True, port=5000)
