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
from datetime import datetime, timezone

app = Flask(__name__, static_folder='static')

SCAN_LOG_FILE = 'scan_results.json'
_log_lock = threading.Lock()


def ping_host(ip):
    """Pings a single IP address and returns enriched host details."""
    system = platform.system().lower()
    count_param = '-n' if system == 'windows' else '-c'
    timeout_param = '-w' if system == 'windows' else '-W'
    timeout_val = '1000' if system == 'windows' else '1'

    command = ['ping', count_param, '1', timeout_param, timeout_val, str(ip)]

    host_info = {"ip": str(ip), "hostname": None, "status": "Down", "latency_ms": None}

    try:
        host_info["hostname"] = socket.gethostbyaddr(str(ip))[0]
    except (socket.herror, socket.gaierror):
        host_info["hostname"] = None

    try:
        output = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if output.returncode == 0:
            host_info["status"] = "Up"
            # Parse RTT from ping output (works on Linux/macOS and Windows)
            rtt_match = re.search(r'[=<]\s*([\d.]+)\s*ms', output.stdout)
            if rtt_match:
                host_info["latency_ms"] = round(float(rtt_match.group(1)), 2)
        else:
            host_info["status"] = "Down"
    except Exception:
        host_info["status"] = "Error"

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

    if not target_network:
        return jsonify({"error": "Network is required (CIDR format)."}), 400

    try:
        network = ipaddress.ip_network(target_network, strict=False)
        hosts = list(network.hosts())
    except ValueError:
        return jsonify({"error": "Invalid CIDR network format."}), 400

    results = []
    max_workers = min(100, max(10, len(hosts)))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(ping_host, ip): ip for ip in hosts}
        for future in concurrent.futures.as_completed(future_to_ip):
            results.append(future.result())

    results = sorted(results, key=lambda x: ipaddress.IPv4Address(x['ip']))

    scan_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "network": target_network,
        "results": results,
    }
    append_scan_log(scan_entry)

    return jsonify({"network": target_network, "results": results})


if __name__ == '__main__':
    app.run(debug=True, port=5000)
