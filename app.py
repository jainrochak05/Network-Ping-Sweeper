from flask import Flask, request, jsonify, send_from_directory
import subprocess
import ipaddress
import platform
import concurrent.futures

app = Flask(__name__, static_folder='static')


def ping_host(ip):
    """Pings a single IP address and returns its status."""
    system = platform.system().lower()
    count_param = '-n' if system == 'windows' else '-c'
    timeout_param = '-w' if system == 'windows' else '-W'
    timeout_val = '1000' if system == 'windows' else '1'

    command = ['ping', count_param, '1', timeout_param, timeout_val, str(ip)]

    try:
        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if output.returncode == 0:
            return {"ip": str(ip), "status": "Up"}
        return {"ip": str(ip), "status": "Down"}
    except Exception:
        return {"ip": str(ip), "status": "Error"}


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
    return jsonify({"network": target_network, "results": results})


if __name__ == '__main__':
    app.run(debug=True, port=5000)
