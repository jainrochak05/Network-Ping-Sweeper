# Network Ping Sweeper

A simple ethical hacking lab project that performs a ping sweep over a CIDR network and displays live host results in a basic web UI.

## Features
- CIDR-based network sweep using ICMP ping
- Concurrent scanning for faster results
- Enriched host details: hostname (reverse DNS) and round-trip latency
- Minimal single-page UI showing IP, hostname, status, and latency
- Clean JSON API endpoint
- Scan results persisted to `scan_results.json` — each sweep appends a new timestamped entry, nothing is overwritten

## Setup
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run
```bash
python app.py
```
Then open http://127.0.0.1:5000 in your browser.

## Usage
Enter a network in CIDR format, for example:
```
192.168.1.0/24
```
The UI will display host status results for the scan.

## Scan Log
Every sweep call appends an entry to `scan_results.json` in the project root. Each entry looks like:
```json
{
  "timestamp": "2024-01-15T10:30:00.123456+00:00",
  "network": "192.168.1.0/24",
  "results": [
    {"ip": "192.168.1.1", "hostname": "router.local", "status": "Up", "latency_ms": 1.23},
    {"ip": "192.168.1.2", "hostname": null, "status": "Down", "latency_ms": null}
  ]
}
```
The file is excluded from version control via `.gitignore`.

## Notes on Ethical Use
Only scan networks you own or have explicit permission to test. Many environments block ICMP, so consider testing on a lab subnet or VM network.

