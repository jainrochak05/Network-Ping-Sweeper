# NetSweep Pro — Advanced Network Ping Sweeper

A network reconnaissance tool that performs ICMP/TCP/UDP ping sweeps over a CIDR range with optional port scanning, nmap-style host detail views, result filtering, and a modern dark-theme UI.

## Features

- **Three scan modes** — ICMP ping, TCP connect probe, or UDP probe (choose independently)
- **Port scanning** — scans 15 common ports by default; fully configurable with custom port lists
- **Host detail view** — click any host row to open a detail panel showing IP, hostname, status, latency, scan method, and all open ports
- **Result filtering** — filter by Up / Down / Has Open Ports / Fast (<10 ms)
- **Stats summary** — live counts for total, online, offline, average latency, and total open ports
- **Concurrent scanning** — thread-pool based; UI stays responsive during scans
- **Scan log** — every sweep is persisted to `scan_results.json` (never overwritten)
- **Modern UI** — dark terminal-inspired theme with responsive layout

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

Then open <http://127.0.0.1:5000> in your browser.

## Usage

1. **Enter a CIDR network**, e.g. `192.168.1.0/24` or a single host like `1.1.1.1/32`.
2. **Choose a scan mode**:
   - *ICMP Ping* — classic ping (fastest, requires ICMP not blocked)
   - *TCP Ping* — tries ports 80/443/22; works when ICMP is firewalled
   - *UDP Probe* — sends UDP datagrams to DNS/SNMP ports; detects hosts via ICMP port-unreachable
3. **Optionally enable Port Scan** and enter a custom comma-separated port list (or leave blank for the 15 default common ports).
4. Click **▶ Start Sweep**.
5. Use the **filter buttons** to narrow results.
6. **Click any row** to open the host detail modal.

### Default ports scanned
`21 (FTP)` · `22 (SSH)` · `23 (Telnet)` · `25 (SMTP)` · `53 (DNS)` · `80 (HTTP)` ·
`110 (POP3)` · `143 (IMAP)` · `443 (HTTPS)` · `445 (SMB)` · `3306 (MySQL)` ·
`3389 (RDP)` · `5432 (PostgreSQL)` · `8080 (HTTP-Alt)` · `8443 (HTTPS-Alt)`

## API

`POST /api/sweep`

```json
{
  "network":   "192.168.1.0/24",
  "mode":      "icmp",
  "port_scan": true,
  "ports":     "22,80,443"
}
```

Response:

```json
{
  "network": "192.168.1.0/24",
  "mode": "icmp",
  "results": [
    {
      "ip": "192.168.1.1",
      "hostname": "router.local",
      "status": "Up",
      "latency_ms": 1.23,
      "scan_method": "ICMP",
      "open_ports": [{"port": 80, "service": "HTTP", "state": "open"}],
      "port_scan_performed": true
    }
  ]
}
```

## Scan Log

Every sweep appends an entry to `scan_results.json` (excluded from version control via `.gitignore`).

## Notes on Ethical Use

Only scan networks you own or have explicit written permission to test. Unauthorised scanning may be illegal.

