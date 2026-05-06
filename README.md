# Network Ping Sweeper

A simple ethical hacking lab project that performs a ping sweep over a CIDR network and displays live host results in a basic web UI.

## Features
- CIDR-based network sweep using ICMP ping
- Concurrent scanning for faster results
- Minimal single-page UI for quick demos
- Clean JSON API endpoint

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

## Notes on Ethical Use
Only scan networks you own or have explicit permission to test. Many environments block ICMP, so consider testing on a lab subnet or VM network.
