# ANAT - Network Anomaly Tracker

ANAT is a lightweight network intrusion detection dashboard for local network
monitoring. It captures live packets with Scapy, stores traffic metadata in
SQLite, runs simple anomaly rules, and shows packet and alert activity in a
Flask web interface.

The project is built for learning, demos, and small lab environments where you
want a quick view of what is moving across the network.

## Features

- Live packet capture with Scapy
- Flask dashboard with auto-refreshing network metrics
- SQLite storage through Flask-SQLAlchemy
- Packet explorer for recent captured traffic
- Security alert feed with severity labels
- CSV export for packets and alerts
- Protocol distribution chart for TCP and UDP traffic
- Alert severity chart for high, medium, and low detections
- Top source IP leaderboard
- Responsive dark security-operations UI
- Environment-based runtime configuration

## Detection Rules

ANAT currently includes these rule-based detections:

- Port scan detection: flags source IPs that touch many ports.
- Suspicious service ports: detects traffic to common risky services such as
  FTP, SSH, Telnet, SMB, RDP, and MySQL.
- Packet flood detection: flags high packet volume from a single source within a
  short time window.
- Large packet detection: flags packets larger than the configured threshold.
- Alert cooldowns: reduces repeated duplicate alerts from the same source and
  alert type.

## Dashboard Pages

- Overview: total packets, total alerts, critical threats, protocol mix, alert
  severity, recent detections, and top source IPs.
- Packets: latest captured packets with source IP, destination IP, protocol,
  destination port, size, and capture time.
- Alerts: latest detections with source IP, alert type, description, severity,
  and detection time.

## CSV Export

The app includes export endpoints for downloading stored data:

- `/export/packets` downloads `anat-packets.csv`
- `/export/alerts` downloads `anat-alerts.csv`

Exports are streamed so larger datasets do not need to be loaded into memory all
at once.

## Tech Stack

- Python
- Flask
- Flask-SQLAlchemy
- SQLite
- Scapy
- Chart.js
- HTML, CSS, and JavaScript

## Installation

```bash
git clone https://github.com/securitygeek15/ANAT.git
cd ANAT

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

Packet capture usually requires administrator/root privileges. On Windows, you
may also need Npcap installed for Scapy packet capture.

## Configuration

ANAT supports these environment variables:

- `DATABASE_URL`: SQLAlchemy database URL. Defaults to `sqlite:///network.db`.
- `ANAT_ENABLE_SNIFFER`: set to `0` to run the web app without packet capture.
- `FLASK_DEBUG`: set to `1` for local debugging only.
- `HOST`: bind address. Defaults to `127.0.0.1`.
- `PORT`: web server port. Defaults to `5000`.

Example:

```bash
set FLASK_DEBUG=1
set PORT=8000
python app.py
```

## Project Structure

```text
ANAT/
|-- analyzer/          # Detection rules and alert throttling
|-- database/          # SQLAlchemy setup and models
|-- scanner/           # Scapy packet capture
|-- static/            # CSS and dashboard JavaScript
|-- templates/         # Flask/Jinja pages
|-- app.py             # Flask app, routes, exports, sniffer startup
|-- requirements.txt   # Python dependencies
`-- README.md
```

