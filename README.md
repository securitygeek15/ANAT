# 🛡️ ANAT - AI Network Anomaly Tracker

ANAT is a lightweight real-time Intrusion Detection System (IDS) built with Python, Flask, Scapy, and SQLite. It captures network traffic, detects suspicious activity, and visualizes alerts through an interactive dashboard.

## ✨ Features

- 📡 Real-time packet capture with Scapy
- 🚨 Port scan detection
- ⚠️ Suspicious port detection
- 🌊 Packet flood detection
- 📦 Large packet detection
- 🗄️ SQLite database storage
- 📊 Interactive dashboard with Chart.js
- 🏆 Top source IP leaderboard
- 🔄 Auto-refreshing interface
- 🎨 Cyberpunk-inspired UI

## 🛠️ Tech Stack

- Python
- Flask
- SQLite
- SQLAlchemy
- Scapy
- Bootstrap 5
- Chart.js

## 📁 Project Structure

```text
ANAT/
├── analyzer/
├── database/
├── scanner/
├── static/
├── templates/
├── instance/
├── app.py
├── requirements.txt
└── README.md
```

## 🚀 Installation

```bash
git clone https://github.com/securitygeek15/ANAT.git
cd ANAT

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt

python app.py
```

Open:

```
http://127.0.0.1:5000
```

## 📸 Dashboard

Real-time monitoring of:

- Network packets
- Alert severity
- Protocol distribution
- Top source IPs
- Recent alerts

## 🔮 Roadmap

- AI anomaly detection
- CSV export
- Packet search and filters
- Discord webhook alerts
- GeoIP attacker map
- Docker support

---

⭐ If you found this project useful, consider giving it a star.