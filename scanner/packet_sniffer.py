from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime
from database.db import db
from analyzer.rules import detect_port_scan
from analyzer.rules import detect_port_scan
from analyzer.suspicious_ports import detect_suspicious_port
from analyzer.packet_rate import detect_packet_flood
from analyzer.large_packet import detect_large_packet
from analyzer.alert_manager import should_alert

from database.models import Packet, Alert
flask_app = None


def save_packet(src_ip, dst_ip, protocol, port, packet_size):
    with flask_app.app_context():

        packet = Packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            port=port,
            packet_size=packet_size,
            timestamp=datetime.now()
        )

        db.session.add(packet)
        db.session.commit()


def process_packet(packet):

    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = "OTHER"
    port = 0

    if TCP in packet:
        protocol = "TCP"
        port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        port = packet[UDP].dport

    packet_size = len(packet)

    print(
        f"{src_ip} -> {dst_ip} | "
        f"{protocol} | Port {port}"
    )

    save_packet(
        src_ip,
        dst_ip,
        protocol,
        port,
        packet_size
    )
    if detect_port_scan(src_ip, port):

        print(f"[ALERT] Port Scan detected from {src_ip}")

        save_alert(
            src_ip,
            "Port Scan",
            "HIGH",
            f"Multiple ports touched by {src_ip}"
        )

    service = detect_suspicious_port(port)

    if service:

        print(f"[ALERT] {service} access")

        save_alert(
            src_ip,
            "Suspicious Port",
            "MEDIUM",
            f"Connection to {service} (Port {port})"
        )


    if detect_packet_flood(src_ip):

        print(f"[ALERT] Packet Flood")

        save_alert(
            src_ip,
            "Packet Flood",
            "HIGH",
            "High packet rate detected"
        )

    if detect_large_packet(packet_size):

        print(f"[ALERT] Large Packet")

        save_alert(
            src_ip,
            "Large Packet",
            "LOW",
            f"Packet size = {packet_size}"
        )

def start_sniffer():
    sniff(prn=process_packet, store=False)


def save_alert(src_ip, alert_type, severity, description):

    with flask_app.app_context():

        alert = Alert(
            src_ip=src_ip,
            alert_type=alert_type,
            severity=severity,
            description=description,
            timestamp=datetime.now()
        )

        db.session.add(alert)
        db.session.commit()