from datetime import datetime
import logging

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

from database.db import db
from analyzer.rules import detect_port_scan
from analyzer.suspicious_ports import detect_suspicious_port
from analyzer.packet_rate import detect_packet_flood
from analyzer.large_packet import detect_large_packet
from analyzer.alert_manager import should_alert
from analyzer.trusted_hosts import is_trusted_source

from database.models import Packet, Alert

flask_app = None
logger = logging.getLogger(__name__)


def require_flask_app():
    if flask_app is None:
        raise RuntimeError("packet sniffer needs scanner.packet_sniffer.flask_app to be set")
    return flask_app


def save_packet(src_ip, dst_ip, protocol, port, packet_size):
    with require_flask_app().app_context():

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

    save_packet(
        src_ip,
        dst_ip,
        protocol,
        port,
        packet_size
    )
    if detect_port_scan(src_ip, port):

        save_alert(
            src_ip,
            "Port Scan",
            "HIGH",
            f"Multiple ports touched by {src_ip}"
        )

    service = detect_suspicious_port(port)

    if service:

        save_alert(
            src_ip,
            "Suspicious Port",
            "MEDIUM",
            f"Connection to {service} (Port {port})"
        )


    if detect_packet_flood(src_ip):

        save_alert(
            src_ip,
            "Packet Flood",
            "HIGH",
            "High packet rate detected"
        )

    if detect_large_packet(packet_size):

        save_alert(
            src_ip,
            "Large Packet",
            "LOW",
            f"Packet size = {packet_size}"
        )


def start_sniffer():
    sniff(prn=process_packet, store=False)


def save_alert(src_ip, alert_type, severity, description):
    if is_trusted_source(src_ip):
        logger.info("[TRUSTED] Suppressed %s from %s", alert_type, src_ip)
        return

    if not should_alert(src_ip, alert_type):
        return

    logger.warning("[ALERT] %s from %s: %s", alert_type, src_ip, description)

    with require_flask_app().app_context():

        alert = Alert(
            src_ip=src_ip,
            alert_type=alert_type,
            severity=severity,
            description=description,
            timestamp=datetime.now()
        )

        db.session.add(alert)
        db.session.commit()
