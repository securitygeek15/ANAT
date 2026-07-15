from datetime import datetime
import logging
import os
import json
import urllib.request

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


stop_sniffer_flag = False

def should_stop_sniffer(packet):
    global stop_sniffer_flag
    return stop_sniffer_flag

def start_sniffer(iface=None):
    global stop_sniffer_flag
    stop_sniffer_flag = False
    kwargs = {"prn": process_packet, "store": False, "stop_filter": should_stop_sniffer}
    if iface and iface != "all":
        kwargs["iface"] = iface
    sniff(**kwargs)

def stop_sniffer():
    global stop_sniffer_flag
    stop_sniffer_flag = True


def notify_discord(alert_type, severity, description, src_ip):
    webhook_url = os.getenv("DISCORD_WEBHOOK_URL")
    if not webhook_url:
        return
    
    if severity not in ("HIGH", "CRITICAL"):
        return
        
    data = {
        "content": f"🚨 **{severity} ALERT**: {alert_type} from `{src_ip}`\n> {description}"
    }
    
    req = urllib.request.Request(
        webhook_url, 
        data=json.dumps(data).encode("utf-8"), 
        headers={"Content-Type": "application/json"}
    )
    
    try:
        urllib.request.urlopen(req, timeout=3)
    except Exception as e:
        logger.error("Failed to send Discord webhook: %s", e)


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
    
    # Send Discord Webhook
    notify_discord(alert_type, severity, description, src_ip)
