from datetime import datetime
import logging
import os
import json
import sys
import urllib.request

from scapy.all import conf, sniff
from scapy.layers.inet import IP, TCP, UDP

from database.db import db
from analyzer.rules import detect_port_scan
from analyzer.suspicious_ports import detect_suspicious_port
from analyzer.packet_rate import detect_syn_flood
from analyzer.alert_manager import should_alert
from analyzer.trusted_hosts import is_trusted_source

from database.models import Packet, Alert

flask_app = None
logger = logging.getLogger(__name__)


def require_flask_app():
    if flask_app is None:
        raise RuntimeError("packet sniffer needs scanner.packet_sniffer.flask_app to be set")
    return flask_app


def uses_windows_native_socket():
    return sys.platform == "win32" and not conf.use_pcap


def available_interfaces():
    return [
        (interface.name, interface.description or interface.name)
        for interface in conf.ifaces.values()
        if interface.name
    ]


def default_interface_name():
    return conf.iface.name


def local_ipv4_addresses():
    return {
        address
        for interface in conf.ifaces.values()
        for address in interface.ips.get(4, [])
        if address
    }


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
    gateway_ip = os.getenv("ANAT_GATEWAY_IP", "").strip()
    if not gateway_ip:
        gateway_ip = conf.route.route("0.0.0.0")[2]

    if (
        os.getenv("ANAT_IGNORE_GATEWAY_PACKETS", "1").strip().lower()
        not in {"0", "false", "no"}
        and gateway_ip
        and src_ip == gateway_ip
    ):
        logger.debug("Ignoring packet sourced by the local gateway %s", gateway_ip)
        return

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
    local_addresses = local_ipv4_addresses()
    initial_tcp_syn = (
        TCP in packet
        and bool(int(packet[TCP].flags) & 0x02)
        and not bool(int(packet[TCP].flags) & 0x10)
    )
    if (
        not initial_tcp_syn
        or dst_ip not in local_addresses
        or src_ip in local_addresses
    ):
        return

    if detect_port_scan(src_ip, dst_ip, port):
        save_alert(
            src_ip,
            "Port Scan",
            "HIGH",
            f"{src_ip} attempted connections to multiple ports on {dst_ip}"
        )

    service = detect_suspicious_port(port)
    if service:
        save_alert(
            src_ip,
            "Suspicious Port",
            "MEDIUM",
            f"Inbound connection attempt to {service} on port {port}"
        )

    if detect_syn_flood(src_ip, dst_ip, port):
        save_alert(
            src_ip,
            "SYN Flood",
            "HIGH",
            f"More than 100 initial TCP connection attempts per second from {src_ip} to {dst_ip}:{port}"
        )


stop_sniffer_flag = False

def should_stop_sniffer(packet):
    global stop_sniffer_flag
    return stop_sniffer_flag

def start_sniffer(iface=None):
    global stop_sniffer_flag
    stop_sniffer_flag = False

    kwargs = {
        "prn": process_packet,
        "store": False,
        "stop_filter": should_stop_sniffer
    }

    if uses_windows_native_socket():
        if iface and iface != "all":
            raise RuntimeError(
                "Selecting a specific interface on Windows requires Npcap. "
                "Without Npcap, ANAT listens for local IPv4 traffic on the default interface."
            )

        try:
            capture_socket = conf.L3socket()
        except OSError as exc:
            raise RuntimeError(
                "Windows packet capture requires Administrator privileges when "
                "Npcap is unavailable. Restart ANAT from an Administrator terminal."
            ) from exc

        try:
            sniff(opened_socket=capture_socket, **kwargs)
        finally:
            capture_socket.close()
        return

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
