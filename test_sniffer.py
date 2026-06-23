from app import app
from scanner import packet_sniffer

packet_sniffer.flask_app = app
packet_sniffer.start_sniffer()
