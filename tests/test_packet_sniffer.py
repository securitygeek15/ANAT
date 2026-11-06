import unittest
from unittest import mock

from flask import Flask
from scapy.layers.inet import IP, TCP

from analyzer import alert_manager, packet_rate, rules
from database.db import db
from database.models import Alert, Packet
from scanner import packet_sniffer


class PacketSnifferTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
        self.app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
        db.init_app(self.app)
        with self.app.app_context():
            db.create_all()

        packet_sniffer.flask_app = self.app
        alert_manager.recent_alerts.clear()
        packet_rate.syn_history.clear()
        rules.port_history.clear()
        rules.already_alerted.clear()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
            db.engine.dispose()
        packet_sniffer.flask_app = None

    def test_windows_without_pcap_uses_native_layer_three_socket(self):
        capture_socket = mock.Mock()
        with (
            mock.patch.object(
                packet_sniffer, "uses_windows_native_socket", return_value=True
            ),
            mock.patch.object(
                packet_sniffer.conf, "L3socket", return_value=capture_socket
            ),
            mock.patch.object(packet_sniffer, "sniff") as sniff,
        ):
            packet_sniffer.start_sniffer()

        sniff.assert_called_once()
        self.assertIs(sniff.call_args.kwargs["opened_socket"], capture_socket)
        capture_socket.close.assert_called_once_with()

    def test_windows_native_socket_reports_missing_admin_privileges(self):
        with (
            mock.patch.object(
                packet_sniffer, "uses_windows_native_socket", return_value=True
            ),
            mock.patch.object(
                packet_sniffer.conf,
                "L3socket",
                side_effect=PermissionError("permission denied"),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "Administrator privileges"):
                packet_sniffer.start_sniffer()

    def test_packet_processing_persists_packet_and_suspicious_port_alert(self):
        with mock.patch.object(
            packet_sniffer, "local_ipv4_addresses", return_value={"192.0.2.1"}
        ):
            packet_sniffer.process_packet(
                IP(src="198.51.100.40", dst="192.0.2.1")
                / TCP(dport=22, flags="S")
            )

        with self.app.app_context():
            packet = Packet.query.one()
            alert = Alert.query.filter_by(alert_type="Suspicious Port").one()
            self.assertEqual(packet.src_ip, "198.51.100.40")
            self.assertEqual(packet.protocol, "TCP")
            self.assertEqual(packet.port, 22)
            self.assertEqual(alert.severity, "MEDIUM")

    def test_https_replies_and_large_packets_do_not_create_alerts(self):
        with mock.patch.object(
            packet_sniffer, "local_ipv4_addresses", return_value={"192.0.2.1"}
        ):
            packet_sniffer.process_packet(
                IP(src="203.0.113.8", dst="192.0.2.1")
                / TCP(dport=53124, flags="A")
                / (b"x" * 2000)
            )
            packet_sniffer.process_packet(
                IP(src="203.0.113.8", dst="192.0.2.1")
                / TCP(dport=443, flags="S")
                / (b"x" * 2000)
            )

        with self.app.app_context():
            self.assertEqual(Packet.query.count(), 2)
            self.assertEqual(Alert.query.count(), 0)

    def test_outbound_https_syn_does_not_trigger_port_scan(self):
        with mock.patch.object(
            packet_sniffer, "local_ipv4_addresses", return_value={"192.0.2.1"}
        ):
            for port in range(443, 455):
                packet_sniffer.process_packet(
                    IP(src="192.0.2.1", dst="203.0.113.8")
                    / TCP(dport=port, flags="S")
                )

        with self.app.app_context():
            self.assertEqual(Packet.query.count(), 12)
            self.assertEqual(Alert.query.count(), 0)

    def test_port_scan_requires_more_than_ten_unique_ports_to_one_host(self):
        for port in range(1000, 1010):
            self.assertFalse(
                rules.detect_port_scan("198.51.100.40", "192.0.2.1", port, now=0)
            )
        self.assertTrue(
            rules.detect_port_scan("198.51.100.40", "192.0.2.1", 1010, now=0)
        )

    def test_inbound_scan_to_local_host_creates_alert(self):
        with mock.patch.object(
            packet_sniffer, "local_ipv4_addresses", return_value={"192.0.2.1"}
        ):
            for port in range(1000, 1011):
                packet_sniffer.process_packet(
                    IP(src="198.51.100.40", dst="192.0.2.1")
                    / TCP(dport=port, flags="S")
                )

        with self.app.app_context():
            alert = Alert.query.filter_by(alert_type="Port Scan").one()
            self.assertEqual(alert.severity, "HIGH")
            self.assertIn("198.51.100.40", alert.description)

    def test_syn_flood_requires_more_than_one_hundred_attempts_per_second(self):
        for _ in range(100):
            self.assertFalse(
                packet_rate.detect_syn_flood(
                    "198.51.100.40", "192.0.2.1", 443, now=0
                )
            )
        self.assertTrue(
            packet_rate.detect_syn_flood(
                "198.51.100.40", "192.0.2.1", 443, now=0
            )
        )

    def test_gateway_source_packet_is_not_saved_or_analyzed(self):
        with mock.patch.dict(
            "os.environ",
            {
                "ANAT_IGNORE_GATEWAY_PACKETS": "1",
                "ANAT_GATEWAY_IP": "192.168.1.1",
            },
        ):
            packet_sniffer.process_packet(
                IP(src="192.168.1.1", dst="192.168.1.20") / TCP(dport=22)
            )

        with self.app.app_context():
            self.assertEqual(Packet.query.count(), 0)
            self.assertEqual(Alert.query.count(), 0)


if __name__ == "__main__":
    unittest.main()
