import csv
import os
from io import StringIO

from flask import Flask, Response, jsonify, render_template, request, stream_with_context
from sqlalchemy import func
from database.db import db
from database.models import Packet, Alert

import threading
import scanner.packet_sniffer as sniffer

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    "sqlite:///network-traffic.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

with app.app_context():
    db.create_all()

sniffer.flask_app = app


def start_background_sniffer():
    thread = threading.Thread(
        target=sniffer.start_sniffer,
        daemon=True,
        name="packet-sniffer"
    )
    thread.start()
    return thread


def parse_limit(default=100, maximum=500):
    try:
        limit = int(request.args.get("limit", default))
    except (TypeError, ValueError):
        return default

    return max(1, min(limit, maximum))


def serialize_packet(packet):
    return {
        "id": packet.id,
        "source_ip": packet.src_ip,
        "destination_ip": packet.dst_ip,
        "protocol": packet.protocol,
        "port": packet.port,
        "packet_size": packet.packet_size,
        "captured_at": packet.timestamp.isoformat() if packet.timestamp else None
    }


def serialize_alert(alert):
    return {
        "id": alert.id,
        "source_ip": alert.src_ip,
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "description": alert.description,
        "detected_at": alert.timestamp.isoformat() if alert.timestamp else None
    }


@app.route("/")
def home():

    total_packets = Packet.query.count()
    total_alerts = Alert.query.count()

    high_alerts = Alert.query.filter_by(
        severity="HIGH"
    ).count()

    medium_alerts = Alert.query.filter_by(
        severity="MEDIUM"
    ).count()

    low_alerts = Alert.query.filter_by(
        severity="LOW"
    ).count()

    recent_alerts = Alert.query.order_by(
        Alert.id.desc()
    ).limit(10).all()

    tcp_count = Packet.query.filter_by(
        protocol="TCP"
    ).count()

    udp_count = Packet.query.filter_by(
        protocol="UDP"
    ).count()

    top_ips = (
        db.session.query(
            Packet.src_ip,
            func.count(Packet.id)
        )
        .group_by(Packet.src_ip)
        .order_by(func.count(Packet.id).desc())
        .limit(5)
        .all()
    )

    return render_template(
        "dashboard.html",

        total_packets=total_packets,
        total_alerts=total_alerts,

        high_alerts=high_alerts,
        medium_alerts=medium_alerts,
        low_alerts=low_alerts,

        alerts=recent_alerts,

        tcp_count=tcp_count,
        udp_count=udp_count,

        top_ips=top_ips
    )

@app.route("/packets")
def packets():

    packets = Packet.query.order_by(
        Packet.id.desc()
    ).limit(100).all()

    return render_template(
        "packets.html",
        packets=packets
    )


@app.route("/alerts")
def alerts():

    alerts = Alert.query.order_by(
        Alert.id.desc()
    ).limit(100).all()

    return render_template(
        "alerts.html",
        alerts=alerts
    )


@app.route("/api/stats")
def api_stats():

    severity_counts = {
        "HIGH": Alert.query.filter_by(severity="HIGH").count(),
        "MEDIUM": Alert.query.filter_by(severity="MEDIUM").count(),
        "LOW": Alert.query.filter_by(severity="LOW").count()
    }

    protocol_counts = {
        "TCP": Packet.query.filter_by(protocol="TCP").count(),
        "UDP": Packet.query.filter_by(protocol="UDP").count(),
        "OTHER": Packet.query.filter_by(protocol="OTHER").count()
    }

    top_sources = (
        db.session.query(
            Packet.src_ip,
            func.count(Packet.id).label("packet_count")
        )
        .group_by(Packet.src_ip)
        .order_by(func.count(Packet.id).desc())
        .limit(5)
        .all()
    )

    recent_alerts = Alert.query.order_by(
        Alert.id.desc()
    ).limit(10).all()

    return jsonify({
        "totals": {
            "packets": Packet.query.count(),
            "alerts": Alert.query.count()
        },
        "severity": severity_counts,
        "protocols": protocol_counts,
        "top_sources": [
            {
                "source_ip": src_ip,
                "packet_count": packet_count
            }
            for src_ip, packet_count in top_sources
        ],
        "recent_alerts": [
            serialize_alert(alert)
            for alert in recent_alerts
        ]
    })


@app.route("/api/packets")
def api_packets():

    packets = Packet.query.order_by(
        Packet.id.desc()
    ).limit(parse_limit()).all()

    return jsonify({
        "packets": [
            serialize_packet(packet)
            for packet in packets
        ]
    })


@app.route("/api/alerts")
def api_alerts():

    alerts = Alert.query.order_by(
        Alert.id.desc()
    ).limit(parse_limit()).all()

    return jsonify({
        "alerts": [
            serialize_alert(alert)
            for alert in alerts
        ]
    })


def build_csv_response(filename, headers, rows):

    def generate():
        output = StringIO()
        writer = csv.writer(output)

        writer.writerow(headers)
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)

        for row in rows:
            writer.writerow(row)
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)

    return Response(
        stream_with_context(generate()),
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )


@app.route("/export/packets")
def export_packets():

    packets = Packet.query.order_by(
        Packet.id.desc()
    ).yield_per(500)

    rows = (
        [
            packet.id,
            packet.src_ip,
            packet.dst_ip,
            packet.protocol,
            packet.port,
            packet.packet_size,
            packet.timestamp.isoformat(sep=" ") if packet.timestamp else ""
        ]
        for packet in packets
    )

    return build_csv_response(
        "anat-packets.csv",
        [
            "id",
            "source_ip",
            "destination_ip",
            "protocol",
            "port",
            "packet_size",
            "captured_at"
        ],
        rows
    )


@app.route("/export/alerts")
def export_alerts():

    alerts = Alert.query.order_by(
        Alert.id.desc()
    ).yield_per(500)

    rows = (
        [
            alert.id,
            alert.src_ip,
            alert.alert_type,
            alert.description,
            alert.severity,
            alert.timestamp.isoformat(sep=" ") if alert.timestamp else ""
        ]
        for alert in alerts
    )

    return build_csv_response(
        "anat-alerts.csv",
        [
            "id",
            "source_ip",
            "alert_type",
            "description",
            "severity",
            "detected_at"
        ],
        rows
    )


if __name__ == "__main__":

    if os.getenv("ANAT_ENABLE_SNIFFER", "1") == "1":
        start_background_sniffer()

    debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"

    app.run(
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "5000")),
        debug=debug_mode,
        use_reloader=False
    )
