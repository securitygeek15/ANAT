import csv
import os
from io import StringIO

from flask import Flask, Response, jsonify, render_template, request, stream_with_context
from sqlalchemy import func, or_
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


def clean_arg(name):
    return request.args.get(name, "").strip()


def packet_filter_values():
    return {
        "q": clean_arg("q"),
        "src_ip": clean_arg("src_ip"),
        "dst_ip": clean_arg("dst_ip"),
        "protocol": clean_arg("protocol").upper(),
        "port": clean_arg("port")
    }


def alert_filter_values():
    return {
        "q": clean_arg("q"),
        "src_ip": clean_arg("src_ip"),
        "severity": clean_arg("severity").upper(),
        "alert_type": clean_arg("alert_type")
    }


def parse_port(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def filtered_packet_query(filters):
    query = Packet.query

    if filters["q"]:
        pattern = f"%{filters['q']}%"
        query = query.filter(or_(
            Packet.src_ip.ilike(pattern),
            Packet.dst_ip.ilike(pattern),
            Packet.protocol.ilike(pattern)
        ))

    if filters["src_ip"]:
        query = query.filter(Packet.src_ip.ilike(f"%{filters['src_ip']}%"))

    if filters["dst_ip"]:
        query = query.filter(Packet.dst_ip.ilike(f"%{filters['dst_ip']}%"))

    if filters["protocol"] in {"TCP", "UDP", "OTHER"}:
        query = query.filter(Packet.protocol == filters["protocol"])

    if filters["port"]:
        port = parse_port(filters["port"])
        if port is not None:
            query = query.filter(Packet.port == port)

    return query


def filtered_alert_query(filters):
    query = Alert.query

    if filters["q"]:
        pattern = f"%{filters['q']}%"
        query = query.filter(or_(
            Alert.src_ip.ilike(pattern),
            Alert.alert_type.ilike(pattern),
            Alert.description.ilike(pattern),
            Alert.severity.ilike(pattern)
        ))

    if filters["src_ip"]:
        query = query.filter(Alert.src_ip.ilike(f"%{filters['src_ip']}%"))

    if filters["severity"] in {"HIGH", "MEDIUM", "LOW"}:
        query = query.filter(Alert.severity == filters["severity"])

    if filters["alert_type"]:
        query = query.filter(Alert.alert_type.ilike(f"%{filters['alert_type']}%"))

    return query


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

    filters = packet_filter_values()
    query = filtered_packet_query(filters)

    result_count = query.count()

    packets = query.order_by(
        Packet.id.desc()
    ).limit(100).all()

    return render_template(
        "packets.html",
        packets=packets,
        filters=filters,
        result_count=result_count
    )


@app.route("/alerts")
def alerts():

    filters = alert_filter_values()
    query = filtered_alert_query(filters)

    result_count = query.count()

    alerts = query.order_by(
        Alert.id.desc()
    ).limit(100).all()

    return render_template(
        "alerts.html",
        alerts=alerts,
        filters=filters,
        result_count=result_count
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

    filters = packet_filter_values()

    packets = filtered_packet_query(filters).order_by(
        Packet.id.desc()
    ).limit(parse_limit()).all()

    return jsonify({
        "filters": filters,
        "packets": [
            serialize_packet(packet)
            for packet in packets
        ]
    })


@app.route("/api/alerts")
def api_alerts():

    filters = alert_filter_values()

    alerts = filtered_alert_query(filters).order_by(
        Alert.id.desc()
    ).limit(parse_limit()).all()

    return jsonify({
        "filters": filters,
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

    packets = filtered_packet_query(packet_filter_values()).order_by(
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

    alerts = filtered_alert_query(alert_filter_values()).order_by(
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
