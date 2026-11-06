import csv
import os
import time
import datetime
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


sniffer_thread = None
capture_state_lock = threading.Lock()
capture_state = {
    "status": "not_started",
    "message": "Packet capture has not been started."
}


def set_capture_state(status, message):
    with capture_state_lock:
        capture_state["status"] = status
        capture_state["message"] = message


def run_sniffer(iface):
    if sniffer.uses_windows_native_socket():
        message = (
            "Windows native IPv4 capture is running on "
            f"{sniffer.default_interface_name()}."
        )
    else:
        message = "Packet capture is running."
    set_capture_state("running", message)
    try:
        sniffer.start_sniffer(iface)
    except Exception as exc:
        app.logger.exception("Packet capture stopped unexpectedly")
        set_capture_state("error", str(exc))
    else:
        set_capture_state("stopped", "Packet capture has stopped.")


@app.context_processor
def inject_capture_state():
    with capture_state_lock:
        state = dict(capture_state)
    state["native_windows_capture"] = sniffer.uses_windows_native_socket()
    return {
        "capture_state": state,
        "capture_interfaces": sniffer.available_interfaces()
    }

def start_background_sniffer(iface=None):
    global sniffer_thread
    if sniffer_thread and sniffer_thread.is_alive():
        sniffer.stop_sniffer()
        sniffer_thread.join(timeout=2)

    set_capture_state("starting", "Starting packet capture.")
    sniffer_thread = threading.Thread(
        target=run_sniffer,
        args=(iface,),
        daemon=True,
        name="packet-sniffer"
    )
    sniffer_thread.start()
    return sniffer_thread


def start_background_cleanup():
    def cleanup_task():
        while True:
            with app.app_context():
                try:
                    retention_days = int(os.getenv("ANAT_RETENTION_DAYS", "30"))
                    if retention_days > 0:
                        cutoff_date = datetime.datetime.utcnow() - datetime.timedelta(days=retention_days)
                        Packet.query.filter(Packet.timestamp < cutoff_date).delete()
                        Alert.query.filter(Alert.timestamp < cutoff_date).delete()
                        db.session.commit()
                except Exception as e:
                    print(f"Error in cleanup task: {e}")
            
            # Sleep for 6 hours
            time.sleep(21600)

    thread = threading.Thread(
        target=cleanup_task,
        daemon=True,
        name="db-cleanup"
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


@app.route("/api/interface", methods=["POST"])
def change_interface():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Missing JSON"}), 400

    iface = data.get("interface")
    if not isinstance(iface, str):
        return jsonify({"error": "Interface must be a string"}), 400
    if iface != "all":
        available = {name for name, _ in sniffer.available_interfaces()}
        if sniffer.uses_windows_native_socket():
            return jsonify({
                "error": "Selecting an interface requires Npcap on Windows."
            }), 400
        if iface not in available:
            return jsonify({"error": "Unknown network interface"}), 400

    start_background_sniffer(iface)
    return jsonify({"status": "success", "interface": iface})


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
    else:
        set_capture_state("disabled", "Live packet capture is disabled.")

    if os.getenv("ANAT_ENABLE_CLEANUP", "1") == "1":
        start_background_cleanup()

    debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"

    app.run(
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "5000")),
        debug=debug_mode,
        use_reloader=False
    )
