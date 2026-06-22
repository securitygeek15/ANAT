from flask import Flask, render_template
from sqlalchemy import func
from database.db import db
from database.models import Packet, Alert

import threading
import scanner.packet_sniffer as sniffer

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///network.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

with app.app_context():
    db.create_all()

sniffer.flask_app = app


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
    ).limit(10)

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

        # Stats
        total_packets=total_packets,
        total_alerts=total_alerts,

        # Alert counts
        high_alerts=high_alerts,
        medium_alerts=medium_alerts,
        low_alerts=low_alerts,

        # Recent alerts table
        alerts=recent_alerts,

        # Protocol chart
        tcp_count=tcp_count,
        udp_count=udp_count,

        # Top IP leaderboard
        top_ips=top_ips
    )

@app.route("/packets")
def packets():

    packets = Packet.query.order_by(
        Packet.id.desc()
    ).limit(100)

    return render_template(
        "packets.html",
        packets=packets
    )


@app.route("/alerts")
def alerts():

    alerts = Alert.query.order_by(
        Alert.id.desc()
    ).limit(100)

    return render_template(
        "alerts.html",
        alerts=alerts
    )


if __name__ == "__main__":

    thread = threading.Thread(
        target=sniffer.start_sniffer
    )

    thread.daemon = True
    thread.start()

    app.run(
        debug=True,
        use_reloader=False
    )