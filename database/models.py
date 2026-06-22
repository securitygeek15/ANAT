from database.db import db


class Packet(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    src_ip = db.Column(db.String(50))
    dst_ip = db.Column(db.String(50))

    protocol = db.Column(db.String(20))
    port = db.Column(db.Integer)

    packet_size = db.Column(db.Integer)

    timestamp = db.Column(db.DateTime)


class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    src_ip = db.Column(db.String(50))

    alert_type = db.Column(db.String(50))

    severity = db.Column(db.String(20))

    description = db.Column(db.String(200))

    timestamp = db.Column(db.DateTime)