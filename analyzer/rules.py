from collections import defaultdict
from time import monotonic

SCAN_WINDOW_SECONDS = 60
SCAN_PORT_THRESHOLD = 10

port_history = defaultdict(list)
already_alerted = set()


def detect_port_scan(src_ip, dst_ip, port, now=None):
    now = monotonic() if now is None else now
    key = (src_ip, dst_ip)
    recent_ports = [
        (seen_at, seen_port)
        for seen_at, seen_port in port_history[key]
        if now - seen_at <= SCAN_WINDOW_SECONDS
    ]
    recent_ports.append((now, port))
    port_history[key] = recent_ports

    if len({seen_port for _, seen_port in recent_ports}) <= SCAN_PORT_THRESHOLD:
        return False

    if key in already_alerted:
        return False

    already_alerted.add(key)
    return True