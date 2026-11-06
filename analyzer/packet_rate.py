from collections import defaultdict
from time import monotonic

SYN_FLOOD_WINDOW_SECONDS = 1
SYN_FLOOD_THRESHOLD = 100

syn_history = defaultdict(list)


def detect_syn_flood(src_ip, dst_ip, dst_port, now=None):
    now = monotonic() if now is None else now
    key = (src_ip, dst_ip, dst_port)
    recent_syns = [
        t for t in syn_history[key]
        if now - t <= SYN_FLOOD_WINDOW_SECONDS
    ]
    recent_syns.append(now)
    syn_history[key] = recent_syns

    return len(recent_syns) > SYN_FLOOD_THRESHOLD