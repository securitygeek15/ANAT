from collections import defaultdict
from time import time

packet_counter = defaultdict(list)


def detect_packet_flood(src_ip):

    now = time()

    packet_counter[src_ip].append(now)

    packet_counter[src_ip] = [
        t for t in packet_counter[src_ip]
        if now - t <= 1
    ]

    if len(packet_counter[src_ip]) > 100:
        return True

    return False