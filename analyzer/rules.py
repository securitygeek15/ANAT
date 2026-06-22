from collections import defaultdict

port_history = defaultdict(set)
already_alerted = set()


def detect_port_scan(src_ip, port):

    port_history[src_ip].add(port)

    if len(port_history[src_ip]) > 10:

        if src_ip not in already_alerted:

            already_alerted.add(src_ip)

            return True

    return False