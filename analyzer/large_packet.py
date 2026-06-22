def detect_large_packet(packet_size):

    if packet_size > 1500:
        return True

    return False