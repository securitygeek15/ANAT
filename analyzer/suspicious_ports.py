SUSPICIOUS_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    445: "SMB",
    3389: "RDP",
    3306: "MYSQL"
}


def detect_suspicious_port(port):
    return SUSPICIOUS_PORTS.get(port)