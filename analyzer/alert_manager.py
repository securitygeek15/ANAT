from time import time

recent_alerts = {}

COOLDOWN = 30


def should_alert(src_ip, alert_type):

    key = f"{src_ip}:{alert_type}"

    now = time()

    if key not in recent_alerts:
        recent_alerts[key] = now
        return True

    if now - recent_alerts[key] > COOLDOWN:
        recent_alerts[key] = now
        return True

    return False