import ipaddress
import os
from functools import lru_cache


@lru_cache(maxsize=1)
def trusted_networks():
    raw_sources = os.getenv("ANAT_TRUSTED_IPS", "")
    networks = []

    for raw_source in raw_sources.split(","):
        source = raw_source.strip()

        if not source:
            continue

        try:
            networks.append(ipaddress.ip_network(source, strict=False))
        except ValueError:
            continue

    return tuple(networks)


def is_trusted_source(src_ip):
    try:
        address = ipaddress.ip_address(src_ip)
    except ValueError:
        return False

    return any(address in network for network in trusted_networks())
