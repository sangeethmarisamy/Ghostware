import re
import socket
import uuid
from datetime import datetime, timezone


seen_events = set()


def parse_network_event(raw_line):
    raw_line = raw_line.strip()

    if not raw_line:
        return None

    parts = raw_line.split("\t")

    if len(parts) != 14:
        return None

    (
        timestamp,
        interface,
        ipv4_src,
        ipv4_dst,
        ipv6_src,
        ipv6_dst,
        protocol,
        ipv6_next_header,
        tcp_src_port,
        tcp_dst_port,
        tcp_flags,
        udp_src_port,
        udp_dst_port,
        frame_length,
        *extra
    ) = parts

    if extra:
        return None

    return {
        "source": "network",
        "timestamp": timestamp,
        "interface": interface,
        "ipv4_src": ipv4_src,
        "ipv4_dst": ipv4_dst,
        "ipv6_src": ipv6_src,
        "ipv6_dst": ipv6_dst,
        "protocol": protocol,
        "ipv6_next_header": ipv6_next_header,
        "tcp_src_port": tcp_src_port,
        "tcp_dst_port": tcp_dst_port,
        "tcp_flags": tcp_flags,
        "udp_src_port": udp_src_port,
        "udp_dst_port": udp_dst_port,
        "frame_length": frame_length,
        "event_type": "network_packet",
        "raw": raw_line
    }


def validate_network_event(event):
    if not event or event.get("source") != "network":
        return False

    if not isinstance(event.get("timestamp"), str):
        return False

    if not isinstance(event.get("interface"), str) or not event["interface"]:
        return False

    if (
        not isinstance(event.get("protocol"), str)
        or not isinstance(event.get("ipv6_next_header"), str)
    ):
        return False

    if not event["protocol"] and not event["ipv6_next_header"]:
        return False

    if not isinstance(event.get("frame_length"), str):
        return False

    if not event["frame_length"].isdigit():
        return False

    if event.get("event_type") != "network_packet":
        return False

    return True


def deduplicate_network_event(event):
    fingerprint = (
        event["source"],
        event["timestamp"],
        event["interface"],
        event["ipv4_src"],
        event["ipv4_dst"],
        event["ipv6_src"],
        event["ipv6_dst"],
        event["protocol"],
        event["tcp_src_port"],
        event["tcp_dst_port"],
        event["tcp_flags"],
        event["udp_src_port"],
        event["udp_dst_port"],
        event["frame_length"],
    )

    if fingerprint in seen_events:
        return False

    seen_events.add(fingerprint)
    return True


def normalize_network_event(event):
    if not validate_network_event(event):
        return None

    source_ip = None

    if event["ipv4_src"]:
        source_ip = event["ipv4_src"]
    elif event["ipv6_src"]:
        source_ip = event["ipv6_src"]

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": event.get(
            "timestamp",
            datetime.now(timezone.utc).isoformat()
        ),
        "hostname": socket.gethostname(),
        "source": "network",
        "event_type": event["event_type"],
        "source_ip": source_ip,
        "metadata": {
            "interface": event["interface"],
            "ipv4_src": event["ipv4_src"],
            "ipv4_dst": event["ipv4_dst"],
            "ipv6_src": event["ipv6_src"],
            "ipv6_dst": event["ipv6_dst"],
            "protocol": (
                event["protocol"]
                if event["protocol"]
                else event["ipv6_next_header"]
            ),
            "ipv6_next_header": event["ipv6_next_header"],
            "tcp_src_port": event["tcp_src_port"],
            "tcp_dst_port": event["tcp_dst_port"],
            "tcp_flags": event["tcp_flags"],
            "udp_src_port": event["udp_src_port"],
            "udp_dst_port": event["udp_dst_port"],
            "frame_length": event["frame_length"],
        },
        "raw": event["raw"]
    }
