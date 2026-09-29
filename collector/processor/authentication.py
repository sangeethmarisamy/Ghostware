import re
import socket
import uuid
from datetime import datetime, timezone


seen_events = set()


def parse_authentication_event(raw_line):
    raw_line = raw_line.strip()

    login_pattern = re.search(
        r"^(\S+)\s+\S+\s+sshd-session\[\d+\]:\s+"
        r"Accepted password for (\S+) from (\S+) port \d+ ssh2",
        raw_line
    )

    if login_pattern:
        timestamp = login_pattern.group(1)
        username = login_pattern.group(2)
        source_ip = login_pattern.group(3)

        return {
            "source": "authentication",
            "timestamp": timestamp,
            "username": username,
            "source_ip": source_ip,
            "event_type": "login_success",
            "raw": raw_line
        }

    logout_pattern = re.search(
        r"^(\S+)\s+\S+\s+sshd-session\[\d+\]:\s+"
        r"pam_unix\(sshd:session\): session closed for user (\S+)",
        raw_line
    )

    if logout_pattern:
        timestamp = logout_pattern.group(1)
        username = logout_pattern.group(2)

        return {
            "source": "authentication",
            "timestamp": timestamp,
            "username": username,
            "source_ip": None,
            "event_type": "session_close",
            "raw": raw_line
        }

    return None


def validate_authentication_event(event):
    if not event:
        return False

    if event.get("source") != "authentication":
        return False

    if not isinstance(event.get("timestamp"), str):
        return False

    if not isinstance(event.get("username"), str) or not event["username"]:
        return False

    if event.get("event_type") not in (
        "login_success",
        "session_close"
    ):
        return False

    source_ip = event.get("source_ip")

    if source_ip is not None and not re.match(
        r"^[0-9a-fA-F:.]+$",
        source_ip
    ):
        return False

    return True


def deduplicate_authentication_event(event):
    fingerprint = (
        event["source"],
        event["timestamp"],
        event["username"],
        event["source_ip"],
        event["event_type"]
    )

    if fingerprint in seen_events:
        return False

    seen_events.add(fingerprint)
    return True


def normalize_authentication_event(event):
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": event.get(
            "timestamp",
            datetime.now(timezone.utc).isoformat()
        ),
        "hostname": socket.gethostname(),
        "source": "authentication",
        "event_type": event["event_type"],
        "source_ip": event["source_ip"],
        "metadata": {
            "username": event["username"]
        },
        "raw": event["raw"]
    }
