import re
import socket
import uuid
from datetime import datetime, timezone


seen_events = set()


def parse_cron_event(raw_line):
    raw_line = raw_line.strip()

    if not raw_line:
        return None

    pattern = re.search(
        r"^(\S+)\s+\S+\s+CRON\[(\d+)\]:\s+\((\S+)\)\s+CMD\s+\((.+)\)$",
        raw_line
    )

    if not pattern:
        return None

    timestamp = pattern.group(1)
    pid = pattern.group(2)
    username = pattern.group(3)
    command = pattern.group(4)

    return {
        "source": "cron",
        "timestamp": timestamp,
        "pid": pid,
        "username": username,
        "command": command,
        "source_ip": None,
        "event_type": "scheduled_task",
        "raw": raw_line
    }


def validate_cron_event(event):
    if not event or event.get("source") != "cron":
        return False

    if not isinstance(event.get("timestamp"), str):
        return False

    if not isinstance(event.get("pid"), str) or not event["pid"].isdigit():
        return False

    if not isinstance(event.get("username"), str) or not event["username"]:
        return False

    if not isinstance(event.get("command"), str) or not event["command"]:
        return False

    if event.get("event_type") != "scheduled_task":
        return False

    return True


def deduplicate_cron_event(event):
    fingerprint = (
        event["source"],
        event["timestamp"],
        event["pid"],
        event["username"],
        event["command"]
    )

    if fingerprint in seen_events:
        return False

    seen_events.add(fingerprint)
    return True


def normalize_cron_event(event):
    if not validate_cron_event(event):
        return None

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": event.get(
            "timestamp",
            datetime.now(timezone.utc).isoformat()
        ),
        "hostname": socket.gethostname(),
        "source": "cron",
        "event_type": event["event_type"],
        "source_ip": event.get("source_ip"),
        "metadata": {
            "pid": event["pid"],
            "username": event["username"],
            "command": event["command"]
        },
        "raw": event["raw"]
    }
