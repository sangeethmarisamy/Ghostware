import re
import socket
import uuid
from datetime import datetime, timezone


seen_events = set()


def parse_command_event(raw_line):
    raw_line = raw_line.strip()

    source_ip = None

    ip_match = re.search(r"\[SOURCE_IP=([^\]]+)\]", raw_line)

    if ip_match:
        source_ip = ip_match.group(1)

    clean_line = re.sub(r"\[SOURCE_IP=[^\]]+\]\s*", "", raw_line)

    command_pattern = re.search(
        r"^(\S+)\s+\S+\s+sudo\[(\d+)\]:\s+"
        r"(\S+)\s+:\s+TTY=(\S+)\s*;\s+"
        r"PWD=(.*?)\s*;\s+USER=(\S+)\s*;\s+"
        r"COMMAND=(.+)$",
        clean_line
    )

    if command_pattern:
        timestamp = command_pattern.group(1)
        pid = command_pattern.group(2)
        username = command_pattern.group(3)
        tty = command_pattern.group(4)
        pwd = command_pattern.group(5)
        target_user = command_pattern.group(6)
        command = command_pattern.group(7)

        return {
            "source": "command",
            "timestamp": timestamp,
            "pid": pid,
            "username": username,
            "tty": tty,
            "pwd": pwd,
            "target_user": target_user,
            "command": command,
            "source_ip": source_ip,
            "event_type": "command_execution",
            "raw": raw_line
        }

    session_pattern = re.search(
        r"^(\S+)\s+\S+\s+sudo\[(\d+)\]:\s+"
        r"pam_unix\(sudo:session\): session "
        r"(opened|closed) for user ([^( \t]+)"
        r"(?:\(uid=(\d+)\))?",
        clean_line
    )

    if session_pattern:
        timestamp = session_pattern.group(1)
        pid = session_pattern.group(2)
        action = session_pattern.group(3)
        target_user = session_pattern.group(4)

        event_type = (
            "sudo_session_open"
            if action == "opened"
            else "sudo_session_close"
        )

        return {
            "source": "command",
            "timestamp": timestamp,
            "pid": pid,
            "username": None,
            "tty": None,
            "pwd": None,
            "target_user": target_user,
            "command": None,
            "source_ip": source_ip,
            "event_type": event_type,
            "raw": raw_line
        }

    return None


def validate_command_event(event):
    if not event:
        return False

    if event.get("source") != "command":
        return False

    if not isinstance(event.get("timestamp"), str):
        return False

    if not isinstance(event.get("pid"), str) or not event["pid"].isdigit():
        return False

    event_type = event.get("event_type")

    if event_type == "command_execution":
        if not isinstance(event.get("username"), str) or not event["username"]:
            return False

        if not isinstance(event.get("tty"), str) or not event["tty"]:
            return False

        if not isinstance(event.get("target_user"), str) or not event["target_user"]:
            return False

        if not isinstance(event.get("command"), str) or not event["command"]:
            return False

    elif event_type in (
        "sudo_session_open",
        "sudo_session_close"
    ):
        if not isinstance(event.get("target_user"), str) or not event["target_user"]:
            return False

    else:
        return False

    source_ip = event.get("source_ip")

    if source_ip is not None and not re.match(
        r"^[0-9a-fA-F:.]+$",
        source_ip
    ):
        return False

    return True


def deduplicate_command_event(event):
    fingerprint = (
        event["source"],
        event["timestamp"],
        event["pid"],
        event["username"],
        event["tty"],
        event["command"],
        event["event_type"],
        event["source_ip"]
    )

    if fingerprint in seen_events:
        return False

    seen_events.add(fingerprint)
    return True


def normalize_command_event(event):
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": event.get(
            "timestamp",
            datetime.now(timezone.utc).isoformat()
        ),
        "hostname": socket.gethostname(),
        "source": "command",
        "event_type": event["event_type"],
        "source_ip": event["source_ip"],
        "metadata": {
            "pid": event["pid"],
            "username": event["username"],
            "tty": event["tty"],
            "pwd": event["pwd"],
            "target_user": event["target_user"],
            "command": event["command"]
        },
        "raw": event["raw"]
    }
