import re
import socket
import uuid
from datetime import datetime, timezone


seen_events = set()


def parse_process_event(raw_line):
    raw_line = raw_line.strip()

    if not raw_line:
        return None

    source_ip = None

    ip_match = re.search(r"\[SOURCE_IP=([^\]]+)\]", raw_line)

    if ip_match:
        source_ip = ip_match.group(1)

    clean_line = re.sub(r"\[SOURCE_IP=[^\]]+\]\s*", "", raw_line)

    if not clean_line.startswith("type=SYSCALL"):
        return None

    def get_field(name):
        match = re.search(
            rf"\b{name}=([^\s]+)",
            clean_line
        )
        return match.group(1).strip('"') if match else None

    timestamp = None

    human_timestamp_match = re.search(
        r"msg=audit\((\d{2}/\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2}\.\d+):",
        clean_line
    )

    epoch_timestamp_match = re.search(
        r"msg=audit\((\d+\.\d+):",
        clean_line
    )

    if human_timestamp_match:
        timestamp = (
            f"20{human_timestamp_match.group(1)[-2:]}-"
            f"{human_timestamp_match.group(1)[3:5]}-"
            f"{human_timestamp_match.group(1)[0:2]}T"
            f"{human_timestamp_match.group(2)}"
        )

    elif epoch_timestamp_match:
        epoch = float(epoch_timestamp_match.group(1))
        timestamp = datetime.fromtimestamp(
            epoch,
            tz=timezone.utc
        ).isoformat()

    syscall = get_field("syscall")
    pid = get_field("pid")
    ppid = get_field("ppid")
    auid = get_field("auid")
    uid = get_field("uid")
    tty = get_field("tty")
    session_id = get_field("ses")
    comm = get_field("comm")
    exe = get_field("exe")
    exit_code = get_field("exit")

    if syscall is None or pid is None:
        return None

    event_type = "process_start" if syscall == "59" else (
        "process_end" if syscall == "231" else "process_syscall"
    )

    return {
        "source": "process",
        "timestamp": timestamp,
        "syscall": syscall,
        "pid": pid,
        "ppid": ppid,
        "auid": auid,
        "uid": uid,
        "tty": tty,
        "session_id": session_id,
        "comm": comm,
        "exe": exe,
        "exit_code": exit_code,
        "source_ip": source_ip,
        "event_type": event_type,
        "raw": raw_line
    }


def validate_process_event(event):
    if not event or event.get("source") != "process":
        return False

    if not isinstance(event.get("syscall"), str) or not event["syscall"]:
        return False

    if not isinstance(event.get("pid"), str) or not event["pid"].isdigit():
        return False

    if event.get("ppid") is not None:
        if not isinstance(event["ppid"], str) or not event["ppid"].isdigit():
            return False

    if event.get("session_id") is not None:
        if not isinstance(event["session_id"], str) or not event["session_id"].isdigit():
            return False

    if not isinstance(event.get("event_type"), str):
        return False

    if event["event_type"] not in (
        "process_start",
        "process_end",
        "process_syscall"
    ):
        return False

    source_ip = event.get("source_ip")

    if source_ip is not None and not re.match(
        r"^[0-9a-fA-F:.]+$",
        source_ip
    ):
        return False

    return True


def deduplicate_process_event(event):
    fingerprint = (
        event["source"],
        event["syscall"],
        event["pid"],
        event["ppid"],
        event["session_id"],
        event["comm"],
        event["exe"],
        event["event_type"],
        event["source_ip"]
    )

    if fingerprint in seen_events:
        return False

    seen_events.add(fingerprint)
    return True


def normalize_process_event(event):
    if not validate_process_event(event):
        return None

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": event.get(
            "timestamp",
            datetime.now(timezone.utc).isoformat()
        ),
        "hostname": socket.gethostname(),
        "source": "process",
        "event_type": event["event_type"],
        "source_ip": event.get("source_ip"),
        "metadata": {
            "syscall": event["syscall"],
            "pid": event["pid"],
            "ppid": event["ppid"],
            "auid": event["auid"],
            "uid": event["uid"],
            "tty": event["tty"],
            "session_id": event["session_id"],
            "comm": event["comm"],
            "exe": event["exe"],
            "exit_code": event["exit_code"]
        },
        "raw": event["raw"]
    }
