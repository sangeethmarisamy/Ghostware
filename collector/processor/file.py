import re
import socket
import uuid
from datetime import datetime, timezone

seen_events = set()

AUDIT_FIELDS = (
    "audit_user",
    "audit_session",
    "process",
    "terminal",
)


def parse_file_event(raw_line):
    raw_line = raw_line.strip()
    if not raw_line:
        return None

    fields = {}
    pattern = r"\[(SOURCE_IP|AUDIT_USER|AUDIT_SESSION|PROCESS|TERMINAL)=([^\]]*)\]"

    for match in re.finditer(pattern, raw_line):
        fields[match.group(1)] = match.group(2)

    clean_line = re.sub(pattern, "", raw_line).strip()
    parts = clean_line.split(maxsplit=2)

    if len(parts) != 3:
        return None

    mask, cookie, path = parts

    if not mask.isdigit() or not cookie.isdigit():
        return None

    session = fields.get("AUDIT_SESSION")
    if session is not None:
        if not session.isdigit():
            return None
        session = int(session)

    return {
        "source": "file",
        "source_ip": fields.get("SOURCE_IP") or None,
        "audit_user": fields.get("AUDIT_USER") or None,
        "audit_session": session,
        "process": fields.get("PROCESS") or None,
        "terminal": fields.get("TERMINAL") or None,
        "mask": int(mask),
        "cookie": int(cookie),
        "path": path,
        "raw": raw_line,
    }


def validate_file_event(event):
    if not isinstance(event, dict) or event.get("source") != "file":
        return False

    if type(event.get("mask")) is not int or event["mask"] < 0:
        return False

    if type(event.get("cookie")) is not int or event["cookie"] < 0:
        return False

    if not isinstance(event.get("path"), str) or not event["path"]:
        return False

    source_ip = event.get("source_ip")
    if source_ip is not None:
        if not isinstance(source_ip, str):
            return False
        if not re.fullmatch(r"[0-9a-fA-F:.]+", source_ip):
            return False

    for field in ("audit_user", "process", "terminal"):
        value = event.get(field)
        if value is not None and not isinstance(value, str):
            return False

    session = event.get("audit_session")
    if session is not None and (type(session) is not int or session < 0):
        return False

    return True


def deduplicate_file_event(event):
    fingerprint = (
        event.get("source"),
        event.get("source_ip"),
        event.get("audit_user"),
        event.get("audit_session"),
        event.get("process"),
        event.get("terminal"),
        event.get("mask"),
        event.get("cookie"),
        event.get("path"),
    )

    if fingerprint in seen_events:
        return False

    seen_events.add(fingerprint)
    return True


def get_file_event_type(mask):
    if mask & 0x00000100:
        return "file_create"
    if mask & 0x00000002:
        return "file_modify"
    if mask & 0x00000200:
        return "file_delete"
    if mask & 0x00000040:
        return "file_move_from"
    if mask & 0x00000080:
        return "file_move_to"
    if mask & 0x00000400:
        return "file_delete_self"
    if mask & 0x00000800:
        return "file_move_self"
    return "file_other"


def normalize_file_event(event):
    if not validate_file_event(event):
        return None

    metadata = {
        "mask": event["mask"],
        "cookie": event["cookie"],
        "path": event["path"],
    }

    for field in AUDIT_FIELDS:
        if event.get(field) is not None:
            metadata[field] = event[field]

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": event.get(
            "timestamp", datetime.now(timezone.utc).isoformat()
        ),
        "hostname": socket.gethostname(),
        "source": "file",
        "event_type": get_file_event_type(event["mask"]),
        "source_ip": event.get("source_ip"),
        "metadata": metadata,
        "raw": event["raw"],
    }
