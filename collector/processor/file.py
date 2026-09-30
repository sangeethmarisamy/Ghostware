import re
import socket
import uuid
import os
import pwd
import time
from datetime import datetime, timezone

seen_events = set()

AUDIT_FIELDS = (
    "audit_user",
    "audit_session",
    "process",
    "terminal",
    "source_ip",
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

    event = {
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

    # If the raw collector did not provide audit attribution,
    # enrich the event from the matching auditd transaction.
    if (
        event["audit_user"] is None
        or event["audit_session"] is None
        or event["process"] is None
        or event["terminal"] is None
        or event["source_ip"] is None
    ):
        audit = get_audit_metadata(
            path,
            session_id=event.get("audit_session")
        )

        for field in AUDIT_FIELDS:
            if event.get(field) is None and audit.get(field) is not None:
                event[field] = audit[field]

    return event

def get_audit_metadata(full_path, event_time=None, session_id=None):
    audit_log = "/var/log/audit/audit.log"

    result = {
        "audit_user": None,
        "audit_session": None,
        "process": None,
        "terminal": None,
        "source_ip": None,
    }

    if event_time is None:
        event_time = time.time()

    path_marker = f'name="{full_path}"'

    # auditd can write slightly after inotify reports the event.
    # Retry briefly while looking for the matching PATH transaction.
    for _ in range(10):
        try:
            with open(audit_log, "r", errors="replace") as audit:
                audit.seek(0, os.SEEK_END)
                size = audit.tell()
                audit.seek(max(0, size - 4_000_000))
                lines = audit.readlines()

            candidates = []

            for line in lines:
                if path_marker not in line:
                    continue

                match = re.search(
                    r"msg=audit\((\d+(?:\.\d+)?):(\d+)\)",
                    line
                )
                if not match:
                    continue

                timestamp = float(match.group(1))
                serial = match.group(2)
                candidates.append((timestamp, serial))

            # If the raw collector already supplied the audit session,
            # use that session directly instead of relying on wall-clock time.
            if session_id is not None:
                session_pattern = re.compile(
                    rf"\bses={re.escape(str(session_id))}\b"
                )

                for session_line in lines:
                    if not session_pattern.search(session_line):
                        continue

                    if "sshd-session" not in session_line:
                        continue

                    ip_match = re.search(
                        r"\baddr=([0-9a-fA-F:.]+)\b",
                        session_line
                    )

                    if ip_match:
                        result["source_ip"] = ip_match.group(1)
                        break

            if not candidates:
                if result["source_ip"] is not None:
                    return result
                time.sleep(0.1)
                continue

            timestamp, serial = min(
                candidates,
                key=lambda item: abs(item[0] - event_time)
            )

            if abs(timestamp - event_time) > 5.0:
                time.sleep(0.1)
                continue

            transaction_pattern = re.compile(
                rf"msg=audit\([^:]+:{re.escape(serial)}\)"
            )

            for line in lines:
                if not transaction_pattern.search(line):
                    continue

                if "type=SYSCALL" not in line:
                    continue

                match = re.search(r"\bauid=(\d+)", line)
                if match and match.group(1) != "4294967295":
                    try:
                        result["audit_user"] = pwd.getpwuid(
                            int(match.group(1))
                        ).pw_name
                    except (KeyError, ValueError, OSError):
                        result["audit_user"] = match.group(1)

                match = re.search(r"\bses=(\d+)", line)
                if match:
                    result["audit_session"] = int(match.group(1))

                match = re.search(r"\bcomm=([^\s]+)", line)
                if match:
                    result["process"] = match.group(1)

                match = re.search(r"\btty=(\S+)", line)
                if match and match.group(1) != "(none)":
                    result["terminal"] = match.group(1)

                # Resolve remote IP from the SSH audit session.
                session = result.get("audit_session")
                if session is not None:
                    session_pattern = re.compile(
                        rf"\bses={re.escape(str(session))}\b"
                    )

                    for session_line in lines:
                        if not session_pattern.search(session_line):
                            continue

                        if "sshd-session" not in session_line:
                            continue

                        ip_match = re.search(
                            r"\baddr=([0-9a-fA-F:.]+)\b",
                            session_line
                        )

                        if ip_match:
                            result["source_ip"] = ip_match.group(1)
                            break

                return result

        except OSError:
            pass

        time.sleep(0.1)

    return result

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
