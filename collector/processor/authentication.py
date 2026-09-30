import re
import socket
import uuid
from datetime import datetime, timezone


seen_events = set()
active_sessions = {}


def parse_authentication_event(raw_line):
    raw_line = raw_line.rstrip("\n")

    header = re.search(
        r"^(\S+)\s+\S+\s+sshd-session\[(\d+)\]:\s+(.*)$",
        raw_line
    )

    if not header:
        return None

    timestamp = header.group(1)
    session_id = header.group(2)
    message = header.group(3)

    # ---------------------------------------------------------
    # 1. Successful SSH authentication
    # ---------------------------------------------------------
    match = re.match(
        r"Accepted password for (\S+) from (\S+) port (\d+) ssh2",
        message
    )

    if match:
        username = match.group(1)
        source_ip = match.group(2)
        source_port = match.group(3)

        active_sessions[session_id] = {
            "username": username,
            "source_ip": source_ip,
        }

        return {
            "source": "authentication",
            "timestamp": timestamp,
            "username": username,
            "source_ip": source_ip,
            "session_id": session_id,
            "event_type": "login_success",
            "metadata": {
                "source_port": source_port
            },
            "raw": raw_line
        }

    # ---------------------------------------------------------
    # 2. SSH authentication failure
    # ---------------------------------------------------------
    match = re.match(
        r"pam_unix\(sshd:auth\): authentication failure;.*"
        r"rhost=(\S+).*user=(\S+)",
        message
    )

    if match:
        source_ip = match.group(1)
        username = match.group(2)

        return {
            "source": "authentication",
            "timestamp": timestamp,
            "username": username,
            "source_ip": source_ip,
            "session_id": session_id,
            "event_type": "login_failure",
            "metadata": {},
            "raw": raw_line
        }

    # ---------------------------------------------------------
    # 3. Failed SSH password
    # ---------------------------------------------------------
    match = re.match(
        r"Failed password for (?:invalid user )?(\S+) "
        r"from (\S+) port (\d+) ssh2",
        message
    )

    if match:
        username = match.group(1)
        source_ip = match.group(2)
        source_port = match.group(3)

        return {
            "source": "authentication",
            "timestamp": timestamp,
            "username": username,
            "source_ip": source_ip,
            "session_id": session_id,
            "event_type": "login_failure",
            "metadata": {
                "source_port": source_port
            },
            "raw": raw_line
        }

    # ---------------------------------------------------------
    # 3. Pre-authentication connection closed
    # ---------------------------------------------------------
    match = re.match(
        r"Connection closed by authenticating user (\S+) "
        r"(\S+) port (\d+) \[preauth\]",
        message
    )

    if match:
        username = match.group(1)
        source_ip = match.group(2)
        source_port = match.group(3)

        return {
            "source": "authentication",
            "timestamp": timestamp,
            "username": username,
            "source_ip": source_ip,
            "session_id": session_id,
            "event_type": "connection_close_preauth",
            "metadata": {
                "source_port": source_port
            },
            "raw": raw_line
        }

    # ---------------------------------------------------------
    # 4. SSH session opened
    # ---------------------------------------------------------
    match = re.match(
        r"pam_unix\(sshd:session\): session opened for user "
        r"(\S+?)(?:\(uid=(\d+)\))? by (\S+?)\(uid=(\d+)\)",
        message
    )

    if match:
        username = match.group(1)
        uid = match.group(2)
        opened_by = match.group(3)
        opened_by_uid = match.group(4)

        session_info = active_sessions.get(session_id, {})

        return {
            "source": "authentication",
            "timestamp": timestamp,
            "username": username,
            "source_ip": session_info.get("source_ip"),
            "session_id": session_id,
            "event_type": "session_open",
            "metadata": {
                "uid": uid,
                "opened_by": opened_by,
                "opened_by_uid": opened_by_uid
            },
            "raw": raw_line
        }

    # ---------------------------------------------------------
    # 5. SSH session closed
    # ---------------------------------------------------------
    match = re.match(
        r"pam_unix\(sshd:session\): session closed for user (\S+)",
        message
    )

    if match:
        username = match.group(1)

        session_info = active_sessions.pop(
            session_id,
            {}
        )

        return {
            "source": "authentication",
            "timestamp": timestamp,
            "username": username,
            "source_ip": session_info.get("source_ip"),
            "session_id": session_id,
            "event_type": "session_close",
            "metadata": {},
            "raw": raw_line
        }

    # ---------------------------------------------------------
    # 6. SSH disconnect
    # ---------------------------------------------------------
    match = re.match(
        r"Received disconnect from (\S+) port (\d+):(.+)",
        message
    )

    if match:
        source_ip = match.group(1)
        source_port = match.group(2)
        reason = match.group(3).strip()

        return {
            "source": "authentication",
            "timestamp": timestamp,
            "username": None,
            "source_ip": source_ip,
            "session_id": session_id,
            "event_type": "connection_disconnect",
            "metadata": {
                "source_port": source_port,
                "reason": reason
            },
            "raw": raw_line
        }

    # ---------------------------------------------------------
    # 7. Preserve other sshd authentication events
    # ---------------------------------------------------------
    username = None
    source_ip = None

    user_match = re.search(
        r"user\s+(\S+)",
        message
    )

    if not user_match:
        user_match = re.search(
            r"for\s+(?:user\s+)?(\S+)",
            message
        )

    if user_match:
        username = user_match.group(1)

    ip_match = re.search(
        r"(?:from|user\s+\S+\s+)(\d{1,3}(?:\.\d{1,3}){3})",
        message
    )

    if ip_match:
        source_ip = ip_match.group(1)

    return {
        "source": "authentication",
        "timestamp": timestamp,
        "username": username,
        "source_ip": source_ip,
        "session_id": session_id,
        "event_type": "authentication_event_unknown",
        "metadata": {
            "message": message
        },
        "raw": raw_line
    }


def validate_authentication_event(event):
    if not event:
        return False

    if event.get("source") != "authentication":
        return False

    if not isinstance(event.get("timestamp"), str):
        return False

    if not isinstance(event.get("session_id"), str):
        return False

    if not isinstance(event.get("event_type"), str):
        return False

    username = event.get("username")

    if username is not None and not isinstance(username, str):
        return False

    source_ip = event.get("source_ip")

    if source_ip is not None:
        if not isinstance(source_ip, str):
            return False

        if not re.match(
            r"^[0-9a-fA-F:.]+$",
            source_ip
        ):
            return False

    if not isinstance(event.get("raw"), str):
        return False

    return True


def deduplicate_authentication_event(event):
    fingerprint = (
        event["source"],
        event["timestamp"],
        event.get("username"),
        event.get("source_ip"),
        event.get("session_id"),
        event["event_type"],
        event["raw"]
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
        "source_ip": event.get("source_ip"),
        "metadata": {
            "username": event.get("username"),
            "session_id": event.get("session_id"),
            **event.get("metadata", {})
        },
        "raw": event["raw"]
    }
