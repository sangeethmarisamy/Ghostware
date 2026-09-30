import json
import re
import socket
import sys
import uuid
from datetime import datetime, timezone

from processor.command import (
    parse_command_event as parse_command_event_new,
    validate_command_event,
    deduplicate_command_event,
    normalize_command_event,
)

seen_events = set()


def parse_event(raw_line):
    raw_line = raw_line.strip()

    if not raw_line:
        return None

    source_ip = None

    ip_match = re.search(r"\[SOURCE_IP=([^\]]+)\]", raw_line)

    if ip_match:
        source_ip = ip_match.group(1)

    clean_line = re.sub(r"\[SOURCE_IP=[^\]]+\]\s*", "", raw_line)

    parts = clean_line.split(maxsplit=2)

    if len(parts) != 3:
        return None

    mask, cookie, path = parts

    if not mask.isdigit() or not cookie.isdigit():
        return None

    return {
        "source": "file",
        "source_ip": source_ip,
        "mask": int(mask),
        "cookie": int(cookie),
        "path": path,
        "raw": raw_line
    }



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


def parse_cron_event(raw_line):
    raw_line = raw_line.strip()

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


def parse_network_event(raw_line):
    raw_line = raw_line.strip()

    if not raw_line:
        return None

    parts = raw_line.split()

    if len(parts) < 13:
        return None

    timestamp = parts[0]
    interface = parts[1]
    ipv4_src = parts[2]
    ipv4_dst = parts[3]
    ipv6_src = parts[4]
    ipv6_dst = parts[5]
    protocol = parts[6]
    ipv6_next_header = parts[7]
    tcp_src_port = parts[8]
    tcp_dst_port = parts[9]
    tcp_flags = parts[10]
    udp_src_port = parts[11]
    udp_dst_port = parts[12]
    frame_length = parts[13] if len(parts) > 13 else None

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
        "source_ip": ipv4_src if ipv4_src != "-" else ipv6_src,
        "event_type": "network_packet",
        "raw": raw_line
    }


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

    timestamp_match = re.search(
        r"msg=audit\((\d{2}/\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2}\.\d+):",
        clean_line
    )

    timestamp = None

    if timestamp_match:
        timestamp = (
            f"20{timestamp_match.group(1)[-2:]}-"
            f"{timestamp_match.group(1)[3:5]}-"
            f"{timestamp_match.group(1)[0:2]}T"
            f"{timestamp_match.group(2)}"
        )

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

def validate_event(event):
    if not event:
        return False

    source = event.get("source")

    if source == "file":
        if not isinstance(event.get("mask"), int):
            return False

        if not isinstance(event.get("cookie"), int):
            return False

        if not isinstance(event.get("path"), str) or not event["path"]:
            return False

    elif source == "authentication":
        if not isinstance(event.get("timestamp"), str):
            return False

        if not isinstance(event.get("username"), str) or not event["username"]:
            return False

        if event.get("event_type") not in (
            "login_success",
            "session_close"
        ):
            return False

    elif source == "command":
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

    elif source == "cron":
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

    elif source == "network":
        if not isinstance(event.get("timestamp"), str) or not event["timestamp"]:
            return False

        if not isinstance(event.get("interface"), str) or not event["interface"]:
            return False

        if not isinstance(event.get("protocol"), str) or not event["protocol"]:
            return False

        if event.get("event_type") != "network_packet":
            return False

        source_ip = event.get("source_ip")

        if source_ip is not None and not re.match(
            r"^[0-9a-fA-F:.]+$",
            source_ip
        ):
            return False

    elif source == "process":
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

    else:
        return False

    source_ip = event.get("source_ip")

    if source_ip is not None and not re.match(
        r"^[0-9a-fA-F:.]+$",
        source_ip
    ):
        return False

    return True


def deduplicate_event(event):
    if event["source"] == "file":
        fingerprint = (
            event["source"],
            event["source_ip"],
            event["mask"],
            event["cookie"],
            event["path"]
        )

    elif event["source"] == "authentication":
        fingerprint = (
            event["source"],
            event["timestamp"],
            event["username"],
            event["source_ip"],
            event["event_type"]
        )

    elif event["source"] == "command":
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

    elif event["source"] == "cron":
        fingerprint = (
            event["source"],
            event["timestamp"],
            event["pid"],
            event["username"],
            event["command"]
        )

    elif event["source"] == "network":
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
            event["frame_length"]
        )

    elif event["source"] == "process":
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

    else:
        return False

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


def normalize_event(event):
    if event["source"] == "file":
        event_type = get_file_event_type(event["mask"])

        metadata = {
            "mask": event["mask"],
            "cookie": event["cookie"],
            "path": event["path"]
        }

    elif event["source"] == "authentication":
        event_type = event["event_type"]

        metadata = {
            "username": event["username"]
        }

    elif event["source"] == "command":
        event_type = event["event_type"]

        metadata = {
            "pid": event["pid"],
            "username": event["username"],
            "tty": event["tty"],
            "pwd": event["pwd"],
            "target_user": event["target_user"],
            "command": event["command"]
        }

    elif event["source"] == "cron":
        event_type = event["event_type"]

        metadata = {
            "pid": event["pid"],
            "username": event["username"],
            "command": event["command"]
        }

    elif event["source"] == "network":
        event_type = event["event_type"]

        metadata = {
            "interface": event["interface"],
            "ipv4_src": event["ipv4_src"],
            "ipv4_dst": event["ipv4_dst"],
            "ipv6_src": event["ipv6_src"],
            "ipv6_dst": event["ipv6_dst"],
            "protocol": event["protocol"],
            "ipv6_next_header": event["ipv6_next_header"],
            "tcp_src_port": event["tcp_src_port"],
            "tcp_dst_port": event["tcp_dst_port"],
            "tcp_flags": event["tcp_flags"],
            "udp_src_port": event["udp_src_port"],
            "udp_dst_port": event["udp_dst_port"],
            "frame_length": event["frame_length"]
        }

    elif event["source"] == "process":
        event_type = event["event_type"]

        metadata = {
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
        }

    else:
        return None

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "hostname": socket.gethostname(),
        "source": event["source"],
        "event_type": event_type,
        "source_ip": event["source_ip"],
        "metadata": metadata,
        "raw": event["raw"]
    }


print("GHOSTWIRE Processor started...")
print("Waiting for raw events...\n")

for line in sys.stdin:
    event = parse_event(line)

    if event is None:
        event = parse_authentication_event(line)

    if event is None:
        event = parse_command_event_new(line)

    if event is None:
        event = parse_cron_event(line)

    if event is None:
        event = parse_process_event(line)

    if event is None:
        event = parse_network_event(line)

    if event:
        if event["source"] == "command":
            if (
                validate_command_event(event)
                and deduplicate_command_event(event)
            ):
                normalized = normalize_command_event(event)
                print(json.dumps(normalized))

        elif validate_event(event) and deduplicate_event(event):
            normalized = normalize_event(event)
            print(json.dumps(normalized))
