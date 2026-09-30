import ctypes
import os
import struct
import re
import time

WATCH_ROOTS = [
    "/home/sangeeth/Desktop",
    "/home/sangeeth/Documents",
    "/home/sangeeth/Downloads",
    "/home/sangeeth/Pictures",
    "/home/sangeeth/Videos",
    "/home/sangeeth/Music",
    "/home/sangeeth/Projects",
    "/home/sangeeth/Public",
    "/home/sangeeth/Templates",
    "/home/sangeeth/.local/share/Trash",
    "/mnt",
    "/media",
]

IN_CREATE = 0x00000100
IN_MODIFY = 0x00000002
IN_DELETE = 0x00000200
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080

IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_IGNORED = 0x00008000

MASK = (
    IN_CREATE
    | IN_MODIFY
    | IN_DELETE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_DELETE_SELF
    | IN_MOVE_SELF
)

libc = ctypes.CDLL(None)

fd = libc.inotify_init1(0)

if fd < 0:
    raise OSError("inotify_init1 failed")

EVENT_STRUCT = struct.Struct("iIII")

watch_paths = {}
watch_descriptors = {}


def get_audit_metadata(full_path):
    audit_log = "/var/log/audit/audit.log"

    result = {
        "audit_user": None,
        "audit_session": None,
        "process": None,
        "terminal": None,
        "source_ip": None,
    }

    try:
        with open(audit_log, "r", errors="replace") as audit:
            audit.seek(0, os.SEEK_END)
            size = audit.tell()
            audit.seek(max(0, size - 4_000_000))
            lines = audit.readlines()

        path_marker = f'name="{full_path}"'
        candidates = []

        for line in lines:
            if path_marker not in line:
                continue

            match = re.search(
                r"msg=audit\\((\\d+(?:\\.\\d+)?):(\\d+)\\)",
                line
            )
            if match:
                candidates.append(match.group(2))

        if not candidates:
            return result

        for serial in reversed(candidates):
            event_pattern = re.compile(
                rf"msg=audit\\([^:]+:{re.escape(serial)}\\)"
            )

            session_id = None

            for line in lines:
                if not event_pattern.search(line):
                    continue

                if "type=SYSCALL" not in line:
                    continue

                match = re.search(r"\\bauid=(\\d+)", line)
                if match and match.group(1) != "4294967295":
                    result["audit_user"] = match.group(1)

                match = re.search(r"\\bses=(\\d+)", line)
                if match:
                    session_id = int(match.group(1))
                    result["audit_session"] = session_id

                match = re.search(r'\\bcomm="([^"]+)"', line)
                if match:
                    result["process"] = match.group(1)

                match = re.search(r"\\btty=(\\S+)", line)
                if match and match.group(1) != "(none)":
                    result["terminal"] = match.group(1)

                break

            if session_id is not None:
                session_pattern = re.compile(
                    rf"\\bses={re.escape(str(session_id))}\\b"
                )

                for line in lines:
                    if not session_pattern.search(line):
                        continue

                    if "USER_LOGIN" not in line and "sshd-session" not in line:
                        continue

                    ip_match = re.search(
                        r"\\baddr=([0-9a-fA-F:.]+)\\b",
                        line
                    )

                    if ip_match:
                        result["source_ip"] = ip_match.group(1)
                        break

            if result["audit_session"] is not None:
                break

        uid = result["audit_user"]

        if uid is not None:
            try:
                import pwd
                result["audit_user"] = pwd.getpwuid(int(uid)).pw_name
            except (KeyError, ValueError, OSError):
                pass

    except OSError:
        pass

    return result

def remove_watch(wd):
    path = watch_paths.pop(wd, None)

    if path is not None:
        watch_descriptors.pop(path, None)


def add_watch(path):
    if not os.path.isdir(path):
        return

    if path in watch_descriptors:
        return

    wd = libc.inotify_add_watch(
        fd,
        path.encode(),
        MASK
    )

    if wd < 0:
        return

    watch_paths[wd] = path
    watch_descriptors[path] = wd


def add_recursive(root):
    if not os.path.isdir(root):
        return

    add_watch(root)

    for current_root, directories, _ in os.walk(root):
        for directory in directories:
            add_watch(os.path.join(current_root, directory))


for root in WATCH_ROOTS:
    add_recursive(root)

print("GHOSTWIRE File Collector started...")
print("Waiting for filesystem events...\n")

try:
    while True:
        data = os.read(fd, 65536)

        offset = 0

        while offset < len(data):
            wd, mask, cookie, name_len = EVENT_STRUCT.unpack_from(
                data,
                offset
            )

            offset += EVENT_STRUCT.size

            name = data[offset:offset + name_len].split(b"\0", 1)[0]
            offset += name_len

            name = name.decode(errors="replace")

            parent = watch_paths.get(wd)

            if parent is None:
                continue

            full_path = os.path.join(parent, name)

            audit = get_audit_metadata(full_path)

            fields = []
            if audit["audit_user"]:
                fields.append(f"[AUDIT_USER={audit['audit_user']}]")
            if audit["audit_session"] is not None:
                fields.append(f"[AUDIT_SESSION={audit['audit_session']}]")
            if audit["process"]:
                fields.append(f"[PROCESS={audit['process']}]")
            if audit["terminal"]:
                fields.append(f"[TERMINAL={audit['terminal']}]")

            prefix = " ".join(fields)
            event_line = f"{mask} {cookie} {full_path}"
            print(f"{prefix} {event_line}".strip(), flush=True)
            if mask & IN_CREATE:
                if os.path.isdir(full_path):
                    add_recursive(full_path)

            if mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED):
                remove_watch(wd)

finally:
    os.close(fd)
