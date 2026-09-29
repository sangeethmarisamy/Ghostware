import subprocess
import re
import os

CURSOR_FILE = "state/command.cursor"

os.makedirs("state", exist_ok=True)


def get_source_ip(pid):
    if not pid:
        return None

    audit_log = "/var/log/audit/audit.log"

    try:
        with open(audit_log, "r", errors="replace") as audit:
            for line in audit:
                if f"pid={pid}" not in line:
                    continue

                session_match = re.search(r"\bses=(\d+)", line)
                if not session_match:
                    continue

                session_id = session_match.group(1)
                session_file = f"/run/systemd/sessions/{session_id}"

                try:
                    with open(session_file, "r") as session:
                        for session_line in session:
                            if session_line.startswith("REMOTE_HOST="):
                                source_ip = session_line.split("=", 1)[1].strip()
                                return source_ip if source_ip else None
                except OSError:
                    pass

    except OSError:
        pass

    return None

process = subprocess.Popen(
    [
        "journalctl",
        "--cursor-file=" + CURSOR_FILE,
        "-f",
        "--no-pager",
        "-o",
        "short-iso",
        "_COMM=sudo",
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)

print("GHOSTWIRE Command Collector started...")
print("Waiting for sudo command events...\n")

for line in process.stdout:
    match = re.search(r"sudo\[(\d+)\]", line)

    if match:
        pid = match.group(1)
        source_ip = get_source_ip(pid)

        if source_ip:
            print(f"[SOURCE_IP={source_ip}]")

    print(line, end="")
