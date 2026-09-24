import os
import time

AUDIT_LOG = "/var/log/audit/audit.log"
CURSOR_FILE = "state/process.cursor"

os.makedirs("state", exist_ok=True)


def load_cursor():
    try:
        with open(CURSOR_FILE, "r") as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return 0


def save_cursor(position):
    with open(CURSOR_FILE, "w") as f:
        f.write(str(position))


print("GHOSTWIRE Process Collector started...")
print("Waiting for process events...\n")

position = load_cursor()

with open(AUDIT_LOG, "r", errors="replace") as audit_file:

    audit_file.seek(position)

    while True:
        line = audit_file.readline()

        if not line:
            time.sleep(0.2)
            continue

        position = audit_file.tell()
        save_cursor(position)

        if (
    'key="ghostwire_process_test"' in line
    and (
        "SYSCALL=execve" in line
        or "syscall=execve" in line
        or "SYSCALL=exit_group" in line
        or "syscall=exit_group" in line
    )
):
            print(line, end="")
