import subprocess
import os

CURSOR_FILE = "state/authentication.cursor"

os.makedirs("state", exist_ok=True)

process = subprocess.Popen(
    [
        "journalctl",
        "--cursor-file=" + CURSOR_FILE,
        "-f",
        "--no-pager",
        "-o",
        "short-iso",
        "_COMM=sshd-session",
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)

print("GHOSTWIRE Authentication Collector started...")
print("Waiting for SSH authentication events...\n")

for line in process.stdout:
    print(line, end="")
