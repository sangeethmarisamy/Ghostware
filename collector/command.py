import subprocess
import os

CURSOR_FILE = "state/command.cursor"

os.makedirs("state", exist_ok=True)

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
    print(line, end="")
