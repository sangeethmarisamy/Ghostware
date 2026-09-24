import subprocess
import os

CURSOR_FILE = "state/cron.cursor"

os.makedirs("state", exist_ok=True)

process = subprocess.Popen(
    [
        "journalctl",
        "--cursor-file=" + CURSOR_FILE,
        "-f",
        "--no-pager",
        "-o",
        "short-iso",
        "_COMM=cron",
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)

print("GHOSTWIRE Cron Collector started...")
print("Waiting for scheduled task events...\n")

for line in process.stdout:
    print(line, end="")
