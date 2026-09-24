import subprocess

process = subprocess.Popen(
    ["journalctl", "-f", "--no-pager"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

print("GHOSTWIRE Collector started...")
print("Waiting for new journal events...\n")

for line in process.stdout:
    print(line, end="")
