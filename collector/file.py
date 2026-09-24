import subprocess

process = subprocess.Popen(
    ["sudo", "tail", "-F", "/var/log/audit/audit.log"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)

print("GHOSTWIRE File Collector started...")
print("Waiting for live audit events...\n")

for line in process.stdout:
    print(line, end="")
