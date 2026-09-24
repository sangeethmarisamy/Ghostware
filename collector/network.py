import subprocess
import os

print("GHOSTWIRE Network Collector started...")
print("Capturing network packets...\n")

process = subprocess.Popen(
    [
        "sudo", "tshark",
        "-i", "wlan0",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "frame.interface_name",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ipv6.src",
        "-e", "ipv6.dst",
        "-e", "ip.proto",
        "-e", "ipv6.nxt",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "tcp.flags",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "frame.len",
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)

for line in process.stdout:
    line = line.strip()

    if line:
        print(line)

