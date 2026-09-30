import json
import subprocess

from processor.authentication import (
    parse_authentication_event,
    validate_authentication_event,
    deduplicate_authentication_event,
    normalize_authentication_event,
)


process = subprocess.Popen(
    ["python3", "-u", "authentication.py"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1,
)


print("=== LIVE AUTHENTICATION RAW → PROCESSOR TEST ===")
print("Waiting for authentication events...\n")


for raw_line in process.stdout:
    raw_line = raw_line.rstrip("\n")

    if not raw_line:
        continue

    print("\n--- RAW EVENT ---")
    print(raw_line)

    parsed = parse_authentication_event(raw_line)

    if parsed is None:
        print("--- PROCESSOR RESULT ---")
        print("Not an sshd authentication event.")
        continue

    if not validate_authentication_event(parsed):
        print("--- PROCESSOR RESULT ---")
        print("REJECTED BY VALIDATION")
        print(json.dumps(parsed, indent=2))
        continue

    if not deduplicate_authentication_event(parsed):
        print("--- PROCESSOR RESULT ---")
        print("DUPLICATE EVENT")
        continue

    normalized = normalize_authentication_event(parsed)

    print("--- NORMALIZED JSON ---")
    print(json.dumps(normalized, indent=2))
