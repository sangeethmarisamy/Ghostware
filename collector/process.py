import os
import re
import time

AUDIT_LOG = "/var/log/audit/audit.log"
CURSOR_FILE = "state/process.cursor"

os.makedirs("state", exist_ok=True)

SERIAL_PATTERN = re.compile(r"msg=audit\([^:]+:(\d+)\)")


def save_cursor(position):
    with open(CURSOR_FILE, "w") as cursor:
        cursor.write(str(position))


def load_cursor():
    if not os.path.exists(CURSOR_FILE):
        return None

    with open(CURSOR_FILE, "r") as cursor:
        value = cursor.read().strip()

    if not value:
        return None

    return int(value)


position = load_cursor()

while not os.path.exists(AUDIT_LOG):
    time.sleep(0.2)

current_size = os.path.getsize(AUDIT_LOG)

if position is None or position > current_size:
    position = current_size


audit = open(AUDIT_LOG, "r")
audit.seek(position)

print("GHOSTWIRE Process Collector started...")
print("Waiting for process events...\n")

current_serial = None
current_event = []
last_event_time = 0

try:
    while True:

        try:
            current_file_size = os.path.getsize(AUDIT_LOG)

        except FileNotFoundError:
            time.sleep(0.2)
            continue

        if current_file_size < audit.tell():

            audit.close()

            while not os.path.exists(AUDIT_LOG):
                time.sleep(0.2)

            audit = open(AUDIT_LOG, "r")

            # New rotated audit.log: start from live end
            audit.seek(0, os.SEEK_END)

            position = audit.tell()
            save_cursor(position)

            current_serial = None
            current_event = []
            last_event_time = 0

            continue

        line_start_position = audit.tell()
        line = audit.readline()

        if not line:

            if current_event and time.time() - last_event_time >= 0.5:

                if any(
                    'key="ghostwire_process"' in event_line
                    for event_line in current_event
                ):
                    for event_line in current_event:
                        print(event_line, end="")

                position = audit.tell()
                save_cursor(position)

                current_event = []
                current_serial = None

            time.sleep(0.1)
            continue

        match = SERIAL_PATTERN.search(line)

        if not match:
            continue

        serial = match.group(1)

        if current_serial is None:
            current_serial = serial

        if serial != current_serial:

            if any(
                'key="ghostwire_process"' in event_line
                for event_line in current_event
            ):
                for event_line in current_event:
                    print(event_line, end="")

            position = line_start_position
            save_cursor(position)

            current_event = []
            current_serial = serial

        current_event.append(line)
        last_event_time = time.time()

finally:
    audit.close()
