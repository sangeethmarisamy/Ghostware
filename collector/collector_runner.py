import json
import subprocess
import threading
import time

from pipeline import EventPipeline
from websocket_sender import WebSocketSender


# -------------------------------------------------------------
# NETWORK TEMPORARILY DISABLED
# -------------------------------------------------------------
#
# Network collector intentionally excluded for now.
# We are testing authentication end-to-end first.
#
# Add network back later when authentication transfer is stable.
# -------------------------------------------------------------

COLLECTORS = {
    "authentication": "authentication.py",
    "command": "command.py",
"cron": "cron.py",
}


class CollectorRunner:

    def __init__(self):

        self.pipeline = EventPipeline()

        self.processes = {}

        self.running = True

        self.websocket_sender = WebSocketSender(
            host="10.143.202.56",
            port=8765,
        )

    # ---------------------------------------------------------
    # NORMAL CONTEXT EVENT DISPLAY
    # ---------------------------------------------------------

    def print_context_event(self, event):

        context = event.get("context")

        if not context:
            return

        print("\n" + "=" * 70)
        print("                GHOSTWARE CONTEXT CONTROLLER")
        print("=" * 70)

        print(
            f"HOST IP       : "
            f"{context.get('host_ip')}"
        )

        print(
            f"REMOTE IP     : "
            f"{context.get('remote_ip')}"
        )

        print(
            f"USERNAME      : "
            f"{context.get('username')}"
        )

        print(
            f"SESSION ID    : "
            f"{context.get('session_id')}"
        )

        print(
            f"TTY           : "
            f"{context.get('tty')}"
        )

        print("-" * 70)

        print(
            f"EVENT SOURCE  : "
            f"{event.get('source')}"
        )

        print(
            f"EVENT TYPE    : "
            f"{event.get('event_type')}"
        )

        print(
            f"EVENT ID      : "
            f"{event.get('event_id')}"
        )

        print(
            f"EVENT TIME    : "
            f"{event.get('timestamp')}"
        )

        metadata = event.get("metadata", {})

        if event.get("source") == "command":

            print(
                f"COMMAND       : "
                f"{metadata.get('command')}"
            )

            print(
                f"COMMAND USER  : "
                f"{metadata.get('username')}"
            )

            print(
                f"COMMAND TTY   : "
                f"{metadata.get('tty')}"
            )

        elif event.get("source") == "authentication":

            print(
                f"SSH SOURCE IP : "
                f"{event.get('source_ip')}"
            )

        print("-" * 70)

        print("IP VERIFICATION: CONTEXT")
        print(
            f"                 "
            f"{context.get('remote_ip')}"
        )

        print("=" * 70)

    # ---------------------------------------------------------
    # NORMAL CONTEXT BATCH
    # ---------------------------------------------------------

    def handle_batch(self, batch):

        print("\n")
        print("#" * 70)
        print("                  SECURITY CONTEXT BATCH")
        print("#" * 70)

        print(
            f"TYPE       : "
            f"{batch.get('type')}"
        )

        print(
            f"HOST IP    : "
            f"{batch.get('host_ip')}"
        )

        print(
            f"REMOTE IP  : "
            f"{batch.get('remote_ip')}"
        )

        print(
            f"USERNAME   : "
            f"{batch.get('username')}"
        )

        print(
            f"SESSION ID : "
            f"{batch.get('session_id')}"
        )

        print(
            f"TTY        : "
            f"{batch.get('tty')}"
        )

        print(
            f"STATUS     : "
            f"{batch.get('status')}"
        )

        print(
            f"EVENT COUNT: "
            f"{len(batch.get('events', []))}"
        )

        print("-" * 70)

        for index, event in enumerate(
            batch.get("events", []),
            start=1,
        ):

            print(
                f"[{index}] "
                f"{event.get('source')} / "
                f"{event.get('event_type')}"
            )

        print("#" * 70)

        # Send context batch to WebSocket.
        self.websocket_sender.send_batch(
            batch
        )

    # ---------------------------------------------------------
    # AUTHENTICATION SECURITY BATCH
    # ---------------------------------------------------------

    def handle_security_batch(self, batch):

        print("\n")
        print("!" * 70)
        print("             AUTHENTICATION SECURITY EVENTS")
        print("!" * 70)

        print(
            f"TYPE        : "
            f"{batch.get('type')}"
        )

        print(
            f"EVENT COUNT : "
            f"{batch.get('event_count')}"
        )

        print("-" * 70)

        for index, item in enumerate(
            batch.get("events", []),
            start=1,
        ):

            event = item.get(
                "event",
                {},
            )

            print(
                f"[{index}] "
                f"{event.get('source')} / "
                f"{event.get('event_type')}"
            )

            print(
                f"    Source IP : "
                f"{event.get('source_ip')}"
            )

            print(
                f"    Timestamp : "
                f"{event.get('timestamp')}"
            )

            print(
                f"    Metadata  : "
                f"{json.dumps(event.get('metadata', {}), ensure_ascii=False)}"
            )

            print(
                f"    Context   : "
                f"{item.get('context')}"
            )

        print("!" * 70)

        # Send authentication security batch
        # to WebSocket receiver.
        self.websocket_sender.send_batch(
            batch
        )

    # ---------------------------------------------------------
    # COLLECTOR OUTPUT
    # ---------------------------------------------------------

    def handle_collector_output(
        self,
        source,
        process,
    ):

        for raw_line in process.stdout:

            raw_line = raw_line.rstrip(
                "\n"
            )

            if not raw_line:
                continue

            result = (
                self.pipeline.process_raw_line(
                    source,
                    raw_line,
                )
            )

            if not result:
                continue

            print("\n=== NORMALIZED EVENT ===")

            print(
                json.dumps(
                    result,
                    indent=2,
                    ensure_ascii=False,
                )
            )

            # Normal context event.
            if result.get("context"):

                self.print_context_event(
                    result
                )

            # Authentication security event.
            elif result.get("type") == "security_event":

                print("\n" + "!" * 70)
                print(
                    "       SECURITY EVENT - NO SSH CONTEXT"
                )
                print("!" * 70)

                print(
                    json.dumps(
                        result,
                        indent=2,
                        ensure_ascii=False,
                    )
                )

                print("!" * 70)

    # ---------------------------------------------------------
    # START COLLECTOR
    # ---------------------------------------------------------

    def start_collector(
        self,
        source,
        filename,
    ):

        process = subprocess.Popen(
            [
                "python3",
                "-u",
                filename,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        self.processes[source] = process

        thread = threading.Thread(
            target=self.handle_collector_output,
            args=(
                source,
                process,
            ),
            daemon=True,
        )

        thread.start()

    # ---------------------------------------------------------
    # START
    # ---------------------------------------------------------

    def start(self):

        self.websocket_sender.start()

        self.pipeline.start(
            self.handle_batch,
            self.handle_security_batch,
        )

        for source, filename in COLLECTORS.items():

            print(
                f"Starting {source} collector..."
            )

            self.start_collector(
                source,
                filename,
            )

        print(
            "\nGHOSTWIRE Collector Runner started."
        )

        print(
            "Context Controller active."
        )

        print(
            "Authentication security "
            "event transfer active."
        )

        print(
            "Network collector temporarily disabled."
        )

        print(
            "Waiting for security events...\n"
        )

        try:

            while self.running:

                time.sleep(1)

        except KeyboardInterrupt:

            print(
                "\nStopping "
                "GHOSTWIRE Collector Runner..."
            )

        finally:

            self.stop()

    # ---------------------------------------------------------
    # STOP
    # ---------------------------------------------------------

    def stop(self):

        self.running = False

        self.pipeline.stop()

        self.websocket_sender.stop()

        for process in self.processes.values():

            if process.poll() is None:

                process.terminate()

        for process in self.processes.values():

            try:

                process.wait(
                    timeout=2
                )

            except subprocess.TimeoutExpired:

                process.kill()

        print(
            "All collectors stopped."
        )


if __name__ == "__main__":

    runner = CollectorRunner()

    runner.start()
