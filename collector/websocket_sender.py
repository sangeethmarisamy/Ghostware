import asyncio
import json
import queue
import threading
import websockets

class WebSocketSender:
    def __init__(self, host="127.0.0.1", port=8765):
        self.url = f"ws://{host}:{port}"
        self.queue = queue.Queue()
        self.running = False
        self.thread = None
        self.reconnect_delay = 3
        self.ping_interval = 20
        self.ping_timeout = 20
        self.close_timeout = 5

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        print(f"[WebSocket] Sender started → {self.url}")

    def send_batch(self, batch):
        if self.running:
            self.queue.put(dict(batch))

    def _run(self):
        asyncio.run(self._sender_loop())

    async def _sender_loop(self):
        while self.running:
            reconnect_delay = self.reconnect_delay

            try:
                print(f"[WebSocket] Connecting → {self.url}")

                async with websockets.connect(
                    self.url,
                    ping_interval=self.ping_interval,
                    ping_timeout=self.ping_timeout,
                    close_timeout=self.close_timeout,
                ) as websocket:

                    print("[WebSocket] Connected")

                    while self.running:
                        try:
                            batch = await asyncio.to_thread(
                                self.queue.get, True, 1
                            )
                        except queue.Empty:
                            continue

                        await websocket.send(
                            json.dumps(batch, ensure_ascii=False)
                        )

                        print(
                            "[WebSocket] Batch sent "
                            f"(type={batch.get('type')}, "
                            f"events={len(batch.get('events', []))})"
                        )

            except Exception as error:
                if not self.running:
                    break

                print(f"[WebSocket] Connection error: {error}")
                print(
                    f"[WebSocket] Reconnecting in "
                    f"{reconnect_delay} seconds..."
                )

                await asyncio.sleep(reconnect_delay)

    def stop(self):
        self.running = False
        print("[WebSocket] Sender stopped")
