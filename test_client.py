import asyncio
import json
import websockets


async def main():
    uri = "ws://localhost:8765"

    event = {
        "source": "authentication",
        "timestamp": "2026-09-27T15:45:00",
        "host": "linux-pc",
        "event": {
            "message": "SSH login successful",
            "user": "testuser"
        }
    }

    async with websockets.connect(uri) as websocket:
        await websocket.send(json.dumps(event))
        print("JSON event sent.")


asyncio.run(main())
