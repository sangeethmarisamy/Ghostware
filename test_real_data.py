import asyncio
import json
import websockets

async def main():
    with open("test_events.json", "r", encoding="utf-8") as f:
        events = json.load(f)

    async with websockets.connect("ws://localhost:8765") as ws:
        for event in events:
            print(f"Sending: {event['source']} -> {event['event_type']}")

            await ws.send(json.dumps(event))

            result = await ws.recv()
            print("Received:", result)
            print("-" * 50)

            await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())