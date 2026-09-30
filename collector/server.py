import asyncio
import json

import websockets

try:
    from .detection import DetectionPipeline
except ImportError:
    from detection import DetectionPipeline


HOST = "0.0.0.0"
PORT = 8765
pipeline = DetectionPipeline()


async def receive_events(websocket):
    print("Client connected.")
    try:
        async for message in websocket:
            try:
                request = json.loads(message)
                if isinstance(request, dict) and request.get("action") == "verify_evidence":
                    result = await asyncio.to_thread(pipeline.verify_evidence,
                        request.get("reference", ""), request.get("sha256", ""))
                else:
                    result = await asyncio.to_thread(pipeline.process, request)
                await websocket.send(json.dumps(result))
                response_status = result.get("status", result.get("level", "INVALID"))
                risk_score = result.get("risk_score", result.get("scores", {}).get("risk", 0))
                print(f"{result.get('host', result.get('username', 'unknown'))}: {response_status} risk={risk_score:.3f}")
            except (json.JSONDecodeError, ValueError) as error:
                await websocket.send(json.dumps({"error": str(error)}))
            except Exception as error:
                print(f"Processing error: {error}")
                await websocket.send(json.dumps({"error": str(error)}))
    except websockets.ConnectionClosed:
        print("Client disconnected.")


async def main():
    print(f"Ghostware hybrid detection engine running on port {PORT}")
    async with websockets.serve(receive_events, HOST, PORT):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())