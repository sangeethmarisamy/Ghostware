
import asyncio
import json

import websockets

try:
    from .detection import DetectionPipeline, unpack_payload
except ImportError:
    from detection import DetectionPipeline,  unpack_payload


HOST = "0.0.0.0"
PORT = 8765

pipeline = None
pipeline_error = None


def build_anomaly_response(result, event):
    """Build anomaly response using IPs from the original incoming event."""

    return {
        "request_id": event.get("request_id") or result.get("request_id"),
        "status": "ANOMALY",
        "risk_level": "HIGH",
        "reason": result.get("reason"),
        "username": event.get("username") or result.get("username"),
        "local_ip": event.get("local_ip") or result.get("local_ip"),
        "remote_ip": event.get("remote_ip") or result.get("remote_ip"),
        "action": result.get("action") or "BLOCK_REMOTE_IP",
    }


def get_pipeline():
    global pipeline, pipeline_error
    if pipeline is not None:
        return pipeline
    if pipeline_error is not None:
        return None
    try:
        pipeline = DetectionPipeline()
        return pipeline
    except Exception as error:
        pipeline_error = str(error)
        return None


async def handle_client(websocket):
    print("\n" + "=" * 70)
    print("             GHOSTWARE WEBSOCKET RECEIVER")
    print("=" * 70)
    print("Client connected")

    try:
        async for message in websocket:
            try:
                # 1. Receive and parse telemetry.
                data = json.loads(message)

                if not isinstance(data, dict):
                    await websocket.send(json.dumps({
                        "type": "error",
                        "error": "Expected a JSON object"
                    }))
                    continue

                request_id = data.get("request_id") or data.get("event_id")
                detection = get_pipeline()
                if detection is None:
                    await websocket.send(json.dumps({"type": "error", "status": "failed",
                        "request_id": request_id, "error": "Detection pipeline unavailable",
                        "details": pipeline_error}))
                    continue

                if data.get("action") == "verify_evidence":
                    result = await asyncio.to_thread(detection.verify_evidence,
                        data.get("reference", ""), data.get("sha256", ""))
                    await websocket.send(json.dumps({"type": "evidence_verification",
                        "status": "success", "request_id": request_id, "event_id": data.get("event_id"),
                        "detection": result}, ensure_ascii=False, default=str))
                    continue

                events = unpack_payload(data)
                for event in events:
                    result = await asyncio.to_thread(detection.process_event, event)
                    print(f"[RECEIVED] event_id={result.get('event_id')}")
                    print(f"[PREDICTION] anomaly_score={result.get('anomaly_score')}")
                    try:
                        anomaly_score = float(result.get("anomaly_score"))
                    except (TypeError, ValueError):
                        anomaly_score = None
                    mismatch_anomaly = result.get("reason") == "LOCAL_REMOTE_IP_MISMATCH"
                    if not mismatch_anomaly and (anomaly_score is None or anomaly_score >= 0):
                        print(f"[NORMAL] event_id={result.get('event_id')} -> no response")
                        continue
                    print(f"[ANOMALY] {result.get('reason')}")
                    response = build_anomaly_response(result, event)
                    await websocket.send(json.dumps(response, ensure_ascii=False, default=str))
                    print(f"[SEND_BACK] event_id={result.get('event_id')} -> original sender")

            except json.JSONDecodeError:
                await websocket.send(json.dumps({
                    "type": "error",
                    "error": "Invalid JSON received"
                }))
                print("[ERROR] Invalid JSON received")

            except Exception as error:
                print(f"[PROCESSING ERROR] {error}")

                await websocket.send(json.dumps({
                    "type": "error",
                    "status": "failed",
                    "error": str(error)
                }))

    except websockets.exceptions.ConnectionClosed:
        print("Client disconnected")


async def main():
    print("=" * 70)
    print("       GHOSTWARE HYBRID DETECTION ENGINE")
    print("=" * 70)
    print(f"Listening on ws://{HOST}:{PORT}")
    print("Automatic ML detection: enabled")
    print("Evidence verification: enabled")
    print("Client response: enabled")
    print("Waiting for telemetry...")
    print()

    if get_pipeline() is None:
        print(f"Detection pipeline unavailable: {pipeline_error}")

    async with websockets.serve(
        handle_client,
        HOST,
        PORT,
        max_size=1024 * 1024
    ):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())