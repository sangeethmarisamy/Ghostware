import asyncio
import json
import websockets

from detection import DetectionPipeline


HOST = "0.0.0.0"
PORT = 8765

pipeline = None
pipeline_error = None


def get_pipeline():
    global pipeline
    global pipeline_error

    if pipeline is not None:
        return pipeline

    if pipeline_error is not None:
        return None

    try:
        pipeline = DetectionPipeline()
        print("[Detection] Pipeline initialized successfully.")
        return pipeline

    except Exception as error:
        pipeline_error = str(error)
        print(f"[Detection] Pipeline unavailable: {error}")
        return None


async def handle_client(websocket):
    print("\n" + "=" * 70)
    print("       GHOSTWARE HYBRID DETECTION RECEIVER")
    print("=" * 70)
    print("Client connected.")

    try:
        async for message in websocket:
            try:
                request = json.loads(message)

                print("\n" + "-" * 70)
                print("RECEIVED FROM GHOSTWARE COLLECTOR")
                print("-" * 70)
                print(json.dumps(request, indent=2, ensure_ascii=False))
                print("-" * 70)

                if (
                    isinstance(request, dict)
                    and request.get("action") == "verify_evidence"
                ):
                    detection = get_pipeline()

                    if detection is None:
                        result = {
                            "status": "DETECTION_UNAVAILABLE",
                            "reason": "DetectionPipeline is unavailable",
                            "error": pipeline_error,
                        }
                    else:
                        result = await asyncio.to_thread(
                            detection.verify_evidence,
                            request.get("reference", ""),
                            request.get("sha256", ""),
                        )

                else:
                    detection = get_pipeline()

                    if detection is None:
                        result = {
                            "status": "DETECTION_UNAVAILABLE",
                            "reason": "Trained Isolation Forest model is unavailable",
                            "error": pipeline_error,
                            "received": True,
                        }
                    else:
                        result = await asyncio.to_thread(
                            detection.process,
                            request,
                        )

                await websocket.send(
                    json.dumps(result, ensure_ascii=False)
                )

                print("\n" + "=" * 70)
                print("DETECTION RESULT")
                print("=" * 70)
                print(json.dumps(result, indent=2, ensure_ascii=False))
                print("=" * 70)

            except json.JSONDecodeError:
                error = {
                    "status": "ERROR",
                    "error": "Invalid JSON received",
                }

                await websocket.send(json.dumps(error))

            except Exception as error:
                print(f"[ERROR] Processing error: {error}")

                await websocket.send(
                    json.dumps({
                        "status": "ERROR",
                        "error": str(error),
                    })
                )

    except websockets.exceptions.ConnectionClosed:
        print("Client disconnected.")


async def main():
    print("=" * 70)
    print("       GHOSTWARE HYBRID DETECTION ENGINE")
    print("=" * 70)
    print(f"Listening on ws://{HOST}:{PORT}")
    print()

    async with websockets.serve(
        handle_client,
        HOST,
        PORT,
    ):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
