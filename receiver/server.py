import asyncio
import json
import joblib
import pandas as pd
import websockets

HOST = "0.0.0.0"
PORT = 8765

MODEL_PATH = "training/model/anomaly_model.pkl"

model = joblib.load(MODEL_PATH)


def extract_features(event):
    data = event.get("features", {})

    return pd.DataFrame([{
        "failed_login_count": data.get("failed_login_count", 0),
        "successful_login_count": data.get("successful_login_count", 0),
        "sudo_count": data.get("sudo_count", 0),
        "process_count": data.get("process_count", 0),
        "network_connection_count": data.get("network_connection_count", 0),
        "unique_destination_ip_count": data.get(
            "unique_destination_ip_count", 0
        ),
        "file_event_count": data.get("file_event_count", 0),
        "cron_event_count": data.get("cron_event_count", 0),
    })


async def receive_events(websocket):
    print("Client connected.")

    try:
        async for message in websocket:

            try:
                event = json.loads(message)

                features = extract_features(event)

                prediction = model.predict(features)[0]
                score = model.decision_function(features)[0]

                if prediction == -1:
                    result = "ANOMALY"
                else:
                    result = "NORMAL"

                print("\n----------------------------")
                print("Event received")
                print(f"Anomaly score : {score:.4f}")
                print(f"Detection     : {result}")
                print("----------------------------")

            except json.JSONDecodeError:
                print("Invalid JSON received.")

            except Exception as e:
                print(f"Processing error: {e}")

    except websockets.ConnectionClosed:
        print("Client disconnected.")


async def main():
    print(f"Ghostware Detection Engine running on port {PORT}")

    async with websockets.serve(receive_events, HOST, PORT):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())