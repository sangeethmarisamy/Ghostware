import pandas as pd
import joblib

MODEL_PATH = "training/model/anomaly_model.pkl"

# Load trained model
model = joblib.load(MODEL_PATH)

# New normal-like behavior
normal_event = pd.DataFrame([{
    "failed_login_count": 1,
    "successful_login_count": 5,
    "sudo_count": 2,
    "process_count": 80,
    "network_connection_count": 30,
    "unique_destination_ip_count": 5,
    "file_event_count": 50,
    "cron_event_count": 2
}])

# New unusual behavior
suspicious_event = pd.DataFrame([{
    "failed_login_count": 40,
    "successful_login_count": 1,
    "sudo_count": 50,
    "process_count": 500,
    "network_connection_count": 900,
    "unique_destination_ip_count": 100,
    "file_event_count": 800,
    "cron_event_count": 30
}])


def detect(event, name):
    prediction = model.predict(event)[0]
    score = model.decision_function(event)[0]

    if prediction == -1:
        result = "ANOMALY"
    else:
        result = "NORMAL"

    print(f"{name}")
    print(f"Anomaly score: {score:.4f}")
    print(f"Result: {result}")
    print()


detect(normal_event, "Normal Event")
detect(suspicious_event, "Suspicious Event")