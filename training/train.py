import pandas as pd
import joblib
from pathlib import Path

from sklearn.ensemble import IsolationForest


ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = ROOT / "training/data/training_data.csv"
MODEL_PATH = ROOT / "training/model/anomaly_model.pkl"
FEATURES = [
    "failed_login_count", "successful_login_count", "sudo_count", "process_count",
    "network_connection_count", "unique_destination_ip_count", "file_event_count", "cron_event_count",
]


# Load training data
df = pd.read_csv(DATA_PATH)
missing = set(FEATURES) - set(df.columns)
if missing:
    raise ValueError(f"Training telemetry is missing features: {sorted(missing)}")
df = df[FEATURES].apply(pd.to_numeric, errors="raise")
if df.empty or not df.notna().all().all():
    raise ValueError("Training telemetry must contain finite feature values")

print("Training data loaded")
print(f"Rows: {len(df)}")
print(f"Features: {len(df.columns)}")


# Create model
model = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    random_state=42
)


# Train model
model.fit(df)


# Save model
joblib.dump(model, MODEL_PATH)

print("\nModel training completed.")
print(f"Model saved to: {MODEL_PATH}")