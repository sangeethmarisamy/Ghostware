import pandas as pd
import joblib

from sklearn.ensemble import IsolationForest


DATA_PATH = "training/data/training_data.csv"
MODEL_PATH = "training/model/anomaly_model.pkl"


# Load training data
df = pd.read_csv(DATA_PATH)

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