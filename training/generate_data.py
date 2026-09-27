import pandas as pd
import random

rows = []

for _ in range(1000):
    row = {
        "failed_login_count": random.randint(0, 3),
        "successful_login_count": random.randint(1, 10),
        "sudo_count": random.randint(0, 5),
        "process_count": random.randint(30, 150),
        "network_connection_count": random.randint(10, 80),
        "unique_destination_ip_count": random.randint(1, 15),
        "file_event_count": random.randint(10, 100),
        "cron_event_count": random.randint(0, 5),
    }

    rows.append(row)

df = pd.DataFrame(rows)

df.to_csv(
    "training/data/training_data.csv",
    index=False
)

print("Training dataset created.")
print(f"Rows: {len(df)}")
print(df.head())