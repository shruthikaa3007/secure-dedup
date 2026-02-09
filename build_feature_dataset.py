import pandas as pd
from logger import REQUEST_LOGS
from features import extract_features

rows = []

for client_id, logs in REQUEST_LOGS.items():
    if len(logs) < 5:
        continue  # skip very small sessions

    features = extract_features(logs, REQUEST_LOGS)
    features["client_id"] = client_id
    rows.append(features)

df = pd.DataFrame(rows)
df.to_csv("feature_dataset.csv", index=False)

print("✅ feature_dataset.csv created")
print(df.head())
