import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

# Load training data
df = pd.read_csv("training_data.csv")

print("Columns in dataset:", df.columns.tolist())

# Keep ONLY numeric columns
X = df.select_dtypes(include=[np.number])

if X.empty:
    raise ValueError("❌ No numeric feature columns found")

print("Numeric feature columns used:", X.columns.tolist())

# Normalize features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train Isolation Forest
model = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    random_state=42
)

model.fit(X_scaled)

# Save model & scaler
joblib.dump(model, "isolation_forest.pkl")
joblib.dump(scaler, "scaler.pkl")

print("✅ Model training complete")
