import joblib
import numpy as np

# Load trained model and scaler ONCE
model = joblib.load("isolation_forest.pkl")
scaler = joblib.load("scaler.pkl")

def detect_anomaly(feature_dict):
    """
    Input: feature_dict (15 features)
    Output: anomaly score + label
    """
    X = np.array(list(feature_dict.values())).reshape(1, -1)
    X_scaled = scaler.transform(X)

    score = model.decision_function(X_scaled)[0]
    prediction = model.predict(X_scaled)[0]  # -1 = anomaly, 1 = normal

    return {
        "anomaly_score": score,
        "is_anomaly": prediction == -1
    }
