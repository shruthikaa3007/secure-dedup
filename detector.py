import json
from collections import defaultdict, deque
from pathlib import Path

import joblib
import numpy as np

MODEL_DIR = Path(".")

scaler = joblib.load(MODEL_DIR / "scaler.pkl")
isolation_forest = joblib.load(MODEL_DIR / "isolation_forest.pkl")
one_class_svm = joblib.load(MODEL_DIR / "one_class_svm.pkl")

metadata_path = MODEL_DIR / "model_metadata.json"
if metadata_path.exists():
    with open(metadata_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)
    FEATURE_COLUMNS = metadata.get("feature_columns", [])
    SEQUENCE_LENGTH = metadata.get("sequence_length", 10)
else:
    FEATURE_COLUMNS = []
    SEQUENCE_LENGTH = 10

# Optional LSTM autoencoder support
LSTM_MODEL = None
LSTM_THRESHOLD = None
try:
    import tensorflow as tf

    lstm_path = MODEL_DIR / "lstm_autoencoder.keras"
    threshold_path = MODEL_DIR / "lstm_threshold.npy"
    if lstm_path.exists() and threshold_path.exists():
        LSTM_MODEL = tf.keras.models.load_model(lstm_path)
        LSTM_THRESHOLD = float(np.load(threshold_path)[0])
except Exception:
    LSTM_MODEL = None
    LSTM_THRESHOLD = None

_CLIENT_HISTORY = defaultdict(lambda: deque(maxlen=SEQUENCE_LENGTH))


def _ordered_vector(feature_dict):
    if FEATURE_COLUMNS:
        return np.array([feature_dict.get(col, 0.0) for col in FEATURE_COLUMNS], dtype=float)
    return np.array(list(feature_dict.values()), dtype=float)


def detect_anomaly(feature_dict, client_id=None):
    """
    Input: feature_dict
    Output: ensemble anomaly scores + label
    """
    vector = _ordered_vector(feature_dict)
    X = vector.reshape(1, -1)
    X_scaled = scaler.transform(X)

    if_score = float(isolation_forest.decision_function(X_scaled)[0])
    if_pred = int(isolation_forest.predict(X_scaled)[0])

    svm_score = float(one_class_svm.decision_function(X_scaled)[0])
    svm_pred = int(one_class_svm.predict(X_scaled)[0])

    votes = [if_pred == -1, svm_pred == -1]
    model_scores = {
        "isolation_forest": if_score,
        "one_class_svm": svm_score,
    }

    lstm_error = None
    lstm_is_anomaly = False
    if client_id and LSTM_MODEL is not None and LSTM_THRESHOLD is not None:
        history = _CLIENT_HISTORY[client_id]
        history.append(X_scaled[0])

        if len(history) == SEQUENCE_LENGTH:
            seq = np.array(history, dtype=float).reshape(1, SEQUENCE_LENGTH, -1)
            recon = LSTM_MODEL.predict(seq, verbose=0)
            lstm_error = float(np.mean(np.abs(recon - seq)))
            lstm_is_anomaly = lstm_error > LSTM_THRESHOLD
            votes.append(lstm_is_anomaly)
            model_scores["lstm_reconstruction_error"] = lstm_error
            model_scores["lstm_threshold"] = LSTM_THRESHOLD

    anomaly_votes = sum(votes)
    is_anomaly = anomaly_votes >= 2 if len(votes) >= 2 else any(votes)

    return {
        "model_scores": model_scores,
        "is_anomaly": is_anomaly,
        "anomaly_votes": anomaly_votes,
        "models_considered": len(votes),
        "lstm_is_anomaly": lstm_is_anomaly,
        "lstm_error": lstm_error,
    }
