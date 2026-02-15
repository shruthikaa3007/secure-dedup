import json
import os
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, List

import joblib
import numpy as np
import pandas as pd

MODEL_DIR = Path(os.getenv("MODEL_DIR", "."))
DEFAULT_UNSUPERVISED_WEIGHTS = {
    "isolation_forest": 0.25,
    "one_class_svm": 0.20,
    "dense_autoencoder": 0.25,
    "lstm_autoencoder": 0.30,
}

metadata_path = MODEL_DIR / "model_metadata.json"
if metadata_path.exists():
    with open(metadata_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)
else:
    metadata = {}

FEATURE_COLUMNS: List[str] = metadata.get("feature_columns", [])
SEQUENCE_LENGTH = int(metadata.get("sequence_length", 10))
DETECTION_MODE = metadata.get("mode", "unsupervised")
UNSUPERVISED_ANOMALY_THRESHOLD = float(
    metadata.get("unsupervised_anomaly_threshold", 0.50)
)
UNSUPERVISED_WEIGHTS = {
    **DEFAULT_UNSUPERVISED_WEIGHTS,
    **metadata.get("unsupervised_weights", {}),
}

# Supervised artifacts
SUPERVISED_MODEL = None
LABEL_ENCODER = None

attack_model_path = MODEL_DIR / "attack_classifier.pkl"
label_encoder_path = MODEL_DIR / "attack_label_encoder.pkl"

if attack_model_path.exists():
    try:
        SUPERVISED_MODEL = joblib.load(attack_model_path)
        if label_encoder_path.exists():
            LABEL_ENCODER = joblib.load(label_encoder_path)
        DETECTION_MODE = "supervised"
    except Exception:
        SUPERVISED_MODEL = None
        LABEL_ENCODER = None

# Unsupervised artifacts
scaler = None
isolation_forest = None
one_class_svm = None

try:
    scaler_path = MODEL_DIR / "scaler.pkl"
    if_path = MODEL_DIR / "isolation_forest.pkl"
    svm_path = MODEL_DIR / "one_class_svm.pkl"

    if scaler_path.exists() and if_path.exists() and svm_path.exists():
        scaler = joblib.load(scaler_path)
        isolation_forest = joblib.load(if_path)
        one_class_svm = joblib.load(svm_path)
except Exception:
    scaler = None
    isolation_forest = None
    one_class_svm = None

# Optional deep models (unsupervised mode)
DENSE_AE_MODEL = None
DENSE_AE_THRESHOLD = None
LSTM_MODEL = None
LSTM_THRESHOLD = None
if DETECTION_MODE != "supervised":
    try:
        import tensorflow as tf

        dense_path = MODEL_DIR / "dense_autoencoder.keras"
        dense_threshold_path = MODEL_DIR / "dense_ae_threshold.npy"
        if dense_path.exists() and dense_threshold_path.exists():
            DENSE_AE_MODEL = tf.keras.models.load_model(dense_path)
            DENSE_AE_THRESHOLD = float(np.load(dense_threshold_path)[0])

        lstm_path = MODEL_DIR / "lstm_autoencoder.keras"
        threshold_path = MODEL_DIR / "lstm_threshold.npy"
        if lstm_path.exists() and threshold_path.exists():
            LSTM_MODEL = tf.keras.models.load_model(lstm_path)
            LSTM_THRESHOLD = float(np.load(threshold_path)[0])
    except Exception:
        DENSE_AE_MODEL = None
        DENSE_AE_THRESHOLD = None
        LSTM_MODEL = None
        LSTM_THRESHOLD = None

_CLIENT_HISTORY = defaultdict(lambda: deque(maxlen=SEQUENCE_LENGTH))


def _ordered_vector(feature_dict: Dict[str, float]) -> np.ndarray:
    if FEATURE_COLUMNS:
        return np.array([feature_dict.get(col, 0.0) for col in FEATURE_COLUMNS], dtype=float)
    return np.array(list(feature_dict.values()), dtype=float)


def _model_input_frame(feature_dict: Dict[str, float]) -> pd.DataFrame:
    if FEATURE_COLUMNS:
        values = {col: float(feature_dict.get(col, 0.0)) for col in FEATURE_COLUMNS}
        return pd.DataFrame([values], columns=FEATURE_COLUMNS)

    ordered_items = list(feature_dict.items())
    if not ordered_items:
        return pd.DataFrame([[0.0]])
    return pd.DataFrame([[float(v) for _, v in ordered_items]], columns=[k for k, _ in ordered_items])


def _decode_label(pred_value) -> str:
    if LABEL_ENCODER is not None:
        try:
            return str(LABEL_ENCODER.inverse_transform([int(pred_value)])[0])
        except Exception:
            pass
    return str(pred_value)


def _weighted_risk(flags: Dict[str, bool]) -> float:
    if not flags:
        return 0.0

    active_weights = {
        key: float(UNSUPERVISED_WEIGHTS.get(key, 1.0)) for key in flags
    }
    weight_sum = float(sum(active_weights.values()))
    if weight_sum <= 0:
        return float(any(flags.values()))

    weighted = 0.0
    for key, is_anomalous in flags.items():
        weighted += active_weights[key] * (1.0 if is_anomalous else 0.0)

    return float(weighted / weight_sum)


def _supervised_detect(feature_dict: Dict[str, float]):
    X = _model_input_frame(feature_dict)

    pred_value = SUPERVISED_MODEL.predict(X)[0]
    predicted_label = _decode_label(pred_value)

    class_probabilities = {}
    confidence = None
    normal_probability = None

    if hasattr(SUPERVISED_MODEL, "predict_proba"):
        proba = SUPERVISED_MODEL.predict_proba(X)[0]

        if LABEL_ENCODER is not None:
            classes = [str(c) for c in LABEL_ENCODER.classes_]
        elif hasattr(SUPERVISED_MODEL, "classes_"):
            classes = [str(c) for c in SUPERVISED_MODEL.classes_]
        else:
            classes = [str(i) for i in range(len(proba))]

        class_probabilities = {
            cls: float(prob) for cls, prob in zip(classes, proba)
        }
        confidence = float(
            class_probabilities.get(predicted_label, max(class_probabilities.values()))
        )
        normal_probability = class_probabilities.get("normal")

    is_anomaly = predicted_label != "normal"

    if normal_probability is not None:
        risk_score = float(max(0.0, min(1.0, 1.0 - normal_probability)))
    elif confidence is not None:
        risk_score = float(confidence if is_anomaly else 1.0 - confidence)
    else:
        risk_score = float(1.0 if is_anomaly else 0.0)

    model_scores = {
        "predicted_label": predicted_label,
    }
    if confidence is not None:
        model_scores["prediction_confidence"] = confidence
    if normal_probability is not None:
        model_scores["normal_probability"] = float(normal_probability)

    return {
        "model_scores": model_scores,
        "is_anomaly": is_anomaly,
        "risk_score": risk_score,
        "anomaly_votes": 1 if is_anomaly else 0,
        "models_considered": 1,
        "model_flags": {"supervised_classifier": is_anomaly},
        "lstm_is_anomaly": False,
        "lstm_error": None,
        "predicted_attack_label": predicted_label,
        "class_probabilities": class_probabilities,
        "detection_mode": "supervised",
    }


def _unsupervised_detect(feature_dict: Dict[str, float], client_id=None):
    if scaler is None or isolation_forest is None or one_class_svm is None:
        raise RuntimeError(
            "No usable model artifacts found. Train supervised model artifacts "
            "(attack_classifier.pkl) or unsupervised artifacts "
            "(scaler.pkl, isolation_forest.pkl, one_class_svm.pkl)."
        )

    X = _model_input_frame(feature_dict)
    X_scaled = scaler.transform(X)

    if_score = float(isolation_forest.decision_function(X_scaled)[0])
    if_pred = int(isolation_forest.predict(X_scaled)[0])

    svm_score = float(one_class_svm.decision_function(X_scaled)[0])
    svm_pred = int(one_class_svm.predict(X_scaled)[0])

    model_scores = {
        "isolation_forest": if_score,
        "one_class_svm": svm_score,
    }
    flags = {
        "isolation_forest": if_pred == -1,
        "one_class_svm": svm_pred == -1,
    }

    dense_ae_error = None
    dense_ae_is_anomaly = False
    if DENSE_AE_MODEL is not None and DENSE_AE_THRESHOLD is not None:
        recon = DENSE_AE_MODEL.predict(X_scaled, verbose=0)
        dense_ae_error = float(np.mean(np.abs(recon - X_scaled), axis=1)[0])
        dense_ae_is_anomaly = dense_ae_error > DENSE_AE_THRESHOLD
        flags["dense_autoencoder"] = dense_ae_is_anomaly
        model_scores["dense_autoencoder_error"] = dense_ae_error
        model_scores["dense_autoencoder_threshold"] = DENSE_AE_THRESHOLD

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
            flags["lstm_autoencoder"] = lstm_is_anomaly
            model_scores["lstm_reconstruction_error"] = lstm_error
            model_scores["lstm_threshold"] = LSTM_THRESHOLD

    risk_score = _weighted_risk(flags)
    is_anomaly = risk_score >= UNSUPERVISED_ANOMALY_THRESHOLD

    return {
        "model_scores": model_scores,
        "is_anomaly": is_anomaly,
        "risk_score": risk_score,
        "anomaly_votes": sum(1 for v in flags.values() if v),
        "models_considered": len(flags),
        "model_flags": flags,
        "lstm_is_anomaly": lstm_is_anomaly,
        "lstm_error": lstm_error,
        "dense_autoencoder_error": dense_ae_error,
        "dense_autoencoder_is_anomaly": dense_ae_is_anomaly,
        "predicted_attack_label": "anomaly" if is_anomaly else "normal",
        "class_probabilities": {},
        "detection_mode": "unsupervised",
        "unsupervised_threshold": UNSUPERVISED_ANOMALY_THRESHOLD,
    }


def detect_anomaly(feature_dict, client_id=None):
    """
    Input: feature_dict
    Output: model scores + anomaly label
    """
    if SUPERVISED_MODEL is not None:
        return _supervised_detect(feature_dict)
    return _unsupervised_detect(feature_dict, client_id=client_id)
