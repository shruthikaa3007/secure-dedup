import argparse
import json
from pathlib import Path
from typing import Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Train anomaly detection models from a CSV feature dataset "
            "(IsolationForest + OneClassSVM + optional LSTM autoencoder)."
        )
    )
    parser.add_argument(
        "--dataset",
        default="training_data.csv",
        help="Path to CSV dataset used for training (default: training_data.csv)",
    )
    parser.add_argument(
        "--model-dir",
        default=".",
        help="Directory to save all trained artifacts (default: current directory)",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.05,
        help="Expected anomaly ratio for Isolation Forest (default: 0.05)",
    )
    parser.add_argument(
        "--estimators",
        type=int,
        default=200,
        help="Number of trees for Isolation Forest (default: 200)",
    )
    parser.add_argument(
        "--ocsvm-nu",
        type=float,
        default=0.05,
        help="Upper bound of outlier fraction for One-Class SVM (default: 0.05)",
    )
    parser.add_argument(
        "--sequence-length",
        type=int,
        default=10,
        help="Sequence length used by optional LSTM autoencoder (default: 10)",
    )
    parser.add_argument(
        "--disable-lstm",
        action="store_true",
        help="Disable LSTM autoencoder training even if TensorFlow is installed",
    )
    return parser.parse_args()


def make_sequences(values: np.ndarray, sequence_length: int) -> np.ndarray:
    if len(values) < sequence_length:
        return np.array([])
    return np.array(
        [values[i : i + sequence_length] for i in range(len(values) - sequence_length + 1)]
    )


def train_lstm_autoencoder(
    X_scaled: np.ndarray, sequence_length: int, model_dir: Path
) -> Tuple[bool, str]:
    try:
        import tensorflow as tf
        from tensorflow.keras import Sequential
        from tensorflow.keras.layers import LSTM, Dense, RepeatVector, TimeDistributed
    except Exception:
        return False, "TensorFlow not available; skipped LSTM autoencoder training"

    sequences = make_sequences(X_scaled, sequence_length)
    if sequences.size == 0:
        return (
            False,
            f"Not enough rows ({len(X_scaled)}) for sequence length {sequence_length}; skipped LSTM",
        )

    tf.random.set_seed(42)
    np.random.seed(42)

    n_features = X_scaled.shape[1]

    model = Sequential(
        [
            LSTM(64, activation="tanh", input_shape=(sequence_length, n_features)),
            RepeatVector(sequence_length),
            LSTM(64, activation="tanh", return_sequences=True),
            TimeDistributed(Dense(n_features)),
        ]
    )
    model.compile(optimizer="adam", loss="mae")
    model.fit(sequences, sequences, epochs=10, batch_size=32, verbose=0)

    recon = model.predict(sequences, verbose=0)
    errors = np.mean(np.abs(recon - sequences), axis=(1, 2))
    threshold = float(np.percentile(errors, 95))

    model.save(model_dir / "lstm_autoencoder.keras")
    np.save(model_dir / "lstm_threshold.npy", np.array([threshold]))

    return True, f"LSTM autoencoder trained (threshold={threshold:.6f})"


def main() -> None:
    args = parse_args()

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    model_dir = Path(args.model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(dataset_path)
    print("Columns in dataset:", df.columns.tolist())

    X = df.select_dtypes(include=[np.number])
    if X.empty:
        raise ValueError("❌ No numeric feature columns found")

    feature_columns = X.columns.tolist()
    print("Numeric feature columns used:", feature_columns)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    isolation_forest = IsolationForest(
        n_estimators=args.estimators,
        contamination=args.contamination,
        random_state=42,
    )
    isolation_forest.fit(X_scaled)

    one_class_svm = OneClassSVM(kernel="rbf", gamma="scale", nu=args.ocsvm_nu)
    one_class_svm.fit(X_scaled)

    joblib.dump(isolation_forest, model_dir / "isolation_forest.pkl")
    joblib.dump(one_class_svm, model_dir / "one_class_svm.pkl")
    joblib.dump(scaler, model_dir / "scaler.pkl")

    metadata = {
        "feature_columns": feature_columns,
        "sequence_length": args.sequence_length,
        "models": ["isolation_forest", "one_class_svm"],
    }

    if not args.disable_lstm:
        trained_lstm, message = train_lstm_autoencoder(
            X_scaled, args.sequence_length, model_dir
        )
        print(message)
        if trained_lstm:
            metadata["models"].append("lstm_autoencoder")
    else:
        print("LSTM autoencoder training disabled by --disable-lstm")

    with open(model_dir / "model_metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"✅ Model training complete using {dataset_path}")
    print(f"Saved artifacts in: {model_dir}")


if __name__ == "__main__":
    main()
