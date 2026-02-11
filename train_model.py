import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import GridSearchCV, StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.svm import OneClassSVM
from sklearn.linear_model import LogisticRegression

UNSUPERVISED_WEIGHTS = {
    "isolation_forest": 0.25,
    "one_class_svm": 0.20,
    "dense_autoencoder": 0.25,
    "lstm_autoencoder": 0.30,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Train anomaly/attack models from a CSV dataset. "
            "Prefers supervised training when labels are available, "
            "with unsupervised fallback."
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
        "--label-column",
        default="attack_label",
        help="Target label column for supervised training (default: attack_label)",
    )
    parser.add_argument(
        "--force-unsupervised",
        action="store_true",
        help="Ignore labels and train only unsupervised models",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Holdout test split ratio for supervised training (default: 0.2)",
    )
    parser.add_argument(
        "--cv-folds",
        type=int,
        default=3,
        help="Maximum CV folds for supervised model selection (default: 3)",
    )
    parser.add_argument(
        "--scoring",
        default="f1_macro",
        help="GridSearchCV scoring metric for supervised mode (default: f1_macro)",
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
        default=300,
        help="Number of trees for Isolation Forest (default: 300)",
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
        "--disable-autoencoder",
        action="store_true",
        help="Disable dense autoencoder training even if TensorFlow is installed",
    )
    parser.add_argument(
        "--disable-lstm",
        action="store_true",
        help="Disable LSTM autoencoder training even if TensorFlow is installed",
    )
    parser.add_argument(
        "--unsupervised-threshold",
        type=float,
        default=0.50,
        help=(
            "Risk threshold used by unsupervised runtime decision "
            "(default: 0.50)"
        ),
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed (default: 42)",
    )
    return parser.parse_args()


def make_sequences(values: np.ndarray, sequence_length: int) -> np.ndarray:
    if len(values) < sequence_length:
        return np.array([])
    return np.array(
        [values[i : i + sequence_length] for i in range(len(values) - sequence_length + 1)]
    )


def train_dense_autoencoder(X_scaled: np.ndarray, model_dir: Path) -> Tuple[bool, str]:
    try:
        import tensorflow as tf
        from tensorflow.keras import Sequential
        from tensorflow.keras.layers import Dense, Input
    except Exception:
        return False, "TensorFlow not available; skipped dense autoencoder training"

    tf.random.set_seed(42)
    np.random.seed(42)

    n_features = X_scaled.shape[1]
    if n_features < 2:
        return False, "Not enough features for dense autoencoder; skipped"

    hidden_1 = min(8, n_features)
    hidden_2 = min(4, hidden_1)

    model = Sequential(
        [
            Input(shape=(n_features,)),
            Dense(hidden_1, activation="relu"),
            Dense(hidden_2, activation="relu"),
            Dense(hidden_1, activation="relu"),
            Dense(n_features, activation="linear"),
        ]
    )
    model.compile(optimizer="adam", loss="mae")
    model.fit(X_scaled, X_scaled, epochs=20, batch_size=32, verbose=0)

    recon = model.predict(X_scaled, verbose=0)
    errors = np.mean(np.abs(recon - X_scaled), axis=1)
    threshold = float(np.percentile(errors, 95))

    model.save(model_dir / "dense_autoencoder.keras")
    np.save(model_dir / "dense_ae_threshold.npy", np.array([threshold]))

    return True, f"Dense autoencoder trained (threshold={threshold:.6f})"


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
            (
                f"Not enough rows ({len(X_scaled)}) for sequence length {sequence_length}; "
                "skipped LSTM"
            ),
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


def get_numeric_features(df: pd.DataFrame, exclude: List[str]) -> pd.DataFrame:
    feature_columns = [c for c in df.columns if c not in exclude]
    if not feature_columns:
        raise ValueError("No candidate feature columns found")

    X = df[feature_columns].copy()
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")

    X = X.dropna(axis=1, how="all")
    if X.empty:
        raise ValueError("No numeric feature columns available after conversion")

    return X


def supervised_candidates(random_state: int) -> Dict[str, Tuple[Pipeline, Dict[str, List]]]:
    return {
        "hist_gradient_boosting": (
            Pipeline(
                [
                    ("imputer", SimpleImputer(strategy="median")),
                    (
                        "model",
                        HistGradientBoostingClassifier(random_state=random_state),
                    ),
                ]
            ),
            {
                "model__max_depth": [None, 6, 10],
                "model__learning_rate": [0.05, 0.1],
                "model__max_iter": [200, 400],
            },
        ),
        "random_forest": (
            Pipeline(
                [
                    ("imputer", SimpleImputer(strategy="median")),
                    (
                        "model",
                        RandomForestClassifier(
                            random_state=random_state,
                            class_weight="balanced_subsample",
                            n_jobs=-1,
                        ),
                    ),
                ]
            ),
            {
                "model__n_estimators": [200, 400],
                "model__max_depth": [None, 10, 20],
                "model__min_samples_leaf": [1, 2, 5],
            },
        ),
        "logistic_regression": (
            Pipeline(
                [
                    ("imputer", SimpleImputer(strategy="median")),
                    ("scaler", StandardScaler()),
                    (
                        "model",
                        LogisticRegression(
                            max_iter=3000,
                            class_weight="balanced",
                            solver="lbfgs",
                        ),
                    ),
                ]
            ),
            {
                "model__C": [0.1, 1.0, 3.0],
            },
        ),
    }


def train_supervised(
    X: pd.DataFrame,
    y_raw: pd.Series,
    feature_columns: List[str],
    model_dir: Path,
    args: argparse.Namespace,
) -> Dict:
    y_raw = y_raw.astype(str)
    label_counts = y_raw.value_counts().to_dict()

    if len(label_counts) < 2:
        raise ValueError("Supervised training requires at least 2 label classes")

    min_class_count = int(min(label_counts.values()))
    if min_class_count < 2:
        raise ValueError(
            "Supervised CV requires at least 2 samples per class; "
            "add more labeled data or use --force-unsupervised"
        )

    cv_folds = max(2, min(args.cv_folds, min_class_count))

    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y_raw)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_encoded,
        test_size=args.test_size,
        stratify=y_encoded,
        random_state=args.random_state,
    )

    cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=args.random_state)

    best_name: Optional[str] = None
    best_search: Optional[GridSearchCV] = None

    for model_name, (pipeline, param_grid) in supervised_candidates(args.random_state).items():
        search = GridSearchCV(
            estimator=pipeline,
            param_grid=param_grid,
            scoring=args.scoring,
            cv=cv,
            n_jobs=-1,
            refit=True,
        )
        search.fit(X_train, y_train)

        print(
            f"[{model_name}] best CV {args.scoring}: "
            f"{search.best_score_:.4f} params={search.best_params_}"
        )

        if best_search is None or search.best_score_ > best_search.best_score_:
            best_search = search
            best_name = model_name

    if best_search is None or best_name is None:
        raise RuntimeError("No supervised model candidate was trained")

    y_pred = best_search.predict(X_test)
    class_names = encoder.inverse_transform(np.arange(len(encoder.classes_)))

    report = classification_report(
        y_test,
        y_pred,
        labels=np.arange(len(encoder.classes_)),
        target_names=class_names,
        output_dict=True,
        zero_division=0,
    )
    matrix = confusion_matrix(y_test, y_pred).tolist()

    joblib.dump(best_search.best_estimator_, model_dir / "attack_classifier.pkl")
    joblib.dump(encoder, model_dir / "attack_label_encoder.pkl")

    metrics = {
        "mode": "supervised",
        "label_column": args.label_column,
        "rows": int(len(X)),
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "class_distribution": {k: int(v) for k, v in label_counts.items()},
        "cv_folds": cv_folds,
        "scoring": args.scoring,
        "best_model": best_name,
        "best_params": best_search.best_params_,
        "best_cv_score": float(best_search.best_score_),
        "classification_report": report,
        "confusion_matrix": matrix,
    }

    with open(model_dir / "training_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    metadata = {
        "mode": "supervised",
        "label_column": args.label_column,
        "feature_columns": feature_columns,
        "models": ["attack_classifier"],
        "classes": encoder.classes_.tolist(),
        "best_model": best_name,
        "best_params": best_search.best_params_,
        "scoring": args.scoring,
    }

    return metadata


def train_unsupervised(
    X: pd.DataFrame,
    feature_columns: List[str],
    model_dir: Path,
    args: argparse.Namespace,
) -> Dict:
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    isolation_forest = IsolationForest(
        n_estimators=args.estimators,
        contamination=args.contamination,
        random_state=args.random_state,
    )
    isolation_forest.fit(X_scaled)

    one_class_svm = OneClassSVM(kernel="rbf", gamma="scale", nu=args.ocsvm_nu)
    one_class_svm.fit(X_scaled)

    joblib.dump(isolation_forest, model_dir / "isolation_forest.pkl")
    joblib.dump(one_class_svm, model_dir / "one_class_svm.pkl")
    joblib.dump(scaler, model_dir / "scaler.pkl")

    metadata = {
        "mode": "unsupervised",
        "feature_columns": feature_columns,
        "sequence_length": args.sequence_length,
        "models": ["isolation_forest", "one_class_svm"],
        "unsupervised_weights": UNSUPERVISED_WEIGHTS,
        "unsupervised_anomaly_threshold": args.unsupervised_threshold,
    }

    if not args.disable_autoencoder:
        trained_dense_ae, message = train_dense_autoencoder(X_scaled, model_dir)
        print(message)
        if trained_dense_ae:
            metadata["models"].append("dense_autoencoder")
    else:
        print("Dense autoencoder training disabled by --disable-autoencoder")

    if not args.disable_lstm:
        trained_lstm, message = train_lstm_autoencoder(
            X_scaled, args.sequence_length, model_dir
        )
        print(message)
        if trained_lstm:
            metadata["models"].append("lstm_autoencoder")
    else:
        print("LSTM autoencoder training disabled by --disable-lstm")

    return metadata


def main() -> None:
    args = parse_args()

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    model_dir = Path(args.model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(dataset_path)
    if df.empty:
        raise ValueError(f"Dataset is empty: {dataset_path}")

    print(f"Loaded dataset: {dataset_path} rows={len(df)}")
    print("Columns:", df.columns.tolist())

    exclude_columns = ["client_id", "is_anomaly", args.label_column]
    X = get_numeric_features(df, exclude=exclude_columns)

    # Drop rows with any missing features to keep training stable for all models.
    combined = X.copy()
    y_raw = None
    if args.label_column in df.columns:
        combined[args.label_column] = df[args.label_column]

    before_drop = len(combined)
    combined = combined.dropna(axis=0)
    dropped = before_drop - len(combined)
    if dropped:
        print(f"Dropped {dropped} rows containing missing values")

    if combined.empty:
        raise ValueError("No rows remain after cleaning missing feature values")

    if args.label_column in combined.columns:
        y_raw = combined.pop(args.label_column)

    feature_columns = combined.columns.tolist()

    label_counts = None
    binary_collapse_applied = False
    if y_raw is not None:
        label_counts = y_raw.astype(str).value_counts()

    if (
        (not args.force_unsupervised)
        and (label_counts is not None)
        and (label_counts.size >= 2)
        and (int(label_counts.min()) < 2)
    ):
        binary_labels = y_raw.astype(str).apply(
            lambda label: "normal" if label == "normal" else "anomaly"
        )
        binary_counts = binary_labels.value_counts()
        if binary_counts.size == 2 and int(binary_counts.min()) >= 2:
            y_raw = binary_labels
            label_counts = binary_counts
            binary_collapse_applied = True
            print(
                "Applied label collapse for supervised training: "
                "non-normal labels -> anomaly"
            )

    use_supervised = (
        (not args.force_unsupervised)
        and (label_counts is not None)
        and (label_counts.size >= 2)
        and (int(label_counts.min()) >= 2)
    )

    if use_supervised:
        print("Training mode: supervised (label-aware model selection)")
        metadata = train_supervised(
            X=combined,
            y_raw=y_raw,
            feature_columns=feature_columns,
            model_dir=model_dir,
            args=args,
        )
        if binary_collapse_applied:
            metadata["label_mode"] = "binary_anomaly"
            metadata["label_collapse"] = {
                "normal": "normal",
                "*": "anomaly",
            }
    else:
        if y_raw is None:
            print("Training mode: unsupervised (no label column found)")
        elif label_counts is not None and label_counts.size < 2:
            print("Training mode: unsupervised (labels have <2 classes)")
        elif label_counts is not None and int(label_counts.min()) < 2:
            print(
                "Training mode: unsupervised "
                "(at least one label class has <2 rows)"
            )
        else:
            print("Training mode: unsupervised (forced by --force-unsupervised)")

        metadata = train_unsupervised(
            X=combined,
            feature_columns=feature_columns,
            model_dir=model_dir,
            args=args,
        )

    with open(model_dir / "model_metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"Training complete. Saved artifacts in: {model_dir}")


if __name__ == "__main__":
    main()
