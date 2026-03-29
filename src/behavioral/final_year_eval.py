from __future__ import annotations

import csv
import hashlib
import math
from collections import defaultdict
from pathlib import Path
from statistics import mean, pstdev

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import average_precision_score, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split

from src.behavioral.evaluation import compare_behavioral_vectors
from src.config import BEHAVIORAL_MODEL_RANDOM_STATE


TIMING_FIELDS = (
    "tau_avg",
    "tau_std",
    "tau_min",
    "tau_max",
    "interarrival_cv",
    "n_chunks",
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _positive_std(values: list[float], fallback: float) -> float:
    if len(values) < 2:
        return max(fallback, 1.0)
    sigma = pstdev(values)
    return sigma if sigma > 1e-9 else max(fallback, 1.0)


def _build_vector(
    delays: list[float],
    n_events: int,
    source: str,
    label: str,
    attack_type: str = "benign",
    prefix: str | None = None,
) -> dict:
    tau_avg = float(mean(delays)) if delays else 0.0
    tau_std = float(pstdev(delays)) if len(delays) > 1 else 0.0
    tau_min = float(min(delays)) if delays else 0.0
    tau_max = float(max(delays)) if delays else 0.0
    interarrival_cv = float(tau_std / tau_avg) if tau_avg > 0 else 0.0
    token = prefix or f"{source}:{label}:{attack_type}:{tau_avg:.4f}:{tau_std:.4f}:{n_events}"
    return {
        "tau_avg": tau_avg,
        "tau_std": tau_std,
        "tau_min": tau_min,
        "tau_max": tau_max,
        "interarrival_cv": interarrival_cv,
        "entropy_mean": 7.0 if label == "benign" else 6.0,
        "entropy_std": 0.15 if label == "benign" else 0.8,
        "entropy_min": 6.85 if label == "benign" else 5.0,
        "entropy_max": 7.15 if label == "benign" else 7.9,
        "tau_seq_hash": _digest(token + ":tau"),
        "entropy_dist_hash": _digest(token + ":entropy"),
        "chunk_order_hash": _digest(token + ":order"),
        "n_chunks": int(n_events),
        "session_id": _digest(token + ":session"),
        "source": source,
        "label": label,
        "attack_type": attack_type,
    }


def extract_azure_trace_vectors(
    trace_path: str,
    window_size_s: float = 120.0,
    min_events: int = 5,
    max_apps: int = 75,
    max_windows_per_app: int = 6,
) -> list[dict]:
    path = Path(trace_path)
    if not path.exists():
        raise FileNotFoundError(f"Trace file not found: {trace_path}")

    events_by_app: dict[str, list[tuple[float, float]]] = defaultdict(list)
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            try:
                app = row["app"]
                end_timestamp = float(row["end_timestamp"])
                duration = float(row["duration"])
            except (KeyError, TypeError, ValueError):
                continue
            events_by_app[app].append((end_timestamp, duration))

    ranked_apps = sorted(events_by_app.items(), key=lambda item: len(item[1]), reverse=True)
    vectors: list[dict] = []
    for app_index, (app, events) in enumerate(ranked_apps):
        if max_apps and app_index >= max_apps:
            break
        events.sort(key=lambda item: item[0])
        current_bucket = None
        current_events: list[tuple[float, float]] = []
        emitted_windows = 0

        def flush_window(bucket_id: int | None, window_events: list[tuple[float, float]]) -> None:
            nonlocal emitted_windows
            if bucket_id is None or len(window_events) < min_events or emitted_windows >= max_windows_per_app:
                return
            timestamps = [item[0] for item in window_events]
            delays = [timestamps[index] - timestamps[index - 1] for index in range(1, len(timestamps))]
            if not delays:
                return
            vectors.append(
                _build_vector(
                    delays,
                    n_events=len(window_events),
                    source="azure_trace",
                    label="benign",
                    prefix=f"azure:{app}:{bucket_id}",
                )
            )
            emitted_windows += 1

        for end_timestamp, duration in events:
            _ = duration
            bucket = int(math.floor(end_timestamp / window_size_s))
            if current_bucket is None:
                current_bucket = bucket
            if bucket != current_bucket:
                flush_window(current_bucket, current_events)
                current_events = []
                current_bucket = bucket
            current_events.append((end_timestamp, duration))
        flush_window(current_bucket, current_events)

    if not vectors:
        raise ValueError("No trace-derived windows were extracted; try reducing min_events or increasing max_apps")
    return vectors


def generate_calibrated_benign_vectors(reference_vectors: list[dict], n: int, seed: int = 2026) -> list[dict]:
    rng = np.random.default_rng(seed)

    vectors: list[dict] = []
    for index in range(n):
        base = reference_vectors[index % len(reference_vectors)]
        n_events = max(5, int(round(float(base["n_chunks"]) * rng.uniform(0.90, 1.10))))
        delay_mean = max(0.05, float(base["tau_avg"]) * rng.uniform(0.90, 1.10))
        delay_cv = min(3.0, max(0.01, float(base["interarrival_cv"]) * rng.uniform(0.85, 1.15)))
        delay_sigma = max(0.01, delay_mean * delay_cv)
        delays = np.clip(rng.normal(delay_mean, delay_sigma, size=max(4, n_events - 1)), 0.01, None).tolist()
        vectors.append(
            _build_vector(
                delays,
                n_events=n_events,
                source="synthetic_calibrated",
                label="benign",
                prefix=f"synthetic:benign:{index}",
            )
        )
    return vectors


def generate_attack_vectors(reference_vectors: list[dict], n: int, seed: int = 2027) -> list[dict]:
    rng = np.random.default_rng(seed)
    vectors: list[dict] = []
    for index in range(n):
        base = reference_vectors[index % len(reference_vectors)]
        attack_type = ("bot_speed", "replay", "dedup_dos")[index % 3]
        base_tau = max(0.05, float(base["tau_avg"]))
        base_cv = max(0.01, float(base["interarrival_cv"]))
        base_n = max(5, int(float(base["n_chunks"])))

        if attack_type == "bot_speed":
            delay_mean = base_tau * rng.uniform(0.25, 0.55)
            delay_cv = max(0.01, base_cv * rng.uniform(0.30, 0.80))
            n_events = max(5, int(round(base_n * rng.uniform(1.00, 1.35))))
        elif attack_type == "replay":
            delay_mean = base_tau * rng.uniform(0.55, 0.90)
            delay_cv = max(0.005, base_cv * rng.uniform(0.05, 0.25))
            n_events = max(5, int(round(base_n * rng.uniform(0.95, 1.15))))
        else:
            delay_mean = base_tau * rng.uniform(0.45, 0.75)
            delay_cv = max(0.01, base_cv * rng.uniform(0.20, 0.60))
            n_events = max(5, int(round(base_n * rng.uniform(1.20, 1.70))))

        delay_sigma = max(0.01, delay_mean * delay_cv)
        delays = np.clip(rng.normal(delay_mean, delay_sigma, size=max(4, n_events - 1)), 0.001, None).tolist()
        vectors.append(
            _build_vector(
                delays,
                n_events=n_events,
                source="synthetic_attack",
                label="attack",
                attack_type=attack_type,
                prefix=f"synthetic:attack:{attack_type}:{index}",
            )
        )
    return vectors


def build_alignment_table(trace_vectors: list[dict], synthetic_vectors: list[dict]) -> pd.DataFrame:
    report = compare_behavioral_vectors(trace_vectors, synthetic_vectors, fields=TIMING_FIELDS)
    rows = []
    for field, metrics in report.items():
        rows.append(
            {
                "feature": field,
                "reference_mean": metrics["reference_mean"],
                "candidate_mean": metrics["candidate_mean"],
                "wasserstein_distance": metrics["wasserstein_distance"],
                "ks_statistic": metrics["ks_statistic"],
                "ks_pvalue": metrics["ks_pvalue"],
            }
        )
    return pd.DataFrame(rows)


def _feature_matrix(vectors: list[dict]) -> np.ndarray:
    return np.asarray([[float(vector[field]) for field in TIMING_FIELDS] for vector in vectors], dtype=float)


def _binary_metrics(name: str, y_true: np.ndarray, y_pred: np.ndarray, score: np.ndarray) -> dict:
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true,
        y_pred,
        average="binary",
        zero_division=0,
    )
    return {
        "method": name,
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "auroc": float(roc_auc_score(y_true, score)),
        "pr_auc": float(average_precision_score(y_true, score)),
    }


def _fit_zscore_profile(X_benign: np.ndarray) -> dict:
    mu_tau = float(np.mean(X_benign[:, 0]))
    sigma_tau = float(np.std(X_benign[:, 0])) or max(mu_tau * 0.05, 1.0)
    mu_cv = float(np.mean(X_benign[:, 4]))
    sigma_cv = float(np.std(X_benign[:, 4])) or 0.05
    mu_n = float(np.mean(X_benign[:, 5]))
    sigma_n = float(np.std(X_benign[:, 5])) or 1.0
    return {
        "mu_tau": mu_tau,
        "sigma_tau": sigma_tau,
        "mu_cv": mu_cv,
        "sigma_cv": sigma_cv,
        "mu_n": mu_n,
        "sigma_n": sigma_n,
    }


def _zscore_score(X: np.ndarray, profile: dict) -> np.ndarray:
    tau_risk = np.maximum(0.0, (profile["mu_tau"] - X[:, 0]) / profile["sigma_tau"])
    cv_risk = np.maximum(0.0, (profile["mu_cv"] - X[:, 4]) / profile["sigma_cv"])
    chunk_risk = np.maximum(0.0, (X[:, 5] - profile["mu_n"]) / profile["sigma_n"])
    return np.maximum.reduce([tau_risk, cv_risk, chunk_risk])


def evaluate_ablation_tables(
    benign_vectors: list[dict],
    attack_vectors: list[dict],
    random_state: int = BEHAVIORAL_MODEL_RANDOM_STATE,
) -> pd.DataFrame:
    dataset = list(benign_vectors) + list(attack_vectors)
    X = _feature_matrix(dataset)
    y = np.asarray([0] * len(benign_vectors) + [1] * len(attack_vectors), dtype=int)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.30,
        random_state=random_state,
        stratify=y,
    )
    X_train_benign = X_train[y_train == 0]

    z_profile = _fit_zscore_profile(X_train_benign)
    z_score = _zscore_score(X_test, z_profile)
    z_pred = z_score >= 1.75

    classifier = RandomForestClassifier(
        n_estimators=160,
        max_depth=6,
        random_state=random_state,
    )
    classifier.fit(X_train, y_train)
    supervised_score = classifier.predict_proba(X_test)[:, 1]
    supervised_pred = supervised_score >= 0.5

    detector = IsolationForest(contamination=0.10, random_state=random_state)
    detector.fit(X_train_benign)
    unsupervised_raw = -detector.decision_function(X_test)
    benign_reference = -detector.decision_function(X_train_benign)
    unsupervised_threshold = float(np.quantile(benign_reference, 0.95))
    unsupervised_pred = unsupervised_raw >= unsupervised_threshold
    unsupervised_score = unsupervised_raw / max(unsupervised_threshold, 1e-6)

    full_score = np.maximum.reduce([supervised_score, z_score / 3.0, unsupervised_score])
    full_pred = supervised_pred | unsupervised_pred | z_pred

    rows = [
        _binary_metrics("z_score_only", y_test, z_pred.astype(int), z_score / 3.0),
        _binary_metrics("supervised_only", y_test, supervised_pred.astype(int), supervised_score),
        _binary_metrics("full_behavioral_gate", y_test, full_pred.astype(int), full_score),
    ]
    return pd.DataFrame(rows)


def generate_final_year_report(trace_path: str) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    trace_vectors = extract_azure_trace_vectors(trace_path)
    synthetic_benign = generate_calibrated_benign_vectors(trace_vectors, n=len(trace_vectors))
    synthetic_attack = generate_attack_vectors(trace_vectors, n=len(trace_vectors))
    alignment_table = build_alignment_table(trace_vectors, synthetic_benign)
    ablation_table = evaluate_ablation_tables(trace_vectors, synthetic_attack)
    summary = {
        "trace_windows": len(trace_vectors),
        "synthetic_benign_windows": len(synthetic_benign),
        "synthetic_attack_windows": len(synthetic_attack),
        "trace_source": str(trace_path),
        "evaluation_story": "hybrid_final_year_project",
    }
    return alignment_table, ablation_table, summary
