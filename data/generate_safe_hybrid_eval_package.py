from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.behavioral.evaluation import compare_behavioral_vectors
from src.behavioral.final_year_eval import _build_vector, extract_azure_trace_vectors, generate_calibrated_benign_vectors


TIMING_FIELDS = [
    "tau_avg",
    "tau_std",
    "tau_min",
    "tau_max",
    "interarrival_cv",
    "n_chunks",
]
FULL_FIELDS = TIMING_FIELDS + ["entropy_mean", "entropy_std", "entropy_min", "entropy_max"]
MULTICLASS_LABELS = ["normal", "hash_probing", "ownership_fraud", "dedup_dos"]
ATTACK_TYPE_COUNTS = {
    "hash_probing": 270,
    "ownership_fraud": 260,
    "dedup_dos": 270,
}
ENTROPY_SIGNATURES = {
    "hash_probing": (6.6, 0.18, 0.45, 0.10, 0.45, 0.18),
    "ownership_fraud": (6.25, 0.22, 0.62, 0.12, 0.75, 0.28),
    "dedup_dos": (5.95, 0.28, 0.86, 0.14, 1.00, 0.35),
}


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _save_figure(fig, path: Path) -> None:
    _ensure_dir(path.parent)
    fig.tight_layout()
    fig.savefig(path, dpi=220, bbox_inches="tight")
    plt.close(fig)


def _metrics_row(name: str, y_true: np.ndarray, y_pred: np.ndarray, score: np.ndarray) -> dict[str, float | str]:
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


def _generic_attack_vectors(reference_vectors: list[dict], n: int, seed: int = 3030) -> list[dict]:
    rng = np.random.default_rng(seed)
    vectors: list[dict] = []
    for index in range(n):
        base = reference_vectors[index % len(reference_vectors)]
        base_tau = max(0.05, float(base["tau_avg"]))
        base_cv = max(0.01, float(base["interarrival_cv"]))
        base_n = max(5, int(float(base["n_chunks"])))

        if rng.random() < 0.25:
            delay_mean = base_tau * rng.uniform(0.88, 1.08)
            delay_cv = max(0.01, base_cv * rng.uniform(0.85, 1.15))
            n_events = max(5, int(round(base_n * rng.uniform(0.96, 1.10))))
        else:
            delay_mean = base_tau * rng.uniform(0.55, 0.90)
            delay_cv = max(0.01, base_cv * rng.uniform(0.20, 0.70))
            n_events = max(5, int(round(base_n * rng.uniform(0.98, 1.25))))

        delay_sigma = max(0.01, delay_mean * delay_cv)
        delays = np.clip(rng.normal(delay_mean, delay_sigma, size=max(4, n_events - 1)), 0.001, None).tolist()
        vectors.append(
            _build_vector(
                delays,
                n_events=n_events,
                source="synthetic_attack",
                label="attack",
                attack_type="attack",
                prefix=f"stress:attack:{index}",
            )
        )
    return vectors


def _apply_entropy_signature(vector: dict, attack_type: str, rng: np.random.Generator, strength: float = 0.98) -> None:
    mean_mu, mean_sd, std_mu, std_sd, span_mu, span_sd = ENTROPY_SIGNATURES[attack_type]
    benign_mean = 7.0

    mean_mu = benign_mean - (benign_mean - mean_mu) * strength
    std_mu = 0.15 + (std_mu - 0.15) * strength
    span_mu = 0.30 + (span_mu - 0.30) * strength

    vector["entropy_mean"] = float(rng.normal(mean_mu, mean_sd))
    vector["entropy_std"] = float(np.clip(rng.normal(std_mu, std_sd), 0.08, 1.20))
    low_span = max(0.15, rng.normal(span_mu, span_sd))
    high_span = max(0.12, rng.normal(span_mu * 0.85, span_sd))
    vector["entropy_min"] = float(np.clip(vector["entropy_mean"] - low_span, 4.8, 6.95))
    vector["entropy_max"] = float(np.clip(vector["entropy_mean"] + high_span, 6.2, 7.85))


def _build_stress_test_dataset(trace_vectors: list[dict]) -> tuple[list[dict], list[dict], pd.DataFrame]:
    synthetic_benign = generate_calibrated_benign_vectors(trace_vectors, n=1400, seed=2026)
    synthetic_attack = _generic_attack_vectors(trace_vectors, n=sum(ATTACK_TYPE_COUNTS.values()), seed=3030)

    attack_types: list[str] = []
    for attack_type, count in ATTACK_TYPE_COUNTS.items():
        attack_types.extend([attack_type] * count)

    for index, vector in enumerate(synthetic_attack):
        attack_type = attack_types[index]
        vector["attack_type"] = attack_type
        _apply_entropy_signature(vector, attack_type, np.random.default_rng(5000 + index))

    rows: list[dict] = []
    for index, vector in enumerate(synthetic_benign):
        row = dict(vector)
        row["sample_id"] = f"stress-benign-{index:04d}"
        row["behavioral_label"] = "normal"
        row["is_simulated"] = True
        row["label_origin"] = "rule_derived"
        row["calibration_source"] = "AzureFunctionsInvocationTraceForTwoWeeksJan2021"
        row["evaluation_tier"] = "stress_test"
        rows.append(row)

    for index, vector in enumerate(synthetic_attack):
        row = dict(vector)
        row["sample_id"] = f"stress-attack-{index:04d}"
        row["behavioral_label"] = row["attack_type"]
        row["is_simulated"] = True
        row["label_origin"] = "rule_derived"
        row["calibration_source"] = "AzureFunctionsInvocationTraceForTwoWeeksJan2021"
        row["evaluation_tier"] = "stress_test"
        rows.append(row)

    dataset = pd.DataFrame(rows)
    return synthetic_benign, synthetic_attack, dataset


def _alignment_table(trace_vectors: list[dict], synthetic_benign: list[dict]) -> pd.DataFrame:
    report = compare_behavioral_vectors(trace_vectors, synthetic_benign, fields=TIMING_FIELDS)
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


def _binary_split(dataset: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    X = dataset[FULL_FIELDS].to_numpy(dtype=float)
    y = (dataset["label"] == "attack").astype(int).to_numpy()
    return train_test_split(X, y, test_size=0.30, random_state=2026, stratify=y)


def _evaluate_binary_supervised(
    dataset: pd.DataFrame,
) -> tuple[dict, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    X = dataset[TIMING_FIELDS].to_numpy(dtype=float)
    y = (dataset["label"] == "attack").astype(int).to_numpy()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.30, random_state=2026, stratify=y)

    classifier = RandomForestClassifier(
        n_estimators=120,
        max_depth=4,
        random_state=2026,
    )
    classifier.fit(X_train, y_train)
    score = classifier.predict_proba(X_test)[:, 1]
    pred = (score >= 0.45).astype(int)

    metrics = _metrics_row("supervised_only", y_test, pred, score)
    metrics.update(
        {
            "tn": int(((y_test == 0) & (pred == 0)).sum()),
            "fp": int(((y_test == 0) & (pred == 1)).sum()),
            "fn": int(((y_test == 1) & (pred == 0)).sum()),
            "tp": int(((y_test == 1) & (pred == 1)).sum()),
        }
    )
    return metrics, X_train, X_test, y_train, y_test, pred, score


def _evaluate_zscore_and_hybrid(
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
    supervised_pred: np.ndarray,
    supervised_score: np.ndarray,
) -> pd.DataFrame:
    X_train_benign = X_train[y_train == 0]
    mu = X_train_benign.mean(axis=0)
    sigma = X_train_benign.std(axis=0)
    sigma = np.where(sigma < 1e-6, 1.0, sigma)

    tau_risk = np.maximum(0.0, (mu[0] - X_test[:, 0]) / sigma[0])
    cv_risk = np.maximum(0.0, (mu[4] - X_test[:, 4]) / sigma[4])
    chunk_risk = np.maximum(0.0, (X_test[:, 5] - mu[5]) / sigma[5])
    z = np.maximum.reduce([tau_risk, cv_risk, chunk_risk])
    z_score = np.clip(z / 3.0, 0.0, 1.5)
    z_pred = (z >= 2.0).astype(int)

    hybrid_score = np.maximum(supervised_score, z_score)
    hybrid_pred = (supervised_pred | z_pred).astype(int)

    rows = [
        _metrics_row("z_score_only", y_test, z_pred, z_score),
        _metrics_row("supervised_only", y_test, supervised_pred, supervised_score),
        _metrics_row("hybrid_trace_gate", y_test, hybrid_pred, hybrid_score),
    ]
    return pd.DataFrame(rows)


def _evaluate_multiclass(dataset: pd.DataFrame) -> tuple[dict, np.ndarray]:
    labels = dataset["behavioral_label"].to_numpy()
    X = dataset[FULL_FIELDS].to_numpy(dtype=float)
    X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.30, random_state=2026, stratify=labels)

    classifier = RandomForestClassifier(
        n_estimators=180,
        max_depth=6,
        random_state=2026,
    )
    classifier.fit(X_train, y_train)
    pred = classifier.predict(X_test)
    macro_f1 = float(f1_score(y_test, pred, average="macro"))

    per_class_rows: list[dict[str, float | str]] = []
    for label in MULTICLASS_LABELS:
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test,
            pred,
            labels=[label],
            average="macro",
            zero_division=0,
        )
        per_class_rows.append(
            {
                "label": label,
                "precision": float(precision),
                "recall": float(recall),
                "f1": float(f1),
            }
        )

    return {
        "macro_f1": macro_f1,
        "per_class": per_class_rows,
        "labels_test": y_test,
        "labels_pred": pred,
    }, confusion_matrix(y_test, pred, labels=MULTICLASS_LABELS)


def _evaluate_cold_start_ocsvm(dataset: pd.DataFrame) -> tuple[dict, np.ndarray, np.ndarray, np.ndarray]:
    X = dataset[FULL_FIELDS].to_numpy(dtype=float)
    y = (dataset["label"] == "attack").astype(int).to_numpy()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.30, random_state=2026, stratify=y)

    scaler = StandardScaler().fit(X_train[y_train == 0])
    X_train_benign = scaler.transform(X_train[y_train == 0])
    X_test_scaled = scaler.transform(X_test)

    detector = OneClassSVM(kernel="rbf", gamma=0.1, nu=0.05)
    detector.fit(X_train_benign)

    raw_score = -detector.decision_function(X_test_scaled)
    benign_reference = -detector.decision_function(X_train_benign)
    threshold = float(np.quantile(benign_reference, 0.75))
    pred = (raw_score >= threshold).astype(int)

    metrics = _metrics_row("ocsvm_cold_start", y_test, pred, raw_score)
    metrics.update(
        {
            "tn": int(((y_test == 0) & (pred == 0)).sum()),
            "fp": int(((y_test == 0) & (pred == 1)).sum()),
            "fn": int(((y_test == 1) & (pred == 0)).sum()),
            "tp": int(((y_test == 1) & (pred == 1)).sum()),
        }
    )
    return metrics, confusion_matrix(y_test, pred), y_test, raw_score


def _simulate_adaptive_pow(dataset: pd.DataFrame) -> dict[str, float | dict[str, int]]:
    X = dataset[TIMING_FIELDS].to_numpy(dtype=float)
    y = (dataset["label"] == "attack").astype(int).to_numpy()

    model = RandomForestClassifier(
        n_estimators=120,
        max_depth=4,
        random_state=2026,
    )
    model.fit(X, y)
    risk = model.predict_proba(X)[:, 1]

    benign_mask = y == 0
    attack_mask = y == 1
    risk_benign = risk[benign_mask]
    risk_attack = risk[attack_mask]

    proof_length = 32.0 + np.round(110.0 * risk)
    proof_length_benign = proof_length[benign_mask]
    proof_length_attack = proof_length[attack_mask]

    baseline_success = 1.0 - (1.0 - 2.0**-20) ** (2.0 * (2.0**20))
    adaptive_difficulty = 20.0 + np.round(2.5 * risk_attack)
    adaptive_success = np.mean(1.0 - (1.0 - 2.0 ** (-adaptive_difficulty)) ** (2.0 * (2.0**20)))

    difficulty_tiers = {
        "static": int((adaptive_difficulty == 20).sum()),
        "elevated": int((adaptive_difficulty == 21).sum()),
        "hardened": int((adaptive_difficulty == 22).sum()),
        "severe": int((adaptive_difficulty >= 23).sum()),
    }

    return {
        "static_proof_length_bytes": 32.0,
        "adaptive_mean_proof_length_all": float(proof_length.mean()),
        "adaptive_mean_proof_length_benign": float(proof_length_benign.mean()),
        "adaptive_mean_proof_length_attack": float(proof_length_attack.mean()),
        "baseline_attacker_success": float(baseline_success),
        "adaptive_attacker_success": float(adaptive_success),
        "relative_reduction_percent": float((baseline_success - adaptive_success) / baseline_success * 100.0),
        "benign_overhead_percent": float((proof_length_benign.mean() - 32.0) / 32.0 * 100.0),
        "difficulty_tiers": difficulty_tiers,
        "risk_mean_benign": float(risk_benign.mean()),
        "risk_mean_attack": float(risk_attack.mean()),
    }


def _plot_binary_confusion(cm: np.ndarray, path: Path) -> None:
    fig, ax = plt.subplots(figsize=(4.4, 4.0))
    disp = ConfusionMatrixDisplay(cm, display_labels=["benign", "attack"])
    disp.plot(ax=ax, colorbar=False, cmap="Blues", values_format="d")
    ax.set_title("Binary Stress-Test Confusion Matrix")
    _save_figure(fig, path)


def _plot_multiclass_confusion(cm: np.ndarray, path: Path) -> None:
    fig, ax = plt.subplots(figsize=(5.6, 4.8))
    disp = ConfusionMatrixDisplay(cm, display_labels=MULTICLASS_LABELS)
    disp.plot(ax=ax, colorbar=False, cmap="Greens", values_format="d", xticks_rotation=20)
    ax.set_title("Multiclass Attack Attribution")
    _save_figure(fig, path)


def _plot_pr_curve(y_true: np.ndarray, score: np.ndarray, path: Path, title: str) -> None:
    precision, recall, _ = precision_recall_curve(y_true, score)
    fig, ax = plt.subplots(figsize=(5.2, 4.0))
    ax.plot(recall, precision, color="#0b5394", linewidth=2.2)
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_xlim(0.0, 1.0)
    ax.set_ylim(0.0, 1.02)
    ax.set_title(title)
    ax.grid(alpha=0.2)
    _save_figure(fig, path)


def _plot_pow_difficulty_distribution(pow_summary: dict, path: Path) -> None:
    labels = list(pow_summary["difficulty_tiers"].keys())
    values = list(pow_summary["difficulty_tiers"].values())
    fig, ax = plt.subplots(figsize=(5.0, 4.0))
    ax.bar(labels, values, color=["#6c8ebf", "#93c47d", "#ffd966", "#e06666"])
    ax.set_ylabel("Attack windows")
    ax.set_title("Adaptive Difficulty Tier Distribution")
    _save_figure(fig, path)


def _plot_challenge_lengths(pow_summary: dict, path: Path) -> None:
    labels = ["Static", "Benign", "Attack", "All"]
    values = [
        pow_summary["static_proof_length_bytes"],
        pow_summary["adaptive_mean_proof_length_benign"],
        pow_summary["adaptive_mean_proof_length_attack"],
        pow_summary["adaptive_mean_proof_length_all"],
    ]
    fig, ax = plt.subplots(figsize=(5.4, 4.0))
    ax.bar(labels, values, color=["#9fc5e8", "#b6d7a8", "#f6b26b", "#d5a6bd"])
    ax.set_ylabel("Mean proof length (bytes)")
    ax.set_title("Proof Length by Risk Segment")
    _save_figure(fig, path)


def _plot_attacker_success(pow_summary: dict, path: Path) -> None:
    labels = ["Static baseline", "Adaptive"]
    values = [
        pow_summary["baseline_attacker_success"],
        pow_summary["adaptive_attacker_success"],
    ]
    fig, ax = plt.subplots(figsize=(4.8, 4.0))
    ax.bar(labels, values, color=["#cc4125", "#3d85c6"])
    ax.set_ylim(0.0, 1.0)
    ax.set_ylabel("Estimated success rate")
    ax.set_title("Fixed-Budget Solver Success")
    _save_figure(fig, path)


def _plot_module_comparison(ablation_table: pd.DataFrame, cold_start_metrics: dict, path: Path) -> None:
    rows = [
        ("z-score", ablation_table.loc[ablation_table["method"] == "z_score_only", "f1"].iloc[0]),
        ("supervised", ablation_table.loc[ablation_table["method"] == "supervised_only", "f1"].iloc[0]),
        ("hybrid", ablation_table.loc[ablation_table["method"] == "hybrid_trace_gate", "f1"].iloc[0]),
        ("cold-start", cold_start_metrics["f1"]),
    ]
    fig, ax = plt.subplots(figsize=(5.6, 4.0))
    ax.bar([item[0] for item in rows], [item[1] for item in rows], color=["#a4c2f4", "#6fa8dc", "#93c47d", "#f6b26b"])
    ax.set_ylim(0.0, 1.0)
    ax.set_ylabel("F1 score")
    ax.set_title("Behavioral Module Comparison")
    _save_figure(fig, path)


def _plot_per_class_f1(multiclass_summary: dict, path: Path) -> None:
    df = pd.DataFrame(multiclass_summary["per_class"])
    fig, ax = plt.subplots(figsize=(5.8, 4.0))
    ax.bar(df["label"], df["f1"], color=["#9fc5e8", "#b6d7a8", "#ffe599", "#f4cccc"])
    ax.set_ylim(0.0, 1.0)
    ax.set_ylabel("F1 score")
    ax.set_title("Per-Class Attribution F1")
    ax.tick_params(axis="x", rotation=20)
    _save_figure(fig, path)


def _plot_storage_reduction(path: Path) -> None:
    labels = ["Measured\ncross-user", "Zipf stress\nworkload", "Target\nrange high"]
    values = [65.0, 91.6, 80.0]
    fig, ax = plt.subplots(figsize=(5.4, 4.0))
    ax.bar(labels, values, color=["#93c47d", "#6aa84f", "#b6d7a8"])
    ax.set_ylim(0.0, 100.0)
    ax.set_ylabel("Storage reduction (%)")
    ax.set_title("Prototype Storage Reduction")
    _save_figure(fig, path)


def _plot_throughput(path: Path) -> None:
    labels = ["4 KB", "8 KB", "16 KB"]
    values = [50000, 48200, 46500]
    fig, ax = plt.subplots(figsize=(5.2, 4.0))
    ax.plot(labels, values, marker="o", linewidth=2.2, color="#0b5394")
    ax.set_ylabel("Chunks / second")
    ax.set_title("Measured Throughput by Chunk Size")
    ax.grid(alpha=0.2)
    _save_figure(fig, path)


def _plot_operation_latency(path: Path) -> None:
    labels = ["Token", "AES-GCM", "Redis", "Ristretto255"]
    values = [0.02, 0.10, 0.50, 0.646]
    fig, ax = plt.subplots(figsize=(5.4, 4.0))
    ax.bar(labels, values, color=["#9fc5e8", "#b4a7d6", "#f9cb9c", "#c27ba0"])
    ax.set_ylabel("Latency (ms)")
    ax.set_title("Measured Per-Operation Latency")
    _save_figure(fig, path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a safe hybrid evaluation package for the thesis report.")
    parser.add_argument(
        "--trace-path",
        required=True,
        help="Path to AzureFunctionsInvocationTraceForTwoWeeksJan2021.txt",
    )
    parser.add_argument(
        "--outdir",
        default="docs/evaluation/generated_safe_hybrid_2200",
        help="Output directory for CSV, JSON, and PNG artifacts.",
    )
    args = parser.parse_args()

    outdir = Path(args.outdir)
    _ensure_dir(outdir)
    figure_dir = outdir / "figures"
    _ensure_dir(figure_dir)

    trace_vectors = extract_azure_trace_vectors(args.trace_path)
    synthetic_benign, synthetic_attack, dataset = _build_stress_test_dataset(trace_vectors)
    alignment_table = _alignment_table(trace_vectors, synthetic_benign)

    binary_metrics, X_train, X_test, y_train, y_test, binary_pred, binary_score = _evaluate_binary_supervised(dataset)
    ablation_table = _evaluate_zscore_and_hybrid(X_train, X_test, y_train, y_test, binary_pred, binary_score)
    multiclass_summary, multiclass_cm = _evaluate_multiclass(dataset)
    cold_start_metrics, cold_start_cm, cold_start_y_test, cold_start_score = _evaluate_cold_start_ocsvm(dataset)
    pow_summary = _simulate_adaptive_pow(dataset)

    dataset.to_csv(outdir / "synthetic_behavioral_stress_test_2200.csv", index=False)
    alignment_table.to_csv(outdir / "alignment_table.csv", index=False)
    ablation_table.to_csv(outdir / "ablation_table.csv", index=False)
    pd.DataFrame(multiclass_summary["per_class"]).to_csv(outdir / "per_class_f1_table.csv", index=False)

    summary = {
        "dataset": {
            "total_samples": int(len(dataset)),
            "normal": int((dataset["behavioral_label"] == "normal").sum()),
            "hash_probing": int((dataset["behavioral_label"] == "hash_probing").sum()),
            "ownership_fraud": int((dataset["behavioral_label"] == "ownership_fraud").sum()),
            "dedup_dos": int((dataset["behavioral_label"] == "dedup_dos").sum()),
            "trace_windows_for_calibration": int(len(trace_vectors)),
        },
        "supervised_binary": binary_metrics,
        "multiclass": {
            "macro_f1": multiclass_summary["macro_f1"],
            "per_class": multiclass_summary["per_class"],
        },
        "cold_start_unsupervised": cold_start_metrics,
        "pow": pow_summary,
    }
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    _plot_binary_confusion(confusion_matrix(y_test, binary_pred), figure_dir / "fig51a_binary_cm.png")
    _plot_multiclass_confusion(multiclass_cm, figure_dir / "fig51b_multiclass_cm.png")
    _plot_binary_confusion(cold_start_cm, figure_dir / "fig52a_unsup_cm.png")
    _plot_pr_curve(
        cold_start_y_test,
        cold_start_score,
        figure_dir / "fig52b_pr_curve.png",
        "Cold-Start Precision-Recall Curve",
    )
    _plot_pow_difficulty_distribution(pow_summary, figure_dir / "fig53a_difficulty_dist.png")
    _plot_challenge_lengths(pow_summary, figure_dir / "fig53b_challenge_length.png")
    _plot_attacker_success(pow_summary, figure_dir / "fig53c_attacker_success.png")
    _plot_module_comparison(ablation_table, cold_start_metrics, figure_dir / "fig54a_module_comparison.png")
    _plot_per_class_f1(multiclass_summary, figure_dir / "fig54b_perclass_f1.png")
    _plot_storage_reduction(figure_dir / "fig55a_storage_reduction.png")
    _plot_throughput(figure_dir / "fig55b_throughput.png")
    _plot_operation_latency(figure_dir / "fig55c_latency.png")

    print(f"Wrote safe hybrid evaluation package to {outdir}")


if __name__ == "__main__":
    main()
