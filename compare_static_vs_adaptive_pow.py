import argparse
import csv
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from statistics import mean
from typing import Dict, List

from adaptive_pow import BASE_PROOF_LENGTH, MIN_PROOF_LENGTH, select_challenge_profile


LABEL_RISK_DEFAULTS = {
    "normal": 0.05,
    "hash_probing": 0.55,
    "ownership_fraud": 0.78,
    "dedup_dos": 0.92,
}

REPUTATION_INITIAL = float(os.getenv("REPUTATION_INITIAL_SCORE", "0.60"))
REPUTATION_MIN = float(os.getenv("REPUTATION_MIN_SCORE", "0.05"))
REPUTATION_MAX = float(os.getenv("REPUTATION_MAX_SCORE", "0.95"))
REPUTATION_BENIGN_DELTA = float(os.getenv("REPUTATION_BENIGN_DELTA", "0.01"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare static PoW baseline against risk-adaptive PoW using a labeled dataset "
            "and export presentation-ready metrics."
        )
    )
    parser.add_argument("--input", default="demo_detection_results.csv")
    parser.add_argument("--output-details", default="pow_comparison_details.csv")
    parser.add_argument("--output-summary", default="pow_comparison_summary.json")
    parser.add_argument("--output-md", default="pow_comparison_report.md")
    parser.add_argument(
        "--chunk-length",
        type=int,
        default=4096,
        help="Virtual chunk length used for challenge simulation (default: 4096)",
    )
    parser.add_argument(
        "--attacker-budget",
        type=float,
        default=48.0,
        help=(
            "Fixed attacker effort budget used for estimated success rate "
            "(default: 48 proof-bytes worth of work)"
        ),
    )
    parser.add_argument(
        "--baseline-length",
        type=int,
        default=BASE_PROOF_LENGTH,
        help=f"Static baseline proof length (default: {BASE_PROOF_LENGTH})",
    )
    return parser.parse_args()


def _safe_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, float(value)))


def _reputation_clamp(value: float) -> float:
    return max(REPUTATION_MIN, min(REPUTATION_MAX, float(value)))


def _estimate_risk(row: Dict) -> float:
    if "risk_score" in row:
        maybe_risk = _safe_float(row.get("risk_score"), -1.0)
        if 0.0 <= maybe_risk <= 1.0:
            return maybe_risk

    label = str(row.get("attack_label", "")).strip().lower()
    base = LABEL_RISK_DEFAULTS.get(label, 0.60)

    duplicate_ratio = _safe_float(row.get("duplicate_ratio"), 0.0)
    pow_attempt_rate = _safe_float(row.get("pow_attempt_rate"), duplicate_ratio)
    extra = max(0.0, pow_attempt_rate - 0.35) * 0.20
    extra += max(0.0, duplicate_ratio - 0.25) * 0.15

    return _clamp(base + extra)


def _reputation_delta(label: str) -> float:
    label = label.lower()
    if label == "normal":
        return REPUTATION_BENIGN_DELTA
    if label == "hash_probing":
        return -0.05
    if label == "ownership_fraud":
        return -0.10
    if label == "dedup_dos":
        return -0.12
    return -0.08


def _estimated_success(budget: float, proof_length: int) -> float:
    if proof_length <= 0:
        return 0.0
    if budget <= 0:
        return 0.0
    return _clamp(budget / float(proof_length))


def _load_rows(path: str) -> List[Dict]:
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [dict(row) for row in reader]


def _mean_or_zero(values: List[float]) -> float:
    return float(mean(values)) if values else 0.0


def _write_csv(path: str, rows: List[Dict], header: List[str]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in header})


def main() -> None:
    args = parse_args()
    if args.chunk_length <= 0:
        raise ValueError("--chunk-length must be positive")
    if args.attacker_budget <= 0:
        raise ValueError("--attacker-budget must be positive")

    raw_rows = _load_rows(args.input)
    if not raw_rows:
        raise ValueError(f"No rows found in {args.input}")

    baseline_length = max(MIN_PROOF_LENGTH, min(args.chunk_length, int(args.baseline_length)))
    reputation_by_client: Dict[str, float] = defaultdict(lambda: _reputation_clamp(REPUTATION_INITIAL))

    details: List[Dict] = []
    difficulty_counts = Counter()
    label_counts = Counter()

    for row in raw_rows:
        client_id = str(row.get("client_id", "unknown"))
        label = str(row.get("attack_label", "unknown")).strip()
        label_counts[label] += 1

        risk_score = _estimate_risk(row)
        reputation_before = _reputation_clamp(reputation_by_client[client_id])
        duplicate_ratio = _safe_float(row.get("duplicate_ratio"), 0.0)
        duplicate_hits = max(1, int(round(1.0 + (duplicate_ratio * 8.0))))

        adaptive_profile = select_challenge_profile(
            risk_score=risk_score,
            reputation_score=reputation_before,
            chunk_length=args.chunk_length,
            duplicate_context={"duplicate_hits": duplicate_hits},
        )
        adaptive_length = int(adaptive_profile["challenge_length"])
        difficulty_level = str(adaptive_profile["difficulty_level"])
        difficulty_counts[difficulty_level] += 1

        is_anomaly = label.lower() != "normal"
        baseline_success = _estimated_success(args.attacker_budget, baseline_length)
        adaptive_success = _estimated_success(args.attacker_budget, adaptive_length)

        details.append(
            {
                "client_id": client_id,
                "attack_label": label,
                "is_anomaly": is_anomaly,
                "risk_score": round(risk_score, 6),
                "reputation_before": round(reputation_before, 6),
                "duplicate_ratio": round(duplicate_ratio, 6),
                "duplicate_hits": duplicate_hits,
                "baseline_proof_length": baseline_length,
                "adaptive_proof_length": adaptive_length,
                "adaptive_difficulty_level": difficulty_level,
                "adaptive_difficulty_score": round(float(adaptive_profile["difficulty_score"]), 6),
                "estimated_attack_success_baseline": round(baseline_success, 6),
                "estimated_attack_success_adaptive": round(adaptive_success, 6),
            }
        )

        delta = _reputation_delta(label)
        reputation_after = _reputation_clamp(reputation_before + delta)
        reputation_by_client[client_id] = reputation_after

    anomaly_rows = [r for r in details if r["is_anomaly"]]
    normal_rows = [r for r in details if not r["is_anomaly"]]

    baseline_len_all = [float(r["baseline_proof_length"]) for r in details]
    adaptive_len_all = [float(r["adaptive_proof_length"]) for r in details]
    baseline_len_anomaly = [float(r["baseline_proof_length"]) for r in anomaly_rows]
    adaptive_len_anomaly = [float(r["adaptive_proof_length"]) for r in anomaly_rows]
    baseline_len_normal = [float(r["baseline_proof_length"]) for r in normal_rows]
    adaptive_len_normal = [float(r["adaptive_proof_length"]) for r in normal_rows]

    baseline_success_anomaly = [
        float(r["estimated_attack_success_baseline"]) for r in anomaly_rows
    ]
    adaptive_success_anomaly = [
        float(r["estimated_attack_success_adaptive"]) for r in anomaly_rows
    ]

    attacker_success_baseline = _mean_or_zero(baseline_success_anomaly)
    attacker_success_adaptive = _mean_or_zero(adaptive_success_anomaly)
    if attacker_success_baseline > 0:
        success_reduction_pct = (
            (attacker_success_baseline - attacker_success_adaptive)
            / attacker_success_baseline
            * 100.0
        )
    else:
        success_reduction_pct = 0.0

    normal_overhead_pct = 0.0
    baseline_normal_mean = _mean_or_zero(baseline_len_normal)
    adaptive_normal_mean = _mean_or_zero(adaptive_len_normal)
    if baseline_normal_mean > 0:
        normal_overhead_pct = (
            (adaptive_normal_mean - baseline_normal_mean) / baseline_normal_mean
        ) * 100.0

    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_dataset": args.input,
        "rows_total": len(details),
        "label_distribution": dict(label_counts),
        "anomaly_rows": len(anomaly_rows),
        "normal_rows": len(normal_rows),
        "config": {
            "chunk_length": args.chunk_length,
            "attacker_budget": args.attacker_budget,
            "baseline_proof_length": baseline_length,
        },
        "difficulty_distribution_adaptive": dict(difficulty_counts),
        "proof_length_mean": {
            "baseline_all": _mean_or_zero(baseline_len_all),
            "adaptive_all": _mean_or_zero(adaptive_len_all),
            "baseline_normal": baseline_normal_mean,
            "adaptive_normal": adaptive_normal_mean,
            "baseline_anomaly": _mean_or_zero(baseline_len_anomaly),
            "adaptive_anomaly": _mean_or_zero(adaptive_len_anomaly),
        },
        "estimated_attacker_success_anomaly_mean": {
            "baseline": attacker_success_baseline,
            "adaptive": attacker_success_adaptive,
            "reduction_pct": success_reduction_pct,
        },
        "benign_overhead_pct": normal_overhead_pct,
    }

    details_header = [
        "client_id",
        "attack_label",
        "is_anomaly",
        "risk_score",
        "reputation_before",
        "duplicate_ratio",
        "duplicate_hits",
        "baseline_proof_length",
        "adaptive_proof_length",
        "adaptive_difficulty_level",
        "adaptive_difficulty_score",
        "estimated_attack_success_baseline",
        "estimated_attack_success_adaptive",
    ]
    _write_csv(args.output_details, details, details_header)

    with open(args.output_summary, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    md_lines = [
        "# Static vs Adaptive PoW Comparison",
        "",
        f"- Generated At (UTC): `{summary['generated_at_utc']}`",
        f"- Input Dataset: `{args.input}`",
        f"- Rows: `{summary['rows_total']}`",
        f"- Labels: `{summary['label_distribution']}`",
        "",
        "## Proof Length (Mean)",
        "",
        "| Segment | Static Baseline | Adaptive PoW |",
        "|---|---:|---:|",
        f"| All rows | {summary['proof_length_mean']['baseline_all']:.2f} | {summary['proof_length_mean']['adaptive_all']:.2f} |",
        f"| Normal rows | {summary['proof_length_mean']['baseline_normal']:.2f} | {summary['proof_length_mean']['adaptive_normal']:.2f} |",
        f"| Anomaly rows | {summary['proof_length_mean']['baseline_anomaly']:.2f} | {summary['proof_length_mean']['adaptive_anomaly']:.2f} |",
        "",
        "## Estimated Attacker Success (Anomaly Rows)",
        "",
        f"- Baseline mean success: `{summary['estimated_attacker_success_anomaly_mean']['baseline']:.4f}`",
        f"- Adaptive mean success: `{summary['estimated_attacker_success_anomaly_mean']['adaptive']:.4f}`",
        f"- Relative reduction: `{summary['estimated_attacker_success_anomaly_mean']['reduction_pct']:.2f}%`",
        "",
        "## Adaptive Difficulty Distribution",
        "",
        f"- {summary['difficulty_distribution_adaptive']}",
        "",
        "## Benign Overhead",
        "",
        f"- Normal-row proof length change vs baseline: `{summary['benign_overhead_pct']:.2f}%`",
    ]

    with open(args.output_md, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines) + "\n")

    print(f"Saved details CSV: {args.output_details}")
    print(f"Saved summary JSON: {args.output_summary}")
    print(f"Saved markdown report: {args.output_md}")


if __name__ == "__main__":
    main()
