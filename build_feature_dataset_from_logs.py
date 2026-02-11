import argparse
import csv
import statistics
from collections import defaultdict
from typing import Dict, List

from attack_labeler import label_attack


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build feature_dataset.csv directly from request_logs.csv generated "
            "from real traces/dataset adapters."
        )
    )
    parser.add_argument("--input", default="request_logs.csv")
    parser.add_argument("--feature-output", default="feature_dataset.csv")
    parser.add_argument("--detection-output", default="detection_results.csv")
    parser.add_argument("--min-events", type=int, default=5)
    return parser.parse_args()


def _safe_float(value, default=0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _load_logs(path: str):
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts = _safe_float(row.get("timestamp"), 0.0)
            rows.append(
                {
                    "timestamp": ts,
                    "client_id": str(row.get("client_id", "unknown")),
                    "operation_type": str(row.get("operation_type", "")),
                    "chunk_hash": str(row.get("chunk_hash", "")) if row.get("chunk_hash") is not None else "",
                    "pow_result": row.get("pow_result"),
                }
            )
    rows.sort(key=lambda r: (r["timestamp"], r["client_id"]))
    return rows


def _extract_features(client_logs: List[Dict], all_hashes_by_client: Dict[str, set]) -> Dict:
    timestamps = [e["timestamp"] for e in client_logs]
    if not timestamps:
        return {}

    now = timestamps[-1]
    last_1_min = [e for e in client_logs if now - e["timestamp"] <= 60]
    last_5_min = [e for e in client_logs if now - e["timestamp"] <= 300]
    last_1_hr = [e for e in client_logs if now - e["timestamp"] <= 3600]

    total_requests = len(client_logs)
    unique_hashes = set(e["chunk_hash"] for e in client_logs if e["chunk_hash"])
    duplicate_requests = [e for e in client_logs if e["operation_type"] == "pow"]

    client_id = client_logs[0]["client_id"]
    other_hashes = set()
    for cid, hashes in all_hashes_by_client.items():
        if cid != client_id:
            other_hashes.update(hashes)

    inter_arrival = [
        timestamps[i + 1] - timestamps[i]
        for i in range(len(timestamps) - 1)
    ]

    return {
        "requests_per_minute": len(last_1_min),
        "requests_per_5_min": len(last_5_min),
        "requests_per_hour": len(last_1_hr),
        "unique_hash_count": len(unique_hashes),
        "duplicate_ratio": len(duplicate_requests) / total_requests if total_requests else 0.0,
        "pow_attempt_rate": len(duplicate_requests) / total_requests if total_requests else 0.0,
        "hash_diversity": len(unique_hashes) / total_requests if total_requests else 0.0,
        "upload_to_query_ratio": (
            sum(1 for e in client_logs if e["operation_type"] == "upload_chunk")
            / max(1, sum(1 for e in client_logs if e["operation_type"] == "hash_query"))
        ),
        "inter_request_time_variance": statistics.variance(inter_arrival) if len(inter_arrival) > 1 else 0.0,
        "burst_score": len(last_1_min) / max(1, len(last_5_min)),
        "session_duration": timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0.0,
        "cross_user_hash_overlap": len(unique_hashes & other_hashes),
    }


def _write_csv(path: str, header: List[str], rows: List[Dict]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in header})


def main() -> None:
    args = parse_args()

    rows = _load_logs(args.input)
    if not rows:
        raise ValueError(f"No rows found in {args.input}")

    logs_by_client: Dict[str, List[Dict]] = defaultdict(list)
    hashes_by_client: Dict[str, set] = defaultdict(set)

    for row in rows:
        cid = row["client_id"]
        logs_by_client[cid].append(row)
        if row["chunk_hash"]:
            hashes_by_client[cid].add(row["chunk_hash"])

    feature_rows = []
    detection_rows = []

    for client_id, client_logs in logs_by_client.items():
        if len(client_logs) < args.min_events:
            continue

        feats = _extract_features(client_logs, hashes_by_client)
        if not feats:
            continue

        attack_label = label_attack(feats)

        feature_rows.append({"client_id": client_id, **feats})
        detection_rows.append(
            {
                "client_id": client_id,
                **feats,
                "is_anomaly": attack_label != "normal",
                "attack_label": attack_label,
            }
        )

    if not feature_rows:
        raise ValueError(
            "No feature rows produced. Lower --min-events or check input schema."
        )

    feature_header = ["client_id"] + list(feature_rows[0].keys())[1:]
    detection_header = ["client_id"] + list(feature_rows[0].keys())[1:] + ["is_anomaly", "attack_label"]

    _write_csv(args.feature_output, feature_header, feature_rows)
    _write_csv(args.detection_output, detection_header, detection_rows)

    print(f"Feature rows: {len(feature_rows)}")
    print(f"Saved feature dataset: {args.feature_output}")
    print(f"Saved detection dataset: {args.detection_output}")


if __name__ == "__main__":
    main()
