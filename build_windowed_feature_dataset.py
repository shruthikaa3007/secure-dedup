import argparse
import csv
import statistics
from collections import Counter, defaultdict
from typing import Dict, List

from attack_labeler import label_attack


FEATURE_COLUMNS = [
    "requests_per_minute",
    "requests_per_5_min",
    "requests_per_hour",
    "unique_hash_count",
    "duplicate_ratio",
    "pow_attempt_rate",
    "hash_diversity",
    "upload_to_query_ratio",
    "inter_request_time_variance",
    "burst_score",
    "session_duration",
    "cross_user_hash_overlap",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a windowed feature dataset from request logs. "
            "This avoids single-row-per-client aggregation and produces more "
            "credible presentation-ready samples."
        )
    )
    parser.add_argument("--input", default="request_logs.csv")
    parser.add_argument("--feature-output", default="demo_feature_dataset.csv")
    parser.add_argument("--detection-output", default="demo_detection_results.csv")
    parser.add_argument(
        "--window-sec",
        type=float,
        default=120.0,
        help="Window size in seconds (default: 120)",
    )
    parser.add_argument(
        "--step-sec",
        type=float,
        default=30.0,
        help="Window step in seconds (default: 30)",
    )
    parser.add_argument(
        "--min-events",
        type=int,
        default=10,
        help="Minimum events required inside a window (default: 10)",
    )
    parser.add_argument(
        "--max-windows-per-client",
        type=int,
        default=200,
        help="Cap windows per client to keep runtime bounded (default: 200)",
    )
    parser.add_argument(
        "--max-clients",
        type=int,
        default=0,
        help="Optional cap on number of clients by event volume (0 = all)",
    )
    return parser.parse_args()


def _safe_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _load_logs(path: str) -> Dict[str, List[Dict]]:
    logs_by_client: Dict[str, List[Dict]] = defaultdict(list)

    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            timestamp = _safe_float(row.get("timestamp"), 0.0)
            client_id = str(row.get("client_id", "unknown"))
            operation_type = str(row.get("operation_type", ""))
            chunk_hash = row.get("chunk_hash")
            chunk_hash = str(chunk_hash) if chunk_hash is not None else ""
            if chunk_hash.lower() == "nan":
                chunk_hash = ""

            logs_by_client[client_id].append(
                {
                    "timestamp": timestamp,
                    "operation_type": operation_type,
                    "chunk_hash": chunk_hash,
                }
            )

    for client_id in logs_by_client:
        logs_by_client[client_id].sort(key=lambda x: x["timestamp"])

    return logs_by_client


def _window_starts(client_logs: List[Dict], step_sec: float) -> List[float]:
    if not client_logs:
        return []

    t0 = client_logs[0]["timestamp"]
    starts: List[float] = []
    last = None

    for event in client_logs:
        bucket = int((event["timestamp"] - t0) // step_sec)
        start = t0 + (bucket * step_sec)
        if last is None or start > last:
            starts.append(start)
            last = start

    return starts


def _extract_window_features(
    window_logs: List[Dict],
    window_end: float,
    other_hashes: set,
) -> Dict:
    timestamps = [e["timestamp"] for e in window_logs]

    last_1_min = [e for e in window_logs if window_end - e["timestamp"] <= 60.0]
    last_5_min = [e for e in window_logs if window_end - e["timestamp"] <= 300.0]
    last_1_hr = [e for e in window_logs if window_end - e["timestamp"] <= 3600.0]

    total_requests = len(window_logs)
    unique_hashes = {e["chunk_hash"] for e in window_logs if e["chunk_hash"]}

    duplicate_requests = [e for e in window_logs if e["operation_type"] == "pow"]
    upload_count = sum(1 for e in window_logs if e["operation_type"] == "upload_chunk")
    query_count = sum(1 for e in window_logs if e["operation_type"] == "hash_query")

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
        "upload_to_query_ratio": upload_count / max(1, query_count),
        "inter_request_time_variance": (
            statistics.variance(inter_arrival) if len(inter_arrival) > 1 else 0.0
        ),
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
    if args.window_sec <= 0:
        raise ValueError("--window-sec must be positive")
    if args.step_sec <= 0:
        raise ValueError("--step-sec must be positive")
    if args.min_events <= 0:
        raise ValueError("--min-events must be positive")
    if args.max_windows_per_client <= 0:
        raise ValueError("--max-windows-per-client must be positive")

    logs_by_client = _load_logs(args.input)
    if not logs_by_client:
        raise ValueError(f"No logs found in {args.input}")

    if args.max_clients > 0:
        ranked_clients = sorted(
            logs_by_client.items(),
            key=lambda kv: len(kv[1]),
            reverse=True,
        )
        logs_by_client = dict(ranked_clients[: args.max_clients])

    hashes_by_client: Dict[str, set] = {}
    global_hashes: set = set()
    for client_id, logs in logs_by_client.items():
        hashes = {e["chunk_hash"] for e in logs if e["chunk_hash"]}
        hashes_by_client[client_id] = hashes
        global_hashes.update(hashes)

    feature_rows: List[Dict] = []
    detection_rows: List[Dict] = []

    for client_id, logs in logs_by_client.items():
        if len(logs) < args.min_events:
            continue

        other_hashes = global_hashes - hashes_by_client.get(client_id, set())
        starts = _window_starts(logs, args.step_sec)
        if not starts:
            continue

        timestamps = [e["timestamp"] for e in logs]
        left = 0
        right = 0
        collected = 0

        for window_start in starts:
            window_end = window_start + args.window_sec

            while left < len(logs) and timestamps[left] < window_start:
                left += 1
            if right < left:
                right = left
            while right < len(logs) and timestamps[right] < window_end:
                right += 1

            window_logs = logs[left:right]
            if len(window_logs) < args.min_events:
                continue

            features = _extract_window_features(window_logs, window_end, other_hashes)
            attack_label = label_attack(features)

            feature_row = {
                "client_id": client_id,
                **features,
            }
            detection_row = {
                "client_id": client_id,
                **features,
                "is_anomaly": attack_label != "normal",
                "attack_label": attack_label,
            }

            feature_rows.append(feature_row)
            detection_rows.append(detection_row)

            collected += 1
            if collected >= args.max_windows_per_client:
                break

    if not feature_rows:
        raise ValueError(
            "No feature windows produced. Lower --min-events or increase --window-sec."
        )

    feature_header = ["client_id", *FEATURE_COLUMNS]
    detection_header = ["client_id", *FEATURE_COLUMNS, "is_anomaly", "attack_label"]

    _write_csv(args.feature_output, feature_header, feature_rows)
    _write_csv(args.detection_output, detection_header, detection_rows)

    label_counts = Counter(row["attack_label"] for row in detection_rows)
    print(f"Clients processed: {len(logs_by_client)}")
    print(f"Feature rows: {len(feature_rows)}")
    print(f"Saved feature dataset: {args.feature_output}")
    print(f"Saved detection dataset: {args.detection_output}")
    print(f"Label distribution: {dict(label_counts)}")


if __name__ == "__main__":
    main()
