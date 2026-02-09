import time
import numpy as np

WINDOWS = {
    "1min": 60,
    "5min": 300,
    "1hour": 3600
}

def get_window_logs(logs, window_seconds):
    now = time.time()
    return [
        entry for entry in logs
        if now - entry["timestamp"] <= window_seconds
    ]


def compute_window_stats(logs):
    stats = {}

    timestamps = [e["timestamp"] for e in logs]
    hashes = [e["chunk_hash"] for e in logs if e["chunk_hash"]]

    stats["request_count"] = len(logs)
    stats["unique_hash_count"] = len(set(hashes))
    stats["duplicate_ratio"] = (
        1 - len(set(hashes)) / len(hashes)
    ) if hashes else 0

    if len(timestamps) > 1:
        deltas = np.diff(sorted(timestamps))
        stats["inter_request_variance"] = np.var(deltas)
    else:
        stats["inter_request_variance"] = 0

    stats["session_duration"] = (
        max(timestamps) - min(timestamps)
    ) if timestamps else 0

    return stats
