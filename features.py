import time
import statistics

def extract_features(client_logs, all_logs):
    now = time.time()

    # ⏱ Sliding windows
    last_1_min = [e for e in client_logs if now - e["timestamp"] <= 60]
    last_5_min = [e for e in client_logs if now - e["timestamp"] <= 300]
    last_1_hr = [e for e in client_logs if now - e["timestamp"] <= 3600]

    total_requests = len(client_logs)
    unique_hashes = set(e["chunk_hash"] for e in client_logs if e["chunk_hash"])

    duplicate_requests = [
        e for e in client_logs
        if e["operation_type"] == "pow"
    ]

    # ✅ FIXED cross-user hash overlap
    other_hashes = set(
        e["chunk_hash"]
        for cid, logs in all_logs.items()
        for e in logs
        if cid != client_logs and e.get("chunk_hash")
    )

    timestamps = [e["timestamp"] for e in client_logs]
    inter_arrival = [
        timestamps[i+1] - timestamps[i]
        for i in range(len(timestamps)-1)
    ]

    return {
        # Frequency
        "requests_per_minute": len(last_1_min),
        "requests_per_5_min": len(last_5_min),
        "requests_per_hour": len(last_1_hr),
        "unique_hash_count": len(unique_hashes),
        "duplicate_ratio": len(duplicate_requests) / total_requests if total_requests else 0,
        "pow_attempt_rate": len(duplicate_requests) / total_requests if total_requests else 0,

        # Hash behavior
        "hash_diversity": len(unique_hashes) / total_requests if total_requests else 0,
        "upload_to_query_ratio": (
            sum(1 for e in client_logs if e["operation_type"] == "upload_chunk") /
            max(1, sum(1 for e in client_logs if e["operation_type"] == "hash_query"))
        ),

        # Temporal
        "inter_request_time_variance": statistics.variance(inter_arrival) if len(inter_arrival) > 1 else 0,
        "burst_score": len(last_1_min) / max(1, len(last_5_min)),
        "session_duration": timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0,

        # Cross-user
        "cross_user_hash_overlap": len(unique_hashes & other_hashes)
    }
