def label_attack(features):
    """
    Rule-based attack labeling (for evaluation only)
    """
    requests_per_minute = features.get("requests_per_minute", 0)
    pow_attempt_rate = features.get("pow_attempt_rate", 0)
    upload_to_query_ratio = features.get("upload_to_query_ratio", 1)
    duplicate_ratio = features.get("duplicate_ratio", 0)
    session_duration = features.get("session_duration", 0)

    if (
        requests_per_minute > 200 and
        duplicate_ratio > 0.4 and
        pow_attempt_rate > 0.4 and
        session_duration > 10
    ):
        return "dedup_dos"

    if pow_attempt_rate > 0.5 and duplicate_ratio > 0.3:
        return "ownership_fraud"

    if upload_to_query_ratio < 0.2:
        return "hash_probing"

    if requests_per_minute > 100:
        return "dedup_dos"

    return "normal"
