def label_attack(features):
    """
    Rule-based attack labeling (for evaluation only)
    """
    if features["requests_per_minute"] > 100:
        return "dedup_dos"

    if features["pow_attempt_rate"] > 0.5:
        return "ownership_fraud"

    if features["upload_to_query_ratio"] < 0.2:
        return "hash_probing"

    if (
        features["requests_per_minute"] > 200 and
        features["duplicate_ratio"] > 0.4 and
        features["pow_attempt_rate"] > 0.4 and
        features["session_duration"] > 10
    ):
        return "dedup_dos"



    return "normal"
