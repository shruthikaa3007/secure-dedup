import os
import time
from typing import Dict

from dedup_index import r as redis_client

DEFAULT_REPUTATION = float(os.getenv("REPUTATION_INITIAL_SCORE", "0.60"))
MIN_REPUTATION = float(os.getenv("REPUTATION_MIN_SCORE", "0.05"))
MAX_REPUTATION = float(os.getenv("REPUTATION_MAX_SCORE", "0.95"))
REPUTATION_HALF_LIFE_SEC = int(os.getenv("REPUTATION_HALF_LIFE_SEC", "21600"))

POW_SUCCESS_DELTA = float(os.getenv("REPUTATION_POW_SUCCESS_DELTA", "0.04"))
POW_FAILURE_DELTA = float(os.getenv("REPUTATION_POW_FAILURE_DELTA", "-0.12"))
RATE_LIMIT_DELTA = float(os.getenv("REPUTATION_RATE_LIMIT_DELTA", "-0.05"))
BLOCK_DELTA = float(os.getenv("REPUTATION_BLOCK_DELTA", "-0.10"))
BENIGN_DELTA = float(os.getenv("REPUTATION_BENIGN_DELTA", "0.01"))

_IN_MEMORY_REPUTATION: Dict[str, Dict] = {}


def _clamp(value: float, low: float = MIN_REPUTATION, high: float = MAX_REPUTATION) -> float:
    return max(low, min(high, float(value)))


def _now() -> float:
    return time.time()


def _key(client_id: str) -> str:
    return f"reputation:{client_id}"


def _redis_ok() -> bool:
    try:
        redis_client.ping()
        return True
    except Exception:
        return False


def _decay(score: float, elapsed_sec: float) -> float:
    if REPUTATION_HALF_LIFE_SEC <= 0:
        return score
    decay_factor = 0.5 ** (max(0.0, elapsed_sec) / float(REPUTATION_HALF_LIFE_SEC))
    decayed = DEFAULT_REPUTATION + (score - DEFAULT_REPUTATION) * decay_factor
    return _clamp(decayed)


def _default_payload() -> Dict:
    return {
        "score": _clamp(DEFAULT_REPUTATION),
        "event_count": 0,
        "last_updated": _now(),
        "last_reason": "init",
    }


def _load(client_id: str) -> Dict:
    now = _now()

    if _redis_ok():
        data = redis_client.hgetall(_key(client_id))
        if data:
            try:
                score = float(data.get("score", DEFAULT_REPUTATION))
                last_updated = float(data.get("last_updated", now))
                event_count = int(float(data.get("event_count", 0)))
                last_reason = str(data.get("last_reason", "unknown"))
                return {
                    "score": _decay(score, now - last_updated),
                    "event_count": event_count,
                    "last_updated": now,
                    "last_reason": last_reason,
                }
            except Exception:
                pass

    payload = _IN_MEMORY_REPUTATION.get(client_id)
    if not payload:
        return _default_payload()

    decayed_score = _decay(float(payload.get("score", DEFAULT_REPUTATION)), now - float(payload.get("last_updated", now)))
    return {
        "score": decayed_score,
        "event_count": int(payload.get("event_count", 0)),
        "last_updated": now,
        "last_reason": str(payload.get("last_reason", "unknown")),
    }


def _store(client_id: str, payload: Dict) -> None:
    if _redis_ok():
        redis_client.hset(
            _key(client_id),
            mapping={
                "score": payload["score"],
                "event_count": payload["event_count"],
                "last_updated": payload["last_updated"],
                "last_reason": payload["last_reason"],
            },
        )

    _IN_MEMORY_REPUTATION[client_id] = payload


def get_reputation(client_id: str) -> Dict:
    payload = _load(client_id)
    _store(client_id, payload)
    return payload


def _apply_delta(client_id: str, delta: float, reason: str) -> Dict:
    payload = _load(client_id)
    payload["score"] = _clamp(float(payload["score"]) + float(delta))
    payload["event_count"] = int(payload.get("event_count", 0)) + 1
    payload["last_updated"] = _now()
    payload["last_reason"] = reason
    _store(client_id, payload)
    return payload


def record_pow_result(client_id: str, success: bool) -> Dict:
    if success:
        return _apply_delta(client_id, POW_SUCCESS_DELTA, "pow_success")
    return _apply_delta(client_id, POW_FAILURE_DELTA, "pow_failure")


def record_policy_action(client_id: str, action: str) -> Dict:
    action = (action or "").upper()
    if action == "BLOCK":
        return _apply_delta(client_id, BLOCK_DELTA, "policy_block")
    if action == "RATE_LIMIT":
        return _apply_delta(client_id, RATE_LIMIT_DELTA, "policy_rate_limit")
    return _apply_delta(client_id, BENIGN_DELTA, "policy_allow")


def record_benign_activity(client_id: str) -> Dict:
    return _apply_delta(client_id, BENIGN_DELTA, "benign_activity")
