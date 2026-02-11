import os
import time
from typing import Dict, Optional

from dedup_index import r as redis_client

DEFAULT_RATE_LIMIT_THRESHOLD = float(os.getenv("RATE_LIMIT_THRESHOLD", "0.55"))
DEFAULT_BLOCK_THRESHOLD = float(os.getenv("BLOCK_THRESHOLD", "0.80"))
RATE_LIMIT_COOLDOWN_SEC = int(os.getenv("RATE_LIMIT_COOLDOWN_SEC", "30"))
BLOCK_COOLDOWN_SEC = int(os.getenv("BLOCK_COOLDOWN_SEC", "180"))

_IN_MEMORY_POLICY: Dict[str, Dict] = {}


def _policy_key(client_id: str) -> str:
    return f"policy:active:{client_id}"


def _redis_ok() -> bool:
    try:
        redis_client.ping()
        return True
    except Exception:
        return False


def _now() -> float:
    return time.time()


def _cleanup_memory() -> None:
    now = _now()
    for client_id, payload in list(_IN_MEMORY_POLICY.items()):
        if float(payload.get("expires_at", 0.0)) <= now:
            _IN_MEMORY_POLICY.pop(client_id, None)


def decide_response(
    detection_result: Dict,
    rate_limit_threshold: float = DEFAULT_RATE_LIMIT_THRESHOLD,
    block_threshold: float = DEFAULT_BLOCK_THRESHOLD,
) -> Dict:
    """
    Map anomaly/risk signals into runtime policy actions.
    """
    risk_score = float(
        detection_result.get(
            "risk_score",
            1.0 if detection_result.get("is_anomaly") else 0.0,
        )
    )

    if risk_score >= block_threshold:
        action = "BLOCK"
        status_code = 403
    elif risk_score >= rate_limit_threshold:
        action = "RATE_LIMIT"
        status_code = 429
    else:
        action = "ALLOW"
        status_code = 200

    return {
        "action": action,
        "status_code": status_code,
        "risk_score": risk_score,
        "rate_limit_threshold": rate_limit_threshold,
        "block_threshold": block_threshold,
    }


def register_policy_action(client_id: str, action: str) -> None:
    """
    Register active policy state to enforce cooldown windows.
    """
    action = action.upper()
    if action not in {"RATE_LIMIT", "BLOCK"}:
        return

    ttl = RATE_LIMIT_COOLDOWN_SEC if action == "RATE_LIMIT" else BLOCK_COOLDOWN_SEC
    expires_at = _now() + ttl

    if _redis_ok():
        redis_client.hset(_policy_key(client_id), mapping={
            "action": action,
            "expires_at": expires_at,
            "ttl_sec": ttl,
        })
        redis_client.expire(_policy_key(client_id), ttl)
        return

    _cleanup_memory()
    _IN_MEMORY_POLICY[client_id] = {
        "action": action,
        "expires_at": expires_at,
        "ttl_sec": ttl,
    }


def get_active_policy_action(client_id: str) -> Optional[Dict]:
    """
    Get currently enforced action for a client, if any.
    """
    if _redis_ok():
        data = redis_client.hgetall(_policy_key(client_id))
        if not data:
            return None
        try:
            expires_at = float(data.get("expires_at", 0.0))
            if expires_at <= _now():
                redis_client.delete(_policy_key(client_id))
                return None
            return {
                "action": str(data.get("action", "ALLOW")).upper(),
                "expires_at": expires_at,
                "ttl_sec": int(float(data.get("ttl_sec", 0))),
                "remaining_sec": max(0.0, expires_at - _now()),
            }
        except Exception:
            redis_client.delete(_policy_key(client_id))
            return None

    _cleanup_memory()
    data = _IN_MEMORY_POLICY.get(client_id)
    if not data:
        return None

    return {
        "action": str(data.get("action", "ALLOW")).upper(),
        "expires_at": float(data.get("expires_at", 0.0)),
        "ttl_sec": int(data.get("ttl_sec", 0)),
        "remaining_sec": max(0.0, float(data.get("expires_at", 0.0)) - _now()),
    }
