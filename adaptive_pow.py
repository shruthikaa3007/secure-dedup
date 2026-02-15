import os
from typing import Dict, Optional


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, float(value)))


ADAPTIVE_POW_ENABLED = os.getenv("ADAPTIVE_POW_ENABLED", "true").lower() == "true"
BASE_PROOF_LENGTH = int(os.getenv("POW_BASE_PROOF_LENGTH", "32"))
MIN_PROOF_LENGTH = int(os.getenv("POW_MIN_PROOF_LENGTH", "16"))
MAX_EXTRA_PROOF_LENGTH = int(os.getenv("POW_MAX_EXTRA_PROOF_LENGTH", "96"))

RISK_WEIGHT = float(os.getenv("POW_RISK_WEIGHT", "0.65"))
REPUTATION_WEIGHT = float(os.getenv("POW_REPUTATION_WEIGHT", "0.25"))
DUPLICATE_WEIGHT = float(os.getenv("POW_DUPLICATE_WEIGHT", "0.10"))


def select_challenge_profile(
    risk_score: Optional[float],
    reputation_score: Optional[float],
    chunk_length: int,
    duplicate_context: Optional[Dict] = None,
) -> Dict:
    """
    Select adaptive challenge profile for duplicate verification.

    Returns a stable profile dict used by pow_session to create the challenge.
    """
    if chunk_length <= 0:
        raise ValueError("chunk_length must be positive")

    safe_risk = _clamp(risk_score or 0.0)
    safe_reputation = _clamp(reputation_score if reputation_score is not None else 0.6)

    duplicate_hits = 1.0
    if duplicate_context and "duplicate_hits" in duplicate_context:
        try:
            duplicate_hits = max(1.0, float(duplicate_context.get("duplicate_hits", 1.0)))
        except Exception:
            duplicate_hits = 1.0

    duplicate_pressure = _clamp((duplicate_hits - 1.0) / 5.0)

    difficulty_score = _clamp(
        (RISK_WEIGHT * safe_risk)
        + (REPUTATION_WEIGHT * (1.0 - safe_reputation))
        + (DUPLICATE_WEIGHT * duplicate_pressure)
    )

    base_length = min(max(1, BASE_PROOF_LENGTH), chunk_length)
    min_length = min(max(1, MIN_PROOF_LENGTH), chunk_length)
    extra_room = max(0, min(MAX_EXTRA_PROOF_LENGTH, chunk_length - base_length))

    if not ADAPTIVE_POW_ENABLED:
        return {
            "adaptive_enabled": False,
            "difficulty_level": "static",
            "difficulty_score": 0.0,
            "challenge_length": max(min_length, base_length),
            "challenge_window_start": 0,
            "challenge_window_end": chunk_length,
            "risk_score": safe_risk,
            "reputation_score": safe_reputation,
        }

    challenge_length = base_length + int(round(extra_room * difficulty_score))
    challenge_length = min(chunk_length, max(min_length, challenge_length))

    if difficulty_score >= 0.70:
        level = "hardened"
    elif difficulty_score >= 0.35:
        level = "elevated"
    else:
        level = "normal"

    return {
        "adaptive_enabled": True,
        "difficulty_level": level,
        "difficulty_score": difficulty_score,
        "challenge_length": challenge_length,
        "challenge_window_start": 0,
        "challenge_window_end": chunk_length,
        "risk_score": safe_risk,
        "reputation_score": safe_reputation,
    }
