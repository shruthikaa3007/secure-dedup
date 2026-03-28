from __future__ import annotations

import hashlib
import json

from src.config import (
    BPOW_DIFFICULTY_EASY,
    BPOW_DIFFICULTY_EXTREME,
    BPOW_DIFFICULTY_HARD,
    BPOW_DIFFICULTY_MEDIUM,
)


def compute_difficulty(tau_avg_ms: float) -> int:
    if tau_avg_ms > 200:
        return BPOW_DIFFICULTY_EASY
    if tau_avg_ms > 50:
        return BPOW_DIFFICULTY_MEDIUM
    if tau_avg_ms > 10:
        return BPOW_DIFFICULTY_HARD
    return BPOW_DIFFICULTY_EXTREME


def serialize_B(B_vector: dict) -> bytes:
    return json.dumps(B_vector, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _pow_digest(B_vector: dict, session_id: str, epoch: int, K_U_public: bytes, nonce: int) -> bytes:
    payload = serialize_B(B_vector)
    payload += session_id.encode("utf-8")
    payload += epoch.to_bytes(8, "big", signed=False)
    payload += K_U_public
    payload += nonce.to_bytes(16, "big", signed=False)
    return hashlib.sha256(payload).digest()


def _leading_zero_bits(digest: bytes) -> int:
    count = 0
    for byte in digest:
        if byte == 0:
            count += 8
            continue
        for offset in range(7, -1, -1):
            if byte & (1 << offset):
                return count
            count += 1
    return count


def solve_pow(B_vector: dict, session_id: str, epoch: int, K_U_public: bytes) -> tuple[int, str]:
    difficulty = compute_difficulty(float(B_vector.get("tau_avg", 0.0)))
    nonce = 0
    while True:
        digest = _pow_digest(B_vector, session_id, epoch, K_U_public, nonce)
        if _leading_zero_bits(digest) >= difficulty:
            return nonce, digest.hex()
        nonce += 1


def verify_pow(
    B_vector: dict,
    session_id: str,
    epoch: int,
    K_U_public: bytes,
    nonce: int,
    difficulty: int,
) -> bool:
    expected_difficulty = compute_difficulty(float(B_vector.get("tau_avg", 0.0)))
    if difficulty != expected_difficulty:
        return False
    digest = _pow_digest(B_vector, session_id, epoch, K_U_public, nonce)
    return _leading_zero_bits(digest) >= difficulty
