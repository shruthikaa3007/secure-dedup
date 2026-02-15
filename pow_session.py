import os
import time
import uuid
from typing import Dict, Optional

from adaptive_pow import select_challenge_profile
from dedup_index import r as redis_client
from pow import compute_proof, generate_challenge

CHALLENGE_TTL_SEC = int(os.getenv("POW_CHALLENGE_TTL_SEC", "120"))
VERIFIED_TTL_SEC = int(os.getenv("POW_VERIFIED_TTL_SEC", "300"))

_IN_MEMORY_CHALLENGES: Dict[str, Dict] = {}
_IN_MEMORY_ACTIVE: Dict[str, str] = {}
_IN_MEMORY_VERIFIED: Dict[str, float] = {}
_IN_MEMORY_USED: Dict[str, float] = {}


def _now() -> float:
    return time.time()


def _active_key(client_id: str, chunk_hash: str) -> str:
    return f"pow:active:{client_id}:{chunk_hash}"


def _challenge_key(challenge_id: str) -> str:
    return f"pow:challenge:{challenge_id}"


def _used_key(challenge_id: str) -> str:
    return f"pow:used:{challenge_id}"


def _verified_key(client_id: str, chunk_hash: str) -> str:
    return f"pow:verified:{client_id}:{chunk_hash}"


def _safe_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _safe_int(value, default: int = 0) -> int:
    try:
        return int(float(value))
    except Exception:
        return default


def _safe_bool(value, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _redis_ok() -> bool:
    try:
        redis_client.ping()
        return True
    except Exception:
        return False


def _cleanup_memory() -> None:
    now = _now()
    for key, expires in list(_IN_MEMORY_VERIFIED.items()):
        if expires <= now:
            _IN_MEMORY_VERIFIED.pop(key, None)
    for key, expires in list(_IN_MEMORY_USED.items()):
        if expires <= now:
            _IN_MEMORY_USED.pop(key, None)
    for cid, challenge_id in list(_IN_MEMORY_ACTIVE.items()):
        challenge = _IN_MEMORY_CHALLENGES.get(challenge_id)
        if not challenge or challenge["expires_at"] <= now:
            _IN_MEMORY_ACTIVE.pop(cid, None)


def _serialize_challenge(
    challenge_id: str,
    client_id: str,
    chunk_hash: str,
    challenge: Dict,
    profile: Dict,
) -> Dict:
    now = _now()
    return {
        "challenge_id": challenge_id,
        "client_id": client_id,
        "chunk_hash": chunk_hash,
        "nonce_hex": challenge["nonce"].hex(),
        "offset": int(challenge["offset"]),
        "length": int(challenge["length"]),
        "created_at": now,
        "expires_at": now + CHALLENGE_TTL_SEC,
        "adaptive_enabled": bool(profile.get("adaptive_enabled", False)),
        "difficulty_level": str(profile.get("difficulty_level", "static")),
        "difficulty_score": _safe_float(profile.get("difficulty_score", 0.0), 0.0),
        "challenge_window_start": _safe_int(profile.get("challenge_window_start", 0), 0),
        "challenge_window_end": _safe_int(profile.get("challenge_window_end", 0), 0),
        "risk_score": _safe_float(profile.get("risk_score", 0.0), 0.0),
        "reputation_score": _safe_float(profile.get("reputation_score", 0.6), 0.6),
    }


def _deserialize_challenge(
    challenge_id: str,
    client_id: str,
    chunk_hash: str,
    challenge_map: Dict,
) -> Dict:
    length = _safe_int(challenge_map.get("length", 0), 0)
    window_end_default = max(length, 1)
    return {
        "challenge_id": challenge_id,
        "client_id": challenge_map.get("client_id", client_id),
        "chunk_hash": challenge_map.get("chunk_hash", chunk_hash),
        "nonce_hex": challenge_map.get("nonce_hex", ""),
        "offset": _safe_int(challenge_map.get("offset", 0), 0),
        "length": length,
        "created_at": _safe_float(challenge_map.get("created_at", _now()), _now()),
        "expires_at": _safe_float(
            challenge_map.get("expires_at", _now() + CHALLENGE_TTL_SEC),
            _now() + CHALLENGE_TTL_SEC,
        ),
        "adaptive_enabled": _safe_bool(challenge_map.get("adaptive_enabled"), False),
        "difficulty_level": str(challenge_map.get("difficulty_level", "static")),
        "difficulty_score": _safe_float(challenge_map.get("difficulty_score", 0.0), 0.0),
        "challenge_window_start": _safe_int(challenge_map.get("challenge_window_start", 0), 0),
        "challenge_window_end": _safe_int(
            challenge_map.get("challenge_window_end", window_end_default),
            window_end_default,
        ),
        "risk_score": _safe_float(challenge_map.get("risk_score", 0.0), 0.0),
        "reputation_score": _safe_float(challenge_map.get("reputation_score", 0.6), 0.6),
    }


def _create_new_challenge(
    client_id: str,
    chunk_hash: str,
    chunk_length: int,
    risk_score: Optional[float] = None,
    reputation_score: Optional[float] = None,
    duplicate_context: Optional[Dict] = None,
) -> Dict:
    challenge_id = str(uuid.uuid4())
    profile = select_challenge_profile(
        risk_score=risk_score,
        reputation_score=reputation_score,
        chunk_length=chunk_length,
        duplicate_context=duplicate_context,
    )
    challenge = generate_challenge(
        chunk_length=chunk_length,
        proof_length=profile.get("challenge_length"),
        window_start=profile.get("challenge_window_start"),
        window_end=profile.get("challenge_window_end"),
    )
    payload = _serialize_challenge(challenge_id, client_id, chunk_hash, challenge, profile)

    if _redis_ok():
        redis_client.hset(_challenge_key(challenge_id), mapping={
            "client_id": payload["client_id"],
            "chunk_hash": payload["chunk_hash"],
            "nonce_hex": payload["nonce_hex"],
            "offset": payload["offset"],
            "length": payload["length"],
            "created_at": payload["created_at"],
            "expires_at": payload["expires_at"],
            "adaptive_enabled": int(payload["adaptive_enabled"]),
            "difficulty_level": payload["difficulty_level"],
            "difficulty_score": payload["difficulty_score"],
            "challenge_window_start": payload["challenge_window_start"],
            "challenge_window_end": payload["challenge_window_end"],
            "risk_score": payload["risk_score"],
            "reputation_score": payload["reputation_score"],
        })
        redis_client.expire(_challenge_key(challenge_id), CHALLENGE_TTL_SEC)
        redis_client.setex(_active_key(client_id, chunk_hash), CHALLENGE_TTL_SEC, challenge_id)
    else:
        _cleanup_memory()
        _IN_MEMORY_CHALLENGES[challenge_id] = payload
        _IN_MEMORY_ACTIVE[f"{client_id}:{chunk_hash}"] = challenge_id

    return payload


def get_or_create_challenge(
    client_id: str,
    chunk_hash: str,
    chunk_length: int,
    risk_score: Optional[float] = None,
    reputation_score: Optional[float] = None,
    duplicate_context: Optional[Dict] = None,
) -> Dict:
    if _redis_ok():
        active_key = _active_key(client_id, chunk_hash)
        challenge_id = redis_client.get(active_key)
        if challenge_id:
            challenge = redis_client.hgetall(_challenge_key(challenge_id))
            if challenge:
                return _deserialize_challenge(challenge_id, client_id, chunk_hash, challenge)
        return _create_new_challenge(
            client_id=client_id,
            chunk_hash=chunk_hash,
            chunk_length=chunk_length,
            risk_score=risk_score,
            reputation_score=reputation_score,
            duplicate_context=duplicate_context,
        )

    _cleanup_memory()
    active_id = _IN_MEMORY_ACTIVE.get(f"{client_id}:{chunk_hash}")
    if active_id:
        challenge = _IN_MEMORY_CHALLENGES.get(active_id)
        if challenge and challenge["expires_at"] > _now():
            return challenge
    return _create_new_challenge(
        client_id=client_id,
        chunk_hash=chunk_hash,
        chunk_length=chunk_length,
        risk_score=risk_score,
        reputation_score=reputation_score,
        duplicate_context=duplicate_context,
    )


def verify_challenge(
    client_id: str,
    challenge_id: str,
    chunk_hash: str,
    stored_chunk: bytes,
    client_proof: str,
) -> bool:
    if _redis_ok():
        if redis_client.exists(_used_key(challenge_id)):
            return False

        challenge = redis_client.hgetall(_challenge_key(challenge_id))
        if not challenge:
            return False

        if challenge.get("client_id") != client_id:
            return False
        if challenge.get("chunk_hash") != chunk_hash:
            return False

        nonce_hex = challenge.get("nonce_hex", "")
        offset = int(float(challenge.get("offset", 0)))
        length = int(float(challenge.get("length", 0)))

        try:
            nonce = bytes.fromhex(nonce_hex)
        except Exception:
            return False

        expected = compute_proof(stored_chunk, nonce, offset, length)
        if expected != client_proof:
            return False

        redis_client.setex(_used_key(challenge_id), CHALLENGE_TTL_SEC, 1)
        redis_client.delete(_challenge_key(challenge_id))
        redis_client.delete(_active_key(client_id, chunk_hash))
        redis_client.setex(_verified_key(client_id, chunk_hash), VERIFIED_TTL_SEC, 1)
        return True

    _cleanup_memory()
    if challenge_id in _IN_MEMORY_USED:
        return False

    challenge = _IN_MEMORY_CHALLENGES.get(challenge_id)
    if not challenge:
        return False
    if challenge["client_id"] != client_id or challenge["chunk_hash"] != chunk_hash:
        return False

    nonce = bytes.fromhex(challenge["nonce_hex"])
    expected = compute_proof(
        stored_chunk,
        nonce,
        int(challenge["offset"]),
        int(challenge["length"]),
    )
    if expected != client_proof:
        return False

    _IN_MEMORY_USED[challenge_id] = _now() + CHALLENGE_TTL_SEC
    _IN_MEMORY_CHALLENGES.pop(challenge_id, None)
    _IN_MEMORY_ACTIVE.pop(f"{client_id}:{chunk_hash}", None)
    _IN_MEMORY_VERIFIED[_verified_key(client_id, chunk_hash)] = _now() + VERIFIED_TTL_SEC
    return True


def consume_verified(client_id: str, chunk_hash: str) -> bool:
    key = _verified_key(client_id, chunk_hash)
    if _redis_ok():
        if not redis_client.exists(key):
            return False
        redis_client.delete(key)
        return True

    _cleanup_memory()
    if key not in _IN_MEMORY_VERIFIED:
        return False
    _IN_MEMORY_VERIFIED.pop(key, None)
    return True
