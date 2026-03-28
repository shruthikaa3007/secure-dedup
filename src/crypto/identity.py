from __future__ import annotations

import hashlib
import hmac
import json
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.config import TOTP_WINDOW


def derive_identity_key(user_secret: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"identity-v1")
    return hkdf.derive(user_secret)


def get_time_epoch() -> int:
    return int(time.time() // TOTP_WINDOW)


def behavioral_hash(B_vector: dict) -> bytes:
    serialized = json.dumps(B_vector, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(serialized).digest()


def _token_for_epoch(identity_key: bytes, epoch: int, behavior_digest: bytes, user_id: str) -> bytes:
    payload = epoch.to_bytes(8, "big") + behavior_digest + user_id.encode("utf-8")
    return hmac.new(identity_key, payload, hashlib.sha256).digest()


def generate_session_token(user_secret: bytes, B_vector: dict, user_id: str) -> bytes:
    identity_key = derive_identity_key(user_secret)
    epoch = get_time_epoch()
    return _token_for_epoch(identity_key, epoch, behavioral_hash(B_vector), user_id)


def verify_session_token(
    token: bytes,
    user_secret: bytes,
    B_vector: dict,
    user_id: str,
    tolerance: int = 1,
) -> bool:
    identity_key = derive_identity_key(user_secret)
    behavior_digest = behavioral_hash(B_vector)
    current_epoch = get_time_epoch()
    for candidate_epoch in range(current_epoch - tolerance, current_epoch + tolerance + 1):
        expected = _token_for_epoch(identity_key, candidate_epoch, behavior_digest, user_id)
        if hmac.compare_digest(token, expected):
            return True
    return False
