from __future__ import annotations

import hmac
import os

from src.config import ARGON2_HASH_LEN, ARGON2_ITERATIONS, ARGON2_MEMORY, ARGON2_PARALLELISM

try:
    from argon2.low_level import Type, hash_secret_raw
except Exception as exc:  # pragma: no cover - exercised only when dependency is missing
    Type = None
    hash_secret_raw = None
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


def _require_argon2() -> None:
    if hash_secret_raw is None or Type is None:
        raise RuntimeError("argon2-cffi is required for derive_K_U()") from _IMPORT_ERROR


def derive_K_U(password: str, salt: bytes) -> bytes:
    _require_argon2()
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_ITERATIONS,
        memory_cost=ARGON2_MEMORY,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )


def generate_salt() -> bytes:
    return os.urandom(16)


def verify_password(password: str, salt: bytes, expected_K_U: bytes) -> bool:
    actual = derive_K_U(password, salt)
    return hmac.compare_digest(actual, expected_K_U)
