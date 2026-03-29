from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from src.config import OPRF_BACKEND

try:
    import rbcl

    RBCL_AVAILABLE = True
    RBCL_IMPORT_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover - only exercised when rbcl is unavailable
    rbcl = None
    RBCL_AVAILABLE = False
    RBCL_IMPORT_ERROR = exc


ACTIVE_BACKEND = OPRF_BACKEND
RISTRETTO_ELEMENT_BYTES = 32


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _derive_ristretto_scalar(server_secret: bytes) -> bytes:
    if not RBCL_AVAILABLE:  # pragma: no cover - handled by __post_init__
        raise ImportError("rbcl is required for the ristretto255 backend") from RBCL_IMPORT_ERROR

    base_secret = server_secret or _sha512(b"secure-dedup-bpow/oprf-default")
    for counter in range(256):
        seed = (
            b"secure-dedup-bpow/ristretto255/server-scalar|"
            + base_secret
            + counter.to_bytes(1, "big", signed=False)
        )
        scalar = rbcl.crypto_core_ristretto255_scalar_reduce(_sha512(seed))
        if any(scalar):
            return scalar
    raise RuntimeError("Failed to derive a non-zero ristretto255 scalar from the configured server secret")


def _hash_to_ristretto_point(chunk: bytes) -> bytes:
    if not RBCL_AVAILABLE:  # pragma: no cover - handled by __post_init__
        raise ImportError("rbcl is required for the ristretto255 backend") from RBCL_IMPORT_ERROR
    return rbcl.crypto_core_ristretto255_from_hash(
        _sha512(b"secure-dedup-bpow/ristretto255/hash-to-group|" + chunk)
    )


@dataclass
class HMACBackend:
    server_secret: bytes | None = None

    def __post_init__(self) -> None:
        if self.server_secret is None:
            self.server_secret = hashlib.sha256(b"secure-dedup-bpow/oprf-default").digest()

    def blind(self, chunk: bytes) -> tuple[bytes, bytes]:
        digest = hashlib.sha256(chunk).digest()
        blinding_scalar = os.urandom(32)
        blind_marker = hashlib.sha256(b"blind|" + blinding_scalar).digest()
        return digest + blind_marker, blinding_scalar

    def evaluate(self, blinded_point: bytes) -> bytes:
        digest = blinded_point[:32]
        return hmac.new(self.server_secret, b"oprf-evaluate|" + digest, hashlib.sha256).digest()

    def unblind(self, evaluated: bytes, r: bytes) -> bytes:
        _ = r
        return evaluated

    def finalize(self, N: bytes, chunk: bytes, epoch: int) -> bytes:
        chunk_hash = hashlib.sha256(chunk).digest()
        payload = b"OPRF-Finalize" + N + chunk_hash + epoch.to_bytes(4, "big", signed=False)
        return hashlib.sha512(payload).digest()[:32]


@dataclass
class Ristretto255Backend:
    server_secret: bytes | None = None
    server_scalar: bytes | None = None

    def __post_init__(self) -> None:
        if not RBCL_AVAILABLE:
            raise ImportError(
                "rbcl is required for the ristretto255 backend. Install requirements.txt or set OPRF_BACKEND=hmac."
            ) from RBCL_IMPORT_ERROR
        if self.server_secret is None:
            self.server_secret = _sha512(b"secure-dedup-bpow/oprf-default")
        self.server_scalar = _derive_ristretto_scalar(self.server_secret)

    def blind(self, chunk: bytes) -> tuple[bytes, bytes]:
        point = _hash_to_ristretto_point(chunk)
        blinding_scalar = rbcl.crypto_core_ristretto255_scalar_random()
        blinded_generator = rbcl.crypto_scalarmult_ristretto255_base(blinding_scalar)
        blinded_point = rbcl.crypto_core_ristretto255_add(point, blinded_generator)
        if not rbcl.crypto_core_ristretto255_is_valid_point(blinded_point):
            raise ValueError("Generated blinded ristretto255 point is not valid")
        return blinded_point, blinding_scalar

    def evaluate(self, blinded_point: bytes) -> bytes:
        if len(blinded_point) != RISTRETTO_ELEMENT_BYTES:
            raise ValueError("blinded_point must be a 32-byte ristretto255 element")
        if not rbcl.crypto_core_ristretto255_is_valid_point(blinded_point):
            raise ValueError("blinded_point is not a canonical ristretto255 element")

        server_public = rbcl.crypto_scalarmult_ristretto255_base(self.server_scalar)
        evaluated = rbcl.crypto_scalarmult_ristretto255(self.server_scalar, blinded_point)
        # The API surface is still bytes-only, so the server returns g^k || a^k.
        return server_public + evaluated

    def unblind(self, evaluated: bytes, r: bytes) -> bytes:
        if len(evaluated) != RISTRETTO_ELEMENT_BYTES * 2:
            raise ValueError("evaluated must contain server_public || evaluated_point")
        if len(r) != rbcl.crypto_core_ristretto255_SCALARBYTES:
            raise ValueError("r must be a 32-byte ristretto255 scalar")

        server_public = evaluated[:RISTRETTO_ELEMENT_BYTES]
        evaluated_point = evaluated[RISTRETTO_ELEMENT_BYTES:]
        negated_blind = rbcl.crypto_core_ristretto255_scalar_negate(r)
        correction = rbcl.crypto_scalarmult_ristretto255(negated_blind, server_public)
        unblinded = rbcl.crypto_core_ristretto255_add(evaluated_point, correction)
        if not rbcl.crypto_core_ristretto255_is_valid_point(unblinded):
            raise ValueError("unblinded point is not a canonical ristretto255 element")
        return unblinded

    def finalize(self, N: bytes, chunk: bytes, epoch: int) -> bytes:
        chunk_hash = hashlib.sha256(chunk).digest()
        payload = (
            b"OPRF-Ristretto255-Finalize"
            + N
            + chunk_hash
            + epoch.to_bytes(4, "big", signed=False)
        )
        return hashlib.sha512(payload).digest()[:32]


def get_backend(name: str | None = None, server_secret: bytes | None = None):
    selected = (name or ACTIVE_BACKEND or "ristretto255").strip().lower()
    if selected == "ristretto255":
        return Ristretto255Backend(server_secret=server_secret)
    return HMACBackend(server_secret=server_secret)
