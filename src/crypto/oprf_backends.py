from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

ACTIVE_BACKEND = os.getenv("OPRF_BACKEND", "hmac").strip().lower()


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

    def blind(self, chunk: bytes) -> tuple[bytes, bytes]:
        raise NotImplementedError(
            "Ristretto255Backend is a documented upgrade path. Use OPRF_BACKEND=hmac for the runnable v1 backend."
        )

    def evaluate(self, blinded_point: bytes) -> bytes:
        raise NotImplementedError(
            "Ristretto255Backend is not implemented in this environment yet."
        )

    def unblind(self, evaluated: bytes, r: bytes) -> bytes:
        raise NotImplementedError(
            "Ristretto255Backend is not implemented in this environment yet."
        )

    def finalize(self, N: bytes, chunk: bytes, epoch: int) -> bytes:
        raise NotImplementedError(
            "Ristretto255Backend is not implemented in this environment yet."
        )


def get_backend(name: str | None = None, server_secret: bytes | None = None):
    selected = (name or ACTIVE_BACKEND or "hmac").strip().lower()
    if selected == "ristretto255":
        return Ristretto255Backend(server_secret=server_secret)
    return HMACBackend(server_secret=server_secret)
