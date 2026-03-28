from __future__ import annotations

from src.crypto.oprf_backends import ACTIVE_BACKEND, get_backend


def blind(chunk: bytes, epoch_key: bytes | None = None) -> tuple[bytes, bytes]:
    backend = get_backend(ACTIVE_BACKEND, server_secret=epoch_key)
    return backend.blind(chunk)


def evaluate(blinded_point: bytes, epoch_key: bytes | None = None) -> bytes:
    backend = get_backend(ACTIVE_BACKEND, server_secret=epoch_key)
    return backend.evaluate(blinded_point)


def unblind(evaluated: bytes, r: bytes, epoch_key: bytes | None = None) -> bytes:
    backend = get_backend(ACTIVE_BACKEND, server_secret=epoch_key)
    return backend.unblind(evaluated, r)


def finalize(N: bytes, chunk: bytes, epoch: int, epoch_key: bytes | None = None) -> bytes:
    backend = get_backend(ACTIVE_BACKEND, server_secret=epoch_key)
    return backend.finalize(N, chunk, epoch)


def full_oprf(chunk: bytes, epoch: int, epoch_key: bytes | None = None) -> bytes:
    backend = get_backend(ACTIVE_BACKEND, server_secret=epoch_key)
    blinded_point, blinding_scalar = backend.blind(chunk)
    evaluated = backend.evaluate(blinded_point)
    unblinded = backend.unblind(evaluated, blinding_scalar)
    return backend.finalize(unblinded, chunk, epoch)
