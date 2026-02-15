# pow.py
import hashlib
import os
import random
from typing import Optional


def _clamp_int(value: int, low: int, high: int) -> int:
    return max(low, min(high, int(value)))


def generate_challenge(
    chunk_length: int,
    proof_length: Optional[int] = None,
    window_start: Optional[int] = None,
    window_end: Optional[int] = None,
):
    if chunk_length <= 0:
        raise ValueError("chunk_length must be positive")

    chosen_length = proof_length if proof_length is not None else min(32, chunk_length)
    chosen_length = _clamp_int(chosen_length, 1, chunk_length)

    start = 0 if window_start is None else _clamp_int(window_start, 0, chunk_length - 1)
    end = chunk_length if window_end is None else _clamp_int(window_end, start + 1, chunk_length)

    # Ensure the selected window can contain the requested proof length.
    if end - start < chosen_length:
        start = max(0, end - chosen_length)
        if end - start < chosen_length:
            end = min(chunk_length, start + chosen_length)

    max_offset = max(start, end - chosen_length)
    return {
        "nonce": os.urandom(16),
        "offset": random.randint(start, max_offset),
        "length": chosen_length,
        "window_start": start,
        "window_end": end,
    }


def compute_proof(chunk: bytes, nonce: bytes, offset: int, length: int):
    partial = chunk[offset : offset + length]
    return hashlib.sha256(nonce + partial).hexdigest()


def verify_proof(
    stored_chunk: bytes,
    nonce: bytes,
    offset: int,
    length: int,
    client_proof: str,
) -> bool:
    expected = compute_proof(stored_chunk, nonce, offset, length)
    return expected == client_proof
