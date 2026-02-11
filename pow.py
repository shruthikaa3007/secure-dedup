# pow.py
import os
import random
import hashlib


def generate_challenge(chunk_length: int):
    if chunk_length <= 0:
        raise ValueError("chunk_length must be positive")

    proof_length = min(32, chunk_length)
    max_offset = max(0, chunk_length - proof_length)
    return {
        "nonce": os.urandom(16),
        "offset": random.randint(0, max_offset),
        "length": proof_length
    }


def compute_proof(chunk: bytes, nonce: bytes, offset: int, length: int):
    partial = chunk[offset: offset + length]
    return hashlib.sha256(nonce + partial).hexdigest()


def verify_proof(
    stored_chunk: bytes,
    nonce: bytes,
    offset: int,
    length: int,
    client_proof: str
) -> bool:
    expected = compute_proof(stored_chunk, nonce, offset, length)
    return expected == client_proof
