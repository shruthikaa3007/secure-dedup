# pow.py
import os
import random
import hashlib

def generate_challenge():
    return {
        "nonce": os.urandom(16),
        "offset": random.randint(0, 128),
        "length": 32
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
