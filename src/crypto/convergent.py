from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

from Crypto.Cipher import AES

_MAGIC_C = b"REFA1"
_MAGIC_T = b"TOK1"
_NONCE_LEN = 12
_TAG_LEN = 16
_ST_LEN = 32
_HASH_LEN = 32


class IntegrityError(ValueError):
    """Raised when ciphertext or recovered chunk integrity validation fails."""


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("Byte strings must be the same length")
    return bytes(a ^ b for a, b in zip(left, right))


def chunk_file(filepath: str, chunk_size: int = 4096) -> list[bytes]:
    data = Path(filepath).read_bytes()
    if not data:
        return []
    return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]


def compute_fingerprint(chunk: bytes) -> bytes:
    return hashlib.sha256(chunk).digest()


def _derive_recovery_key(st_value: bytes, masked_key: bytes) -> bytes:
    return hashlib.sha256(_xor_bytes(st_value, masked_key)).digest()


def _encrypt_with_key(key: bytes, plaintext: bytes, magic: bytes) -> bytes:
    nonce = os.urandom(_NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return magic + nonce + tag + ciphertext


def _decrypt_with_key(key: bytes, payload: bytes, magic: bytes) -> bytes:
    if not payload.startswith(magic):
        raise IntegrityError("Payload magic mismatch")
    if len(payload) < len(magic) + _NONCE_LEN + _TAG_LEN:
        raise IntegrityError("Payload is too short")

    pos = len(magic)
    nonce = payload[pos : pos + _NONCE_LEN]
    pos += _NONCE_LEN
    tag = payload[pos : pos + _TAG_LEN]
    pos += _TAG_LEN
    ciphertext = payload[pos:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise IntegrityError("Payload authentication failed") from exc


def refa_encrypt(chunk: bytes, K_M: bytes, K_U: bytes) -> tuple[bytes, bytes, bytes]:
    if len(K_M) != 32 or len(K_U) != 32:
        raise ValueError("K_M and K_U must be 32 bytes")

    p = os.urandom(32)
    recovery_key = hashlib.sha256(_xor_bytes(p, K_M)).digest()
    chunk_hash = compute_fingerprint(chunk)
    payload = chunk + chunk_hash
    ciphertext = _encrypt_with_key(recovery_key, payload, _MAGIC_C)
    h1 = hashlib.sha256(chunk_hash + K_M).digest()
    st_value = _xor_bytes(h1, p)
    masked_key = _xor_bytes(h1, K_M)
    ownership_token = _encrypt_with_key(K_U, masked_key, _MAGIC_T)
    integrity_tag = hmac.new(K_U, masked_key, hashlib.sha256).digest()
    return ciphertext + st_value, ownership_token, integrity_tag


def refa_decrypt(C: bytes, t: bytes, K_U: bytes) -> bytes:
    if len(C) < len(_MAGIC_C) + _NONCE_LEN + _TAG_LEN + _ST_LEN:
        raise IntegrityError("Ciphertext envelope is incomplete")

    ciphertext = C[:-_ST_LEN]
    st_value = C[-_ST_LEN:]
    masked_key = _decrypt_with_key(K_U, t, _MAGIC_T)
    recovery_key = _derive_recovery_key(st_value, masked_key)
    plaintext = _decrypt_with_key(recovery_key, ciphertext, _MAGIC_C)
    if len(plaintext) < _HASH_LEN:
        raise IntegrityError("Recovered payload is too short")

    chunk = plaintext[:-_HASH_LEN]
    recovered_hash = plaintext[-_HASH_LEN:]
    actual_hash = compute_fingerprint(chunk)
    if recovered_hash != actual_hash:
        raise IntegrityError("Recovered chunk hash does not match payload")
    return chunk

