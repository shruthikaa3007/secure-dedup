import os
from contextlib import contextmanager

import pytest

from encryption import (
    decrypt_chunk,
    encrypt_chunk,
    encryption_enabled,
    encryption_status,
    is_encrypted_payload,
)
from hashing import hash_chunk


DEMO_ENCRYPTION_KEY_B64 = "c2VjdXJlLWRlZHVwLWRlbW8ta2V5LTMyYnl0ZXMhISE="
DEMO_FINGERPRINT_KEY_B64 = "c2VjdXJlLWRlZHVwLWZpbmdlcnByaW50LWtleSEhISE="


@contextmanager
def env_override(overrides):
    original = {}
    for key, value in overrides.items():
        original[key] = os.environ.get(key)
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    try:
        yield
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_encrypt_decrypt_roundtrip_with_bound_context():
    payload = b"secure dedup encryption test payload" * 128
    with env_override(
        {
            "CHUNK_ENCRYPTION_KEY": DEMO_ENCRYPTION_KEY_B64,
            "CHUNK_ENCRYPTION_DEFAULT_ON": "true",
            "DEMO_MODE": "true",
        }
    ):
        ciphertext = encrypt_chunk(payload, context="chunk-abc")
        plaintext = decrypt_chunk(ciphertext, context="chunk-abc")

    assert ciphertext != payload
    assert is_encrypted_payload(ciphertext) is True
    assert plaintext == payload


def test_wrong_context_fails_decryption():
    payload = b"context binding matters for encrypted dedup chunks" * 64
    with env_override(
        {
            "CHUNK_ENCRYPTION_KEY": DEMO_ENCRYPTION_KEY_B64,
            "CHUNK_ENCRYPTION_DEFAULT_ON": "true",
            "DEMO_MODE": "true",
        }
    ):
        ciphertext = encrypt_chunk(payload, context="chunk-a")
        with pytest.raises(ValueError):
            decrypt_chunk(ciphertext, context="chunk-b")


def test_encryption_disabled_returns_plain_payload():
    payload = b"plaintext path"
    with env_override(
        {
            "CHUNK_ENCRYPTION_KEY": None,
            "CHUNK_ENCRYPTION_DEFAULT_ON": "false",
            "DEMO_MODE": "false",
        }
    ):
        ciphertext = encrypt_chunk(payload, context="chunk-x")
        plaintext = decrypt_chunk(ciphertext, context="chunk-x")
        enabled = encryption_enabled()

    assert ciphertext == payload
    assert plaintext == payload
    assert enabled is False


def test_secret_hmac_hash_differs_from_public_sha256():
    payload = b"same bytes should produce a different secret-assisted token"
    with env_override(
        {
            "DEDUP_FINGERPRINT_MODE": "sha256",
            "DEDUP_FINGERPRINT_KEY": DEMO_FINGERPRINT_KEY_B64,
            "DEDUP_FINGERPRINT_DEFAULT_ON": "true",
            "DEMO_MODE": "true",
        }
    ):
        public_token = hash_chunk(payload)

    with env_override(
        {
            "DEDUP_FINGERPRINT_MODE": "secret_hmac",
            "DEDUP_FINGERPRINT_KEY": DEMO_FINGERPRINT_KEY_B64,
            "DEDUP_FINGERPRINT_DEFAULT_ON": "true",
            "DEMO_MODE": "true",
        }
    ):
        secret_token = hash_chunk(payload)

    assert public_token != secret_token
    assert len(public_token) == 64
    assert len(secret_token) == 64


def test_encryption_status_reports_expected_scheme_metadata():
    with env_override(
        {
            "CHUNK_ENCRYPTION_KEY": DEMO_ENCRYPTION_KEY_B64,
            "CHUNK_ENCRYPTION_SEGMENT_SIZE": "4096",
            "CHUNK_ENCRYPTION_DEFAULT_ON": "true",
            "DEMO_MODE": "true",
        }
    ):
        status = encryption_status()

    assert status["enabled"] is True
    assert status["scheme"] == "fingerprint-bound segmented AES-GCM"
    assert status["key_derivation"] == "HKDF-SHA256"
    assert status["segment_size"] == 4096
