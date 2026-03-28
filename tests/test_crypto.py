import hashlib

import pytest

from src.crypto.convergent import IntegrityError, chunk_file, refa_decrypt, refa_encrypt
from src.crypto.identity import generate_session_token, verify_session_token
from src.crypto.kdf import derive_K_U, generate_salt, verify_password


def test_chunk_file_uses_fixed_sizes(tmp_path):
    payload = b"A" * 9000
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(payload)
    chunks = chunk_file(str(file_path), chunk_size=4096)
    assert [len(chunk) for chunk in chunks] == [4096, 4096, 808]


def test_refa_encrypt_decrypt_roundtrip():
    payload = (b"secure-dedup-bpow-roundtrip" * 64)[:8192]
    K_M = hashlib.sha256(b"km").digest()
    K_U = hashlib.sha256(b"ku").digest()
    ciphertext, token, integrity_tag = refa_encrypt(payload, K_M, K_U)
    assert integrity_tag
    assert refa_decrypt(ciphertext, token, K_U) == payload


def test_refa_detects_tampered_ciphertext():
    payload = b"tamper-detection" * 128
    K_M = hashlib.sha256(b"km-tamper").digest()
    K_U = hashlib.sha256(b"ku-tamper").digest()
    ciphertext, token, _ = refa_encrypt(payload, K_M, K_U)
    broken = bytearray(ciphertext)
    broken[-1] ^= 0x01
    with pytest.raises(IntegrityError):
        refa_decrypt(bytes(broken), token, K_U)


def test_argon2_kdf_roundtrip():
    pytest.importorskip("argon2.low_level")
    salt = generate_salt()
    derived = derive_K_U("correct horse battery staple", salt)
    assert len(derived) == 32
    assert verify_password("correct horse battery staple", salt, derived) is True
    assert verify_password("wrong password", salt, derived) is False


def test_identity_token_is_behavior_bound():
    secret = hashlib.sha256(b"identity-secret").digest()
    B_vector = {
        "tau_avg": 100.0,
        "tau_std": 5.0,
        "tau_seq_hash": hashlib.sha256(b"tau").hexdigest(),
        "entropy_mean": 7.5,
        "entropy_std": 0.1,
        "entropy_dist_hash": hashlib.sha256(b"entropy").hexdigest(),
        "chunk_order_hash": hashlib.sha256(b"order").hexdigest(),
        "n_chunks": 4,
        "session_id": "session-a",
    }
    token = generate_session_token(secret, B_vector, "user-a")
    assert verify_session_token(token, secret, B_vector, "user-a") is True
    modified = dict(B_vector)
    modified["tau_avg"] = 10.0
    assert verify_session_token(token, secret, modified, "user-a") is False
