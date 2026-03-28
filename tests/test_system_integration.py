import hashlib
import os
import socket
from urllib.parse import urlparse

import pytest

from src.config import LOCALSTACK_ENDPOINT
from src.crypto.kdf import derive_K_U
from src.system import SecureDedupSystem


RUN_LOCALSTACK = os.getenv("RUN_LOCALSTACK_TESTS") == "1"


def _make_payload_file(tmp_path, name="sample.bin"):
    payload = (b"secure-dedup-bpow-payload" * 512)[:8192]
    file_path = tmp_path / name
    file_path.write_bytes(payload)
    return file_path


def _localstack_is_available() -> bool:
    parsed = urlparse(LOCALSTACK_ENDPOINT)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 4566
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def _require_localstack() -> None:
    if not RUN_LOCALSTACK:
        pytest.skip("Set RUN_LOCALSTACK_TESTS=1 to exercise LocalStack integration")
    if not _localstack_is_available():
        pytest.skip(f"LocalStack is not reachable at {LOCALSTACK_ENDPOINT}")


def _make_manual_proof(system: SecureDedupSystem, user_id: str, password: str):
    user = system._ensure_user(user_id, password)
    K_U = derive_K_U(password, user["salt"])
    session = {
        "tau_avg": 120.0,
        "tau_std": 5.0,
        "tau_seq_hash": hashlib.sha256(b"tau").hexdigest(),
        "entropy_mean": 7.0,
        "entropy_std": 0.1,
        "entropy_dist_hash": hashlib.sha256(b"entropy").hexdigest(),
        "chunk_order_hash": hashlib.sha256(b"order").hexdigest(),
        "n_chunks": 2,
        "session_id": hashlib.sha256(f"session:{user_id}".encode("utf-8")).hexdigest(),
    }
    epoch = system.key_server.get_current_epoch()
    K_U_public = hashlib.sha256(K_U).digest()
    proof = system._build_pow_proof(session, session["session_id"], epoch, K_U_public)
    return proof, K_U_public


def test_replay_attack_is_rejected(tmp_path):
    system = SecureDedupSystem(ensure_infra=False)
    proof, _ = _make_manual_proof(system, "user-a", "password-a")
    replay = system.simulate_replay_attack(proof)
    assert replay["rejected"] is True


def test_rotate_epoch_key_directly_changes_km(tmp_path):
    system = SecureDedupSystem(ensure_infra=False)
    proof, _ = _make_manual_proof(system, "epoch-user", "epoch-password")
    chunk_bytes = b"same chunk content" * 64

    km_one = system.key_server.get_K_M(chunk_bytes, "epoch-user", proof)
    rotated_epoch = system.key_server.rotate_epoch_key()

    rotated_proof = dict(proof)
    rotated_proof["session_id"] = proof["session_id"] + "-rotated"
    rotated_proof["epoch"] = rotated_epoch
    rotated_proof = system._build_pow_proof(
        rotated_proof["B_vector"],
        rotated_proof["session_id"],
        rotated_proof["epoch"],
        rotated_proof["K_U_public"],
    )
    km_two = system.key_server.get_K_M(chunk_bytes, "epoch-user", rotated_proof)
    assert km_one != km_two


def test_localstack_upload_download_and_dedup(tmp_path):
    _require_localstack()
    file_path = _make_payload_file(tmp_path)
    system = SecureDedupSystem(ensure_infra=True)
    first = system.upload("user-one", str(file_path), "password-one")
    second = system.upload("user-two", str(file_path), "password-two")
    downloaded = system.download("user-one", first["chunk_tags"], "password-one")

    assert first["chunk_count"] > 0
    assert second["dedup_hits"] >= 1
    assert b"".join(downloaded) == file_path.read_bytes()


def test_localstack_ciphertext_rotation(tmp_path):
    _require_localstack()
    file_path = _make_payload_file(tmp_path)
    system = SecureDedupSystem(ensure_infra=True)
    summaries = []
    for _ in range(5):
        summaries.append(system.upload("rotation-user", str(file_path), "rotation-password"))
    assert summaries[-1]["rotated_ciphertexts"]
