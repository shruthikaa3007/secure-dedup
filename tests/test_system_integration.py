import hashlib
import os
import socket
from urllib.parse import urlparse

import pytest

from src.cloud.dynamo_client import dtable_count, dtable_get
from src.config import LOCALSTACK_ENDPOINT
from src.crypto.convergent import chunk_file, compute_fingerprint
from src.crypto.kdf import derive_K_U
from src.system import SecureDedupSystem


RUN_LOCALSTACK = os.getenv("RUN_LOCALSTACK_TESTS") == "1"


def _make_payload_file(tmp_path, name="sample.bin"):
    seed = name.encode("utf-8") + b"|secure-dedup-bpow-payload|"
    payload = (seed * 1024)[:8192]
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
        "tau_min": 110.0,
        "tau_max": 130.0,
        "interarrival_cv": 0.04,
        "tau_seq_hash": hashlib.sha256(b"tau").hexdigest(),
        "entropy_mean": 7.0,
        "entropy_std": 0.1,
        "entropy_min": 6.9,
        "entropy_max": 7.1,
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
    file_path = _make_payload_file(tmp_path, name="cross-user-dedup.bin")
    chunks = chunk_file(str(file_path))
    baseline_count = dtable_count()
    system = SecureDedupSystem(ensure_infra=True)
    first = system.upload("user-one", str(file_path), "password-one")
    after_first_count = dtable_count()
    second = system.upload("user-two", str(file_path), "password-two")
    downloaded = system.download("user-one", first["chunk_tags"], "password-one")

    assert first["chunk_count"] > 0
    assert first["chunk_tag_mode"] == "opaque_handle"
    assert first["privacy_preserving"] is True
    assert "dedup_hits" not in first
    assert after_first_count == baseline_count + len(chunks)
    assert dtable_count() == after_first_count
    assert first["chunk_tags"] != second["chunk_tags"]
    assert first["chunk_tags"][0] != compute_fingerprint(chunks[0]).hex()
    assert b"".join(downloaded) == file_path.read_bytes()


def test_localstack_same_owner_reupload_is_idempotent(tmp_path):
    _require_localstack()
    file_path = _make_payload_file(tmp_path, name="idempotent.bin")
    baseline_count = dtable_count()
    system = SecureDedupSystem(ensure_infra=True)
    first = system.upload("same-user", str(file_path), "same-password")
    after_first_count = dtable_count()
    second = system.upload("same-user", str(file_path), "same-password")

    assert first["chunk_tags"] == second["chunk_tags"]
    assert after_first_count > baseline_count
    assert dtable_count() == after_first_count


def test_localstack_ciphertext_rotation(tmp_path):
    _require_localstack()
    file_path = _make_payload_file(tmp_path, name="rotation.bin")
    system = SecureDedupSystem(ensure_infra=True)
    for index in range(5):
        system.upload(f"rotation-user-{index}", str(file_path), f"rotation-password-{index}")

    first_chunk = chunk_file(str(file_path))[0]
    chunk_locator = system.key_server.derive_private_chunk_locator(first_chunk)
    entry = dtable_get(chunk_locator)
    assert int(entry["rotation_count"]) >= 1
