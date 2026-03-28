import hashlib

from src.behavioral.anomaly import UserBehavioralProfile
from src.behavioral.extractor import BehavioralSession
from src.behavioral.pow import compute_difficulty, solve_pow, verify_pow
from src.crypto.key_server import KeyServer


def test_behavioral_session_extracts_expected_schema():
    session = BehavioralSession("user-a")
    session.record_chunk(b"A" * 128, timestamp_ms=0.0)
    session.record_chunk(b"B" * 128, timestamp_ms=100.0)
    vector = session.extract_vector()
    assert vector["tau_avg"] == 100.0
    assert vector["n_chunks"] == 2
    assert vector["session_id"] == session.session_id
    assert all(key in vector for key in ["tau_seq_hash", "entropy_dist_hash", "chunk_order_hash"])


def test_pow_solve_and_verify_roundtrip():
    B_vector = {
        "tau_avg": 250.0,
        "tau_std": 5.0,
        "tau_seq_hash": hashlib.sha256(b"tau").hexdigest(),
        "entropy_mean": 6.0,
        "entropy_std": 0.4,
        "entropy_dist_hash": hashlib.sha256(b"entropy").hexdigest(),
        "chunk_order_hash": hashlib.sha256(b"order").hexdigest(),
        "n_chunks": 3,
        "session_id": "session-a",
    }
    K_U_public = hashlib.sha256(b"ku-public").digest()
    nonce, proof_hash = solve_pow(B_vector, "session-a", 11, K_U_public)
    assert proof_hash
    assert verify_pow(B_vector, "session-a", 11, K_U_public, nonce, compute_difficulty(B_vector["tau_avg"])) is True


def test_anomaly_profile_flags_fast_session():
    profile = UserBehavioralProfile("user-a")
    for tau in [95.0, 100.0, 102.0, 98.0]:
        profile.update({"tau_avg": tau, "entropy_mean": 7.0})
    report = profile.anomaly_report({"tau_avg": 1.0, "entropy_mean": 7.0})
    assert report["is_anomalous"] is True
    assert "bot_speed" in report["flags"]


def test_key_server_rotation_changes_km_for_same_chunk():
    key_server = KeyServer()
    B_vector = {
        "tau_avg": 250.0,
        "tau_std": 5.0,
        "tau_seq_hash": hashlib.sha256(b"tau").hexdigest(),
        "entropy_mean": 6.0,
        "entropy_std": 0.4,
        "entropy_dist_hash": hashlib.sha256(b"entropy").hexdigest(),
        "chunk_order_hash": hashlib.sha256(b"order").hexdigest(),
        "n_chunks": 3,
        "session_id": "session-a",
    }
    K_U_public = hashlib.sha256(b"ku-public").digest()
    epoch_one = key_server.get_current_epoch()
    nonce_one, _ = solve_pow(B_vector, "session-a", epoch_one, K_U_public)
    proof_one = {
        "B_vector": B_vector,
        "session_id": "session-a",
        "epoch": epoch_one,
        "K_U_public": K_U_public,
        "nonce": nonce_one,
        "difficulty": compute_difficulty(B_vector["tau_avg"]),
    }
    km_one = key_server.get_K_M(b"same chunk", "user-a", proof_one)

    epoch_two = key_server.rotate_epoch_key()
    nonce_two, _ = solve_pow(B_vector, "session-b", epoch_two, K_U_public)
    proof_two = {
        "B_vector": B_vector,
        "session_id": "session-b",
        "epoch": epoch_two,
        "K_U_public": K_U_public,
        "nonce": nonce_two,
        "difficulty": compute_difficulty(B_vector["tau_avg"]),
    }
    km_two = key_server.get_K_M(b"same chunk", "user-a", proof_two)
    assert km_one != km_two
