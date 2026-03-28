import hashlib

import pytest

from src.behavioral.anomaly import UserBehavioralProfile
from src.behavioral.extractor import BehavioralSession
from src.behavioral.models import get_default_model_suite
from src.behavioral.pow import assess_pow_risk, compute_difficulty, solve_pow, verify_pow
from src.crypto.key_server import ChunkHotspotDetected, KeyServer


HUMAN_VECTOR = {
    "tau_avg": 120.0,
    "tau_std": 10.0,
    "tau_min": 95.0,
    "tau_max": 145.0,
    "interarrival_cv": 0.08,
    "tau_seq_hash": hashlib.sha256(b"tau-human").hexdigest(),
    "entropy_mean": 7.1,
    "entropy_std": 0.2,
    "entropy_min": 6.8,
    "entropy_max": 7.4,
    "entropy_dist_hash": hashlib.sha256(b"entropy-human").hexdigest(),
    "chunk_order_hash": hashlib.sha256(b"order-human").hexdigest(),
    "n_chunks": 6,
    "session_id": "session-human",
}


def test_behavioral_session_extracts_expected_schema():
    session = BehavioralSession("user-a")
    session.record_chunk(b"A" * 128, timestamp_ms=0.0)
    session.record_chunk(b"B" * 128, timestamp_ms=100.0)
    vector = session.extract_vector()
    assert vector["tau_avg"] == 100.0
    assert vector["n_chunks"] == 2
    assert vector["session_id"] == session.session_id
    assert all(key in vector for key in ["tau_seq_hash", "entropy_dist_hash", "chunk_order_hash"])
    assert all(key in vector for key in ["tau_min", "tau_max", "entropy_min", "entropy_max", "interarrival_cv"])


def test_pow_solve_and_verify_roundtrip():
    B_vector = {
        "tau_avg": 250.0,
        "tau_std": 5.0,
        "tau_min": 245.0,
        "tau_max": 255.0,
        "interarrival_cv": 0.02,
        "tau_seq_hash": hashlib.sha256(b"tau").hexdigest(),
        "entropy_mean": 6.0,
        "entropy_std": 0.4,
        "entropy_min": 5.8,
        "entropy_max": 6.2,
        "entropy_dist_hash": hashlib.sha256(b"entropy").hexdigest(),
        "chunk_order_hash": hashlib.sha256(b"order").hexdigest(),
        "n_chunks": 3,
        "session_id": "session-a",
    }
    K_U_public = hashlib.sha256(b"ku-public").digest()
    nonce, proof_hash = solve_pow(B_vector, "session-a", 11, K_U_public)
    assert proof_hash
    assert verify_pow(B_vector, "session-a", 11, K_U_public, nonce, compute_difficulty(B_vector)) is True


def test_anomaly_profile_flags_fast_session():
    profile = UserBehavioralProfile("user-a")
    for tau in [95.0, 100.0, 102.0, 98.0]:
        profile.update(
            {
                "tau_avg": tau,
                "tau_std": 3.0,
                "tau_min": tau - 3.0,
                "tau_max": tau + 3.0,
                "interarrival_cv": 0.03,
                "entropy_mean": 7.0,
                "entropy_std": 0.2,
                "entropy_min": 6.8,
                "entropy_max": 7.2,
                "tau_seq_hash": hashlib.sha256(f"tau:{tau}".encode("utf-8")).hexdigest(),
                "entropy_dist_hash": hashlib.sha256(b"entropy").hexdigest(),
                "chunk_order_hash": hashlib.sha256(b"order").hexdigest(),
                "n_chunks": 4,
            }
        )
    report = profile.anomaly_report(
        {
            "tau_avg": 1.0,
            "tau_std": 0.2,
            "tau_min": 0.8,
            "tau_max": 1.2,
            "interarrival_cv": 0.2,
            "entropy_mean": 7.0,
            "entropy_std": 0.3,
            "entropy_min": 6.7,
            "entropy_max": 7.3,
            "tau_seq_hash": hashlib.sha256(b"tau-bot").hexdigest(),
            "entropy_dist_hash": hashlib.sha256(b"entropy-bot").hexdigest(),
            "chunk_order_hash": hashlib.sha256(b"order-bot").hexdigest(),
            "n_chunks": 4,
        }
    )
    assert report["is_anomalous"] is True
    assert "bot_speed" in report["flags"]
    assert "supervised_bot" in report["flags"]
    assert report["unsupervised_prediction"] == "outlier"


def test_supervised_and_unsupervised_models_score_human_vs_bot():
    suite = get_default_model_suite()
    bot_vector = {
        "tau_avg": 1.0,
        "tau_std": 0.2,
        "tau_min": 0.7,
        "tau_max": 1.4,
        "interarrival_cv": 0.2,
        "tau_seq_hash": hashlib.sha256(b"tau-bot").hexdigest(),
        "entropy_mean": 6.2,
        "entropy_std": 1.4,
        "entropy_min": 4.5,
        "entropy_max": 7.9,
        "entropy_dist_hash": hashlib.sha256(b"entropy-bot").hexdigest(),
        "chunk_order_hash": hashlib.sha256(b"order-bot").hexdigest(),
        "n_chunks": 12,
        "session_id": "session-bot",
    }

    human_report = suite.assess(HUMAN_VECTOR)
    bot_report = suite.assess(bot_vector)
    human_pow = assess_pow_risk(HUMAN_VECTOR)
    bot_pow = assess_pow_risk(bot_vector)

    assert human_report["supervised_prediction"] == "human"
    assert bot_report["supervised_prediction"] == "bot"
    assert human_report["unsupervised_prediction"] == "inlier"
    assert bot_report["unsupervised_prediction"] == "outlier"
    assert bot_pow["effective_difficulty"] >= human_pow["effective_difficulty"]
    assert suite.backend in {"sklearn", "heuristic"}


def test_key_server_limits_duplicate_chunk_hotspots():
    key_server = KeyServer(max_chunk_requests_per_epoch=2)
    K_U_public = hashlib.sha256(b"ku-public").digest()
    chunk = b"same chunk" * 64
    epoch = key_server.get_current_epoch()

    for index, user_id in enumerate(["user-a", "user-b"]):
        session_id = f"session-{index}"
        nonce, _ = solve_pow(HUMAN_VECTOR, session_id, epoch, K_U_public)
        proof = {
            "B_vector": HUMAN_VECTOR,
            "session_id": session_id,
            "epoch": epoch,
            "K_U_public": K_U_public,
            "nonce": nonce,
            "difficulty": compute_difficulty(HUMAN_VECTOR),
        }
        material = key_server.authorize_chunk(chunk, user_id, proof)
        assert material["chunk_locator"]

    nonce, _ = solve_pow(HUMAN_VECTOR, "session-2", epoch, K_U_public)
    proof = {
        "B_vector": HUMAN_VECTOR,
        "session_id": "session-2",
        "epoch": epoch,
        "K_U_public": K_U_public,
        "nonce": nonce,
        "difficulty": compute_difficulty(HUMAN_VECTOR),
    }
    with pytest.raises(ChunkHotspotDetected):
        key_server.authorize_chunk(chunk, "user-c", proof)


def test_key_server_rotation_changes_km_for_same_chunk():
    key_server = KeyServer()
    B_vector = {
        "tau_avg": 250.0,
        "tau_std": 5.0,
        "tau_min": 245.0,
        "tau_max": 255.0,
        "interarrival_cv": 0.02,
        "tau_seq_hash": hashlib.sha256(b"tau").hexdigest(),
        "entropy_mean": 6.0,
        "entropy_std": 0.4,
        "entropy_min": 5.8,
        "entropy_max": 6.2,
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
        "difficulty": compute_difficulty(B_vector),
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
        "difficulty": compute_difficulty(B_vector),
    }
    km_two = key_server.get_K_M(b"same chunk", "user-a", proof_two)
    assert km_one != km_two
