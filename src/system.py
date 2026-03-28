from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

from src.behavioral.anomaly import UserBehavioralProfile
from src.behavioral.extractor import BehavioralSession
from src.behavioral.pow import compute_difficulty, solve_pow
from src.cloud.dynamo_client import (
    bootstrap_tables,
    dtable_get,
    dtable_increment_counter,
    dtable_put,
    utable_add_ownership,
    utable_get_user_chunks,
)
from src.cloud.s3_client import ciphertext_exists, download_ciphertext, ensure_bucket, update_ciphertext, upload_ciphertext
from src.config import DEFAULT_BOT_DELAY_MS, DEFAULT_CHUNK_SIZE, DEFAULT_HUMAN_DELAY_MS, T_M
from src.crypto.convergent import chunk_file, compute_fingerprint, refa_decrypt, refa_encrypt
from src.crypto.identity import generate_session_token, verify_session_token
from src.crypto.kdf import derive_K_U, generate_salt
from src.crypto.key_server import AnomalyDetected, BPoWValidationFailed, KeyServer, RateLimitExceeded


class SecureDedupSystem:
    def __init__(self, key_server: KeyServer | None = None, ensure_infra: bool = True):
        self.key_server = key_server or KeyServer()
        self._users: dict[str, dict] = {}
        if ensure_infra:
            try:
                ensure_bucket()
                bootstrap_tables()
            except Exception:
                pass

    def _ensure_user(self, user_id: str, password: str) -> dict:
        user = self._users.get(user_id)
        if user is None:
            salt = generate_salt()
            verifier = hashlib.sha256(salt + password.encode("utf-8")).hexdigest()
            user = {
                "salt": salt,
                "verifier": verifier,
                "user_secret": os.urandom(32),
            }
            self._users[user_id] = user
            return user

        verifier = hashlib.sha256(user["salt"] + password.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(verifier, user["verifier"]):
            raise ValueError(f"Invalid password for user '{user_id}'")
        return user

    def _build_session(self, user_id: str, chunks: list[bytes], delay_ms: float) -> tuple[BehavioralSession, dict]:
        session = BehavioralSession(user_id)
        timestamp = 0.0
        for chunk in chunks:
            session.record_chunk(chunk, timestamp_ms=timestamp)
            timestamp += delay_ms
        return session, session.extract_vector()

    def _build_pow_proof(self, B_vector: dict, session_id: str, epoch: int, K_U_public: bytes) -> dict:
        nonce, proof_hash = solve_pow(B_vector, session_id, epoch, K_U_public)
        return {
            "B_vector": B_vector,
            "session_id": session_id,
            "epoch": epoch,
            "K_U_public": K_U_public,
            "nonce": nonce,
            "difficulty": compute_difficulty(float(B_vector.get("tau_avg", 0.0))),
            "proof_hash": proof_hash,
        }

    def upload(self, user_id: str, filepath: str, password: str) -> dict:
        user = self._ensure_user(user_id, password)
        K_U = derive_K_U(password, user["salt"])
        chunks = chunk_file(filepath, chunk_size=DEFAULT_CHUNK_SIZE)
        session, B_vector = self._build_session(user_id, chunks, DEFAULT_HUMAN_DELAY_MS)
        epoch = self.key_server.get_current_epoch()
        K_U_public = hashlib.sha256(K_U).digest()
        bpow_proof = self._build_pow_proof(B_vector, session.session_id, epoch, K_U_public)
        session_token = generate_session_token(user["user_secret"], B_vector, user_id)
        if not verify_session_token(session_token, user["user_secret"], B_vector, user_id):
            raise RuntimeError("Session token verification failed during upload")

        uploaded_chunks = []
        dedup_hits = 0
        rotated_ciphertexts = []
        for chunk in chunks:
            chunk_tag = compute_fingerprint(chunk).hex()
            K_M = self.key_server.get_K_M(chunk, user_id, bpow_proof)
            ciphertext, ownership_token_t, integrity_tag = refa_encrypt(chunk, K_M, K_U)
            dtable_entry = dtable_get(chunk_tag)
            if dtable_entry is None or not ciphertext_exists(chunk_tag):
                s3_key = upload_ciphertext(chunk_tag, ciphertext, {"epoch": epoch, "user_id": user_id})
                dtable_put(chunk_tag, s3_key, epoch, T_M=T_M)
            else:
                dedup_hits += 1
                updated = dtable_increment_counter(chunk_tag)
                if int(updated.get("upload_count", 0)) % T_M == 0:
                    update_ciphertext(chunk_tag, ciphertext)
                    rotated_ciphertexts.append(chunk_tag)
            utable_add_ownership(user_id, chunk_tag, ownership_token_t, epoch)
            uploaded_chunks.append(
                {
                    "chunk_tag": chunk_tag,
                    "integrity_tag": integrity_tag.hex(),
                }
            )

        return {
            "user_id": user_id,
            "chunk_count": len(chunks),
            "chunk_tags": [entry["chunk_tag"] for entry in uploaded_chunks],
            "dedup_hits": dedup_hits,
            "rotated_ciphertexts": rotated_ciphertexts,
            "epoch": epoch,
            "session_id": session.session_id,
            "session_token": session_token.hex(),
            "bpow_proof": bpow_proof,
            "uploaded_chunks": uploaded_chunks,
        }

    def download(self, user_id: str, chunk_tags: list[str], password: str) -> list[bytes]:
        user = self._ensure_user(user_id, password)
        K_U = derive_K_U(password, user["salt"])
        B_vector = {
            "tau_avg": DEFAULT_HUMAN_DELAY_MS,
            "tau_std": 0.0,
            "tau_seq_hash": hashlib.sha256("download".encode("utf-8")).hexdigest(),
            "entropy_mean": 0.0,
            "entropy_std": 0.0,
            "entropy_dist_hash": hashlib.sha256("download-entropy".encode("utf-8")).hexdigest(),
            "chunk_order_hash": hashlib.sha256("|".join(chunk_tags).encode("utf-8")).hexdigest(),
            "n_chunks": len(chunk_tags),
            "session_id": hashlib.sha256(f"download:{user_id}".encode("utf-8")).hexdigest(),
        }
        session_token = generate_session_token(user["user_secret"], B_vector, user_id)
        if not verify_session_token(session_token, user["user_secret"], B_vector, user_id):
            raise RuntimeError("Session token verification failed during download")

        ownership = {entry["chunk_tag"]: entry for entry in utable_get_user_chunks(user_id)}
        chunks: list[bytes] = []
        for chunk_tag in chunk_tags:
            if chunk_tag not in ownership:
                raise PermissionError(f"User '{user_id}' does not own chunk '{chunk_tag}'")
            ciphertext = download_ciphertext(chunk_tag)
            chunks.append(refa_decrypt(ciphertext, ownership[chunk_tag]["ownership_token_t"], K_U))
        return chunks

    def simulate_bot_attack(self, user_id: str, filepath: str) -> dict:
        user = self._ensure_user(user_id, "bot-password")
        K_U = derive_K_U("bot-password", user["salt"])
        chunks = chunk_file(filepath, chunk_size=DEFAULT_CHUNK_SIZE)
        session, B_vector = self._build_session(user_id, chunks, DEFAULT_BOT_DELAY_MS)
        epoch = self.key_server.get_current_epoch()
        K_U_public = hashlib.sha256(K_U).digest()
        profile = UserBehavioralProfile(user_id=user_id)
        anomaly_report = profile.anomaly_report(B_vector)
        proof = {
            "B_vector": B_vector,
            "session_id": session.session_id,
            "epoch": epoch,
            "K_U_public": K_U_public,
            "nonce": 0,
            "difficulty": compute_difficulty(float(B_vector.get("tau_avg", 0.0))),
        }
        try:
            self.key_server.get_K_M(chunks[0], user_id, proof)
        except (AnomalyDetected, BPoWValidationFailed, RateLimitExceeded) as exc:
            return {
                "rejected": True,
                "reason": str(exc),
                "z_scores": {
                    "z_tau": anomaly_report["z_tau"],
                    "z_entropy": anomaly_report["z_entropy"],
                },
                "difficulty_assigned": proof["difficulty"],
            }
        return {
            "rejected": False,
            "reason": "Bot attack unexpectedly passed",
            "z_scores": {
                "z_tau": anomaly_report["z_tau"],
                "z_entropy": anomaly_report["z_entropy"],
            },
            "difficulty_assigned": proof["difficulty"],
        }

    def simulate_replay_attack(self, stolen_proof: dict) -> dict:
        replayed = dict(stolen_proof)
        replayed["session_id"] = f"replay-{replayed.get('session_id', 'unknown')}"
        replayed["epoch"] = int(replayed.get("epoch", self.key_server.get_current_epoch())) - 2
        try:
            self.key_server.get_K_M(b"replay-attack-chunk", "replay-user", replayed)
        except (AnomalyDetected, BPoWValidationFailed, RateLimitExceeded) as exc:
            return {
                "rejected": True,
                "reason": str(exc),
            }
        return {
            "rejected": False,
            "reason": "Replay unexpectedly passed",
        }
