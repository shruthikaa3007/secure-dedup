from __future__ import annotations

import hashlib
import hmac
import os
import time
from dataclasses import dataclass, field

from src.behavioral.anomaly import UserBehavioralProfile
from src.behavioral.pow import verify_pow
from src.cloud.dynamo_client import audit_log_get_user_history, audit_log_write, epoch_expire, epoch_store
from src.config import ANOMALY_Z_THRESHOLD, BEHAVIORAL_WINDOW, EPOCH_DURATION_DAYS, MAX_CHUNK_REQUESTS_PER_EPOCH, Q_P
from src.crypto.convergent import compute_fingerprint
from src.crypto.oprf import full_oprf


class BPoWValidationFailed(RuntimeError):
    pass


class AnomalyDetected(RuntimeError):
    pass


class RateLimitExceeded(RuntimeError):
    pass


class ChunkHotspotDetected(RuntimeError):
    pass


@dataclass
class KeyServer:
    rate_limit_counters: dict[tuple[str, int], int] = field(default_factory=dict)
    chunk_request_counters: dict[tuple[str, int], int] = field(default_factory=dict)
    epoch_keys: dict[int, bytes] = field(default_factory=dict)
    dedup_secret: bytes = field(default_factory=lambda: os.urandom(32))
    max_chunk_requests_per_epoch: int = MAX_CHUNK_REQUESTS_PER_EPOCH
    current_epoch: int = field(
        default_factory=lambda: int(time.time() // max(1, (EPOCH_DURATION_DAYS * 86400)))
    )

    def __post_init__(self) -> None:
        self.epoch_keys.setdefault(self.current_epoch, os.urandom(32))
        try:
            epoch_store(self.current_epoch, self.epoch_keys[self.current_epoch])
        except Exception:
            pass

    def get_current_epoch(self) -> int:
        return self.current_epoch

    def _get_epoch_key(self, epoch: int) -> bytes:
        if epoch not in self.epoch_keys:
            self.epoch_keys[epoch] = os.urandom(32)
            try:
                epoch_store(epoch, self.epoch_keys[epoch])
            except Exception:
                pass
        return self.epoch_keys[epoch]

    def _load_profile(self, user_id: str) -> UserBehavioralProfile:
        profile = UserBehavioralProfile(user_id=user_id, window=BEHAVIORAL_WINDOW)
        try:
            history = audit_log_get_user_history(user_id, limit=BEHAVIORAL_WINDOW)
        except Exception:
            history = []
        for item in reversed(history):
            B_vector = item.get("B_vector") or {}
            if B_vector:
                profile.update(B_vector)
        return profile

    def derive_private_chunk_locator(self, chunk: bytes) -> str:
        chunk_hash = compute_fingerprint(chunk)
        payload = b"secure-dedup-bpow/chunk-locator" + chunk_hash
        return hmac.new(self.dedup_secret, payload, hashlib.sha256).hexdigest()

    def check_rate_limit(self, user_id: str, epoch: int) -> bool:
        key = (user_id, epoch)
        current_count = self.rate_limit_counters.get(key, 0)
        if current_count >= Q_P:
            raise RateLimitExceeded(f"Rate limit exceeded for user '{user_id}' in epoch {epoch}")
        self.rate_limit_counters[key] = current_count + 1
        return True

    def check_chunk_hotspot(self, chunk_locator: str, epoch: int) -> bool:
        key = (chunk_locator, epoch)
        current_count = self.chunk_request_counters.get(key, 0)
        if current_count >= self.max_chunk_requests_per_epoch:
            raise ChunkHotspotDetected(
                f"Chunk hotspot throttled for locator '{chunk_locator[:12]}' in epoch {epoch}"
            )
        self.chunk_request_counters[key] = current_count + 1
        return True

    def authorize_chunk(self, chunk: bytes, user_id: str, bpow_proof: dict) -> dict:
        B_vector = bpow_proof["B_vector"]
        session_id = str(bpow_proof["session_id"])
        epoch = int(bpow_proof.get("epoch", self.current_epoch))
        nonce = int(bpow_proof["nonce"])
        difficulty = int(bpow_proof["difficulty"])
        K_U_public = bpow_proof["K_U_public"]
        if isinstance(K_U_public, str):
            K_U_public = bytes.fromhex(K_U_public)

        current_epoch = self.get_current_epoch()
        if abs(epoch - current_epoch) > 1:
            raise BPoWValidationFailed("Epoch mismatch for BPoW proof")

        if not verify_pow(B_vector, session_id, epoch, K_U_public, nonce, difficulty):
            raise BPoWValidationFailed("Invalid BPoW proof")

        profile = self._load_profile(user_id)
        anomaly_report = profile.anomaly_report(B_vector)
        try:
            audit_log_write(session_id, user_id, B_vector, nonce, anomaly_report, current_epoch)
        except Exception:
            pass

        if anomaly_report["is_anomalous"]:
            raise AnomalyDetected(f"Anomalous session rejected: {anomaly_report['flags']}")
        if anomaly_report["z_tau"] < -ANOMALY_Z_THRESHOLD or anomaly_report["z_entropy"] > ANOMALY_Z_THRESHOLD:
            raise AnomalyDetected("Behavioral z-score threshold exceeded")

        self.check_rate_limit(user_id, current_epoch)
        chunk_locator = self.derive_private_chunk_locator(chunk)
        self.check_chunk_hotspot(chunk_locator, current_epoch)

        chunk_tag = compute_fingerprint(chunk).hex().encode("utf-8")
        epoch_key = self._get_epoch_key(current_epoch)
        # v1: calls full_oprf(chunk_tag, epoch_key) - single-process simulation
        # v2: calls evaluate() only; blind/unblind run on client side
        return {
            "K_M": full_oprf(chunk_tag, epoch=current_epoch, epoch_key=epoch_key),
            "chunk_locator": chunk_locator,
            "epoch": current_epoch,
        }

    def get_K_M(self, chunk: bytes, user_id: str, bpow_proof: dict) -> bytes:
        return self.authorize_chunk(chunk, user_id, bpow_proof)["K_M"]

    def rotate_epoch_key(self) -> int:
        old_epoch = self.current_epoch
        try:
            epoch_expire(old_epoch)
        except Exception:
            pass
        self.current_epoch += 1
        self.epoch_keys[self.current_epoch] = os.urandom(32)
        try:
            epoch_store(self.current_epoch, self.epoch_keys[self.current_epoch])
        except Exception:
            pass
        return self.current_epoch


DEFAULT_KEY_SERVER = KeyServer()


def get_current_epoch() -> int:
    return DEFAULT_KEY_SERVER.get_current_epoch()


def get_K_M(chunk: bytes, user_id: str, bpow_proof: dict) -> bytes:
    return DEFAULT_KEY_SERVER.get_K_M(chunk, user_id, bpow_proof)


def check_rate_limit(user_id: str, epoch: int) -> bool:
    return DEFAULT_KEY_SERVER.check_rate_limit(user_id, epoch)


def rotate_epoch_key() -> int:
    return DEFAULT_KEY_SERVER.rotate_epoch_key()
