from __future__ import annotations

import hashlib
import json
import os
import time

import numpy as np
from scipy.stats import entropy as shannon_entropy

from src.config import BOT_TAU_THRESHOLD_MS


class BehavioralSession:
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.session_id = hashlib.sha256(os.urandom(16)).hexdigest()
        self.timestamps: list[float] = []
        self.chunk_entropies: list[float] = []
        self.chunk_hashes: list[bytes] = []

    def record_chunk(self, chunk: bytes, timestamp_ms: float | None = None) -> None:
        if timestamp_ms is None:
            timestamp_ms = time.perf_counter_ns() / 1_000_000
        self.timestamps.append(float(timestamp_ms))
        counts = np.bincount(np.frombuffer(chunk, dtype=np.uint8), minlength=256)
        self.chunk_entropies.append(float(shannon_entropy(counts + 1e-10, base=2)))
        self.chunk_hashes.append(hashlib.sha256(chunk).digest())

    def _delays(self) -> list[float]:
        if len(self.timestamps) < 2:
            return []
        return [self.timestamps[index] - self.timestamps[index - 1] for index in range(1, len(self.timestamps))]

    def extract_vector(self) -> dict:
        delays = self._delays()
        tau_avg = float(np.mean(delays)) if delays else 0.0
        tau_std = float(np.std(delays)) if delays else 0.0
        entropy_mean = float(np.mean(self.chunk_entropies)) if self.chunk_entropies else 0.0
        entropy_std = float(np.std(self.chunk_entropies)) if self.chunk_entropies else 0.0
        tau_seq_hash = hashlib.sha256(json.dumps(self.timestamps, separators=(",", ":")).encode("utf-8")).hexdigest()
        entropy_dist_hash = hashlib.sha256(
            json.dumps(self.chunk_entropies, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        chunk_order_hash = hashlib.sha256(b"".join(self.chunk_hashes)).hexdigest()
        return {
            "tau_avg": tau_avg,
            "tau_std": tau_std,
            "tau_seq_hash": tau_seq_hash,
            "entropy_mean": entropy_mean,
            "entropy_std": entropy_std,
            "entropy_dist_hash": entropy_dist_hash,
            "chunk_order_hash": chunk_order_hash,
            "n_chunks": len(self.chunk_hashes),
            "session_id": self.session_id,
        }

    def is_bot_speed(self, threshold_ms: float = BOT_TAU_THRESHOLD_MS) -> bool:
        return self.extract_vector().get("tau_avg", 0.0) < threshold_ms
