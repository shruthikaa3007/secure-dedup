from __future__ import annotations

import math
from statistics import mean, pstdev

from src.behavioral.models import get_default_model_suite
from src.config import ANOMALY_Z_THRESHOLD, BEHAVIORAL_WINDOW, BOT_TAU_THRESHOLD_MS


class UserBehavioralProfile:
    def __init__(self, user_id: str, window: int = BEHAVIORAL_WINDOW, model_suite=None):
        self.user_id = user_id
        self.window = window
        self.model_suite = model_suite or get_default_model_suite()
        self.tau_history: list[float] = []
        self.entropy_history: list[float] = []

    def update(self, B_vector: dict) -> None:
        self.tau_history.append(float(B_vector.get("tau_avg", 0.0)))
        self.entropy_history.append(float(B_vector.get("entropy_mean", 0.0)))
        self.tau_history = self.tau_history[-self.window :]
        self.entropy_history = self.entropy_history[-self.window :]

    def _z_score(self, value: float, history: list[float]) -> float:
        if len(history) < 2:
            return 0.0
        sigma = pstdev(history)
        if sigma == 0:
            return 0.0 if math.isclose(value, mean(history)) else value - mean(history)
        return (value - mean(history)) / sigma

    def z_score_tau(self, tau_avg: float) -> float:
        return self._z_score(float(tau_avg), self.tau_history)

    def z_score_entropy(self, entropy_mean: float) -> float:
        return self._z_score(float(entropy_mean), self.entropy_history)

    def is_anomalous(self, B_vector: dict, z_threshold: float = ANOMALY_Z_THRESHOLD) -> bool:
        return self.anomaly_report(B_vector, z_threshold=z_threshold)["is_anomalous"]

    def anomaly_report(self, B_vector: dict, z_threshold: float = ANOMALY_Z_THRESHOLD) -> dict:
        tau_avg = float(B_vector.get("tau_avg", 0.0))
        entropy_mean = float(B_vector.get("entropy_mean", 0.0))
        z_tau = self.z_score_tau(tau_avg)
        z_entropy = self.z_score_entropy(entropy_mean)
        model_report = self.model_suite.assess(B_vector)

        flags: list[str] = []
        if tau_avg < BOT_TAU_THRESHOLD_MS:
            flags.append("bot_speed")
        if z_tau < -z_threshold:
            flags.append("tau_anomaly")
        if z_entropy > z_threshold:
            flags.append("entropy_anomaly")
        for flag in model_report["flags"]:
            if flag not in flags:
                flags.append(flag)

        return {
            "is_anomalous": bool(flags),
            "z_tau": z_tau,
            "z_entropy": z_entropy,
            "flags": flags,
            "tau_avg": tau_avg,
            "entropy_mean": entropy_mean,
            "supervised_human_probability": model_report["human_probability"],
            "supervised_prediction": model_report["supervised_prediction"],
            "unsupervised_score": model_report["unsupervised_score"],
            "unsupervised_prediction": model_report["unsupervised_prediction"],
            "model_backend": model_report["model_backend"],
            "difficulty_boost": model_report["difficulty_boost"],
        }
