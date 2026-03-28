from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from src.config import (
    BEHAVIORAL_MODEL_RANDOM_STATE,
    BOT_TAU_THRESHOLD_MS,
    DEFAULT_BOT_DELAY_MS,
    DEFAULT_HUMAN_DELAY_MS,
    MODEL_BOOTSTRAP_SAMPLES,
    MODEL_DIFFICULTY_STEP,
    SUPERVISED_HUMAN_PROB_THRESHOLD,
    UNSUPERVISED_SCORE_THRESHOLD,
)

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier

    SKLEARN_AVAILABLE = True
except Exception:  # pragma: no cover
    IsolationForest = None
    RandomForestClassifier = None
    SKLEARN_AVAILABLE = False


FEATURE_NAMES = [
    "tau_avg",
    "tau_std",
    "tau_min",
    "tau_max",
    "interarrival_cv",
    "entropy_mean",
    "entropy_std",
    "entropy_min",
    "entropy_max",
    "n_chunks",
    "tau_hash_bucket",
    "entropy_hash_bucket",
    "order_hash_bucket",
]


DEFAULT_MODEL_SUITE: "BehavioralModelSuite | None" = None
UNSUPERVISED_CONFIRMATION_HUMAN_PROB = max(SUPERVISED_HUMAN_PROB_THRESHOLD + 0.15, 0.80)


def _safe_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _hash_bucket(value: object) -> float:
    token = str(value or "")
    if not token:
        return 0.0
    head = token[:16]
    try:
        maximum = float((16 ** len(head)) - 1)
        if maximum <= 0:
            return 0.0
        return int(head, 16) / maximum
    except ValueError:
        return 0.0


def vector_to_feature_array(B_vector: dict) -> np.ndarray:
    tau_avg = _safe_float(B_vector.get("tau_avg"))
    tau_std = _safe_float(B_vector.get("tau_std"))
    tau_min = _safe_float(B_vector.get("tau_min"), tau_avg)
    tau_max = _safe_float(B_vector.get("tau_max"), tau_avg)
    entropy_mean = _safe_float(B_vector.get("entropy_mean"))
    entropy_std = _safe_float(B_vector.get("entropy_std"))
    entropy_min = _safe_float(B_vector.get("entropy_min"), entropy_mean)
    entropy_max = _safe_float(B_vector.get("entropy_max"), entropy_mean)
    n_chunks = _safe_float(B_vector.get("n_chunks"), 0.0)
    interarrival_cv = _safe_float(B_vector.get("interarrival_cv"), 0.0)
    if interarrival_cv == 0.0 and tau_avg > 0:
        interarrival_cv = tau_std / tau_avg

    return np.asarray(
        [
            tau_avg,
            tau_std,
            tau_min,
            tau_max,
            interarrival_cv,
            entropy_mean,
            entropy_std,
            entropy_min,
            entropy_max,
            n_chunks,
            _hash_bucket(B_vector.get("tau_seq_hash")),
            _hash_bucket(B_vector.get("entropy_dist_hash")),
            _hash_bucket(B_vector.get("chunk_order_hash")),
        ],
        dtype=float,
    )


def _rng() -> np.random.Generator:
    return np.random.default_rng(BEHAVIORAL_MODEL_RANDOM_STATE)


def _bootstrap_training_data(samples_per_class: int = MODEL_BOOTSTRAP_SAMPLES) -> tuple[np.ndarray, np.ndarray]:
    rng = _rng()

    human_tau_avg = np.clip(rng.normal(loc=DEFAULT_HUMAN_DELAY_MS, scale=25.0, size=samples_per_class), 25.0, 400.0)
    human_tau_std = np.clip(rng.normal(loc=14.0, scale=6.0, size=samples_per_class), 1.0, 90.0)
    human_tau_min = np.clip(human_tau_avg - rng.normal(loc=22.0, scale=8.0, size=samples_per_class), 1.0, None)
    human_tau_max = human_tau_avg + np.clip(rng.normal(loc=28.0, scale=10.0, size=samples_per_class), 2.0, 140.0)
    human_entropy_mean = np.clip(rng.normal(loc=7.0, scale=0.25, size=samples_per_class), 5.5, 8.0)
    human_entropy_std = np.clip(rng.normal(loc=0.18, scale=0.08, size=samples_per_class), 0.01, 0.9)
    human_entropy_min = np.clip(
        human_entropy_mean - np.clip(rng.normal(loc=0.20, scale=0.06, size=samples_per_class), 0.02, 0.9),
        0.0,
        None,
    )
    human_entropy_max = human_entropy_mean + np.clip(
        rng.normal(loc=0.24, scale=0.08, size=samples_per_class),
        0.02,
        1.0,
    )
    human_n_chunks = rng.integers(2, 12, size=samples_per_class)
    human_hashes = rng.uniform(0.0, 1.0, size=(samples_per_class, 3))

    human = np.column_stack(
        [
            human_tau_avg,
            human_tau_std,
            human_tau_min,
            human_tau_max,
            human_tau_std / np.maximum(human_tau_avg, 1.0),
            human_entropy_mean,
            human_entropy_std,
            human_entropy_min,
            human_entropy_max,
            human_n_chunks.astype(float),
            human_hashes[:, 0],
            human_hashes[:, 1],
            human_hashes[:, 2],
        ]
    )

    bot_tau_avg = rng.uniform(
        max(0.1, DEFAULT_BOT_DELAY_MS / 2.0),
        max(2.0, BOT_TAU_THRESHOLD_MS + 2.0),
        size=samples_per_class,
    )
    bot_tau_std = rng.uniform(0.0, 2.0, size=samples_per_class)
    bot_tau_min = np.clip(bot_tau_avg - rng.uniform(0.0, 1.0, size=samples_per_class), 0.0, None)
    bot_tau_max = bot_tau_avg + rng.uniform(0.0, 4.0, size=samples_per_class)
    bot_entropy_mean = np.clip(rng.normal(loc=6.2, scale=1.1, size=samples_per_class), 0.5, 8.0)
    bot_entropy_std = rng.uniform(0.0, 1.8, size=samples_per_class)
    bot_entropy_min = np.clip(bot_entropy_mean - rng.uniform(0.0, 2.0, size=samples_per_class), 0.0, None)
    bot_entropy_max = np.clip(bot_entropy_mean + rng.uniform(0.0, 2.0, size=samples_per_class), 0.0, 8.0)
    bot_n_chunks = rng.integers(2, 20, size=samples_per_class)
    bot_hashes = rng.uniform(0.0, 1.0, size=(samples_per_class, 3))

    bot = np.column_stack(
        [
            bot_tau_avg,
            bot_tau_std,
            bot_tau_min,
            bot_tau_max,
            bot_tau_std / np.maximum(bot_tau_avg, 1.0),
            bot_entropy_mean,
            bot_entropy_std,
            bot_entropy_min,
            bot_entropy_max,
            bot_n_chunks.astype(float),
            bot_hashes[:, 0],
            bot_hashes[:, 1],
            bot_hashes[:, 2],
        ]
    )

    X = np.vstack([human, bot])
    y = np.concatenate([np.ones(samples_per_class, dtype=int), np.zeros(samples_per_class, dtype=int)])
    return X, y


@dataclass
class BehavioralModelSuite:
    supervised_model: object | None = None
    unsupervised_model: object | None = None
    backend: str = "heuristic"
    fitted: bool = False

    def fit(self) -> "BehavioralModelSuite":
        if self.fitted:
            return self
        if not SKLEARN_AVAILABLE:
            self.backend = "heuristic"
            self.fitted = True
            return self

        X, y = _bootstrap_training_data()
        self.supervised_model = RandomForestClassifier(
            n_estimators=120,
            max_depth=6,
            random_state=BEHAVIORAL_MODEL_RANDOM_STATE,
        )
        self.supervised_model.fit(X, y)
        self.unsupervised_model = IsolationForest(
            contamination=0.08,
            random_state=BEHAVIORAL_MODEL_RANDOM_STATE,
        )
        self.unsupervised_model.fit(X[y == 1])
        self.backend = "sklearn"
        self.fitted = True
        return self

    def _heuristic_assessment(self, B_vector: dict) -> dict:
        tau_avg = _safe_float(B_vector.get("tau_avg"))
        entropy_mean = _safe_float(B_vector.get("entropy_mean"), 6.5)
        normalized_tau = (tau_avg - BOT_TAU_THRESHOLD_MS) / max(1.0, DEFAULT_HUMAN_DELAY_MS - BOT_TAU_THRESHOLD_MS)
        human_probability = max(0.0, min(1.0, normalized_tau))
        entropy_penalty = abs(entropy_mean - 7.0) / 7.0
        unsupervised_score = human_probability - entropy_penalty
        flags: list[str] = []
        difficulty_boost = 0
        if human_probability < SUPERVISED_HUMAN_PROB_THRESHOLD:
            flags.append("supervised_bot")
            difficulty_boost += MODEL_DIFFICULTY_STEP
        if unsupervised_score < UNSUPERVISED_SCORE_THRESHOLD and human_probability < UNSUPERVISED_CONFIRMATION_HUMAN_PROB:
            flags.append("unsupervised_outlier")
            difficulty_boost += MODEL_DIFFICULTY_STEP
        return {
            "model_backend": "heuristic",
            "human_probability": human_probability,
            "supervised_prediction": "human" if human_probability >= SUPERVISED_HUMAN_PROB_THRESHOLD else "bot",
            "unsupervised_score": unsupervised_score,
            "unsupervised_prediction": "inlier" if unsupervised_score >= UNSUPERVISED_SCORE_THRESHOLD else "outlier",
            "flags": flags,
            "difficulty_boost": difficulty_boost,
        }

    def assess(self, B_vector: dict) -> dict:
        self.fit()
        if self.backend != "sklearn":
            return self._heuristic_assessment(B_vector)

        features = vector_to_feature_array(B_vector).reshape(1, -1)
        human_probability = float(self.supervised_model.predict_proba(features)[0, 1])
        unsupervised_score = float(self.unsupervised_model.decision_function(features)[0])
        unsupervised_prediction = int(self.unsupervised_model.predict(features)[0])

        flags: list[str] = []
        difficulty_boost = 0
        if human_probability < SUPERVISED_HUMAN_PROB_THRESHOLD:
            flags.append("supervised_bot")
            difficulty_boost += MODEL_DIFFICULTY_STEP
        if (
            (unsupervised_prediction == -1 or unsupervised_score < UNSUPERVISED_SCORE_THRESHOLD)
            and human_probability < UNSUPERVISED_CONFIRMATION_HUMAN_PROB
        ):
            flags.append("unsupervised_outlier")
            difficulty_boost += MODEL_DIFFICULTY_STEP

        return {
            "model_backend": self.backend,
            "human_probability": human_probability,
            "supervised_prediction": "human" if human_probability >= SUPERVISED_HUMAN_PROB_THRESHOLD else "bot",
            "unsupervised_score": unsupervised_score,
            "unsupervised_prediction": "inlier"
            if unsupervised_prediction == 1 and unsupervised_score >= UNSUPERVISED_SCORE_THRESHOLD
            else "outlier",
            "flags": flags,
            "difficulty_boost": difficulty_boost,
        }


def get_default_model_suite() -> BehavioralModelSuite:
    global DEFAULT_MODEL_SUITE
    if DEFAULT_MODEL_SUITE is None:
        DEFAULT_MODEL_SUITE = BehavioralModelSuite().fit()
    return DEFAULT_MODEL_SUITE
