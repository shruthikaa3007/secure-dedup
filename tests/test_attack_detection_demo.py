"""
Self-contained behavioural attack demo tests.

These tests do not require Redis, model artifacts, or a live FastAPI server.
They simulate the key attack stories you want to show during the demo:
hash probing, dedup DoS, ownership fraud, and the gap that REFA leaves open
when there is no behavioural detection layer.
"""

import hashlib
import statistics
import time
from dataclasses import dataclass, field
from typing import Optional

import pytest


@dataclass
class RequestEvent:
    """Minimal request event mirroring the telemetry shape used by the repo."""

    client_id: str
    event_type: str
    timestamp: float = field(default_factory=time.time)
    duplicate: bool = False
    pow_attempts: int = 1
    chunk_hash: Optional[str] = None
    upload_size: int = 4096


@dataclass
class BehaviourFeatures:
    """Minimal feature vector mirroring the runtime feature extractor output."""

    client_id: str
    requests_per_minute: float
    duplicate_ratio: float
    pow_attempt_rate: float
    hash_diversity_ratio: float
    upload_to_query_ratio: float
    burst_score: float
    session_duration_seconds: float
    cross_user_hash_overlap: float
    unique_hash_count: int
    failed_pow_ratio: float
    avg_chunk_size: float
    event_count: int


class SimpleFeatureExtractor:
    """Self-contained approximation of the project's behavioural features."""

    def extract(self, events: list[RequestEvent], client_id: str) -> BehaviourFeatures:
        if not events:
            return BehaviourFeatures(client_id, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        uploads = [event for event in events if event.event_type == "upload"]
        queries = [event for event in events if event.event_type == "hash_query"]
        pow_events = [event for event in events if event.event_type == "pow_challenge"]

        duration = max(event.timestamp for event in events) - min(event.timestamp for event in events)
        duration = max(duration, 1.0)
        duplicate_ratio = sum(1 for event in uploads if event.duplicate) / max(len(uploads), 1)
        unique_hashes = len({event.chunk_hash for event in events if event.chunk_hash})
        total_hashes = len([event for event in events if event.chunk_hash])
        hash_diversity_ratio = unique_hashes / max(total_hashes, 1)
        upload_to_query_ratio = len(uploads) / max(len(queries), 1) if queries else float(len(uploads))
        total_pow_attempts = sum(event.pow_attempts for event in pow_events)
        failed_pow_ratio = sum(1 for event in pow_events if event.pow_attempts > 1) / max(len(pow_events), 1)

        if len(events) > 1:
            buckets = {}
            for event in events:
                bucket = int(event.timestamp / 10)
                buckets[bucket] = buckets.get(bucket, 0) + 1
            burst_score = max(buckets.values()) / max(statistics.mean(buckets.values()), 1.0)
        else:
            burst_score = 1.0

        return BehaviourFeatures(
            client_id=client_id,
            requests_per_minute=len(events) / (duration / 60.0),
            duplicate_ratio=duplicate_ratio,
            pow_attempt_rate=total_pow_attempts / max(len(pow_events), 1),
            hash_diversity_ratio=hash_diversity_ratio,
            upload_to_query_ratio=upload_to_query_ratio,
            burst_score=burst_score,
            session_duration_seconds=duration,
            cross_user_hash_overlap=0.0,
            unique_hash_count=unique_hashes,
            failed_pow_ratio=failed_pow_ratio,
            avg_chunk_size=statistics.mean(event.upload_size for event in uploads) if uploads else 0.0,
            event_count=len(events),
        )


class SimpleDetector:
    """Compact rule-based stand-in for the runtime classifier."""

    def predict(self, features: BehaviourFeatures) -> str:
        if features.upload_to_query_ratio < 0.1 and features.unique_hash_count > 20:
            return "hash_probing"
        if features.duplicate_ratio > 0.8 and features.requests_per_minute > 100:
            return "dedup_dos"
        if features.failed_pow_ratio > 0.5 and features.pow_attempt_rate > 3.0:
            return "ownership_fraud"
        return "normal"

    def risk_score(self, features: BehaviourFeatures) -> float:
        score = 0.0
        if features.duplicate_ratio > 0.5:
            score += 0.3
        if features.requests_per_minute > 60:
            score += 0.2
        if features.upload_to_query_ratio < 0.2 and features.unique_hash_count > 10:
            score += 0.3
        if features.failed_pow_ratio > 0.3:
            score += 0.2
        if features.burst_score > 3.0:
            score += 0.1
        return min(score, 1.0)


class AdaptivePoW:
    """Simple risk-to-difficulty mapping used for the demo prints."""

    BASE_LENGTH = 32
    MAX_EXTENSION = 128

    def challenge_length(self, risk_score: float) -> int:
        return self.BASE_LENGTH + int(risk_score * self.MAX_EXTENSION)


class PolicyEngine:
    """Maps attack labels to the same three demo actions as the real app."""

    ACTIONS = {
        "normal": "ALLOW",
        "hash_probing": "RATE_LIMIT",
        "dedup_dos": "BLOCK",
        "ownership_fraud": "RATE_LIMIT",
    }

    def decide(self, label: str) -> str:
        return self.ACTIONS.get(label, "RATE_LIMIT")


@pytest.fixture
def extractor():
    return SimpleFeatureExtractor()


@pytest.fixture
def detector():
    return SimpleDetector()


@pytest.fixture
def policy():
    return PolicyEngine()


@pytest.fixture
def pow_engine():
    return AdaptivePoW()


def make_events(
    client_id: str,
    n_uploads: int = 0,
    n_queries: int = 0,
    n_pow: int = 0,
    duplicate_frac: float = 0.0,
    pow_attempts: int = 1,
    duration: float = 60.0,
    unique_hashes: Optional[int] = None,
) -> list[RequestEvent]:
    """Generate a synthetic event stream for one client."""

    events = []
    base_time = time.time() - duration
    total_events = max(n_uploads + n_queries + n_pow, 1)
    interval = duration / total_events

    for idx in range(n_uploads):
        is_duplicate = (idx / max(n_uploads, 1)) < duplicate_frac
        chunk_hash = hashlib.sha256(
            f"chunk:{client_id}:{idx % (unique_hashes or max(n_uploads, 1))}".encode("ascii")
        ).hexdigest()
        events.append(
            RequestEvent(
                client_id=client_id,
                event_type="upload",
                timestamp=base_time + idx * interval,
                duplicate=is_duplicate,
                chunk_hash=chunk_hash,
            )
        )

    for idx in range(n_queries):
        chunk_hash = hashlib.sha256(f"query:{idx}".encode("ascii")).hexdigest()
        events.append(
            RequestEvent(
                client_id=client_id,
                event_type="hash_query",
                timestamp=base_time + (n_uploads + idx) * interval,
                chunk_hash=chunk_hash,
            )
        )

    for idx in range(n_pow):
        events.append(
            RequestEvent(
                client_id=client_id,
                event_type="pow_challenge",
                timestamp=base_time + (n_uploads + n_queries + idx) * interval,
                pow_attempts=pow_attempts,
            )
        )

    return events


class TestHashProbingDetection:
    """Hash probing: lots of lookup attempts, almost no legitimate uploads."""

    def test_hash_probing_detected(self, extractor, detector, policy):
        events = make_events("attacker_probe_01", n_uploads=1, n_queries=50, unique_hashes=50)
        features = extractor.extract(events, "attacker_probe_01")
        label = detector.predict(features)
        action = policy.decide(label)

        print(f"\n[hash_probing] upload_to_query_ratio = {features.upload_to_query_ratio:.3f}")
        print(f"[hash_probing] LABEL={label}  ACTION={action}")

        assert label == "hash_probing"
        assert action == "RATE_LIMIT"

    def test_normal_client_not_flagged(self, extractor, detector, policy):
        events = make_events("legitimate_user_01", n_uploads=30, n_queries=3, unique_hashes=30)
        features = extractor.extract(events, "legitimate_user_01")
        label = detector.predict(features)
        action = policy.decide(label)

        print(f"\n[normal] upload_to_query_ratio = {features.upload_to_query_ratio:.3f}")
        print(f"[normal] LABEL={label}  ACTION={action}")

        assert label == "normal"
        assert action == "ALLOW"

    def test_hash_probing_adaptive_pow_increases_difficulty(self, extractor, detector, pow_engine):
        attacker_events = make_events("attacker_pow_01", n_uploads=1, n_queries=50, unique_hashes=50)
        normal_events = make_events("normal_pow_01", n_uploads=30, n_queries=3, unique_hashes=30)

        attacker_risk = detector.risk_score(extractor.extract(attacker_events, "attacker_pow_01"))
        normal_risk = detector.risk_score(extractor.extract(normal_events, "normal_pow_01"))
        attacker_length = pow_engine.challenge_length(attacker_risk)
        normal_length = pow_engine.challenge_length(normal_risk)

        print(f"\n[adaptive_pow] attacker risk={attacker_risk:.2f}  challenge_length={attacker_length}")
        print(f"[adaptive_pow] normal   risk={normal_risk:.2f}  challenge_length={normal_length}")

        assert attacker_length > normal_length
        assert attacker_length > pow_engine.BASE_LENGTH


class TestDedupDoSDetection:
    """Dedup DoS: excessive duplicate-heavy uploads at a high request rate."""

    def test_dedup_dos_detected(self, extractor, detector, policy):
        events = make_events(
            "attacker_dos_01",
            n_uploads=200,
            duplicate_frac=0.90,
            duration=60.0,
            unique_hashes=20,
        )
        features = extractor.extract(events, "attacker_dos_01")
        label = detector.predict(features)
        action = policy.decide(label)

        print(f"\n[dedup_dos] duplicate_ratio = {features.duplicate_ratio:.3f}")
        print(f"[dedup_dos] requests_per_minute = {features.requests_per_minute:.1f}")
        print(f"[dedup_dos] LABEL={label}  ACTION={action}")

        assert label == "dedup_dos"
        assert action == "BLOCK"

    def test_high_duplicate_ratio_alone_is_not_dos(self, extractor, detector):
        events = make_events(
            "backup_client_01",
            n_uploads=50,
            duplicate_frac=0.85,
            duration=3600.0,
            unique_hashes=8,
        )
        features = extractor.extract(events, "backup_client_01")
        label = detector.predict(features)

        print(f"\n[backup] duplicate_ratio = {features.duplicate_ratio:.3f}")
        print(f"[backup] requests_per_minute = {features.requests_per_minute:.1f}")
        print(f"[backup] LABEL={label}")

        assert label == "normal"


class TestOwnershipFraudDetection:
    """Ownership fraud: repeated failed PoW attempts reveal brute-force behaviour."""

    def test_ownership_fraud_detected(self, extractor, detector, policy):
        events = make_events("attacker_fraud_01", n_pow=30, pow_attempts=5)
        features = extractor.extract(events, "attacker_fraud_01")
        label = detector.predict(features)
        action = policy.decide(label)

        print(f"\n[ownership_fraud] failed_pow_ratio = {features.failed_pow_ratio:.3f}")
        print(f"[ownership_fraud] pow_attempt_rate = {features.pow_attempt_rate:.3f}")
        print(f"[ownership_fraud] LABEL={label}  ACTION={action}")

        assert label == "ownership_fraud"
        assert action in {"RATE_LIMIT", "BLOCK"}

    def test_legitimate_pow_retries_are_allowed(self, extractor, detector):
        events = make_events("legit_pow_01", n_pow=10, pow_attempts=1)
        events[3].pow_attempts = 2
        events[7].pow_attempts = 2
        features = extractor.extract(events, "legit_pow_01")
        label = detector.predict(features)

        print(f"\n[legit_pow] failed_pow_ratio = {features.failed_pow_ratio:.3f}")
        print(f"[legit_pow] LABEL={label}")

        assert label == "normal"


class TestPolicyEnforcementPipeline:
    """End-to-end pipeline check: features to label to policy decision."""

    def test_full_pipeline_hash_probing(self, extractor, detector, policy):
        events = make_events("pipeline_attacker", n_uploads=2, n_queries=60, unique_hashes=60)
        features = extractor.extract(events, "pipeline_attacker")
        label = detector.predict(features)
        action = policy.decide(label)

        print(f"\n[e2e_pipeline] client=pipeline_attacker")
        print(f"  rpm={features.requests_per_minute:.1f}  u2q_ratio={features.upload_to_query_ratio:.2f}")
        print(f"  label={label}  action={action}")

        assert action != "ALLOW"

    def test_full_pipeline_normal_user(self, extractor, detector, policy):
        events = make_events("pipeline_normal", n_uploads=20, n_queries=2, n_pow=5, duplicate_frac=0.1)
        features = extractor.extract(events, "pipeline_normal")
        label = detector.predict(features)
        action = policy.decide(label)

        print(f"\n[e2e_pipeline] client=pipeline_normal")
        print(f"  rpm={features.requests_per_minute:.1f}  duplicate_ratio={features.duplicate_ratio:.2f}")
        print(f"  label={label}  action={action}")

        assert action == "ALLOW"


class TestREFAGapDemonstration:
    """Show the behavioural gap left by a REFA-style crypto-only design."""

    def test_gap1_static_pow_fails_against_determined_attacker(self, extractor, detector, pow_engine):
        events = make_events("gap1_attacker", n_uploads=1, n_queries=60, unique_hashes=60)
        features = extractor.extract(events, "gap1_attacker")
        risk = detector.risk_score(features)
        adaptive_length = pow_engine.challenge_length(risk)

        print("\n[gap1_static_pow]")
        print(f"  static PoW length: {pow_engine.BASE_LENGTH} bytes")
        print(f"  adaptive PoW length for high-risk client: {adaptive_length} bytes")
        print(f"  static is only {pow_engine.BASE_LENGTH / adaptive_length * 100:.1f}% of adaptive")

        assert adaptive_length > pow_engine.BASE_LENGTH

    def test_gap2_refa_has_no_behaviour_detection(self, extractor, detector, policy):
        events = make_events(
            "gap2_attacker",
            n_uploads=1,
            n_queries=30,
            duration=300.0,
            unique_hashes=30,
        )
        features = extractor.extract(events, "gap2_attacker")
        label = detector.predict(features)
        action = policy.decide(label)

        static_rate_limit_threshold = 60.0
        refa_decision = "ALLOW" if features.requests_per_minute < static_rate_limit_threshold else "RATE_LIMIT"

        print("\n[gap2_refa_no_detection]")
        print(f"  requests_per_minute = {features.requests_per_minute:.2f} (below typical static rate limit of 60/min)")
        print(f"  upload_to_query_ratio = {features.upload_to_query_ratio:.3f} (ML signal)")
        print(f"  ML LABEL={label}  ACTION={action}")
        print(f"  Static rate-limit decision: {refa_decision}")
        print(f"  REFA would: {refa_decision} | Our framework would: {action}")

        assert features.requests_per_minute < static_rate_limit_threshold
        assert round(features.upload_to_query_ratio, 3) == 0.033
        assert refa_decision == "ALLOW"
        assert action == "RATE_LIMIT"
