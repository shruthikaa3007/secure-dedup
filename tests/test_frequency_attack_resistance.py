"""
REFA-aligned tests for the frequency-attack story.

These tests map to the threat model discussed in Wu et al. (JISA 2024,
Section 3.3): deterministic public dedup tokens are reproducible by an
adversary, while secret-assisted tokens are not.
"""

import hashlib
import hmac
import random
import time


CHUNK_SMALL = b"short test chunk"
CHUNK_LARGE = b"A corporate policy document with sensitive salary information." * 200
CHUNK_POPULAR = b"Terms and Conditions v1.0 - identical across all users" * 50
SERVER_SECRET = b"secure-dedup-server-secret-key!!"
WRONG_SECRET = b"not-the-right-server-secret-key!"
MASTER_KEY = b"secure-dedup-master-key-32bytes!"


def sha256_token(chunk: bytes) -> str:
    """Baseline convergent token: public and reproducible."""
    return hashlib.sha256(chunk).hexdigest()


def hmac_token(chunk: bytes, secret: bytes = SERVER_SECRET) -> str:
    """Proposed token: secret-assisted and deterministic only for the server."""
    return hmac.new(secret, chunk, hashlib.sha256).hexdigest()


def _derive_key(chunk: bytes, master_key: bytes = MASTER_KEY) -> bytes:
    """Mirror the fingerprint-bound HKDF logic used in encryption.py."""
    token = hmac_token(chunk, SERVER_SECRET)
    context = token.encode("utf-8")
    salt = hashlib.sha256(b"secure-dedup/salt:" + context).digest()
    prk = hmac.new(salt, master_key, hashlib.sha256).digest()
    info = b"secure-dedup/chunk-key/v1|" + hashlib.sha256(context).digest()
    return hmac.new(prk, info + bytes([1]), hashlib.sha256).digest()[:32]


def _make_chunk(idx: int, chunk_size: int = 4096) -> bytes:
    seed = hashlib.sha256(f"chunk-{idx}".encode("ascii")).digest()
    repeats = (chunk_size // len(seed)) + 1
    return (seed * repeats)[:chunk_size]


class TestTokenNonReproducibility:
    """
    REFA Section 3.3: an external adversary tries to confirm file existence
    by computing the same dedup token as the server.
    """

    def test_sha256_token_is_reproducible_by_adversary(self):
        """Public SHA-256 tokens reproduce exactly, which is the vulnerability."""
        legitimate_token = sha256_token(CHUNK_POPULAR)
        adversary_token = sha256_token(CHUNK_POPULAR)
        assert legitimate_token == adversary_token

    def test_hmac_token_not_reproducible_with_sha256(self):
        """An HMAC token must not equal the public SHA-256 digest of the chunk."""
        server_token = hmac_token(CHUNK_POPULAR)
        adversary_guess = sha256_token(CHUNK_POPULAR)
        assert server_token != adversary_guess

    def test_hmac_token_not_reproducible_with_wrong_key(self):
        """Using the wrong secret must not reproduce the server token."""
        server_token = hmac_token(CHUNK_POPULAR, SERVER_SECRET)
        adversary_guess = hmac_token(CHUNK_POPULAR, WRONG_SECRET)
        assert server_token != adversary_guess

    def test_hmac_token_reproducible_with_correct_key(self):
        """The same server secret must always reproduce the same token for dedup."""
        token_a = hmac_token(CHUNK_POPULAR, SERVER_SECRET)
        token_b = hmac_token(CHUNK_POPULAR, SERVER_SECRET)
        assert token_a == token_b


class TestDeduplicationPreserved:
    """
    REFA Section 3.3 still requires dedup to work across users for identical
    content; secrecy must not destroy dedup savings.
    """

    def test_ten_users_same_chunk_same_hmac_token(self):
        """Ten users uploading the same chunk should still produce one token."""
        tokens = [hmac_token(CHUNK_POPULAR, SERVER_SECRET) for _ in range(10)]
        assert len(set(tokens)) == 1

    def test_dedup_savings_identical_across_schemes(self):
        """Both token schemes should preserve the same duplicate structure."""
        rng = random.Random(42)
        unique_chunks = [_make_chunk(i) for i in range(30)]
        corpus = [rng.choice(unique_chunks) for _ in range(100)]

        seen_sha256 = set()
        seen_hmac = set()
        for chunk in corpus:
            seen_sha256.add(sha256_token(chunk))
            seen_hmac.add(hmac_token(chunk, SERVER_SECRET))

        assert len(seen_sha256) == len(seen_hmac)
        dedup_saved = (100 - len(seen_sha256)) / 100 * 100
        assert dedup_saved >= 70.0


class TestFrequencyAnalysisAttack:
    """
    REFA Section 3.3: frequency analysis works when tokens are public, but the
    adversary loses that mapping when tokens are HMAC-protected.
    """

    @staticmethod
    def _build_frequency_map(corpus, token_fn):
        freq = {}
        for chunk in corpus:
            token = token_fn(chunk)
            freq[token] = freq.get(token, 0) + 1
        return freq

    def test_sha256_frequency_leaks_to_adversary(self):
        """Public SHA-256 lets an adversary recover the frequency map exactly."""
        popular = b"terms and conditions" * 100
        moderate = b"privacy policy text" * 100
        rare = b"internal memo chunk" * 100
        corpus = ([popular] * 60) + ([moderate] * 30) + ([rare] * 10)

        server_freq = self._build_frequency_map(corpus, sha256_token)
        adversary_candidates = {
            sha256_token(popular): "terms and conditions",
            sha256_token(moderate): "privacy policy text",
            sha256_token(rare): "internal memo chunk",
        }

        recovered = {}
        for token, count in server_freq.items():
            if token in adversary_candidates:
                recovered[adversary_candidates[token]] = count

        assert recovered == {
            "terms and conditions": 60,
            "privacy policy text": 30,
            "internal memo chunk": 10,
        }

    def test_hmac_frequency_opaque_to_adversary(self):
        """With the wrong key, the adversary cannot map any token back to content."""
        popular = b"terms and conditions" * 100
        moderate = b"privacy policy text" * 100
        rare = b"internal memo chunk" * 100
        corpus = ([popular] * 60) + ([moderate] * 30) + ([rare] * 10)

        server_freq = self._build_frequency_map(
            corpus,
            lambda chunk: hmac_token(chunk, SERVER_SECRET),
        )
        adversary_candidates = {
            hmac_token(popular, WRONG_SECRET): "terms and conditions",
            hmac_token(moderate, WRONG_SECRET): "privacy policy text",
            hmac_token(rare, WRONG_SECRET): "internal memo chunk",
        }

        recovered = {}
        for token, count in server_freq.items():
            if token in adversary_candidates:
                recovered[adversary_candidates[token]] = count

        assert recovered == {}

    def test_hmac_adversary_recovers_zero_information(self):
        """The adversary's best public guesses should match zero intercepted HMAC tokens."""
        chunks = [_make_chunk(i, 512) for i in range(50)]
        server_tokens = {hmac_token(chunk, SERVER_SECRET) for chunk in chunks}
        adversary_guesses = {sha256_token(chunk) for chunk in chunks}
        assert len(server_tokens & adversary_guesses) == 0


class TestTokenPerformance:
    """
    REFA Section 3.3 motivates better secrecy, but the replacement token must
    still remain cheap enough for a demoable storage pipeline.
    """

    def _time_tokens(self, token_fn, chunks):
        t0 = time.perf_counter()
        for chunk in chunks:
            token_fn(chunk)
        return (time.perf_counter() - t0) / len(chunks) * 1000.0

    def test_hmac_overhead_within_reasonable_bound(self):
        """HMAC can be slower than SHA-256, but the relative overhead should stay bounded."""
        chunks = [_make_chunk(i) for i in range(500)]
        sha_ms = self._time_tokens(sha256_token, chunks)
        hmac_ms = self._time_tokens(lambda chunk: hmac_token(chunk, SERVER_SECRET), chunks)
        overhead_pct = ((hmac_ms - sha_ms) / sha_ms) * 100 if sha_ms else 0.0
        print(f"\nSHA-256 avg: {sha_ms:.6f} ms/chunk")
        print(f"HMAC avg:    {hmac_ms:.6f} ms/chunk")
        print(f"Overhead:    {overhead_pct:.1f}%")
        assert overhead_pct < 300.0

    def test_absolute_hmac_time_is_negligible(self):
        """In absolute terms, HMAC should remain well below 1 ms per chunk."""
        chunks = [_make_chunk(i) for i in range(500)]
        avg_ms = self._time_tokens(lambda chunk: hmac_token(chunk, SERVER_SECRET), chunks)
        print(f"\nHMAC absolute avg: {avg_ms:.6f} ms/chunk")
        assert avg_ms < 1.0


class TestConfirmationAttack:
    """
    REFA Section 3.3 also covers confirmation-style probing: a public token lets
    an attacker confirm that a file exists in the dedup index.
    """

    def test_sha256_enables_confirmation_attack(self):
        """The attacker can recompute the same public token and probe the index."""
        target_file = b"salary_report_q4_2025.pdf content here" * 50
        server_index = {sha256_token(target_file): 1}
        assert sha256_token(target_file) in server_index

    def test_hmac_blocks_confirmation_attack(self):
        """Without the server secret, the attacker cannot craft the correct probe token."""
        target_file = b"salary_report_q4_2025.pdf content here" * 50
        server_index = {hmac_token(target_file, SERVER_SECRET): 1}
        assert sha256_token(target_file) not in server_index
        assert hmac_token(target_file, WRONG_SECRET) not in server_index


class TestHKDFKeyBinding:
    """
    REFA Section 3.3 is about token secrecy, and the repo strengthens that by
    binding the encryption key derivation to the secret-assisted token.
    """

    def test_different_chunks_produce_different_keys(self):
        """Different chunks should not collapse to the same derived encryption key."""
        key_a = _derive_key(CHUNK_SMALL, MASTER_KEY)
        key_b = _derive_key(CHUNK_LARGE, MASTER_KEY)
        assert key_a != key_b

    def test_same_chunk_produces_stable_32_byte_key(self):
        """The same chunk should derive the same 32-byte key every time."""
        key_a = _derive_key(CHUNK_POPULAR, MASTER_KEY)
        key_b = _derive_key(CHUNK_POPULAR, MASTER_KEY)
        assert key_a == key_b
        assert len(key_a) == 32
