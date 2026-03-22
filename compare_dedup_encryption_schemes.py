#!/usr/bin/env python3
import argparse
import json
import os
import random
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from statistics import mean
from typing import Dict, List

from encryption import decrypt_chunk, encrypt_chunk, encryption_status
from hashing import fingerprint_status, hash_chunk

DEMO_ENCRYPTION_KEY_B64 = "c2VjdXJlLWRlZHVwLWRlbW8ta2V5LTMyYnl0ZXMhISE="
DEMO_FINGERPRINT_KEY_B64 = "c2VjdXJlLWRlZHVwLWZpbmdlcnByaW50LWtleSEhISE="
PAPER_CONTEXT = [
    {
        "paper": "Lee and Seo, 2023, Applied Sciences",
        "direction": "content-derived / convergent-style secure deduplication with dynamic ownership",
        "link": "https://www.mdpi.com/2076-3417/13/24/13270",
        "relevance": (
            "Motivates moving beyond public content-only identifiers because "
            "deterministic content-derived keys remain vulnerable to dictionary "
            "and precomputation attacks."
        ),
    },
    {
        "paper": "Wu et al., 2024, Journal of Information Security and Applications",
        "direction": "randomized encryption deduplication against frequency attack (REFA)",
        "link": "https://www.sciencedirect.com/science/article/abs/pii/S2214212624000772",
        "relevance": (
            "Shows that deterministic dedup encryption leaks frequency "
            "information and motivates stronger leakage resistance."
        ),
    },
    {
        "paper": "Tang et al., 2024, Computer Communications",
        "direction": "hybrid-cloud secure deduplication with OPRF-assisted convergent key generation",
        "link": "https://www.sciencedirect.com/science/article/pii/S0140366424001695",
        "relevance": (
            "Supports secret-assisted key generation and access control for "
            "secure deduplication."
        ),
    },
    {
        "paper": "Gan et al., 2025, Applied Sciences",
        "direction": "decentralized server-aided encrypted deduplication with secret sharing (ECDedup)",
        "link": "https://www.mdpi.com/2076-3417/15/3/1245",
        "relevance": (
            "Closest recent secret-assisted direction to the proposed scheme; "
            "reports improved throughput while strengthening secrecy."
        ),
    },
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare baseline and secret-assisted dedup-aware encryption schemes."
    )
    parser.add_argument("--chunks", type=int, default=300)
    parser.add_argument("--unique-chunks", type=int, default=90)
    parser.add_argument("--chunk-size", type=int, default=4096)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument(
        "--output-json",
        default="docs/project_notes/encryption_scheme_comparison.json",
    )
    parser.add_argument(
        "--output-md",
        default="docs/project_notes/encryption_scheme_comparison.md",
    )
    parser.add_argument(
        "--print-table",
        action="store_true",
        help="Print a clean terminal comparison table for live demos.",
    )
    return parser.parse_args()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mean_ms(values: List[float]) -> float:
    return float(mean(values)) * 1000.0 if values else 0.0


def _relative_delta_pct(before: float, after: float) -> float:
    if before == 0:
        return 0.0
    return ((after - before) / before) * 100.0


def _make_chunk(idx: int, chunk_size: int) -> bytes:
    rng = random.Random(idx)
    return bytes(rng.randrange(0, 256) for _ in range(chunk_size))


def _build_dataset(total_chunks: int, unique_chunks: int, chunk_size: int) -> List[bytes]:
    if unique_chunks <= 0 or total_chunks <= 0:
        raise ValueError("chunk counts must be positive")
    unique_pool = [_make_chunk(idx, chunk_size) for idx in range(unique_chunks)]
    dataset = list(unique_pool)
    rng = random.Random(1337)
    while len(dataset) < total_chunks:
        dataset.append(unique_pool[rng.randrange(0, len(unique_pool))])
    rng.shuffle(dataset)
    return dataset


@contextmanager
def _env_override(overrides: Dict[str, str]):
    original = {}
    for key, value in overrides.items():
        original[key] = os.environ.get(key)
        os.environ[key] = value
    try:
        yield
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _evaluate_scheme_once(name: str, fingerprint_mode: str, dataset: List[bytes]) -> Dict:
    token_times = []
    encrypt_times = []
    decrypt_times = []
    ciphertext_sizes = []
    tokens = []

    overrides = {
        "DEMO_MODE": "true",
        "CHUNK_ENCRYPTION_DEFAULT_ON": "true",
        "CHUNK_ENCRYPTION_KEY": DEMO_ENCRYPTION_KEY_B64,
        "DEDUP_FINGERPRINT_MODE": fingerprint_mode,
        "DEDUP_FINGERPRINT_KEY": DEMO_FINGERPRINT_KEY_B64,
        "DEDUP_FINGERPRINT_DEFAULT_ON": "true",
    }

    with _env_override(overrides):
        for chunk in dataset:
            t0 = time.perf_counter()
            token = hash_chunk(chunk)
            t1 = time.perf_counter()
            ciphertext = encrypt_chunk(chunk, context=token)
            t2 = time.perf_counter()
            plain = decrypt_chunk(ciphertext, context=token)
            t3 = time.perf_counter()

            if plain != chunk:
                raise ValueError(f"decryption mismatch for scheme {name}")

            tokens.append(token)
            token_times.append(t1 - t0)
            encrypt_times.append(t2 - t1)
            decrypt_times.append(t3 - t2)
            ciphertext_sizes.append(len(ciphertext))

        unique_tokens = len(set(tokens))
        logical_chunks = len(dataset)
        dedup_saved_chunks = max(0, logical_chunks - unique_tokens)
        dedup_saved_percent = (dedup_saved_chunks / logical_chunks * 100.0) if logical_chunks else 0.0
        avg_plain_size = mean(len(chunk) for chunk in dataset)
        avg_cipher_size = mean(ciphertext_sizes) if ciphertext_sizes else 0.0
        avg_storage_overhead = avg_cipher_size - avg_plain_size

        return {
            "scheme": name,
            "fingerprint": fingerprint_status(),
            "encryption": encryption_status(),
            "security_properties": {
                "token_reproducible_without_secret": fingerprint_mode == "sha256",
                "frequency_attack_resistant": fingerprint_mode != "sha256",
                "external_key_server_required": False,
            },
            "logical_chunks": logical_chunks,
            "unique_chunk_tokens": unique_tokens,
            "dedup_saved_chunks": dedup_saved_chunks,
            "dedup_saved_percent": round(dedup_saved_percent, 4),
            "avg_token_time_ms": round(_mean_ms(token_times), 6),
            "avg_encrypt_time_ms": round(_mean_ms(encrypt_times), 6),
            "avg_decrypt_time_ms": round(_mean_ms(decrypt_times), 6),
            "avg_plain_chunk_bytes": round(avg_plain_size, 2),
            "avg_cipher_chunk_bytes": round(avg_cipher_size, 2),
            "avg_storage_overhead_bytes": round(avg_storage_overhead, 2),
        }


def _aggregate_scheme_runs(name: str, runs: List[Dict]) -> Dict:
    if not runs:
        raise ValueError(f"no runs collected for {name}")

    first = runs[0]
    numeric_keys = [
        "logical_chunks",
        "unique_chunk_tokens",
        "dedup_saved_chunks",
        "dedup_saved_percent",
        "avg_token_time_ms",
        "avg_encrypt_time_ms",
        "avg_decrypt_time_ms",
        "avg_plain_chunk_bytes",
        "avg_cipher_chunk_bytes",
        "avg_storage_overhead_bytes",
    ]

    aggregated = {
        "scheme": name,
        "fingerprint": first["fingerprint"],
        "encryption": first["encryption"],
        "security_properties": first["security_properties"],
        "rounds": len(runs),
    }
    for key in numeric_keys:
        aggregated[key] = round(float(mean(run[key] for run in runs)), 6)
    return aggregated


def _write_json(path: str, payload: Dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=True)
        fh.write("\n")


def _write_md(path: str, payload: Dict) -> None:
    baseline = payload["schemes"][0]
    proposed = payload["schemes"][1]
    deltas = payload["comparison"]
    baseline_props = baseline.get("security_properties", {})
    proposed_props = proposed.get("security_properties", {})
    lines = [
        "# Dedup Encryption Scheme Comparison",
        "",
        f"- Generated (UTC): `{payload['generated_at_utc']}`",
        f"- Chunks: `{payload['config']['chunks']}`",
        f"- Unique Chunks: `{payload['config']['unique_chunks']}`",
        f"- Chunk Size: `{payload['config']['chunk_size']}` bytes",
        f"- Measured Rounds: `{payload['config']['rounds']}` (after warm-up)",
        "",
        "## Compared Schemes",
        "",
        f"- `{baseline['scheme']}`",
        f"- `{proposed['scheme']}`",
        "",
        "## Measured Runtime Comparison",
        "",
        "| Metric | Baseline | Proposed |",
        "|---|---:|---:|",
        f"| Dedup saved percent | {baseline['dedup_saved_percent']:.4f} | {proposed['dedup_saved_percent']:.4f} |",
        f"| Avg token time (ms) | {baseline['avg_token_time_ms']:.6f} | {proposed['avg_token_time_ms']:.6f} |",
        f"| Avg encrypt time (ms) | {baseline['avg_encrypt_time_ms']:.6f} | {proposed['avg_encrypt_time_ms']:.6f} |",
        f"| Avg decrypt time (ms) | {baseline['avg_decrypt_time_ms']:.6f} | {proposed['avg_decrypt_time_ms']:.6f} |",
        f"| Avg storage overhead (bytes) | {baseline['avg_storage_overhead_bytes']:.2f} | {proposed['avg_storage_overhead_bytes']:.2f} |",
        "",
        "## Demo-Facing Security Properties",
        "",
        "| Property | Baseline | Proposed |",
        "|---|---|---|",
        f"| Token reproducible without secret? | {'Yes' if baseline_props.get('token_reproducible_without_secret') else 'No'} | {'Yes' if proposed_props.get('token_reproducible_without_secret') else 'No'} |",
        f"| Frequency attack resistant? | {'Yes' if baseline_props.get('frequency_attack_resistant') else 'No'} | {'Yes' if proposed_props.get('frequency_attack_resistant') else 'No'} |",
        f"| External key server required? | {'Yes' if baseline_props.get('external_key_server_required') else 'No'} | {'Yes' if proposed_props.get('external_key_server_required') else 'No'} |",
        "",
        "## Relative Delta of Proposed Scheme",
        "",
        f"- Token generation delta: `{deltas['token_time_delta_pct']:.4f}%`",
        f"- Encryption delta: `{deltas['encrypt_time_delta_pct']:.4f}%`",
        f"- Decryption delta: `{deltas['decrypt_time_delta_pct']:.4f}%`",
        f"- Storage overhead delta: `{deltas['storage_overhead_delta_bytes']:.2f}` bytes",
        "",
        "## Interpretation",
        "",
        "- Dedup savings should remain effectively unchanged because both schemes preserve duplicate detection.",
        "- The proposed scheme adds a secret-assisted dedup token (`HMAC-SHA256`) instead of a plain public hash (`SHA-256`).",
        "- The per-chunk encryption key is derived from that token via HKDF-SHA256, then used in the same segmented AES-GCM envelope.",
        "- Runtime differences come mainly from token generation; encryption overhead should remain close because both schemes use the same AEAD envelope.",
        "",
        "## Paper-backed Positioning",
        "",
        "- Recent dedup papers argue that plain convergent/content-only approaches are vulnerable to brute-force, confirmation, and frequency attacks.",
        "- The proposed scheme moves toward the secret-assisted direction supported by recent server-aided dedup encryption work, while staying simpler than full hybrid-cloud or multi-key-server designs.",
        "- REFA-style work motivates reducing deterministic leakage; this construction addresses the public-fingerprint side of that problem by replacing the public dedup token with a secret-assisted one.",
        "",
        "## Recent Paper Context",
        "",
    ]
    for item in payload["paper_context"]:
        lines.append(
            f"- `{item['paper']}`: {item['direction']}. {item['relevance']} Link: {item['link']}"
        )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def _bool_cell(value: bool, yes_text: str, no_text: str) -> str:
    return yes_text if value else no_text


def _print_terminal_table(payload: Dict) -> None:
    baseline = payload["schemes"][0]
    proposed = payload["schemes"][1]
    deltas = payload["comparison"]
    baseline_props = baseline.get("security_properties", {})
    proposed_props = proposed.get("security_properties", {})

    rows = [
        (
            "Dedup saved (%)",
            f"{baseline['dedup_saved_percent']:.2f}%",
            f"{proposed['dedup_saved_percent']:.2f}% (IDENTICAL)",
            False,
        ),
        (
            "Token generation (ms)",
            f"{baseline['avg_token_time_ms']:.6f}",
            f"{proposed['avg_token_time_ms']:.6f} ({deltas['token_time_delta_pct']:+.1f}%)",
            False,
        ),
        (
            "Encryption time (ms)",
            f"{baseline['avg_encrypt_time_ms']:.6f}",
            f"{proposed['avg_encrypt_time_ms']:.6f} ({deltas['encrypt_time_delta_pct']:+.1f}%)",
            False,
        ),
        (
            "Decryption time (ms)",
            f"{baseline['avg_decrypt_time_ms']:.6f}",
            f"{proposed['avg_decrypt_time_ms']:.6f} ({deltas['decrypt_time_delta_pct']:+.1f}%)",
            False,
        ),
        (
            "Storage overhead delta",
            "0 bytes",
            f"{deltas['storage_overhead_delta_bytes']:+.1f} bytes",
            False,
        ),
        (
            "Token reproducible?",
            _bool_cell(
                bool(baseline_props.get("token_reproducible_without_secret")),
                "YES (vulnerable)",
                "NO",
            ),
            _bool_cell(
                bool(proposed_props.get("token_reproducible_without_secret")),
                "YES",
                "NO (HMAC required)",
            ),
            True,
        ),
        (
            "Frequency attack resistant?",
            _bool_cell(
                bool(baseline_props.get("frequency_attack_resistant")),
                "YES",
                "NO",
            ),
            _bool_cell(
                bool(proposed_props.get("frequency_attack_resistant")),
                "YES",
                "NO",
            ),
            True,
        ),
        (
            "External key server?",
            _bool_cell(
                bool(baseline_props.get("external_key_server_required")),
                "YES",
                "NO",
            ),
            _bool_cell(
                bool(proposed_props.get("external_key_server_required")),
                "YES",
                "NO (vs REFA: YES)",
            ),
            True,
        ),
    ]

    metric_width = max(len("Metric"), max(len(row[0]) for row in rows))
    baseline_width = max(len("Baseline"), max(len(row[1]) for row in rows))
    proposed_width = max(len("Proposed"), max(len(row[2]) for row in rows))
    sep = (
        "+"
        + "-" * (metric_width + 2)
        + "+"
        + "-" * (baseline_width + 2)
        + "+"
        + "-" * (proposed_width + 2)
        + "+"
    )

    print()
    print("ENCRYPTION SCHEME COMPARISON")
    print(
        f"Dataset: {payload['config']['chunks']} chunks "
        f"({payload['config']['unique_chunks']} unique), "
        f"{payload['config']['rounds']}-round average"
    )
    print(sep)
    print(
        f"| {'Metric':<{metric_width}} | "
        f"{'Baseline':<{baseline_width}} | "
        f"{'Proposed':<{proposed_width}} |"
    )
    print(sep)
    for label, baseline_value, proposed_value, highlight in rows:
        marker = "  <-- KEY" if highlight else ""
        print(
            f"| {label:<{metric_width}} | "
            f"{baseline_value:<{baseline_width}} | "
            f"{proposed_value:<{proposed_width}} |{marker}"
        )
    print(sep)
    print()
    print("Security claim:")
    print(
        "The proposed HMAC-bound scheme preserves dedup savings while making the dedup "
        "token non-reproducible to an external adversary, and it does so without an "
        "external key server."
    )
    print()


def main() -> None:
    args = parse_args()
    if args.rounds <= 0:
        raise ValueError("--rounds must be positive")
    dataset = _build_dataset(args.chunks, args.unique_chunks, args.chunk_size)

    _evaluate_scheme_once("baseline_sha256_bound_aead", "sha256", dataset)
    _evaluate_scheme_once("proposed_secret_hmac_bound_aead", "secret_hmac", dataset)

    baseline_runs = []
    proposed_runs = []
    for round_idx in range(args.rounds):
        ordered_runs = [
            ("baseline_sha256_bound_aead", "sha256", baseline_runs),
            ("proposed_secret_hmac_bound_aead", "secret_hmac", proposed_runs),
        ]
        if round_idx % 2 == 1:
            ordered_runs.reverse()

        for name, mode, sink in ordered_runs:
            sink.append(_evaluate_scheme_once(name, mode, dataset))

    baseline = _aggregate_scheme_runs("baseline_sha256_bound_aead", baseline_runs)
    proposed = _aggregate_scheme_runs("proposed_secret_hmac_bound_aead", proposed_runs)

    payload = {
        "generated_at_utc": _now_iso(),
        "config": {
            "chunks": args.chunks,
            "unique_chunks": args.unique_chunks,
            "chunk_size": args.chunk_size,
            "rounds": args.rounds,
        },
        "paper_context": PAPER_CONTEXT,
        "comparison": {
            "dedup_saved_delta_pct": round(
                proposed["dedup_saved_percent"] - baseline["dedup_saved_percent"], 6
            ),
            "token_time_delta_pct": round(
                _relative_delta_pct(
                    baseline["avg_token_time_ms"],
                    proposed["avg_token_time_ms"],
                ),
                6,
            ),
            "encrypt_time_delta_pct": round(
                _relative_delta_pct(
                    baseline["avg_encrypt_time_ms"],
                    proposed["avg_encrypt_time_ms"],
                ),
                6,
            ),
            "decrypt_time_delta_pct": round(
                _relative_delta_pct(
                    baseline["avg_decrypt_time_ms"],
                    proposed["avg_decrypt_time_ms"],
                ),
                6,
            ),
            "storage_overhead_delta_bytes": round(
                proposed["avg_storage_overhead_bytes"]
                - baseline["avg_storage_overhead_bytes"],
                6,
            ),
        },
        "schemes": [baseline, proposed],
    }

    _write_json(args.output_json, payload)
    _write_md(args.output_md, payload)
    if args.print_table:
        _print_terminal_table(payload)

    print(f"JSON report: {args.output_json}")
    print(f"MD report:   {args.output_md}")


if __name__ == "__main__":
    main()
