# Dedup Encryption Scheme Comparison

- Generated (UTC): `2026-03-22T17:12:27.777151+00:00`
- Chunks: `300`
- Unique Chunks: `90`
- Chunk Size: `4096` bytes
- Measured Rounds: `5` (after warm-up)

## Compared Schemes

- `baseline_sha256_bound_aead`
- `proposed_secret_hmac_bound_aead`

## Measured Runtime Comparison

| Metric | Baseline | Proposed |
|---|---:|---:|
| Dedup saved percent | 70.0000 | 70.0000 |
| Avg token time (ms) | 0.015735 | 0.024021 |
| Avg encrypt time (ms) | 0.143507 | 0.139190 |
| Avg decrypt time (ms) | 0.160704 | 0.157731 |
| Avg storage overhead (bytes) | 38.00 | 38.00 |

## Demo-Facing Security Properties

| Property | Baseline | Proposed |
|---|---|---|
| Token reproducible without secret? | Yes | No |
| Frequency attack resistant? | No | Yes |
| External key server required? | No | No |

## Relative Delta of Proposed Scheme

- Token generation delta: `52.6597%`
- Encryption delta: `-3.0082%`
- Decryption delta: `-1.8500%`
- Storage overhead delta: `0.00` bytes

## Interpretation

- Dedup savings should remain effectively unchanged because both schemes preserve duplicate detection.
- The proposed scheme adds a secret-assisted dedup token (`HMAC-SHA256`) instead of a plain public hash (`SHA-256`).
- The per-chunk encryption key is derived from that token via HKDF-SHA256, then used in the same segmented AES-GCM envelope.
- Runtime differences come mainly from token generation; encryption overhead should remain close because both schemes use the same AEAD envelope.

## Paper-backed Positioning

- Recent dedup papers argue that plain convergent/content-only approaches are vulnerable to brute-force, confirmation, and frequency attacks.
- The proposed scheme moves toward the secret-assisted direction supported by recent server-aided dedup encryption work, while staying simpler than full hybrid-cloud or multi-key-server designs.
- REFA-style work motivates reducing deterministic leakage; this construction addresses the public-fingerprint side of that problem by replacing the public dedup token with a secret-assisted one.

## Recent Paper Context

- `Lee and Seo, 2023, Applied Sciences`: content-derived / convergent-style secure deduplication with dynamic ownership. Motivates moving beyond public content-only identifiers because deterministic content-derived keys remain vulnerable to dictionary and precomputation attacks. Link: https://www.mdpi.com/2076-3417/13/24/13270
- `Wu et al., 2024, Journal of Information Security and Applications`: randomized encryption deduplication against frequency attack (REFA). Shows that deterministic dedup encryption leaks frequency information and motivates stronger leakage resistance. Link: https://www.sciencedirect.com/science/article/abs/pii/S2214212624000772
- `Tang et al., 2024, Computer Communications`: hybrid-cloud secure deduplication with OPRF-assisted convergent key generation. Supports secret-assisted key generation and access control for secure deduplication. Link: https://www.sciencedirect.com/science/article/pii/S0140366424001695
- `Gan et al., 2025, Applied Sciences`: decentralized server-aided encrypted deduplication with secret sharing (ECDedup). Closest recent secret-assisted direction to the proposed scheme; reports improved throughput while strengthening secrecy. Link: https://www.mdpi.com/2076-3417/15/3/1245
