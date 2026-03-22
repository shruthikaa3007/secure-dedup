# Encryption Positioning and Recent-Paper Comparison

## Base Paper Anchor

This repo now treats Wu et al. (JISA 2024) on randomized deduplication encryption against frequency attack as the primary paper anchor.

That means the main thesis question is no longer "how do we add auditing to secure deduplication?" It is:

`How can we improve on deterministic deduplication encryption in a lightweight, demoable secure dedup pipeline?`

## Proposed Scheme

This project now uses a thesis-safe dedup-aware encryption construction rather than a new cipher:

1. `dedup_token = HMAC(K_fp, chunk)`
2. `K_chunk = HKDF-SHA256(K_master, dedup_token)`
3. each chunk is encrypted with segmented `AES-GCM`
4. AEAD associated data binds the dedup token and segment index

This keeps the cryptographic primitive standard while changing the way deduplication identity and per-chunk encryption are combined.

## Why this is a valid novelty claim

The novelty is not "we invented a new cipher." The novelty is:

- a secret-assisted dedup token instead of a public content hash,
- a fingerprint-bound per-chunk key derivation path,
- integration with proof-of-ownership and behavioural monitoring in one secure dedup pipeline.

That is a defensible systems-security contribution for a project of this scope.

## Comparison to Recent Dedup Encryption Directions

| Paper | Encryption direction | Main security point | Relation to this project |
|---|---|---|---|
| Lee and Seo, 2023, Applied Sciences, https://www.mdpi.com/2076-3417/13/24/13270 | Convergent / message-locked style dedup with dynamic ownership context | Plain content-derived keys remain vulnerable to dictionary and precomputation attacks; server-aided help is motivated. | Supports moving away from public content-only fingerprints. |
| Wu et al., 2024, JISA, https://www.sciencedirect.com/science/article/abs/pii/S2214212624000772 | Randomized encryption dedup against frequency attack (REFA) | Deterministic dedup encryption can leak chunk-frequency information. | Supports adding stronger leakage resistance beyond classic deterministic dedup encryption. |
| Tang et al., 2024, Computer Communications, https://www.sciencedirect.com/science/article/pii/S0140366424001695 | Hybrid-cloud secure dedup with OPRF-assisted convergent key generation and access control | Secret-assisted key generation improves privacy and dictionary-attack resistance while supporting access control. | Supports the secret-assisted token direction used here, but our project stays lighter-weight and single-service. |
| Gan et al., 2025, Applied Sciences, https://www.mdpi.com/2076-3417/15/3/1245 | Decentralized server-aided encrypted deduplication with secret sharing | Combining server-side secrecy with content signals can improve both security and throughput. | Closest recent direction to our proposed secret-assisted dedup token design. |

## What we compare experimentally

The repo benchmark compares two concrete schemes that can be run locally:

1. `baseline_sha256_bound_aead`
   Public `SHA-256` chunk token plus context-bound segmented `AES-GCM`.

2. `proposed_secret_hmac_bound_aead`
   Secret `HMAC-SHA256` dedup token plus HKDF-derived segmented `AES-GCM`.

The benchmark lives in:

- `compare_dedup_encryption_schemes.py`
- `docs/project_notes/encryption_scheme_comparison.json`
- `docs/project_notes/encryption_scheme_comparison.md`

## Thesis-safe wording

Use this wording in the report and viva:

`The project does not introduce a new cryptographic primitive. Instead, it proposes a secret-assisted, fingerprint-bound chunk-encryption construction for secure deduplication, positioned against recent server-aided and randomized dedup-encryption directions in the literature.`
