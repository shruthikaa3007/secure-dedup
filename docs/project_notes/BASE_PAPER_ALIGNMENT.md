# Base Paper Selection and Project Alignment

## Selected Base Paper

**J. Wu et al. (2024)**
**"A randomized encryption deduplication method against frequency attack"**
*Journal of Information Security and Applications*
DOI: `10.1016/j.jisa.2024.103774`

## Why This Is The Right Anchor Now

1. The repo's strongest contribution is encryption-focused, not auditing-focused.
2. Wu et al. give a clean motivation for improving deterministic dedup-encryption behavior.
3. The current implementation already contains a concrete encryption comparison against a deterministic baseline.
4. This makes the thesis story narrower, clearer, and easier to defend.

## What The Project Already Matches

1. **Dedup-aware encrypted storage**
   Chunk identities drive both deduplication and encryption behavior.
2. **Security positioning against deterministic leakage**
   The repo benchmark compares a public-hash baseline with a stronger secret-assisted alternative.
3. **Reproducible runtime comparison**
   The encryption benchmark reports dedup preservation, token cost, encrypt/decrypt time, and storage overhead.

## What The Project Adds Beyond That Direction

1. **Secret-assisted dedup identity**
   The project uses `HMAC-SHA256` chunk identities rather than a plain public content hash.
2. **Fingerprint-bound key derivation**
   Chunk keys are derived from the dedup identity via `HKDF-SHA256`.
3. **Visible duplicate-verification**
   Duplicate chunk reuse is protected by PoW, which is demoable in the API.
4. **Behaviour-aware throttling**
   Suspicious repeated behavior can trigger `RATE_LIMIT` or `BLOCK`, making abuse response visible.

## How To Position The Novelty

1. Base paper focus:
   leakage resistance for deduplication encryption under frequency-attack concerns.
2. Your extension:
   a lighter secret-assisted, fingerprint-bound encryption construction integrated with PoW and runtime throttling.
3. Defense line:
   the project does not claim a new cipher; it claims a stronger dedup-aware systems design that is easier to demonstrate and evaluate in a prototype.

## What To De-Emphasize

These should no longer be the main claim:

- cloud auditing as the core contribution,
- ownership/data-dynamics as the thesis anchor,
- audit endpoints as part of the main demo flow.

They may stay in the repo as secondary code, but they should not dominate the presentation.

## What To Show Instead

For the final report and live demo, prioritize these concrete pieces:

1. `GET /demo/encryption/comparison`
   This is the clearest "Wu et al. baseline direction vs our improvement" artifact.
2. `POST /upload`
   Use this to show encrypted chunk storage, duplicate detection, and PoW gating.
3. `GET /demo/compare-files`
   Use this to make partial chunk reuse visible across controlled similar files.
4. `GET /demo/highlights/{client_id}`
   Use this to show rate limiting, PoW events, and duplicate-reuse success in one place.

## Thesis-Safe One-Line Positioning

Use this sentence consistently:

`This project improves on the deterministic dedup-encryption direction discussed by Wu et al. by using secret-assisted chunk identities, fingerprint-bound AES-GCM, visible proof-of-ownership, and lightweight runtime throttling in a demoable secure deduplication prototype.`

## Best Supporting Artifacts

- `docs/project_notes/encryption_scheme_comparison.json`
- `docs/project_notes/encryption_scheme_comparison.md`
- `docs/project_notes/ENCRYPTION_POSITIONING.md`
- `tests/test_encryption.py`
- `notebooks/encryption_demo_colab.ipynb`
