# secure-dedup-bpow

Notebook-first secure cloud deduplication prototype aligned to Wu et al. (JISA 2024), rebuilt around a research package instead of an HTTP demo. The repository now centers on:

- `src/`: the reusable implementation package.
- `notebooks/`: five numbered walkthrough notebooks.
- `tests/`: unit and integration coverage for the package APIs.
- `docker-compose.yml`: LocalStack-backed cloud simulation for S3 and DynamoDB.

## Architecture

The implementation is organized into four subsystems:

- `src.crypto`: REFA-style encryption, key derivation, identity, OPRF abstraction, and key-server logic.
- `src.behavioral`: behavioral vector extraction, authenticated BPoW, supervised risk scoring, unsupervised anomaly detection, and z-score monitoring.
- `src.cloud`: LocalStack-backed S3 and DynamoDB adapters.
- `src.system`: top-level orchestration through `SecureDedupSystem`.

The behavioral pipeline now combines:

- a supervised classifier for human-vs-bot session scoring,
- an unsupervised detector for outlier behavior,
- and the existing rolling z-score checks for transparent fallback behavior.

The deduplication path is hardened in two additional ways:

- chunk locators are server-private keyed tags rather than raw public SHA-256 fingerprints,
- and the public `chunk_tags` returned by `upload()` are opaque per-user download handles.

This means upload responses do not expose direct dedup-hit signals, which reduces confirmation-style hash probing. The key server also rate-limits per user and throttles per-chunk hotspots to reduce dedup-DoS pressure.

The public entrypoints are:

- `SecureDedupSystem.upload(user_id, filepath, password) -> dict`
- `SecureDedupSystem.download(user_id, chunk_tags, password) -> list[bytes]`
- `SecureDedupSystem.simulate_bot_attack(user_id, filepath) -> dict`
- `SecureDedupSystem.simulate_replay_attack(stolen_proof) -> dict`

## OPRF Note

`src.crypto.oprf` exposes the planned `blind`, `evaluate`, `unblind`, `finalize`, and `full_oprf` API regardless of backend. The default backend is now a real `ristretto255` implementation built on libsodium through `rbcl`, which follows the same blind-evaluate-unblind structure used by DupLESS-style blind GDH key servers. A lightweight `HMACBackend` still exists behind the same interface for constrained environments and sensitivity analysis, but it is no longer the default paper path.

The default backend can be changed with:

```powershell
$env:OPRF_BACKEND = "hmac"
```

Paper-facing notes that clarify the threat model and the current evaluation story live in:

- `docs/security/SECURITY_MODEL_NOTE.md`
- `docs/evaluation/TRACE_EVALUATION_NOTE.md`

## Environment

### Python

Create a fresh environment instead of reusing the checked-in `.venv`:

```powershell
py -3.12 -m venv .venv-local
.\.venv-local\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### LocalStack

Start LocalStack for S3 and DynamoDB:

```powershell
docker compose up -d
```

The package defaults point at `http://127.0.0.1:4566`.

## Tests

Run the package test suite with:

```powershell
py -3.12 -m pytest tests -q
```

Integration tests that exercise LocalStack are skipped unless `RUN_LOCALSTACK_TESTS=1` is set.

## Notebooks

The numbered notebooks in `notebooks/` mirror the implementation areas:

1. `01_refa_core.ipynb`
2. `02_crypto_upgrades.ipynb`
3. `03_bpow_behavioral.ipynb`
4. `04_localstack_integration.ipynb`
5. `05_evaluation.ipynb`

Each notebook imports from `src` and is designed to match the behavior covered by the tests.
