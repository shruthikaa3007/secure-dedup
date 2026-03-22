# Video Narration Sheet

Use this while running `.\record_demo.ps1`.

## Intro

`This project is based on Wu et al.'s frequency-attack motivation for secure deduplication. My improvement is a lighter server-side design that uses secret-assisted chunk identities, fingerprint-bound AES-GCM, visible proof-of-ownership, and behavioural throttling.`

## Step 1 - Frequency Attack Resistance

`These tests show the exact weakness of a public SHA-256 dedup token. An attacker can reproduce it and probe the system. Under HMAC, that token is no longer reproducible without the server secret, while cross-user deduplication still works.`

What to point at:

- SHA-256 token reproducibility
- HMAC non-reproducibility
- cross-user dedup preserved
- zero recovered matches under HMAC

## Step 2 - Encryption Comparison

`The key result is that dedup savings stay the same, but the token is no longer publicly reproducible. The scheme is also simpler to deploy than a design that depends on an external key server.`

What to point at:

- `Dedup saved (%)`
- `Token reproducible?`
- `Frequency attack resistant?`
- `External key server?`

## Step 3 - Live API Flow

`This is the actual API path. The first upload stores encrypted chunks. The second duplicate upload triggers proof-of-ownership before reuse, and after PoW the duplicate can be reused safely. Then I force a rate-limit policy to show runtime defence in action.`

What to point at:

- `chunk_summary`
- `required_challenges`
- `pow_proofs`
- `shared_chunk_count`
- `rate_limit_events`

## Step 4 - Behavioural Detection

Say this line exactly:

`REFA would: ALLOW | Our framework would: RATE_LIMIT.`

Then add:

`That is the value of the behavioural layer. A careful attacker can stay below a static requests-per-minute threshold, but the upload-to-query ratio still exposes the probing behaviour.`

## Step 5 - Dataset Answer

`The small legacy CSV is not the whole data story. The evaluation pipeline starts from over one million standardized request events across FIU and MSRC traces. I generated a denser multi-source dataset with 221 labelled windows across 72 clients, and retrained the detector on that larger trace-derived set. I still present it as prototype-scale, not deployment-scale.`

Point to:

- `multisource_dense_detection_results.csv`
- `dense_artifacts/training_metrics.json`
- `dense_artifacts/evaluation_report.md`
