# Tomorrow Talk Track (3-5 minutes)

## 1) Problem Statement (30-45 sec)
Wu et al. show that deterministic deduplication encryption can leak useful frequency information.
At the same time, cloud providers still want deduplication because it saves storage and bandwidth.
So the project question becomes: how do we keep deduplication useful while making the encryption path less leakage-prone and the duplicate-reuse path safer?

## 2) Base Paper Anchor (30-45 sec)
The base paper is:

`J. Wu et al., "A randomized encryption deduplication method against frequency attack," Journal of Information Security and Applications, 2024.`

That paper motivates improving deterministic dedup-aware encryption.
My project does not claim to reproduce their full construction exactly.
Instead, it builds a lighter prototype that improves on the same problem direction in a way that is easy to test and demo.

## 3) What I Implemented (45-60 sec)
The core implementation has three parts:

1. Secret-assisted chunk identity
   I replaced a plain public `SHA-256` dedup token with `HMAC-SHA256`.
2. Fingerprint-bound chunk encryption
   I derive per-chunk keys through `HKDF-SHA256` and encrypt each chunk with segmented `AES-GCM`.
3. Safe duplicate reuse
   If a chunk already exists, the client must complete proof-of-ownership before reuse, and suspicious behavior can be rate limited.

## 4) What I Show In The Demo (60-90 sec)
I show four concrete pieces in Swagger:

1. `GET /demo/encryption/comparison`
   This compares the public-hash baseline with the proposed secret-assisted scheme.
2. `POST /upload`
   The first upload stores encrypted chunks.
3. Re-upload a duplicate or controlled similar file
   This shows shared chunks and PoW challenge generation.
4. `GET /demo/highlights/{client_id}`
   This shows PoW activity, duplicate reuse success, and rate-limiting events.

## 5) Main Result Lines (30-45 sec)
The most important result is that deduplication savings stay effectively unchanged while the dedup identity becomes secret-assisted.
The checked-in benchmark shows:

1. dedup saved percent remains `70%` in both schemes,
2. storage overhead stays the same,
3. most extra cost appears in token generation, not encryption or decryption.

That makes the design practical enough for a prototype and easy to defend academically.

## 6) Honest Scope Boundary (20-30 sec)
I am not presenting auditing or ownership-transfer workflows as my main contribution.
Those modules may still exist in the repo, but the final claim is narrower:

`a Wu-et-al-inspired secure deduplication prototype with stronger dedup-aware encryption, visible proof-of-ownership, and lightweight runtime throttling.`

## 7) One-Line Claim
This project improves on the deterministic dedup-encryption direction highlighted by Wu et al. with a secret-assisted, fingerprint-bound secure deduplication pipeline that is measurable, testable, and easy to demonstrate.
