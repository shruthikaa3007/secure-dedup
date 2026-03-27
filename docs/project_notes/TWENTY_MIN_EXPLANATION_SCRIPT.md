# 20-Minute Project Explanation Script

This script is designed for a final-year-project style explanation where you
want to cover:

- the problem,
- the literature gap,
- the design,
- the benchmark script,
- the live demo,
- the behavioural detection layer,
- the dataset story,
- and the limitations.

Use it as a spoken script, not as a document to read word-for-word. The wording
below is intentionally natural enough to speak directly if needed.

## 0:00 to 2:00 - Opening

`Good morning. My project is a secure deduplication prototype inspired mainly by Wu et al.'s work on frequency-attack-resistant deduplication encryption.`

`The main problem is this: deduplication saves storage by identifying repeated content, but traditional deduplication often uses deterministic content-derived identifiers, which leak information. If an attacker can reproduce the dedup token from a guessed file, they can probe the system, confirm file presence, or learn frequency information.`

`So the question I address is not whether deduplication is useful. It clearly is. The question is how to preserve deduplication while reducing the leakage caused by public deterministic fingerprints, and how to make suspicious behaviour visible at runtime.`

`My project proposes a lighter server-side improvement in that direction. Instead of relying on a public content hash alone, I use a secret-assisted chunk identity. Then I bind chunk encryption to that identity, require proof-of-ownership before duplicate reuse, and add lightweight behavioural throttling.`

## 2:00 to 4:00 - Literature Positioning

`The main literature anchor is Wu et al., who show that deterministic deduplication encryption leaks frequency information. Their REFA direction motivates stronger leakage resistance.`

`The broader literature also supports the same trend. Older content-derived approaches are vulnerable because the token can often be reproduced if the attacker knows or guesses the file. More recent server-aided or secret-assisted approaches move away from pure public content-only identifiers.`

`My project takes that direction but keeps the design relatively simple for a prototype. I do not use a separate external key server. Instead, I keep a server-side secret and use that to generate secret-assisted chunk fingerprints.`

`So the thesis claim is not that I replaced the whole cloud security model. The claim is that I improved the deduplication encryption path in a concrete way that is visible, testable, and demonstrable.`

## 4:00 to 7:00 - System Design

`At a high level, the upload path works like this. A file is split into chunks. For each chunk, the system computes a dedup fingerprint. In the baseline scheme, that fingerprint is a public SHA-256 hash. In the proposed scheme, it is an HMAC-SHA256 value that depends on a server-side secret.`

`That fingerprint then plays two roles. First, it acts as the dedup identity, meaning repeated chunks still map to the same token. Second, it becomes the context for encryption, because the chunk encryption key is derived from that fingerprint using HKDF-SHA256, and the chunk is then encrypted with segmented AES-GCM.`

`This means identical chunks still deduplicate, but an external attacker can no longer reproduce the dedup token without the secret.`

`Then, before a duplicate chunk can be reused by another client, the system requires proof-of-ownership. This is important because duplicate existence alone should not automatically grant reuse rights.`

`On top of that, the project also tracks behavioural patterns. So if a client starts behaving like a hash prober, a deduplication denial-of-service attacker, or someone repeatedly failing proof-of-ownership, the system can rate-limit or block them.`

## 7:00 to 11:00 - Explaining compare_dedup_encryption_schemes.py

`Now I will explain the benchmark script, because this is the cleanest way to understand the security-performance trade-off.`

`The script compares two schemes. The first is the baseline public-hash design. The second is my proposed secret-assisted design.`

`The script first defines a synthetic dataset of chunks. It does not use a real user dataset here because the point of this benchmark is controlled comparison, not behaviour modelling.`

`The function _build_dataset generates a mixture of unique and duplicate chunks. In the current configuration it uses 300 logical chunks, of which 90 are unique. That means the dataset deliberately contains duplication, which is necessary to measure deduplication savings.`

`Then, for each scheme, the function _evaluate_scheme_once runs the full token-generation, encryption, and decryption path. For every chunk, it measures how long token generation takes, how long encryption takes, how long decryption takes, and what the ciphertext size is.`

`For the baseline, the fingerprint mode is SHA-256. For the proposed scheme, the fingerprint mode is secret_hmac. Both schemes use the same encryption envelope, which is segmented AES-GCM with HKDF-SHA256-based key derivation.`

`This is important because it means the benchmark is fair. I am not comparing one encryption algorithm to a completely different one. I am holding the encryption structure mostly constant and changing the dedup token design.`

`After each run, the script computes how many unique chunk tokens were produced. That gives the deduplication result. If both schemes produce the same number of unique tokens for the same duplicate dataset, then deduplication effectiveness has been preserved.`

`The script repeats the measurements across multiple rounds, averages the results, and writes two artifacts: a JSON file and a Markdown report. It can also print a terminal table for the live demo.`

`The three most important rows in that table are these: token reproducibility, frequency-attack resistance, and whether an external key server is required. Those are the security story, not just the performance story.`

`In my current result, dedup savings remain the same at 70 percent in both schemes. Token generation is slightly more expensive in the proposed design, because HMAC uses a secret and therefore does a bit more work than plain SHA-256. But encryption and decryption times remain very close, and storage overhead is unchanged.`

`So the conclusion is that the main cost is on token generation, while the main benefit is that the dedup token is no longer publicly reproducible.`

## 11:00 to 13:00 - Explaining the Security Meaning

`Why does this matter? If the dedup token is a plain SHA-256 hash, an attacker who guesses a chunk can compute the same token offline and check whether it exists. That enables confirmation attacks and frequency leakage.`

`If the token is HMAC-based with a server-side secret, the attacker cannot compute the correct token without that secret. So the dedup identity becomes opaque to outsiders, while still remaining stable inside the system.`

`That is the key design improvement. We preserve deduplication for honest users, but reduce the attack surface caused by deterministic public fingerprints.`

`Then HKDF key binding strengthens that further by making the encryption key depend on the token-derived context. So the encryption path is aligned with the dedup identity rather than being a separate unrelated layer.`

## 13:00 to 15:00 - Demo Walkthrough

`In the live demo, I first show the backend status. The current demo uses LocalStack for S3-style chunk storage and Redis for state.`

`Then I show the tests. The frequency-attack resistance tests demonstrate that a SHA-256 token is reproducible, while the HMAC token is not reproducible without the secret. They also show that ten users can still deduplicate correctly, which is important because security improvements should not break the storage benefit.`

`After that I show the benchmark comparison table. The key message is that deduplication savings stay the same, but the security properties improve.`

`Then I move to the live API flow. I upload one file first. That stores new encrypted chunks. Then I upload a second aligned similar file. The first retry shows that some chunks are shared, and the duplicate reuse path triggers proof-of-ownership.`

`After solving the proof challenge, I retry the upload and show that the shared chunks are reused safely. I also use the compare-files endpoint to show the shared chunk positions explicitly, which makes the deduplication effect visible.`

## 15:00 to 17:00 - Behavioural Detection Layer

`The cryptographic improvement is one half of the story. The other half is runtime behaviour detection.`

`I classify suspicious behaviour into labels such as hash_probing, dedup_dos, and ownership_fraud.`

`Hash probing means a client performs many content checks or duplicate-oriented queries with almost no legitimate upload activity. Dedup DoS means excessive duplicate-heavy traffic at a high rate intended to overload the dedup path. Ownership fraud refers to repeated failed proof-of-ownership attempts.`

`The reason I added this layer is that cryptography alone does not explain behaviour. A patient attacker may stay below a static rate threshold, so a simple rate limiter can miss them.`

`This is exactly what the REFA gap demonstration shows. The attacker is below a typical static requests-per-minute threshold, so a static policy would allow the traffic. But the upload-to-query ratio is still abnormal, and the model identifies it as hash probing.`

`The sentence I say in the demo is: REFA would allow, but our framework would rate-limit.`

`That is an important contribution because it shows the system is not only protecting the token design, but also observing misuse patterns around the deduplication workflow.`

## 17:00 to 18:30 - Dataset and Evaluation Story

`For the behavioural layer, I do not claim internet-scale production validation. I present it honestly as a prototype-scale evaluation.`

`The small legacy CSV in the repo is not the main dataset story. The stronger evaluation comes from standardized FIU and MSRC request logs. Together they provide over one million raw events. From those, I generated a denser multi-source windowed dataset with 221 labelled windows across 72 clients.`

`The best supervised model in the current artifact is a random forest, with a macro F1 of about 0.965 in cross-validation.`

`So the behavioural layer is supported by a real trace-derived pipeline, but I still state clearly that the labels are trace-derived and not collected from a production deployment.`

## 18:30 to 19:30 - Limitations

`The first limitation is that this is still a prototype, not a production cloud platform.`

`The second limitation is that the benchmark uses a controlled synthetic chunk dataset for the encryption comparison. That is appropriate for isolating the token and encryption costs, but it is not the same thing as full real-world workload benchmarking.`

`The third limitation is that the behavioural labels are derived from traces and rules, not from a live enterprise red-team dataset.`

`The fourth limitation is trust model simplicity. I avoid an external key server to keep the prototype lighter, but that means I rely more on the server-side secret.`

## 19:30 to 20:00 - Closing

`To conclude, the main contribution of this project is a practical secure deduplication prototype that improves on public deterministic dedup tokens by using secret-assisted chunk identities, fingerprint-bound AES-GCM, visible proof-of-ownership, and behavioural throttling.`

`The benchmark shows that deduplication savings are preserved. The tests show the security properties are visible. And the live demo shows the system behaving differently for honest use, duplicate reuse, and suspicious behaviour.`

`So the project is not just a theoretical proposal. It is an implemented and testable prototype that connects literature motivation, system design, security evaluation, and a live demonstrable workflow.`

## Short Examiner Answers

### What is your main novelty?

`The main novelty is not any one primitive by itself. It is the combination of secret-assisted dedup fingerprints, fingerprint-bound encryption, proof-of-ownership before duplicate reuse, and behaviour-aware throttling in one working prototype.`

### Why is HMAC better than plain SHA-256 here?

`Plain SHA-256 is public and reproducible, so an attacker can compute the same token offline. HMAC keeps the token stable inside the system but not reproducible to outsiders without the secret.`

### Why not just use Wu et al. as-is?

`Wu et al. motivate the problem very well. My project takes that motivation and builds a simpler server-side prototype that is easier to implement and demonstrate, while still addressing the public-token leakage problem and adding behavioural defence.`

### What is the key result of the benchmark?

`Dedup savings remain the same, while the proposed scheme removes public token reproducibility. The overhead mainly appears in token generation, not in encryption or storage.`
