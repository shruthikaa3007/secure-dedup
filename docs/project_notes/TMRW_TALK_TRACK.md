# Tomorrow Talk Track (3-5 minutes)

## 1) Problem Statement (30-45 sec)
Cross-user deduplication saves storage, but it is vulnerable to ownership fraud and probing attacks.
If we keep dedup insecure, providers disable it; if we disable dedup, storage and bandwidth costs rise.
Our goal is to keep dedup enabled while adding stronger ownership verification and attack-aware controls.

## 2) Baseline We Replicated (45-60 sec)
We implemented a secure dedup pipeline with proof-of-ownership verification:
1. Chunking + fingerprint index.
2. Duplicate detection.
3. PoW challenge/verify before allowing duplicate reference.
This is the static baseline.

## 3) Our Improvement (45-60 sec)
We added a risk-adaptive control loop:
1. Behavioral detection produces risk score.
2. Client reputation tracks prior behavior over time.
3. Adaptive PoW increases challenge hardness for suspicious clients and keeps normal clients in lower difficulty tiers.

## 4) Visible Results (60-90 sec)
Generated today from `request_logs.csv`:
1. Windowed evaluation dataset: 103 samples, 72 clients.
2. Holdout detection performance (`demo_artifacts/training_metrics.json`):
   - CV macro F1: 0.9484
   - Test accuracy: 0.9615
   - Test weighted F1: 0.9573
   - Advanced benchmarked candidates: HistGradientBoosting, RandomForest, LogisticRegression, ExtraTrees, RBF-SVM, MLP
   - Best selected model by CV: RandomForest
3. Static vs adaptive PoW (`pow_comparison_summary.json`):
   - Baseline attacker success (estimated): 1.0000
   - Adaptive attacker success (estimated): 0.4735
   - Relative reduction: 52.65%
   - Adaptive sends most suspicious cases to elevated/hardened tiers.

## 5) Honest Limitations (20-30 sec)
1. The comparison uses controlled workload assumptions for attack effort estimation.
2. Benign overhead is still high and needs threshold/weight tuning.
3. Auditing and full ownership lifecycle are in-progress.

## 6) Next Milestone (20-30 sec)
1. Add integrity auditing API and scheduler.
2. Add ownership grant/revoke/transfer events.
3. Tune adaptive policy to reduce benign overhead while preserving attack resistance.

## 7) One-Line Claim
We already have a working secure dedup baseline plus a measurable adaptive defense extension, with presentation-visible artifacts and reproducible outputs.
