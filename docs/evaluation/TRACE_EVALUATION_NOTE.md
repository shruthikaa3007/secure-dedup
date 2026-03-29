# Trace Evaluation Note

## Current Status

The behavioral layer has three pieces:

- supervised human-vs-bot scoring,
- unsupervised outlier detection,
- adaptive BPoW difficulty and anomaly gating.

The current repository evaluates those pieces on synthetic timing patterns and rule-derived attack labels. That is acceptable for a prototype, but not enough to claim production-grade attacker realism.

## What The Paper Can Honestly Claim

The strongest accurate claim today is:

`The behavioral pipeline is trace-compatible and prototype-evaluated, but its labels are still trace-derived / rule-derived rather than ground-truth attacker labels.`

Do not claim:

- real adversary ground truth,
- deployment-ready bot detection,
- statistically final attack prevalence estimates.

## What The Repo Now Supports

The vector schema is already shared across the live workflow:

- `src/behavioral/extractor.py`
- `src/behavioral/models.py`
- `src/behavioral/pow.py`
- `src/behavioral/anomaly.py`

The repo now also includes `src/behavioral/evaluation.py`, which can compare reference trace windows against synthetic windows using:

- Kolmogorov-Smirnov distance,
- Wasserstein distance,
- mean / standard deviation gaps.

This gives a concrete way to argue whether the synthetic session generator is close to trace-derived timing behavior once FIU/MSRC windows are available again.

## Minimum Reviewer-Convincing Evaluation Path

If FIU/MSRC or other trace-derived windows are available, the paper should report:

1. Distribution alignment between trace-derived windows and synthetic windows for:
   - `tau_avg`
   - `tau_std`
   - `interarrival_cv`
   - `entropy_mean`
   - `entropy_std`
   - `n_chunks`
2. Model quality on trace-derived windows:
   - precision
   - recall
   - F1
   - AUROC / PR-AUC
3. BPoW and anomaly outcomes on replay, bot-speed, and hotspot-style sessions.
4. An explicit note on which labels are hand-verified vs rule-derived.

## If Real Attack Traces Are Still Unavailable

Then the paper should say:

`We evaluate the behavioral layer on synthetic sessions calibrated to the same feature schema as trace-derived workloads. We report statistical distance to trace-derived windows where available, but the current labels remain rule-derived rather than ground-truth attacker labels.`

That is much stronger than only saying `synthetic data was used`, because it turns the claim into a measurable alignment question.

## Recommended Figures

- Trace vs synthetic histogram for `tau_avg`
- Trace vs synthetic histogram for `entropy_mean`
- KS / Wasserstein comparison table across numeric features
- ROC curve for supervised scoring
- Precision-recall curve for replay / bot detection
- Ablation chart:
  - z-score only
  - supervised only
  - unsupervised only
  - full behavioral gate

## Repo Note

The cleaned repo does not currently check in FIU/MSRC raw traces. That keeps the project lightweight, but it also means the default notebook flow remains synthetic-first until those trace windows are reintroduced.
