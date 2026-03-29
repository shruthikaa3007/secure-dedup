# Final-Year Behavioral Evaluation Report

This report is intentionally scoped for a defensible final-year project rather than a conference-level claim.

## Summary

- Trace source: `C:\Users\Shruthikaa\Downloads\AzureFunctionsInvocationTraceForTwoWeeksJan2021\AzureFunctionsInvocationTraceForTwoWeeksJan2021.txt`
- Trace-derived benign windows: `347`
- Synthetic benign windows: `347`
- Synthetic attack windows: `347`
- Evaluation design: trace-derived benign baseline + calibrated synthetic benign windows + synthetic attack windows
- Label caveat: attack labels remain synthetic / rule-driven, not ground-truth attacker labels

## Framing

Use this as a hybrid evaluation story:

`The behavioral layer is calibrated against a real Azure invocation trace for benign timing behavior, while attack sessions are synthetically generated using the same feature schema. This is appropriate for a final-year prototype, but not presented as production-grade attacker ground truth.`

## KS/Wasserstein Alignment

| feature | reference_mean | candidate_mean | wasserstein_distance | ks_statistic | ks_pvalue |
| --- | --- | --- | --- | --- | --- |
| tau_avg | 4.917104 | 5.970446 | 1.053342 | 0.07781 | 0.244485 |
| tau_std | 6.167851 | 4.349664 | 1.818219 | 0.095101 | 0.086686 |
| tau_min | 0.713818 | 0.872056 | 0.256921 | 0.446686 | 0.0 |
| tau_max | 21.605876 | 13.683899 | 7.921976 | 0.184438 | 1.4e-05 |
| interarrival_cv | 1.734527 | 0.845971 | 0.889104 | 0.498559 | 0.0 |
| n_chunks | 151.806916 | 154.317003 | 6.008646 | 0.014409 | 1.0 |

## Ablation Metrics

| method | precision | recall | f1 | auroc | pr_auc |
| --- | --- | --- | --- | --- | --- |
| z_score_only | 0.727273 | 0.07619 | 0.137931 | 0.850824 | 0.787521 |
| supervised_only | 0.910714 | 0.971429 | 0.940092 | 0.992766 | 0.993098 |
| full_behavioral_gate | 0.844262 | 0.980952 | 0.907489 | 0.926832 | 0.826869 |

## Interpretation

- The alignment table should be read as `calibrated, not identical`. Closer agreement on `tau_avg`, `tau_std`, and `n_chunks` supports the claim that the synthetic benign generator follows the same general timing scale as the Azure trace.
- The larger gaps on `tau_min`, `tau_max`, and `interarrival_cv` are acceptable for a final-year prototype as long as they are acknowledged as approximation error rather than hidden.
- The ablation table should be read as a layered-defense story: `z_score_only` is a weak transparent baseline, `supervised_only` gives the best standalone classifier performance, and `full_behavioral_gate` is the more conservative deployment-style gate because it trades some precision for stronger detection coverage.

## Recommendation

For the final report or viva, claim:

- The cryptographic path is evaluated separately on the deduplication workload.
- The behavioral path is evaluated with a hybrid trace-aligned methodology.
- The current results are defensible for a final-year project because the benign baseline comes from a real cloud trace and the limitations are stated explicitly.
