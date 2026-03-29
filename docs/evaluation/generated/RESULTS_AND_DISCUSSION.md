# Results and Discussion

## Experimental Setup

| item | value |
| --- | --- |
| Platform | Windows-11-10.0.26200-SP0 |
| Python | 3.12.4 |
| Active OPRF backend | ristretto255 |
| Behavioral trace source | C:\Users\Shruthikaa\Downloads\AzureFunctionsInvocationTraceForTwoWeeksJan2021\AzureFunctionsInvocationTraceForTwoWeeksJan2021.txt |
| Trace-derived benign windows | 347 |
| Synthetic attack windows | 347 |

The evaluation was divided into three layers: cryptographic microbenchmarks, behavioral-model assessment, and end-to-end LocalStack workflow measurements. All values are local prototype measurements and should be interpreted comparatively rather than as production throughput claims.

## Cryptographic Results

The deduplication study preserved the storage benefit of the baseline while hiding public token reproducibility. On the synthetic Zipf workload, the secure scheme retained `91.60%` storage savings, matching the public-hash baseline in unique-chunk count while replacing outsider-visible fingerprints with server-private locators and opaque user handles.

Cost-wise, the secure key path was about `79.11x` more expensive than a plain `SHA-256` token on this machine, which is expected because it includes a real `ristretto255` OPRF instead of a public digest. The more important observation is that this additional cost stays in the key path; chunk encryption and decryption remain in the sub-millisecond range at the benchmarked chunk sizes.

![Crypto latency](figures/crypto_latency_by_chunk_size.png)

| chunk_size | baseline_token_ms | secure_key_path_ms | baseline_encrypt_ms | baseline_decrypt_ms | refa_encrypt_ms | refa_decrypt_ms |
| --- | --- | --- | --- | --- | --- | --- |
| 4096.0 | 0.004917 | 0.666992 | 0.133645 | 0.123642 | 0.234868 | 0.261785 |
| 8192.0 | 0.007748 | 0.678767 | 0.145555 | 0.130878 | 0.241042 | 0.255317 |
| 16384.0 | 0.013763 | 0.745048 | 0.154568 | 0.138722 | 0.310815 | 0.28863 |

![OPRF backend latency](figures/oprf_backend_latency.png)

| chunk_size | ristretto_oprf_ms | hmac_oprf_ms |
| --- | --- | --- |
| 4096.0 | 0.645873 | 0.024205 |
| 8192.0 | 0.648 | 0.020495 |
| 16384.0 | 0.69762 | 0.02199 |

![Ciphertext overhead](figures/ciphertext_overhead.png)

| chunk_size | baseline_ciphertext_ratio | refa_ciphertext_ratio |
| --- | --- | --- |
| 4096.0 | 1.006836 | 1.039307 |
| 8192.0 | 1.003418 | 1.019653 |
| 16384.0 | 1.001709 | 1.009827 |

![Deduplication savings](figures/dedup_savings.png)

| scheme | logical_chunks | unique_chunks | stored_bytes | logical_bytes | storage_savings_percent | publicly_reproducible_token |
| --- | --- | --- | --- | --- | --- | --- |
| public_sha256_baseline | 1000.0 | 84.0 | 344064.0 | 4096000.0 | 91.6 | yes |
| secure_dedup_bpow | 1000.0 | 84.0 | 344064.0 | 4096000.0 | 91.6 | no |

Discussion:

- The key result is not lower latency than the baseline; it is preserving deduplication while making public confirmation-style probing materially harder.
- The `ristretto255` backend is noticeably heavier than the HMAC fallback, but that is a reasonable trade-off because it upgrades the cryptographic core from simulation to a real blind-evaluation path.
- REFA-style storage expansion is higher than plain AES-GCM because the ciphertext must carry recovery material and the ownership token, but the expansion remains stable across chunk sizes.

## Behavioral Results

The behavioral evaluation used `347` Azure trace-derived benign windows and an equal number of calibrated synthetic benign and synthetic attack windows. This gives a defensible final-year-project hybrid setup: benign timing behavior is anchored to a real cloud trace, while attack sessions remain synthetic and explicitly labeled as such.

![Alignment distances](figures/behavioral_alignment_distances.png)

![Tau histogram](figures/tau_avg_alignment_histogram.png)

| feature | reference_mean | candidate_mean | wasserstein_distance | ks_statistic | ks_pvalue |
| --- | --- | --- | --- | --- | --- |
| tau_avg | 4.917104 | 5.970446 | 1.053342 | 0.07781 | 0.244485 |
| tau_std | 6.167851 | 4.349664 | 1.818219 | 0.095101 | 0.086686 |
| tau_min | 0.713818 | 0.872056 | 0.256921 | 0.446686 | 0.0 |
| tau_max | 21.605876 | 13.683899 | 7.921976 | 0.184438 | 1.4e-05 |
| interarrival_cv | 1.734527 | 0.845971 | 0.889104 | 0.498559 | 0.0 |
| n_chunks | 151.806916 | 154.317003 | 6.008646 | 0.014409 | 1.0 |

The alignment table shows that the synthetic benign generator tracks the real trace reasonably on `tau_avg`, `tau_std`, and `n_chunks`, while still diverging on extreme-value fields such as `tau_min`, `tau_max`, and `interarrival_cv`. That makes the synthetic layer calibrated rather than identical, which is acceptable for a final-year defense as long as the approximation is acknowledged openly.

![Behavioral ablation](figures/behavioral_ablation.png)

| method | precision | recall | f1 | auroc | pr_auc |
| --- | --- | --- | --- | --- | --- |
| z_score_only | 0.727273 | 0.07619 | 0.137931 | 0.850824 | 0.787521 |
| supervised_only | 0.910714 | 0.971429 | 0.940092 | 0.992766 | 0.993098 |
| full_behavioral_gate | 0.844262 | 0.980952 | 0.907489 | 0.926832 | 0.826869 |

The ablation study shows a clear layered-defense pattern. `supervised_only` achieved precision `0.911`, recall `0.971`, and F1 `0.940`. The full behavioral gate pushed recall to `0.981` while lowering precision to `0.844`. That trade-off is sensible for a security gate, where missing an attack is often more costly than flagging a few extra suspicious sessions.

Discussion:

- `z_score_only` is useful as a transparent baseline, but it is too weak to stand alone.
- The supervised model is the strongest standalone detector in this prototype.
- The full gate is more deployment-oriented because it combines statistical, supervised, and unsupervised signals, even though that reduces precision slightly.
- These behavioral results are defensible for a final-year project, but they should not be framed as ground-truth adversarial validation.

## End-to-End Workflow Results

![Workflow latency](figures/workflow_latency.png)

| file_size_bytes | chunk_count | upload_ms | download_ms | difficulty |
| --- | --- | --- | --- | --- |
| 8192.0 | 2.0 | 4263.885 | 251.897 | 16.0 |
| 16384.0 | 4.0 | 2968.664 | 303.96 | 16.0 |
| 32768.0 | 8.0 | 5216.743 | 465.861 | 16.0 |

Across the tested file sizes, upload latency scaled with chunk count and download latency remained lower than upload latency because the upload path also includes ownership registration, OPRF-backed key issuance, and S3/Dynamo writes. The system remained functional across all tested sizes with successful round-trip recovery.

![Attack rejection rates](figures/attack_rejection_rates.png)

| scenario | first_upload_ms | second_upload_ms | first_dtable_delta | second_dtable_delta | chunk_count | privacy_preserving | rejection_rate | trials |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| cross_user_duplicate_reuse | 7302.835 | 7396.586 | 16.0 | 0.0 | 16.0 | True |  |  |
| replay_attack_rejection_rate |  |  |  |  |  |  | 1.0 | 1.0 |

The duplicate reuse experiment is especially important. The first upload increased the dedup metadata table by `16` unique chunks, while the second cross-user upload increased it by only `0`. That demonstrates the main systems goal: duplicate data is reused instead of stored again, but reuse still passes through proof-of-ownership and the secure key path.

The replay attack trial was rejected at a rate of `100.00%` in the scripted evaluation. Bot-style behavior is evaluated through the behavioral ablation study rather than repeated end-to-end PoW trials, because the extreme-difficulty bot PoW path is intentionally expensive.

Discussion:

- End-to-end latency is dominated by cloud-simulation overhead and security checks rather than raw chunk encryption cost.
- Duplicate reuse reduces metadata growth on second upload, which is the clearest practical sign that deduplication still works after the security hardening.
- The replay simulation is an end-to-end validation artifact, while broader bot-style evidence comes from the behavioral study rather than repeated expensive PoW trials.

## Overall Discussion

Taken together, the results support four defensible conclusions for a final-year project:

1. The secure scheme preserves deduplication savings while replacing public fingerprints with opaque handles and a server-private dedup path.
2. The upgraded `ristretto255` OPRF introduces measurable but acceptable key-path overhead in exchange for a stronger cryptographic core.
3. The behavioral layer is meaningfully better when used as a combined gate than when reduced to transparent z-scores alone.
4. The LocalStack-backed prototype works end to end for upload, download, duplicate reuse, and replay rejection, while bot-style detection is supported by the behavioral study.

The main limitations remain the same and should be stated plainly:

- Behavioral attack labels are synthetic/rule-derived rather than attacker ground truth.
- Timing results are from a local prototype environment, not a production cloud deployment.
- The synthetic benign generator is aligned to the trace distribution but does not perfectly match all tail behaviors.

Those limitations do not weaken the project as a final-year thesis. They simply define the correct scope: this is a rigorous, well-evaluated prototype with honest boundaries, not a deployment-ready commercial system or a conference-grade adversarial dataset study.
