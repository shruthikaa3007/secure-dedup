from __future__ import annotations

from collections.abc import Iterable, Sequence
from statistics import mean, pstdev

from scipy.stats import ks_2samp, wasserstein_distance


NUMERIC_BEHAVIORAL_FIELDS = (
    "tau_avg",
    "tau_std",
    "tau_min",
    "tau_max",
    "interarrival_cv",
    "entropy_mean",
    "entropy_std",
    "entropy_min",
    "entropy_max",
    "n_chunks",
)


def _to_float_series(values: Iterable[object]) -> list[float]:
    series: list[float] = []
    for value in values:
        try:
            series.append(float(value))
        except (TypeError, ValueError):
            continue
    return series


def compare_numeric_distribution(reference: Sequence[object], candidate: Sequence[object]) -> dict:
    reference_series = _to_float_series(reference)
    candidate_series = _to_float_series(candidate)
    if not reference_series or not candidate_series:
        raise ValueError("Both reference and candidate distributions must contain at least one numeric sample")

    ks_result = ks_2samp(reference_series, candidate_series)
    return {
        "n_reference": len(reference_series),
        "n_candidate": len(candidate_series),
        "reference_mean": mean(reference_series),
        "candidate_mean": mean(candidate_series),
        "reference_std": pstdev(reference_series) if len(reference_series) > 1 else 0.0,
        "candidate_std": pstdev(candidate_series) if len(candidate_series) > 1 else 0.0,
        "wasserstein_distance": float(wasserstein_distance(reference_series, candidate_series)),
        "ks_statistic": float(ks_result.statistic),
        "ks_pvalue": float(ks_result.pvalue),
    }


def compare_behavioral_vectors(
    reference_vectors: Sequence[dict],
    candidate_vectors: Sequence[dict],
    fields: Sequence[str] = NUMERIC_BEHAVIORAL_FIELDS,
) -> dict[str, dict]:
    if not reference_vectors or not candidate_vectors:
        raise ValueError("reference_vectors and candidate_vectors must both be non-empty")

    report: dict[str, dict] = {}
    for field in fields:
        reference_values = [vector.get(field) for vector in reference_vectors]
        candidate_values = [vector.get(field) for vector in candidate_vectors]
        report[field] = compare_numeric_distribution(reference_values, candidate_values)
    return report
