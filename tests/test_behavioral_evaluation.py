import pytest

from src.behavioral.evaluation import compare_behavioral_vectors, compare_numeric_distribution


def test_compare_numeric_distribution_returns_distance_metrics():
    report = compare_numeric_distribution([1, 2, 3, 4], [1.5, 2.5, 3.5, 4.5])
    assert report["n_reference"] == 4
    assert report["n_candidate"] == 4
    assert report["wasserstein_distance"] > 0.0
    assert 0.0 <= report["ks_statistic"] <= 1.0


def test_compare_behavioral_vectors_compares_each_numeric_field():
    reference_vectors = [
        {"tau_avg": 100.0, "entropy_mean": 7.1, "n_chunks": 4},
        {"tau_avg": 110.0, "entropy_mean": 7.0, "n_chunks": 5},
    ]
    candidate_vectors = [
        {"tau_avg": 95.0, "entropy_mean": 6.9, "n_chunks": 4},
        {"tau_avg": 98.0, "entropy_mean": 7.2, "n_chunks": 6},
    ]

    report = compare_behavioral_vectors(reference_vectors, candidate_vectors, fields=("tau_avg", "entropy_mean"))
    assert set(report) == {"tau_avg", "entropy_mean"}
    assert report["tau_avg"]["n_reference"] == 2
    assert report["entropy_mean"]["n_candidate"] == 2


def test_compare_behavioral_vectors_requires_samples():
    with pytest.raises(ValueError):
        compare_behavioral_vectors([], [{"tau_avg": 1.0}])
