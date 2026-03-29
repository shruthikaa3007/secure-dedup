from pathlib import Path

from src.behavioral.final_year_eval import (
    build_alignment_table,
    evaluate_ablation_tables,
    extract_azure_trace_vectors,
    generate_attack_vectors,
    generate_calibrated_benign_vectors,
)


def test_extract_azure_trace_vectors_and_generate_report_inputs(tmp_path):
    trace_path = tmp_path / "azure_trace.csv"
    trace_path.write_text(
        "\n".join(
            [
                "app,func,end_timestamp,duration",
                "app-a,func-1,1.0,0.10",
                "app-a,func-1,11.0,0.10",
                "app-a,func-1,21.0,0.10",
                "app-a,func-1,31.0,0.10",
                "app-a,func-1,41.0,0.10",
                "app-a,func-1,51.0,0.10",
                "app-b,func-1,2.0,0.20",
                "app-b,func-1,12.0,0.20",
                "app-b,func-1,22.0,0.20",
                "app-b,func-1,32.0,0.20",
                "app-b,func-1,42.0,0.20",
                "app-b,func-1,52.0,0.20",
            ]
        ),
        encoding="utf-8",
    )

    trace_vectors = extract_azure_trace_vectors(str(trace_path), window_size_s=120.0, min_events=5, max_apps=10)
    assert len(trace_vectors) == 2
    assert all(vector["label"] == "benign" for vector in trace_vectors)

    synthetic_benign = generate_calibrated_benign_vectors(trace_vectors, n=2, seed=1)
    synthetic_attack = generate_attack_vectors(trace_vectors, n=2, seed=2)
    alignment_table = build_alignment_table(trace_vectors, synthetic_benign)
    assert not alignment_table.empty
    assert set(alignment_table["feature"]) == {
        "tau_avg",
        "tau_std",
        "tau_min",
        "tau_max",
        "interarrival_cv",
        "n_chunks",
    }

    # Duplicate vectors are acceptable here; the goal is to verify shape and metrics production.
    ablation_table = evaluate_ablation_tables(trace_vectors * 6, synthetic_attack * 6)
    assert set(ablation_table["method"]) == {
        "z_score_only",
        "supervised_only",
        "full_behavioral_gate",
    }
