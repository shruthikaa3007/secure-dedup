from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.behavioral.final_year_eval import generate_final_year_report


def _markdown_table(title: str, rows: list[dict]) -> list[str]:
    if not rows:
        return [f"## {title}", "", "_No rows generated._", ""]
    columns = list(rows[0].keys())
    output = [f"## {title}", ""]
    output.append("| " + " | ".join(columns) + " |")
    output.append("| " + " | ".join(["---"] * len(columns)) + " |")
    for row in rows:
        output.append("| " + " | ".join(str(row[column]) for column in columns) + " |")
    output.append("")
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a defensible final-year-project behavioral evaluation report.")
    parser.add_argument(
        "--trace-path",
        required=True,
        help="Path to AzureFunctionsInvocationTraceForTwoWeeksJan2021.txt or an equivalent Azure trace file.",
    )
    parser.add_argument(
        "--outdir",
        default="docs/evaluation/generated",
        help="Directory for generated CSV and Markdown report artifacts.",
    )
    args = parser.parse_args()

    alignment_table, ablation_table, summary = generate_final_year_report(args.trace_path)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    alignment_csv = outdir / "final_year_alignment_table.csv"
    metrics_csv = outdir / "final_year_ablation_table.csv"
    report_md = outdir / "FINAL_YEAR_BEHAVIORAL_REPORT.md"

    alignment_table.to_csv(alignment_csv, index=False)
    ablation_table.to_csv(metrics_csv, index=False)

    lines = [
        "# Final-Year Behavioral Evaluation Report",
        "",
        "This report is intentionally scoped for a defensible final-year project rather than a conference-level claim.",
        "",
        "## Summary",
        "",
        f"- Trace source: `{summary['trace_source']}`",
        f"- Trace-derived benign windows: `{summary['trace_windows']}`",
        f"- Synthetic benign windows: `{summary['synthetic_benign_windows']}`",
        f"- Synthetic attack windows: `{summary['synthetic_attack_windows']}`",
        "- Evaluation design: trace-derived benign baseline + calibrated synthetic benign windows + synthetic attack windows",
        "- Label caveat: attack labels remain synthetic / rule-driven, not ground-truth attacker labels",
        "",
        "## Framing",
        "",
        "Use this as a hybrid evaluation story:",
        "",
        "`The behavioral layer is calibrated against a real Azure invocation trace for benign timing behavior, while attack sessions are synthetically generated using the same feature schema. This is appropriate for a final-year prototype, but not presented as production-grade attacker ground truth.`",
        "",
    ]

    lines.extend(_markdown_table("KS/Wasserstein Alignment", alignment_table.round(6).to_dict(orient="records")))
    lines.extend(_markdown_table("Ablation Metrics", ablation_table.round(6).to_dict(orient="records")))

    lines.extend(
        [
            "## Interpretation",
            "",
            "- The alignment table should be read as `calibrated, not identical`. Closer agreement on `tau_avg`, `tau_std`, and `n_chunks` supports the claim that the synthetic benign generator follows the same general timing scale as the Azure trace.",
            "- The larger gaps on `tau_min`, `tau_max`, and `interarrival_cv` are acceptable for a final-year prototype as long as they are acknowledged as approximation error rather than hidden.",
            "- The ablation table should be read as a layered-defense story: `z_score_only` is a weak transparent baseline, `supervised_only` gives the best standalone classifier performance, and `full_behavioral_gate` is the more conservative deployment-style gate because it trades some precision for stronger detection coverage.",
            "",
            "## Recommendation",
            "",
            "For the final report or viva, claim:",
            "",
            "- The cryptographic path is evaluated separately on the deduplication workload.",
            "- The behavioral path is evaluated with a hybrid trace-aligned methodology.",
            "- The current results are defensible for a final-year project because the benign baseline comes from a real cloud trace and the limitations are stated explicitly.",
            "",
        ]
    )

    report_md.write_text("\n".join(lines), encoding="utf-8")

    print(f"Wrote {alignment_csv}")
    print(f"Wrote {metrics_csv}")
    print(f"Wrote {report_md}")


if __name__ == "__main__":
    main()
