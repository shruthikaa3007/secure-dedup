import argparse
import json
import os
import time
from collections import Counter

import pandas as pd

from chunking import chunk_file
from hashing import hash_chunk


def _mutate_bytes(data: bytes, offset: int, span: int, value: int) -> bytes:
    buf = bytearray(data)
    end = min(len(buf), offset + span)
    for i in range(offset, end):
        buf[i] = value
    return bytes(buf)


def _case_metrics(name: str, base: bytes, candidate: bytes) -> dict:
    t0 = time.perf_counter()
    base_recipe = [hash_chunk(c) for c in chunk_file(base) if c]
    candidate_recipe = [hash_chunk(c) for c in chunk_file(candidate) if c]
    elapsed_ms = (time.perf_counter() - t0) * 1000

    c_base, c_cand = Counter(base_recipe), Counter(candidate_recipe)
    shared = sum(min(c_base[h], c_cand[h]) for h in c_base.keys() | c_cand.keys())
    new_chunks = max(0, len(candidate_recipe) - shared)
    dedup_ratio = (shared / len(candidate_recipe)) if candidate_recipe else 1.0

    return {
        "case": name,
        "base_chunks": len(base_recipe),
        "candidate_chunks": len(candidate_recipe),
        "shared_chunks": shared,
        "new_chunks": new_chunks,
        "dedup_ratio": dedup_ratio,
        "processing_ms": elapsed_ms,
    }


def _save_svg_bar(path: str, labels, values, title: str, max_value: float) -> None:
    width, height = 900, 420
    margin = 60
    chart_w = width - 2 * margin
    chart_h = height - 2 * margin
    n = max(1, len(labels))
    bar_w = chart_w / n * 0.7
    gap = chart_w / n * 0.3

    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">']
    parts.append(f'<text x="{width/2}" y="30" text-anchor="middle" font-size="18">{title}</text>')
    parts.append(f'<line x1="{margin}" y1="{height-margin}" x2="{width-margin}" y2="{height-margin}" stroke="black"/>')
    parts.append(f'<line x1="{margin}" y1="{margin}" x2="{margin}" y2="{height-margin}" stroke="black"/>')

    denom = max(max_value, 1e-9)
    for i, (lbl, val) in enumerate(zip(labels, values)):
        x = margin + i * (bar_w + gap) + gap / 2
        h = (val / denom) * (chart_h - 10)
        y = height - margin - h
        parts.append(f'<rect x="{x:.2f}" y="{y:.2f}" width="{bar_w:.2f}" height="{h:.2f}" fill="#4e79a7"/>')
        parts.append(f'<text x="{x + bar_w/2:.2f}" y="{height-margin+18}" text-anchor="middle" font-size="10">{lbl}</text>')
    parts.append('</svg>')
    with open(path, 'w') as f:
        f.write('\n'.join(parts))


def _save_graphs(df: pd.DataFrame, out_dir: str) -> list:
    artifacts = []
    try:
        import matplotlib.pyplot as plt
    except Exception:
        labels = list(df["case"])
        p1 = os.path.join(out_dir, "dedup_ratio_by_case.svg")
        _save_svg_bar(p1, labels, list(df["dedup_ratio"]), "Dedup Ratio by Test Case", 1.0)
        artifacts.append(p1)

        p2 = os.path.join(out_dir, "shared_vs_new_chunks.svg")
        _save_svg_bar(p2, labels, list(df["new_chunks"]), "New Chunks by Test Case", float(max(df["new_chunks"].max(), 1)))
        artifacts.append(p2)

        p3 = os.path.join(out_dir, "processing_time_ms.svg")
        _save_svg_bar(p3, labels, list(df["processing_ms"]), "Processing Time (ms)", float(max(df["processing_ms"].max(), 1)))
        artifacts.append(p3)
        return artifacts

    plt.figure(figsize=(8, 4))
    plt.bar(df["case"], df["dedup_ratio"])
    plt.ylim(0, 1)
    plt.title("Dedup Ratio by Test Case")
    plt.ylabel("dedup_ratio")
    plt.xticks(rotation=25, ha="right")
    plt.tight_layout()
    p1 = os.path.join(out_dir, "dedup_ratio_by_case.png")
    plt.savefig(p1)
    plt.close()
    artifacts.append(p1)

    plt.figure(figsize=(8, 4))
    plt.bar(df["case"], df["shared_chunks"], label="shared_chunks")
    plt.bar(df["case"], df["new_chunks"], bottom=df["shared_chunks"], label="new_chunks")
    plt.title("Shared vs New Chunks")
    plt.ylabel("chunk_count")
    plt.xticks(rotation=25, ha="right")
    plt.legend()
    plt.tight_layout()
    p2 = os.path.join(out_dir, "shared_vs_new_chunks.png")
    plt.savefig(p2)
    plt.close()
    artifacts.append(p2)

    plt.figure(figsize=(8, 4))
    plt.plot(df["case"], df["processing_ms"], marker="o")
    plt.title("Processing Time by Test Case")
    plt.ylabel("processing_ms")
    plt.xticks(rotation=25, ha="right")
    plt.tight_layout()
    p3 = os.path.join(out_dir, "processing_time_ms.png")
    plt.savefig(p3)
    plt.close()
    artifacts.append(p3)

    return artifacts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", default="metrics_artifacts")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    base = (b"ABCDEFGH" * 220000)
    cases = [
        ("identical", base),
        ("tiny_change", _mutate_bytes(base, 10000, 32, 90)),
        ("small_change", _mutate_bytes(base, 200000, 256, 88)),
        ("medium_change", _mutate_bytes(base, 450000, 4096, 77)),
        ("large_change", _mutate_bytes(base, 700000, 65536, 66)),
    ]

    rows = [_case_metrics(name, base, candidate) for name, candidate in cases]
    df = pd.DataFrame(rows)

    csv_path = os.path.join(args.output_dir, "test_metrics.csv")
    df.to_csv(csv_path, index=False)

    summary = {
        "cases": len(rows),
        "avg_dedup_ratio": float(df["dedup_ratio"].mean()),
        "avg_processing_ms": float(df["processing_ms"].mean()),
    }
    json_path = os.path.join(args.output_dir, "summary.json")
    with open(json_path, "w") as f:
        json.dump(summary, f, indent=2)

    graphs = _save_graphs(df, args.output_dir)
    print(json.dumps({"csv": csv_path, "json": json_path, "graphs": graphs}, indent=2))


if __name__ == "__main__":
    main()
