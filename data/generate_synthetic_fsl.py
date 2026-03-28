from __future__ import annotations

import csv
import json
from pathlib import Path

import numpy as np

N_CHUNKS = 1000
CHUNK_SIZE = 4096


def generate_zipf_chunks(n: int, seed: int = 42) -> list[bytes]:
    rng = np.random.default_rng(seed)
    base_population = [rng.integers(0, 256, size=CHUNK_SIZE, dtype=np.uint8).tobytes() for _ in range(max(50, n // 10))]
    frequencies = rng.zipf(a=1.5, size=n)
    return [base_population[index % len(base_population)] for index in frequencies]


def generate_timing_normal(n: int) -> list[float]:
    rng = np.random.default_rng(7)
    return rng.lognormal(mean=4.6, sigma=0.5, size=n).tolist()


def generate_timing_bot(n: int) -> list[float]:
    rng = np.random.default_rng(9)
    return rng.uniform(0.5, 5.0, size=n).tolist()


def save_dataset(chunks: list[bytes], timings: list[float], outdir: str) -> None:
    target = Path(outdir)
    target.mkdir(parents=True, exist_ok=True)
    metadata = []
    for index, (chunk, timing) in enumerate(zip(chunks, timings)):
        chunk_name = f"chunk_{index:04d}.bin"
        (target / chunk_name).write_bytes(chunk)
        metadata.append({"chunk": chunk_name, "timing_ms": float(timing)})
    (target / "timing_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")


def main() -> None:
    root = Path(__file__).resolve().parent
    normal_chunks = generate_zipf_chunks(N_CHUNKS)
    bot_chunks = generate_zipf_chunks(N_CHUNKS, seed=99)
    normal_timings = generate_timing_normal(N_CHUNKS)
    bot_timings = generate_timing_bot(N_CHUNKS)

    save_dataset(normal_chunks, normal_timings, str(root / "chunks_normal"))
    save_dataset(bot_chunks, bot_timings, str(root / "chunks_bot"))

    frequency_rows = []
    for index, chunk in enumerate(normal_chunks):
        frequency_rows.append({"chunk_id": index, "true_frequency": index % 100 + 1})

    with (root / "frequency_dist.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["chunk_id", "true_frequency"])
        writer.writeheader()
        writer.writerows(frequency_rows)


if __name__ == "__main__":
    main()
