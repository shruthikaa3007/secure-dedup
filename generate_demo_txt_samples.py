from pathlib import Path


ROOT = Path(__file__).resolve().parent
OUT_DIR = ROOT / "demo_samples"


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def build_exact_duplicate_text() -> str:
    lines = []
    for idx in range(1, 17):
        lines.append(
            f"EXACT-LINE-{idx:02d} This exact duplicate demo file is plain text on purpose so the upload path stays easy to inspect during the review and the second upload clearly triggers proof of ownership before duplicate reuse is allowed by the server. "
            f"It mentions chunking fingerprint generation HKDF bound encryption AES GCM storage in LocalStack state in Redis and behavioural monitoring so the file still looks relevant to the project while remaining simple and readable. "
            f"This line number is {idx:02d} and the content is intentionally stable across both exact duplicate files."
        )
    return "\n".join(lines) + "\n"


def build_partial_text(variant: str) -> str:
    left_lines = []
    middle_lines = []
    right_lines = []

    for idx in range(1, 31):
        left_lines.append(
            f"COMMON-LEFT-{idx:02d} This shared left block is identical in partial_similar_a and partial_similar_b and exists to create a clearly visible overlap region for the deduplication comparison demo while still reading like natural project documentation for a reviewer. "
            f"It repeatedly mentions chunking fingerprints encryption proof of ownership LocalStack Redis and anomaly detection so the file remains meaningful plain text rather than random filler. "
            f"This shared left line number is {idx:02d}."
        )

    if variant == "A":
        middle_template = (
            "VARIANT-A-{idx:02d} This middle section belongs only to partial_similar_a and represents a version that emphasises implementation details such as secret assisted chunk identifiers fingerprint bound key derivation segmented encryption and the reasoning behind using proof of ownership before duplicate reuse in the storage path. "
            "It is intentionally different from version B so the files become partly similar rather than exact duplicates."
        )
    else:
        middle_template = (
            "VARIANT-B-{idx:02d} This middle section belongs only to partial_similar_b and represents a version that emphasises attack evaluation details such as hash probing deduplication denial of service ownership fraud rate limiting and the gap between static thresholds and behaviour aware runtime monitoring. "
            "It is intentionally different from version A so the files become partly similar rather than exact duplicates."
        )

    for idx in range(1, 13):
        middle_lines.append(middle_template.format(idx=idx))

    for idx in range(1, 31):
        right_lines.append(
            f"COMMON-RIGHT-{idx:02d} This shared right block is identical in partial_similar_a and partial_similar_b and exists to create another visible overlap region after the differing middle section so the compare files endpoint can show that the two files are partly similar rather than completely different or completely identical. "
            f"It again refers to chunk overlap dedup reuse LocalStack objects Redis state and behavioural defence. "
            f"This shared right line number is {idx:02d}."
        )

    return "\n".join(left_lines + middle_lines + right_lines) + "\n"


def build_readme_text() -> str:
    return (
        "Demo sample files for the secure deduplication notebook and API demo.\n\n"
        "Files:\n"
        "- exact_duplicate_a.txt\n"
        "- exact_duplicate_b.txt\n"
        "- partial_similar_a.txt\n"
        "- partial_similar_b.txt\n\n"
        "Recommended usage:\n\n"
        "1. Exact duplicate PoW demo:\n"
        "   upload exact_duplicate_a.txt first\n"
        "   upload exact_duplicate_b.txt second\n"
        "   expected result:\n"
        "   duplicate detection plus PoW challenge plus successful duplicate reuse after proof\n\n"
        "2. Partial similarity demo:\n"
        "   upload partial_similar_a.txt\n"
        "   upload partial_similar_b.txt\n"
        "   expected result:\n"
        "   visible shared chunks between the two files in /demo/compare-files\n\n"
        "Suggested notebook paths:\n\n"
        'path_a = REPO_ROOT / "demo_samples" / "partial_similar_a.txt"\n'
        'path_b = REPO_ROOT / "demo_samples" / "partial_similar_b.txt"\n\n'
        "or for the exact duplicate demo:\n\n"
        'path_a = REPO_ROOT / "demo_samples" / "exact_duplicate_a.txt"\n'
        'path_b = REPO_ROOT / "demo_samples" / "exact_duplicate_b.txt"\n'
    )


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    exact_text = build_exact_duplicate_text()
    write_text(OUT_DIR / "exact_duplicate_a.txt", exact_text)
    write_text(OUT_DIR / "exact_duplicate_b.txt", exact_text)
    write_text(OUT_DIR / "partial_similar_a.txt", build_partial_text("A"))
    write_text(OUT_DIR / "partial_similar_b.txt", build_partial_text("B"))
    write_text(OUT_DIR / "README.txt", build_readme_text())

    print(f"Wrote demo samples to {OUT_DIR}")
    for path in sorted(OUT_DIR.glob("*.txt")):
        print(f"{path.name}: {path.stat().st_size} bytes")


if __name__ == "__main__":
    main()
