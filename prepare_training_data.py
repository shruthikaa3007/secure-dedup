import argparse
from collections import Counter
from typing import Dict

import pandas as pd

from attack_labeler import label_attack

LABEL_COLUMN = "attack_label"
NON_FEATURE_COLUMNS = {"client_id", "is_anomaly", LABEL_COLUMN}
LABEL_INPUT_FEATURES = [
    "requests_per_minute",
    "pow_attempt_rate",
    "upload_to_query_ratio",
    "duplicate_ratio",
    "session_duration",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare a clean supervised training dataset from detection results. "
            "Generates/repairs attack labels when needed."
        )
    )
    parser.add_argument(
        "--input",
        default="detection_results.csv",
        help="Path to source feature dataset (default: detection_results.csv)",
    )
    parser.add_argument(
        "--output",
        default="training_data.csv",
        help="Path to output training CSV (default: training_data.csv)",
    )
    parser.add_argument(
        "--relabel",
        choices=("auto", "always", "never"),
        default="auto",
        help=(
            "Relabel strategy for attack_label: "
            "'auto' relabels if labels are unusable, "
            "'always' forces relabel, 'never' keeps existing labels."
        ),
    )
    return parser.parse_args()


def _label_counts(series: pd.Series) -> Dict[str, int]:
    values = [str(v) for v in series.dropna().tolist()]
    return dict(Counter(values))


def _labels_need_rebuild(df: pd.DataFrame) -> bool:
    if LABEL_COLUMN not in df.columns:
        return True
    counts = _label_counts(df[LABEL_COLUMN])
    if not counts:
        return True
    # Degenerate labels are common in this project due to previous write-order bug.
    if len(counts) <= 1:
        return True
    if set(counts.keys()) == {"normal"}:
        return True
    return False


def _safe_feature_value(row: pd.Series, column: str) -> float:
    value = row.get(column, 0.0)
    if pd.isna(value):
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def rebuild_labels(df: pd.DataFrame) -> pd.Series:
    return df.apply(
        lambda row: label_attack(
            {
                key: _safe_feature_value(row, key)
                for key in LABEL_INPUT_FEATURES
            }
        ),
        axis=1,
    )


def main() -> None:
    args = parse_args()

    df = pd.read_csv(args.input)
    if df.empty:
        raise ValueError(f"Input dataset is empty: {args.input}")

    print("Columns found:", df.columns.tolist())
    print(f"Input rows: {len(df)}")

    feature_columns = [c for c in df.columns if c not in NON_FEATURE_COLUMNS]
    if not feature_columns:
        raise ValueError("No numeric feature columns found in source dataset")

    # Ensure model features are numeric and remove rows that cannot be interpreted.
    for col in feature_columns:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    before_drop = len(df)
    df = df.dropna(subset=feature_columns).copy()
    dropped = before_drop - len(df)
    if dropped:
        print(f"Dropped {dropped} rows with invalid feature values")

    if df.empty:
        raise ValueError("No rows left after cleaning feature columns")

    should_relabel = False
    if args.relabel == "always":
        should_relabel = True
    elif args.relabel == "auto":
        should_relabel = _labels_need_rebuild(df)

    if should_relabel:
        df[LABEL_COLUMN] = rebuild_labels(df)
        print("Rebuilt attack labels using attack_labeler rules")
    elif LABEL_COLUMN not in df.columns:
        # Explicit no-relabel path needs a label column for supervised training.
        df[LABEL_COLUMN] = "normal"
        print("No attack_label column found; defaulted all labels to 'normal'")

    label_dist = _label_counts(df[LABEL_COLUMN])
    print("Label distribution:", label_dist)

    output_columns = []
    if "client_id" in df.columns:
        output_columns.append("client_id")
    output_columns.extend(feature_columns)
    output_columns.append(LABEL_COLUMN)

    df[output_columns].to_csv(args.output, index=False)
    print(f"Saved cleaned training dataset to: {args.output}")
    print(f"Output shape: {df[output_columns].shape}")


if __name__ == "__main__":
    main()
