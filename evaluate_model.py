import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.preprocessing import label_binarize

DEFAULT_UNSUPERVISED_WEIGHTS = {
    "isolation_forest": 0.25,
    "one_class_svm": 0.20,
    "dense_autoencoder": 0.25,
    "lstm_autoencoder": 0.30,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate trained model artifacts and generate metrics/report files "
            "(PR-AUC, F1, confusion matrix)."
        )
    )
    parser.add_argument(
        "--dataset",
        default="training_data.csv",
        help="Path to evaluation CSV (default: training_data.csv)",
    )
    parser.add_argument(
        "--model-dir",
        default=".",
        help="Directory containing model artifacts (default: current directory)",
    )
    parser.add_argument(
        "--label-column",
        default="attack_label",
        help="Ground-truth label column name (default: attack_label)",
    )
    parser.add_argument(
        "--output-json",
        default="evaluation_report.json",
        help="Output JSON report path (default: evaluation_report.json)",
    )
    parser.add_argument(
        "--output-md",
        default="evaluation_report.md",
        help="Output markdown report path (default: evaluation_report.md)",
    )
    parser.add_argument(
        "--unsupervised-threshold",
        type=float,
        default=None,
        help="Override unsupervised anomaly threshold from metadata",
    )
    return parser.parse_args()


def _resolve_path(base_dir: Path, raw_path: str) -> Path:
    path = Path(raw_path)
    if path.is_absolute():
        return path
    return base_dir / path


def _load_metadata(model_dir: Path) -> Dict:
    metadata_path = model_dir / "model_metadata.json"
    if not metadata_path.exists():
        return {}
    with open(metadata_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _prepare_features(
    df: pd.DataFrame,
    feature_columns: List[str],
    label_column: str,
) -> Tuple[pd.DataFrame, List[str]]:
    if feature_columns:
        available = [c for c in feature_columns if c in df.columns]
        if available:
            X = df[available].copy()
            for col in X.columns:
                X[col] = pd.to_numeric(X[col], errors="coerce")
            X = X.dropna(axis=0)
            return X, available

    exclude = {"client_id", "is_anomaly", label_column}
    inferred = [c for c in df.columns if c not in exclude]
    X = df[inferred].copy()
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    X = X.dropna(axis=1, how="all")
    X = X.dropna(axis=0)
    if X.empty:
        raise ValueError("No numeric feature rows available for evaluation")
    return X, X.columns.tolist()


def _align_labels(df: pd.DataFrame, X: pd.DataFrame, label_column: str) -> pd.Series:
    if label_column in df.columns:
        return df.loc[X.index, label_column].astype(str)
    if "is_anomaly" in df.columns:
        values = df.loc[X.index, "is_anomaly"].astype(bool)
        return values.map(lambda x: "anomaly" if x else "normal")
    raise ValueError(
        f"Ground truth not found. Expected '{label_column}' or 'is_anomaly' column."
    )


def _decode_predictions(pred_raw: np.ndarray, model, label_encoder) -> np.ndarray:
    if label_encoder is not None:
        try:
            return label_encoder.inverse_transform(pred_raw.astype(int)).astype(str)
        except Exception:
            pass

    if hasattr(model, "classes_"):
        model_classes = np.array([str(c) for c in model.classes_])
        if np.issubdtype(np.array(pred_raw).dtype, np.integer):
            idx = pred_raw.astype(int)
            if idx.min() >= 0 and idx.max() < len(model_classes):
                return model_classes[idx]
    return np.array([str(v) for v in pred_raw], dtype=str)


def _binary_metrics(
    y_true_bin: np.ndarray,
    y_pred_bin: np.ndarray,
    risk_scores: np.ndarray,
) -> Dict:
    summary = {
        "available": True,
        "positive_class": "anomaly",
        "confusion_matrix_labels": ["normal", "anomaly"],
    }

    unique_truth = np.unique(y_true_bin)
    if len(unique_truth) < 2:
        summary["available"] = False
        summary["reason"] = "Ground truth has a single class; PR-AUC/F1 are not informative."
        summary["truth_class_counts"] = {
            "normal": int(np.sum(y_true_bin == 0)),
            "anomaly": int(np.sum(y_true_bin == 1)),
        }
        return summary

    matrix = confusion_matrix(y_true_bin, y_pred_bin, labels=[0, 1])
    summary["confusion_matrix"] = matrix.tolist()
    summary["f1_binary"] = float(f1_score(y_true_bin, y_pred_bin, zero_division=0))
    summary["f1_macro"] = float(
        f1_score(y_true_bin, y_pred_bin, average="macro", zero_division=0)
    )
    summary["precision"] = float(
        precision_score(y_true_bin, y_pred_bin, zero_division=0)
    )
    summary["recall"] = float(recall_score(y_true_bin, y_pred_bin, zero_division=0))
    summary["pr_auc"] = float(average_precision_score(y_true_bin, risk_scores))
    summary["truth_class_counts"] = {
        "normal": int(np.sum(y_true_bin == 0)),
        "anomaly": int(np.sum(y_true_bin == 1)),
    }
    return summary


def _multiclass_metrics(
    y_true_label: np.ndarray,
    y_pred_label: np.ndarray,
    class_probabilities: Optional[np.ndarray],
    probability_classes: Optional[List[str]],
) -> Dict:
    unique_labels = sorted(set(y_true_label) | set(y_pred_label))
    if len(unique_labels) < 2:
        return {
            "available": False,
            "reason": "Only one class present in multiclass labels.",
            "labels": unique_labels,
        }

    matrix = confusion_matrix(y_true_label, y_pred_label, labels=unique_labels)
    report = classification_report(
        y_true_label,
        y_pred_label,
        labels=unique_labels,
        output_dict=True,
        zero_division=0,
    )
    metrics = {
        "available": True,
        "labels": unique_labels,
        "confusion_matrix": matrix.tolist(),
        "f1_macro": float(report.get("macro avg", {}).get("f1-score", 0.0)),
        "classification_report": report,
    }

    if class_probabilities is not None and probability_classes:
        present_classes = [c for c in probability_classes if c in set(y_true_label)]
        if len(present_classes) >= 2:
            class_to_idx = {c: i for i, c in enumerate(probability_classes)}
            selected_indices = [class_to_idx[c] for c in present_classes]
            y_true_bin = label_binarize(y_true_label, classes=present_classes)
            y_score = class_probabilities[:, selected_indices]
            if len(present_classes) == 2:
                y_true_for_ap = (y_true_label == present_classes[1]).astype(int)
                y_score_for_ap = y_score[:, 1]
                metrics["pr_auc_ovr_macro"] = float(
                    average_precision_score(y_true_for_ap, y_score_for_ap)
                )
            else:
                metrics["pr_auc_ovr_macro"] = float(
                    average_precision_score(y_true_bin, y_score, average="macro")
                )
        else:
            metrics["pr_auc_ovr_macro"] = None
            metrics["pr_auc_note"] = (
                "PR-AUC (multiclass) skipped: fewer than 2 overlapping truth/probability classes."
            )
    else:
        metrics["pr_auc_ovr_macro"] = None
        metrics["pr_auc_note"] = (
            "PR-AUC (multiclass) unavailable because probability outputs were not found."
        )

    return metrics


def evaluate_and_write_reports(
    dataset_path: Path,
    model_dir: Path,
    label_column: str = "attack_label",
    output_json_path: Optional[Path] = None,
    output_md_path: Optional[Path] = None,
    unsupervised_threshold: Optional[float] = None,
) -> Dict:
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")
    if not model_dir.exists():
        raise FileNotFoundError(f"Model directory not found: {model_dir}")

    metadata = _load_metadata(model_dir)
    mode = metadata.get("mode", "unsupervised")
    feature_columns = metadata.get("feature_columns", [])
    weights = {
        **DEFAULT_UNSUPERVISED_WEIGHTS,
        **metadata.get("unsupervised_weights", {}),
    }
    threshold = (
        float(unsupervised_threshold)
        if unsupervised_threshold is not None
        else float(metadata.get("unsupervised_anomaly_threshold", 0.50))
    )

    df = pd.read_csv(dataset_path)
    if df.empty:
        raise ValueError(f"Dataset is empty: {dataset_path}")

    X, used_feature_columns = _prepare_features(df, feature_columns, label_column)
    y_true_label = _align_labels(df, X, label_column).to_numpy(dtype=str)
    y_true_bin = (y_true_label != "normal").astype(int)

    class_probabilities = None
    probability_classes = None
    notes: List[str] = []

    if (model_dir / "attack_classifier.pkl").exists():
        eval_mode = "supervised"
        model = joblib.load(model_dir / "attack_classifier.pkl")

        label_encoder = None
        if (model_dir / "attack_label_encoder.pkl").exists():
            label_encoder = joblib.load(model_dir / "attack_label_encoder.pkl")

        y_pred_raw = model.predict(X)
        y_pred_label = _decode_predictions(
            np.asarray(y_pred_raw),
            model=model,
            label_encoder=label_encoder,
        )

        if hasattr(model, "predict_proba"):
            class_probabilities = model.predict_proba(X)
            if label_encoder is not None:
                probability_classes = [str(c) for c in label_encoder.classes_]
            elif hasattr(model, "classes_"):
                probability_classes = [str(c) for c in model.classes_]
            else:
                probability_classes = [str(i) for i in range(class_probabilities.shape[1])]

        if class_probabilities is not None and probability_classes and "normal" in probability_classes:
            normal_idx = probability_classes.index("normal")
            risk_scores = 1.0 - class_probabilities[:, normal_idx]
        else:
            risk_scores = (y_pred_label != "normal").astype(float)
            notes.append(
                "Risk scores approximated from predicted labels because normal-class probabilities were unavailable."
            )

    elif (model_dir / "isolation_forest.pkl").exists() and (model_dir / "one_class_svm.pkl").exists():
        eval_mode = "unsupervised"
        scaler = joblib.load(model_dir / "scaler.pkl")
        isolation_forest = joblib.load(model_dir / "isolation_forest.pkl")
        one_class_svm = joblib.load(model_dir / "one_class_svm.pkl")

        X_scaled = scaler.transform(X)
        if_pred = isolation_forest.predict(X_scaled) == -1
        svm_pred = one_class_svm.predict(X_scaled) == -1

        active_weights = {
            "isolation_forest": float(weights.get("isolation_forest", 1.0)),
            "one_class_svm": float(weights.get("one_class_svm", 1.0)),
        }
        weight_sum = sum(active_weights.values())
        if weight_sum <= 0:
            risk_scores = np.logical_or(if_pred, svm_pred).astype(float)
        else:
            risk_scores = (
                active_weights["isolation_forest"] * if_pred.astype(float)
                + active_weights["one_class_svm"] * svm_pred.astype(float)
            ) / weight_sum

        y_pred_bin = (risk_scores >= threshold).astype(int)
        y_pred_label = np.where(y_pred_bin == 1, "anomaly", "normal")
        notes.append(
            "Unsupervised evaluation uses weighted votes from IsolationForest and OneClassSVM."
        )
    else:
        raise RuntimeError(
            "No supported model artifacts found in model directory."
        )

    y_pred_bin = (y_pred_label != "normal").astype(int)

    binary = _binary_metrics(y_true_bin, y_pred_bin, risk_scores)
    if eval_mode == "supervised":
        multiclass = _multiclass_metrics(
            y_true_label=y_true_label,
            y_pred_label=y_pred_label,
            class_probabilities=class_probabilities,
            probability_classes=probability_classes,
        )
    else:
        multiclass = {
            "available": False,
            "reason": (
                "Multiclass metrics are only computed for supervised classifier outputs. "
                "Use binary metrics (normal vs anomaly) for unsupervised evaluation."
            ),
        }

    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_path": str(dataset_path),
        "model_dir": str(model_dir),
        "mode_from_metadata": mode,
        "mode_evaluated": eval_mode,
        "rows_evaluated": int(len(X)),
        "label_column": label_column if label_column in df.columns else "is_anomaly",
        "feature_columns": used_feature_columns,
        "binary_metrics": binary,
        "multiclass_metrics": multiclass,
        "prediction_summary": {
            "predicted_normal": int(np.sum(y_pred_bin == 0)),
            "predicted_anomaly": int(np.sum(y_pred_bin == 1)),
            "predicted_anomaly_rate": float(np.mean(y_pred_bin)),
            "mean_risk_score": float(np.mean(risk_scores)),
            "unsupervised_threshold": threshold if eval_mode == "unsupervised" else None,
        },
        "notes": notes,
    }

    json_out = output_json_path or (model_dir / "evaluation_report.json")
    md_out = output_md_path or (model_dir / "evaluation_report.md")

    with open(json_out, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    lines: List[str] = [
        "# Model Evaluation Report",
        "",
        f"- Generated At (UTC): `{summary['generated_at_utc']}`",
        f"- Dataset: `{summary['dataset_path']}`",
        f"- Model Dir: `{summary['model_dir']}`",
        f"- Training Metadata Mode: `{summary['mode_from_metadata']}`",
        f"- Evaluated Mode: `{summary['mode_evaluated']}`",
        f"- Rows Evaluated: `{summary['rows_evaluated']}`",
        "",
        "## Binary Metrics (normal vs anomaly)",
    ]

    if binary.get("available"):
        cm = binary.get("confusion_matrix", [[0, 0], [0, 0]])
        lines.extend(
            [
                f"- PR-AUC: `{binary.get('pr_auc'):.6f}`",
                f"- F1 (binary): `{binary.get('f1_binary'):.6f}`",
                f"- F1 (macro): `{binary.get('f1_macro'):.6f}`",
                f"- Precision: `{binary.get('precision'):.6f}`",
                f"- Recall: `{binary.get('recall'):.6f}`",
                "",
                "| Truth \\ Pred | normal | anomaly |",
                "|---|---:|---:|",
                f"| normal | {cm[0][0]} | {cm[0][1]} |",
                f"| anomaly | {cm[1][0]} | {cm[1][1]} |",
            ]
        )
    else:
        lines.extend(
            [
                f"- Available: `False`",
                f"- Reason: {binary.get('reason', 'N/A')}",
            ]
        )

    lines.extend(["", "## Multiclass Metrics"])
    if multiclass.get("available"):
        lines.extend(
            [
                f"- Labels: `{', '.join(multiclass.get('labels', []))}`",
                f"- F1 (macro): `{multiclass.get('f1_macro', 0.0):.6f}`",
                f"- PR-AUC (OvR macro): `{multiclass.get('pr_auc_ovr_macro')}`",
                "",
                "Confusion matrix (JSON):",
                "```json",
                json.dumps(multiclass.get("confusion_matrix", []), indent=2),
                "```",
            ]
        )
        if "pr_auc_note" in multiclass:
            lines.append(f"- Note: {multiclass['pr_auc_note']}")
    else:
        lines.extend(
            [
                "- Available: `False`",
                f"- Reason: {multiclass.get('reason', 'N/A')}",
            ]
        )

    lines.extend(
        [
            "",
            "## Prediction Summary",
            f"- Predicted Normal: `{summary['prediction_summary']['predicted_normal']}`",
            f"- Predicted Anomaly: `{summary['prediction_summary']['predicted_anomaly']}`",
            f"- Predicted Anomaly Rate: `{summary['prediction_summary']['predicted_anomaly_rate']:.6f}`",
            f"- Mean Risk Score: `{summary['prediction_summary']['mean_risk_score']:.6f}`",
        ]
    )
    if summary["prediction_summary"]["unsupervised_threshold"] is not None:
        lines.append(
            f"- Unsupervised Threshold: `{summary['prediction_summary']['unsupervised_threshold']:.6f}`"
        )

    if notes:
        lines.extend(["", "## Notes"])
        for note in notes:
            lines.append(f"- {note}")

    with open(md_out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    return summary


def main() -> None:
    args = parse_args()

    model_dir = Path(args.model_dir)
    dataset_path = Path(args.dataset)
    output_json = _resolve_path(model_dir, args.output_json)
    output_md = _resolve_path(model_dir, args.output_md)

    summary = evaluate_and_write_reports(
        dataset_path=dataset_path,
        model_dir=model_dir,
        label_column=args.label_column,
        output_json_path=output_json,
        output_md_path=output_md,
        unsupervised_threshold=args.unsupervised_threshold,
    )

    print(f"Evaluation mode: {summary['mode_evaluated']}")
    print(f"Rows evaluated: {summary['rows_evaluated']}")
    print(f"Saved JSON report: {output_json}")
    print(f"Saved Markdown report: {output_md}")


if __name__ == "__main__":
    main()
