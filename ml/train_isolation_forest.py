"""
Trains an Isolation Forest on runtime telemetry and evaluates it
against ground-truth labels when available.

Usage:
    python simulate_telemetry.py
    python train_isolation_forest.py
"""

import os
import sys
import json
import joblib
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix

FEATURE_COLUMNS = [
    "process_count",
    "network_conn_count",
    "file_op_count",
    "cpu_usage_pct",
    "mem_usage_pct",
]


def train(
    csv_path="telemetry.csv",
    model_path="model/isolation_forest.joblib",
    contamination=0.05,
):
    df = pd.read_csv(csv_path)

    missing = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required telemetry columns: {missing}")

    X = df[FEATURE_COLUMNS]

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
    )
    model.fit(X)

    os.makedirs(os.path.dirname(model_path) or ".", exist_ok=True)

    joblib.dump(
        {"model": model, "feature_columns": FEATURE_COLUMNS},
        model_path,
    )
    print(f"Saved trained Isolation Forest to {model_path}")

    if "label" not in df.columns:
        print("No ground-truth 'label' column found. FPR was not calculated.")
        return model

    y_true = pd.to_numeric(df["label"], errors="raise").astype(int)

    if not set(y_true.unique()).issubset({0, 1}):
        raise ValueError(
            "Labels must be 0 (normal) or 1 (anomalous)."
        )

    predictions = model.predict(X)
    y_pred = (predictions == -1).astype(int)

    # Confusion matrix: 0 = normal, 1 = anomalous.
    tn, fp, fn, tp = confusion_matrix(
        y_true, y_pred, labels=[0, 1]
    ).ravel()

    print("\nValidation against ground-truth labels:")
    print(
        classification_report(
            y_true,
            y_pred,
            labels=[0, 1],
            target_names=["normal", "anomalous"],
            zero_division=0,
        )
    )

    print("Confusion matrix counts:")
    print(f"True Negatives (TN):  {tn}")
    print(f"False Positives (FP): {fp}")
    print(f"False Negatives (FN): {fn}")
    print(f"True Positives (TP):  {tp}")

    normal_samples = tn + fp
    fpr = (
        round((fp / normal_samples) * 100, 2)
        if normal_samples > 0
        else None
    )

    evaluation = {
        "evaluation_type": "synthetic_ground_truth",
        "total_samples": int(len(y_true)),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
        "fpr_percent": fpr,
    }

    evaluation_path = os.path.join(
        os.path.dirname(model_path) or ".",
        "fpr_evaluation.json",
    )

    with open(evaluation_path, "w", encoding="utf-8") as file:
        json.dump(evaluation, file, indent=4)

    print(f"\nSaved FPR evaluation to {evaluation_path}")

    if fpr is not None:
        print("\nRuntime False Positive Rate (FPR):")
        print("FPR = FP / (FP + TN) * 100")
        print(f"FPR = {fp} / ({fp} + {tn}) * 100")
        print(f"FPR = {fpr:.2f}%")
    else:
        print("FPR unavailable: no normal samples in the evaluation data.")

    return model


if __name__ == "__main__":
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "telemetry.csv"
    train(csv_path)
