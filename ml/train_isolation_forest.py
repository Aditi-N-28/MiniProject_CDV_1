"""
Trains an unsupervised Isolation Forest on runtime telemetry windows and
saves the fitted model for use by score_runtime_window.py.

Usage:
    python simulate_telemetry.py        # if you don't have telemetry.csv yet
    python train_isolation_forest.py
"""
import sys
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report

FEATURE_COLUMNS = [
    "process_count", "network_conn_count", "file_op_count",
    "cpu_usage_pct", "mem_usage_pct",
]


def train(csv_path="telemetry.csv", model_path="model/isolation_forest.joblib",
          contamination=0.05):
    df = pd.read_csv(csv_path)
    X = df[FEATURE_COLUMNS]

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,   # expected fraction of anomalous windows
        random_state=42,
    )
    model.fit(X)

    joblib.dump({"model": model, "feature_columns": FEATURE_COLUMNS}, model_path)
    print(f"Saved trained Isolation Forest to {model_path}")

    # If the input CSV has a ground-truth 'label' column (only true for
    # simulate_telemetry.py output), report how well the unsupervised model
    # lines up with it — purely for your own validation, never used in training.
    if "label" in df.columns:
        raw_scores = model.decision_function(X)         # higher = more normal
        predictions = model.predict(X)                  # -1 = anomaly, 1 = normal
        pred_labels = (predictions == -1).astype(int)
        print("\nValidation against injected ground-truth labels "
              "(for sanity-checking only, not used by the model):")
        print(classification_report(df["label"], pred_labels, target_names=["normal", "anomalous"]))
    return model


if __name__ == "__main__":
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "telemetry.csv"
    train(csv_path)
