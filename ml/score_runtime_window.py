"""
Loads the trained Isolation Forest and scores telemetry windows, posting
each result to the FastAPI backend's /anomaly-scores endpoint so it shows
up on the Streamlit dashboard and triggers a Slack alert if anomalous.

In a real deployment this would run as a small sidecar/cron job reading a
live feature stream (see feature_extraction.py). For local testing it
replays telemetry.csv one window at a time.
"""
import argparse
import time
import joblib
import pandas as pd
import requests

from train_isolation_forest import FEATURE_COLUMNS

BACKEND_URL_DEFAULT = "http://localhost:8000"


def score_and_publish(csv_path: str, model_path: str, backend_url: str, sleep_seconds: float = 0):
    bundle = joblib.load(model_path)
    model = bundle["model"]

    df = pd.read_csv(csv_path)
    X = df[FEATURE_COLUMNS]

    scores = model.decision_function(X)      # higher = more normal
    predictions = model.predict(X)            # -1 = anomaly, 1 = normal

    posted, anomalies = 0, 0
    for i, row in df.iterrows():
        payload = {
            "window_start": row["window_start"],
            "window_end": row["window_end"],
            "process_count": float(row["process_count"]),
            "network_conn_count": float(row["network_conn_count"]),
            "file_op_count": float(row["file_op_count"]),
            "cpu_usage_pct": float(row["cpu_usage_pct"]),
            "mem_usage_pct": float(row["mem_usage_pct"]),
            "anomaly_score": float(scores[i]),
            "is_anomalous": bool(predictions[i] == -1),
        }
        try:
            resp = requests.post(f"{backend_url}/anomaly-scores", json=payload, timeout=5)
            resp.raise_for_status()
            posted += 1
            if payload["is_anomalous"]:
                anomalies += 1
        except requests.RequestException as exc:
            print(f"Failed to post window {i}: {exc}")
        if sleep_seconds:
            time.sleep(sleep_seconds)

    print(f"Posted {posted}/{len(df)} windows to {backend_url} ({anomalies} flagged anomalous).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", default="telemetry.csv")
    parser.add_argument("--model", default="model/isolation_forest.joblib")
    parser.add_argument("--backend-url", default=BACKEND_URL_DEFAULT)
    parser.add_argument("--sleep", type=float, default=0, help="seconds between posts, to simulate a live feed")
    args = parser.parse_args()
    score_and_publish(args.csv, args.model, args.backend_url, args.sleep)
