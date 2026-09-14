"""
Generates synthetic runtime telemetry windows shaped like the features the
project extracts from real Falco/eBPF output (process count, network
connection count, file-operation count, CPU %, memory %).

Why this exists: Isolation Forest needs data to train on, and a live
Minikube + Falco cluster (Review 3) isn't available until you actually run
this project on your own machine. This script lets you build and validate
the ml/ and dashboard/ pipeline end-to-end right now with realistic-looking
data, and produces a labelled CSV (label 1 = injected anomaly) purely for
your own sanity-checking — the Isolation Forest itself never sees the label,
since it's trained unsupervised, matching the design in the project report.

Once Falco is running for real, point feature_extraction.py at its JSON
output instead of this script.
"""
import numpy as np
import pandas as pd
from datetime import datetime, timedelta, UTC

RNG = np.random.default_rng(42)


def generate_normal_window():
    return {
        "process_count": RNG.normal(12, 2),
        "network_conn_count": RNG.normal(4, 1.2),
        "file_op_count": RNG.normal(45, 8),
        "cpu_usage_pct": RNG.normal(20, 4),
        "mem_usage_pct": RNG.normal(28, 5),
    }


def generate_anomalous_window():
    # Simulates behaviour like a reverse shell / cryptominer / data
    # exfiltration attempt: process/network spikes and heavy CPU.
    return {
        "process_count": RNG.normal(40, 6),
        "network_conn_count": RNG.normal(25, 5),
        "file_op_count": RNG.normal(160, 20),
        "cpu_usage_pct": RNG.normal(88, 6),
        "mem_usage_pct": RNG.normal(70, 8),
    }


def simulate(n_normal=480, n_anomalous=20, start=None):
    """n_normal/n_anomalous are 1-minute windows -> defaults to 8 hours of
    mostly-normal traffic with ~20 anomalous minutes scattered through it."""
    start = start or (datetime.now(UTC) - timedelta(hours=8))
    rows = []
    anomaly_minutes = set(RNG.choice(n_normal + n_anomalous, size=n_anomalous, replace=False))

    for i in range(n_normal + n_anomalous):
        window_start = start + timedelta(minutes=i)
        window_end = window_start + timedelta(minutes=1)
        is_anomaly = i in anomaly_minutes
        feats = generate_anomalous_window() if is_anomaly else generate_normal_window()
        feats = {k: max(0, round(v, 2)) for k, v in feats.items()}
        rows.append({
            "window_start": window_start.isoformat(),
            "window_end": window_end.isoformat(),
            **feats,
            "label": int(is_anomaly),  # ground truth, NOT used for training
        })
    return pd.DataFrame(rows)


if __name__ == "__main__":
    df = simulate()
    out_path = "telemetry.csv"
    df.to_csv(out_path, index=False)
    print(f"Wrote {len(df)} synthetic telemetry windows to {out_path} "
          f"({df['label'].sum()} labelled anomalous, for validation only).")
