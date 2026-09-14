"""
Converts real Falco output (JSON-lines, one alert/event per line — see
falco/falco.yaml's file_output config) into the same 1-minute feature
windows used to train the Isolation Forest in train_isolation_forest.py.

Falco alerts alone only tell you about rule matches, not raw syscall
volume, so in a full deployment you would pair this with a lightweight
eBPF counter (e.g. via a bpftrace script or Falco's own syscall counters)
for process/network/file/cpu/mem stats per pod. This module is written so
that swapping in that real counter source only means changing
`_read_raw_metrics()` — the windowing and output schema stay the same.
"""
import json
import pandas as pd
from collections import defaultdict
from datetime import datetime, timedelta


def parse_falco_jsonlines(path: str) -> pd.DataFrame:
    """Parses a Falco JSON-lines log file into a flat DataFrame of alerts."""
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            records.append({
                "time": evt.get("time"),
                "rule": evt.get("rule"),
                "priority": evt.get("priority"),
                "output": evt.get("output"),
                "pod_name": evt.get("output_fields", {}).get("k8s.pod.name"),
                "container_name": evt.get("output_fields", {}).get("container.name"),
            })
    return pd.DataFrame(records)


def build_feature_windows(alerts_df: pd.DataFrame, raw_metrics_df: pd.DataFrame,
                           window_minutes: int = 1) -> pd.DataFrame:
    """Combines Falco alert counts with raw per-minute resource metrics
    (process/network/file/cpu/mem) into the 5-feature schema the model expects.

    raw_metrics_df is expected to already have one row per minute with
    columns: window_start, process_count, network_conn_count, file_op_count,
    cpu_usage_pct, mem_usage_pct — e.g. produced by your own eBPF counter
    collector, or by simulate_telemetry.py for local testing.
    """
    if alerts_df.empty:
        alerts_df = pd.DataFrame(columns=["time", "rule", "priority"])

    alerts_df = alerts_df.copy()
    if not alerts_df.empty:
        alerts_df["time"] = pd.to_datetime(alerts_df["time"], errors="coerce")
        alerts_df["window_start"] = alerts_df["time"].dt.floor(f"{window_minutes}min")
        alert_counts = alerts_df.groupby("window_start").size().rename("falco_alert_count")
    else:
        alert_counts = pd.Series(dtype=int, name="falco_alert_count")

    merged = raw_metrics_df.copy()
    merged["window_start"] = pd.to_datetime(merged["window_start"])
    merged = merged.merge(alert_counts, on="window_start", how="left")
    merged["falco_alert_count"] = merged["falco_alert_count"].fillna(0)
    return merged


if __name__ == "__main__":
    print(__doc__)
    print("Run this against a real falco events.log once Falco is deployed. "
          "For local testing without a live cluster, use simulate_telemetry.py instead.")
