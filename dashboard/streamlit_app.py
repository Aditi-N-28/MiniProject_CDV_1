"""
Security dashboard for the Container & Kubernetes Security Scanner project.
Reads from the FastAPI backend (backend/main.py) and visualises:
  - Trivy pre-deployment scan results (pass/fail, severity breakdown)
  - Falco runtime events
  - Isolation Forest anomaly scores over time

use this command to run the dashboard file:  streamlit run streamlit_app.py
(make sure the backend is running first: uvicorn main:app, from backend/)
"""
import os
import pandas as pd
import plotly.express as px
import requests
import streamlit as st

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

st.set_page_config(page_title="Container & K8s Security Scanner", layout="wide")
st.title("🛡️ Container & Kubernetes Security Scanner — Dashboard")
st.caption(f"Backend: {BACKEND_URL}")


@st.cache_data(ttl=5)
def fetch(endpoint: str, limit: int = 200):
    try:
        resp = requests.get(f"{BACKEND_URL}/{endpoint}", params={"limit": limit}, timeout=5)
        resp.raise_for_status()
        return pd.DataFrame(resp.json())
    except requests.RequestException as exc:
        st.error(f"Could not reach backend at {BACKEND_URL}/{endpoint}: {exc}")
        return pd.DataFrame()


tab_scans, tab_runtime, tab_anomalies = st.tabs(
    ["🔍 Pre-Deployment Scans", "📡 Runtime Events (Falco)", "🤖 AI Anomaly Detection"]
)

# ------------------------------- Tab 1: Trivy scan results -------------------------------
with tab_scans:
    df = fetch("scan-results")
    if df.empty:
        st.info("No scan results yet. Run the Jenkins pipeline (or POST to /scan-results) to populate this.")
    else:
        col1, col2, col3 = st.columns(3)
        col1.metric("Total scans", len(df))
        col2.metric("Passed", int(df["passed"].sum()))
        col3.metric("Failed (blocked deployment)", int((~df["passed"]).sum()))

        st.subheader("Severity findings per scan")
        melted = df.melt(
            id_vars=["target", "scan_type", "created_at"],
            value_vars=["critical_count", "high_count", "medium_count", "low_count"],
            var_name="severity", value_name="count",
        )
        fig = px.bar(melted, x="target", y="count", color="severity", barmode="stack",
                     title="Trivy findings by severity")
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("Recent scan results")
        st.dataframe(
            df[["created_at", "scan_type", "target", "passed",
                "critical_count", "high_count", "medium_count", "low_count"]]
            .sort_values("created_at", ascending=False),
            use_container_width=True,
        )

# ------------------------------- Tab 2: Falco runtime events -------------------------------
with tab_runtime:
    df = fetch("runtime-events")
    if df.empty:
        st.info("No runtime events yet. Deploy to Minikube with Falco running to populate this "
                "(or POST a test event to /runtime-events).")
    else:
        col1, col2 = st.columns(2)
        col1.metric("Total Falco alerts", len(df))
        col2.metric("Critical alerts", int((df["priority"] == "CRITICAL").sum()))

        st.subheader("Alerts by priority")
        counts = df["priority"].value_counts().reset_index()
        counts.columns = ["priority", "count"]
        fig = px.pie(counts, names="priority", values="count", title="Falco alert priority breakdown")
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("Recent runtime events")
        st.dataframe(
            df[["created_at", "priority", "rule", "pod_name", "output"]]
            .sort_values("created_at", ascending=False),
            use_container_width=True,
        )

# ------------------------------- Tab 3: Isolation Forest anomalies -------------------------------
with tab_anomalies:
    df = fetch("anomaly-scores", limit=1000)
    if df.empty:
        st.info("No anomaly scores yet. Run `ml/train_isolation_forest.py` then "
                "`ml/score_runtime_window.py` to populate this.")
    else:
        df["window_start"] = pd.to_datetime(df["window_start"])
        col1, col2, col3 = st.columns(3)
        col1.metric("Windows scored", len(df))
        col2.metric("Flagged anomalous", int(df["is_anomalous"].sum()))
        col3.metric("Anomaly rate", f"{100 * df['is_anomalous'].mean():.1f}%")

        st.subheader("Anomaly score over time")
        fig = px.scatter(
            df.sort_values("window_start"), x="window_start", y="anomaly_score",
            color="is_anomalous", color_discrete_map={True: "red", False: "steelblue"},
            title="Isolation Forest decision score per window (lower = more anomalous)",
        )
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("Feature values for flagged windows")
        flagged = df[df["is_anomalous"]]
        if not flagged.empty:
            st.dataframe(
                flagged[["window_start", "process_count", "network_conn_count",
                         "file_op_count", "cpu_usage_pct", "mem_usage_pct", "anomaly_score"]]
                .sort_values("window_start", ascending=False),
                use_container_width=True,
            )
        else:
            st.write("No windows currently flagged as anomalous.")

st.divider()
st.caption("Container & Kubernetes Security Scanner — DevSecOps project. "
           "Data refreshes every 5 seconds while this tab is open.")
