
import os
import json
import ast

import pandas as pd
import plotly.express as px
import requests
import streamlit as st

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

FPR_EVALUATION_PATH = os.path.join(
    PROJECT_ROOT,
    "ml",
    "model",
    "fpr_evaluation.json",
)

st.set_page_config(
    page_title="Container & K8s Security Scanner",
    layout="wide",
)

st.title("🛡️ Container & Kubernetes Security Scanner — Dashboard")
st.caption(f"Backend: {BACKEND_URL}")


# ---------------- Mathematical metrics ----------------

def calculate_container_risk(
    trivy_critical_count,
    trivy_high_count,
    falco_alert_frequency,
):
    alpha = 0.4
    beta = 0.3
    gamma = 0.3

    risk_score = (
        alpha * trivy_critical_count
        + beta * trivy_high_count
        + gamma * falco_alert_frequency
    )

    return round(min(risk_score, 10.0), 2)


def calculate_vulnerability_density(raw_report):
    """
    VD = (V / P) * 100

    V = distinct vulnerable package/version pairs found in inventory.
    P = distinct package/version pairs in the inventory.
    """
    if not raw_report:
        return None, 0, 0, "raw_report_missing"

    try:
        if isinstance(raw_report, dict):
            report = raw_report
        else:
            try:
                report = json.loads(raw_report)
            except (json.JSONDecodeError, TypeError):
                report = ast.literal_eval(raw_report)

        if not isinstance(report, dict):
            return None, 0, 0, "invalid_report"

        total_packages = set()
        vulnerable_packages = set()

        for result in report.get("Results", []) or []:
            for package in result.get("Packages", []) or []:
                name = package.get("Name")
                version = package.get("Version") or ""

                if name:
                    total_packages.add((name, version))

            for vuln in result.get("Vulnerabilities", []) or []:
                name = vuln.get("PkgName")
                version = vuln.get("InstalledVersion") or ""

                if name:
                    vulnerable_packages.add((name, version))

        package_count = len(total_packages)

        if package_count == 0:
            return (
                None,
                0,
                0,
                "unavailable_package_inventory_missing",
            )

        matched_vulnerable = vulnerable_packages & total_packages
        vulnerable_count = len(matched_vulnerable)

        density = round(
            vulnerable_count / package_count * 100,
            2,
        )

        return density, vulnerable_count, package_count, "calculated"

    except (ValueError, TypeError, SyntaxError, AttributeError):
        return None, 0, 0, "invalid_report"


# ---------------- Backend data ----------------

@st.cache_data(ttl=5)
def fetch(endpoint: str, limit: int = 200):
    try:
        response = requests.get(
            f"{BACKEND_URL}/{endpoint}",
            params={"limit": limit},
            timeout=5,
        )
        response.raise_for_status()
        return pd.DataFrame(response.json())

    except requests.RequestException as exc:
        st.error(
            f"Could not reach backend at "
            f"{BACKEND_URL}/{endpoint}: {exc}"
        )
        return pd.DataFrame()


# ---------------- FPR evaluation ----------------

def show_fpr_evaluation():
    st.subheader("📊 Model Evaluation — Synthetic Test Data")

    if not os.path.exists(FPR_EVALUATION_PATH):
        st.info(
            "FPR evaluation not found. Run "
            "`python train_isolation_forest.py` from the ml folder "
            "to generate it."
        )
        return

    try:
        with open(
            FPR_EVALUATION_PATH,
            "r",
            encoding="utf-8",
        ) as file:
            evaluation = json.load(file)

        fpr = evaluation.get("fpr_percent")

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "False Positive Rate",
            f"{fpr:.2f}%" if fpr is not None else "N/A",
        )
        col2.metric(
            "False Positives",
            evaluation["false_positives"],
        )
        col3.metric(
            "True Negatives",
            evaluation["true_negatives"],
        )
        col4.metric(
            "Evaluation Samples",
            evaluation["total_samples"],
        )

        st.caption(
            "Offline evaluation using labelled synthetic telemetry. "
            "This is not the false-positive rate of live runtime alerts."
        )

        with st.expander("View evaluation details"):
            st.json(evaluation)

    except (OSError, ValueError, KeyError, TypeError) as exc:
        st.warning(f"Could not load FPR evaluation: {exc}")


# ---------------- Dashboard tabs ----------------

tab_scans, tab_runtime, tab_anomalies, tab_drift = st.tabs(
    [
        "🔍 Pre-Deployment Scans",
        "📡 Runtime Events (Falco)",
        "🤖 AI Anomaly Detection",
        "🛡️ Security Drift",
    ]
)


# ---------------- Pre-deployment Trivy scans ----------------

with tab_scans:
    df = fetch("scan-results")

    if df.empty:
        st.info(
            "No scan results yet. Run the Jenkins pipeline "
            "or POST to /scan-results to populate this."
        )
    else:
        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Total scans", len(df))
        col2.metric(
            "Passed",
            int(df["passed"].astype(bool).sum()),
        )
        col3.metric(
            "Failed (blocked deployment)",
            int((~df["passed"].astype(bool)).sum()),
        )
        col4.metric(
            "Composite Risk Index",
            f"{calculate_container_risk(
                int(df['critical_count'].sum()),
                int(df['high_count'].sum()),
                1
            )} / 10",
        )

        st.divider()
        st.subheader("📦 Equation 2 — Vulnerability Density")

        if "raw_report" not in df.columns:
            st.info(
                "Saved scan records do not include raw Trivy reports, "
                "so Vulnerability Density cannot be calculated."
            )
        else:
            sorted_scans = df.sort_values(
                "created_at",
                ascending=False,
                na_position="last",
            )

            selected_metrics = None
            selected_scan = None

            for _, scan in sorted_scans.iterrows():
                density, vulnerable_count, package_count, status = (
                    calculate_vulnerability_density(
                        scan.get("raw_report")
                    )
                )

                if status == "calculated":
                    selected_metrics = (
                        density,
                        vulnerable_count,
                        package_count,
                    )
                    selected_scan = scan
                    break

            if selected_metrics is not None:
                density, vulnerable_count, package_count = selected_metrics

                col1, col2, col3 = st.columns(3)

                col1.metric(
                    "Vulnerability Density",
                    f"{density:.2f}%",
                )
                col2.metric("Vulnerable Packages", vulnerable_count)
                col3.metric("Total Packages", package_count)

                st.caption(
                    "VD = distinct vulnerable package/version pairs "
                    "÷ distinct scanned package/version pairs × 100."
                )
                st.caption(
                    f"Calculated from scan target: "
                    f"{selected_scan.get('target', 'unknown')} "
                    f"(scan ID {selected_scan.get('id', 'unknown')})."
                )
            else:
                st.info(
                    "Vulnerability Density is unavailable because "
                    "none of the saved reports contains a usable "
                    "package inventory. Ensure Trivy includes package "
                    "inventory in its JSON report."
                )

        st.divider()
        st.subheader("Severity findings per scan")

        melted = df.melt(
            id_vars=["target", "scan_type", "created_at"],
            value_vars=[
                "critical_count",
                "high_count",
                "medium_count",
                "low_count",
            ],
            var_name="severity",
            value_name="count",
        )

        fig = px.bar(
            melted,
            x="target",
            y="count",
            color="severity",
            barmode="stack",
            title="Trivy findings by severity",
        )
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("Recent scan results")

        st.dataframe(
            df[
                [
                    "created_at",
                    "scan_type",
                    "target",
                    "passed",
                    "critical_count",
                    "high_count",
                    "medium_count",
                    "low_count",
                ]
            ].sort_values("created_at", ascending=False),
            use_container_width=True,
        )


# ---------------- Falco runtime events ----------------

with tab_runtime:
    df = fetch("runtime-events")

    if df.empty:
        st.info(
            "No runtime events yet. Deploy to Minikube with Falco "
            "running, or POST a test event to /runtime-events."
        )
    else:
        col1, col2 = st.columns(2)

        col1.metric("Total Falco alerts", len(df))
        col2.metric(
            "Critical alerts",
            int((df["priority"] == "CRITICAL").sum()),
        )

        st.subheader("Alerts by priority")

        counts = df["priority"].value_counts().reset_index()
        counts.columns = ["priority", "count"]

        fig = px.pie(
            counts,
            names="priority",
            values="count",
            title="Falco alert priority breakdown",
        )
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("Recent runtime events")

        st.dataframe(
            df[
                [
                    "created_at",
                    "priority",
                    "rule",
                    "pod_name",
                    "output",
                ]
            ].sort_values("created_at", ascending=False),
            use_container_width=True,
        )


# ---------------- Isolation Forest anomaly detection ----------------

with tab_anomalies:
    show_fpr_evaluation()

    st.divider()
    st.subheader("📡 Runtime Anomaly Monitoring")

    df = fetch("anomaly-scores", limit=1000)

    if df.empty:
        st.info(
            "No anomaly scores yet. Run "
            "`ml/train_isolation_forest.py` and then "
            "`ml/score_runtime_window.py` to populate this."
        )
    else:
        df["window_start"] = pd.to_datetime(
            df["window_start"],
            errors="coerce",
        )

        col1, col2, col3 = st.columns(3)

        col1.metric("Windows scored", len(df))
        col2.metric(
            "Flagged anomalous",
            int(df["is_anomalous"].astype(bool).sum()),
        )
        col3.metric(
            "Anomaly rate",
            f"{100 * df['is_anomalous'].astype(bool).mean():.1f}%",
        )

        st.subheader("Anomaly score over time")

        fig = px.scatter(
            df.sort_values("window_start"),
            x="window_start",
            y="anomaly_score",
            color="is_anomalous",
            color_discrete_map={
                True: "red",
                False: "steelblue",
            },
            title=(
                "Isolation Forest decision score per window "
                "(lower = more anomalous)"
            ),
        )
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("Feature values for flagged windows")

        flagged = df[df["is_anomalous"].astype(bool)]

        if not flagged.empty:
            st.dataframe(
                flagged[
                    [
                        "window_start",
                        "process_count",
                        "network_conn_count",
                        "file_op_count",
                        "cpu_usage_pct",
                        "mem_usage_pct",
                        "anomaly_score",
                    ]
                ].sort_values(
                    "window_start",
                    ascending=False,
                ),
                use_container_width=True,
            )
        else:
            st.write("No windows currently flagged as anomalous.")


# ---------------- Automated Security Drift Measurement ----------------

with tab_drift:
    st.subheader("🛡️ Equation 3 — Security Drift Percentage (SDP)")
    st.caption(
        "Compares approved Kubernetes security settings from the "
        "manifest with the live deployment returned by the backend."
    )

    if st.button("🔄 Refresh security drift", key="refresh_security_drift"):
        st.cache_data.clear()
        st.rerun()

    try:
        response = requests.get(
            f"{BACKEND_URL}/security-drift",
            timeout=25,
        )
        response.raise_for_status()
        drift_data = response.json()

        drift_percent = drift_data.get("security_drift_percent")
        drifted_count = int(drift_data.get("drifted_checks", 0))
        comparable_count = int(drift_data.get("comparable_checks", 0))
        unknown_count = int(drift_data.get("unknown_checks", 0))
        checks = drift_data.get("checks", [])

        matching_count = sum(
            1 for item in checks if item.get("status") == "match"
        )

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "Security Drift Percentage",
            f"{drift_percent:.2f}%"
            if drift_percent is not None
            else "N/A",
        )
        col2.metric("Matching checks", matching_count)
        col3.metric("Drifted checks", drifted_count)
        col4.metric("Unknown checks", unknown_count)

        if drift_data.get("metric_status") != "calculated":
            st.warning(
                "Security drift could not be calculated because "
                "there are no comparable security checks."
            )
        elif drifted_count > 0:
            st.error(
                f"Security configuration drift detected: {drifted_count} "
                f"of {comparable_count} comparable checks differ."
            )
        elif unknown_count > 0:
            st.warning(
                "No drift was found among comparable checks, but some "
                "checks are unknown. Unknown checks are not compliant."
            )
        else:
            st.success(
                f"No drift detected: all {comparable_count} comparable "
                "security checks match the baseline."
            )

        if drift_percent is not None:
            st.progress(
                max(0.0, min(float(drift_percent) / 100.0, 1.0))
            )
            st.caption(
                "SDP = (drifted security checks ÷ comparable security "
                "checks) × 100. Unknown checks are excluded."
            )

        if checks:
            display_checks = pd.DataFrame(checks)

            st.subheader("Security configuration comparison")
            st.dataframe(
                display_checks,
                use_container_width=True,
                hide_index=True,
            )

            drifted_checks_df = display_checks[
                display_checks["status"] == "drift"
            ]

            if not drifted_checks_df.empty:
                st.subheader("Checks requiring attention")
                st.dataframe(
                    drifted_checks_df,
                    use_container_width=True,
                    hide_index=True,
                )

        with st.expander("View complete API response"):
            st.json(drift_data)

    except requests.RequestException as exc:
        st.error(
            f"Could not retrieve security drift from "
            f"{BACKEND_URL}/security-drift: {exc}"
        )
        st.info(
            "Ensure FastAPI is running and GET /security-drift "
            "works in your browser."
        )
    except (ValueError, TypeError, KeyError) as exc:
        st.error(f"Could not display security drift response: {exc}")


st.divider()
st.caption(
    "Container & Kubernetes Security Scanner — DevSecOps project. "
    "Backend data refreshes every 5 seconds while the dashboard is active."
)
