
from collections import Counter
from pathlib import Path
import json
import subprocess

from typing import List

import yaml

from fastapi import FastAPI, Depends, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

import crud
import models
import schemas
from database import engine, get_db
from slack_alert import send_slack_alert


# ---------------------- Database initialization ----------------------

models.Base.metadata.create_all(bind=engine)


# ---------------------- FastAPI application ----------------------

app = FastAPI(
    title="Container & Kubernetes Security Scanner — Backend",
    description=(
        "Ingestion API for Trivy scan results, Falco runtime events, "
        "Isolation Forest anomaly scores, vulnerability density, "
        "and automated Kubernetes security drift measurement."
    ),
    version="1.3.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Local demo only; restrict in production.
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------- Mathematical metrics ----------------------

def calculate_vulnerability_density(report: dict) -> dict:
    """
    Vulnerability Density = (V / P) * 100

    V = distinct vulnerable package name/version pairs
        that exist in the package inventory.
    P = distinct package name/version pairs in the inventory.

    Returns None for density when usable package inventory is missing.
    """
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

    matched_vulnerable_packages = vulnerable_packages & total_packages
    vulnerable_count = len(matched_vulnerable_packages)

    if package_count == 0:
        density = None
        status = "unavailable_package_inventory_missing"
    else:
        density = round(
            (vulnerable_count / package_count) * 100,
            2,
        )
        status = "calculated"

    return {
        "total_packages": package_count,
        "vulnerable_packages": vulnerable_count,
        "vulnerability_density_percent": density,
        "metric_status": status,
    }


# ---------------------- Health check ----------------------

@app.get("/health")
def health():
    return {"status": "ok"}


# ---------------------- Pre-deployment: Trivy scan results ----------------------

@app.post(
    "/scan-results",
    response_model=schemas.ScanResultOut,
)
def create_scan_result(
    item: schemas.ScanResultIn,
    db: Session = Depends(get_db),
):
    row = crud.create_scan_result(db, item)

    if not row.passed:
        send_slack_alert(
            f"🛑 Security gate FAILED for {row.target} "
            f"({row.scan_type} scan): "
            f"{row.critical_count} CRITICAL / "
            f"{row.high_count} HIGH findings."
        )

    return row


@app.post("/ingest/trivy-report", response_model=None)
def ingest_trivy_report(
    payload: dict,
    scan_type: str = "image",
    target: str = "unknown",
    db: Session = Depends(get_db),
):
    """
    Accept a raw Trivy JSON report, count vulnerability and
    misconfiguration findings, calculate Vulnerability Density,
    and save the scan result.
    """
    counts = Counter()

    for result in payload.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            counts[vuln.get("Severity", "UNKNOWN").upper()] += 1

        for mis in result.get("Misconfigurations", []) or []:
            counts[mis.get("Severity", "UNKNOWN").upper()] += 1

    passed = (
        counts.get("CRITICAL", 0) == 0
        and counts.get("HIGH", 0) == 0
    )

    density_metrics = calculate_vulnerability_density(payload)

    item = schemas.ScanResultIn(
        scan_type=scan_type,
        target=target,
        critical_count=counts.get("CRITICAL", 0),
        high_count=counts.get("HIGH", 0),
        medium_count=counts.get("MEDIUM", 0),
        low_count=counts.get("LOW", 0),
        passed=passed,
        raw_report=str(payload)[:20000],
    )

    row = crud.create_scan_result(db, item)

    if not row.passed:
        send_slack_alert(
            f"🛑 Security gate FAILED for {target} "
            f"({scan_type} scan): "
            f"{row.critical_count} CRITICAL / "
            f"{row.high_count} HIGH findings."
        )

    response = jsonable_encoder(row)
    response["vulnerability_density"] = density_metrics

    return response


@app.get(
    "/scan-results",
    response_model=List[schemas.ScanResultOut],
)
def get_scan_results(
    limit: int = 100,
    db: Session = Depends(get_db),
):
    return crud.list_scan_results(db, limit)


# ---------------------- Post-deployment: Falco runtime events ----------------------

@app.post(
    "/runtime-events",
    response_model=schemas.RuntimeEventOut,
)
def create_runtime_event(
    item: schemas.RuntimeEventIn,
    db: Session = Depends(get_db),
):
    row = crud.create_runtime_event(db, item)

    if row.priority in ("CRITICAL", "EMERGENCY", "ALERT"):
        send_slack_alert(
            f"🚨 Falco alert [{row.priority}] "
            f"{row.rule}: {row.output}"
        )

    return row


@app.get(
    "/runtime-events",
    response_model=List[schemas.RuntimeEventOut],
)
def get_runtime_events(
    limit: int = 100,
    db: Session = Depends(get_db),
):
    return crud.list_runtime_events(db, limit)


# ---------------------- AI layer: Isolation Forest anomaly scores ----------------------

@app.post(
    "/anomaly-scores",
    response_model=schemas.AnomalyScoreOut,
)
def create_anomaly_score(
    item: schemas.AnomalyScoreIn,
    db: Session = Depends(get_db),
):
    row = crud.create_anomaly_score(db, item)

    if row.is_anomalous:
        send_slack_alert(
            f"⚠️ AI anomaly detected "
            f"(score={row.anomaly_score:.3f}) "
            f"in window {row.window_start} → {row.window_end}."
        )

    return row


@app.get(
    "/anomaly-scores",
    response_model=List[schemas.AnomalyScoreOut],
)
def get_anomaly_scores(
    limit: int = 200,
    db: Session = Depends(get_db),
):
    return crud.list_anomaly_scores(db, limit)


# ---------------------- Automated Security Drift Measurement ----------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BASELINE_FILE = PROJECT_ROOT / "k8s" / "deployment.yaml"

# The paths are relative to the Deployment object.
SECURITY_CHECKS = {
    "runAsNonRoot": (
        "spec", "template", "spec", "containers", 0,
        "securityContext", "runAsNonRoot"
    ),
    "runAsUser": (
        "spec", "template", "spec", "containers", 0,
        "securityContext", "runAsUser"
    ),
    "allowPrivilegeEscalation": (
        "spec", "template", "spec", "containers", 0,
        "securityContext", "allowPrivilegeEscalation"
    ),
    "readOnlyRootFilesystem": (
        "spec", "template", "spec", "containers", 0,
        "securityContext", "readOnlyRootFilesystem"
    ),
    "capabilities.drop": (
        "spec", "template", "spec", "containers", 0,
        "securityContext", "capabilities", "drop"
    ),
    "fsGroup": (
        "spec", "template", "spec", "securityContext", "fsGroup"
    ),
}


def get_nested_value(data, path):
    """Return (value, found) for a nested dictionary/list path."""
    current = data

    for key in path:
        if isinstance(current, dict) and key in current:
            current = current[key]
        elif isinstance(current, list) and isinstance(key, int):
            if 0 <= key < len(current):
                current = current[key]
            else:
                return None, False
        else:
            return None, False

    return current, True


def values_match(check_name, expected, actual):
    """Compare security settings, ignoring list order for capabilities."""
    if check_name == "capabilities.drop":
        return (
            isinstance(expected, list)
            and isinstance(actual, list)
            and set(expected) == set(actual)
        )

    return expected == actual


@app.get("/security-drift")
def get_security_drift():
    """
    Compare security settings in the approved manifest against
    the live Kubernetes Deployment.

    SDP = (drifted checks / comparable checks) * 100.

    Unknown checks are excluded from the denominator.
    """
    # Load the approved manifest.
    if not BASELINE_FILE.is_file():
        raise HTTPException(
            status_code=500,
            detail=f"Approved baseline not found: {BASELINE_FILE}",
        )

    try:
        with BASELINE_FILE.open("r", encoding="utf-8") as file:
            baseline = yaml.safe_load(file)
    except (OSError, yaml.YAMLError) as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Could not read approved baseline: {exc}",
        )

    if not isinstance(baseline, dict):
        raise HTTPException(
            status_code=500,
            detail="The approved baseline is not a valid Kubernetes object.",
        )

    # Retrieve the live deployment.
    try:
        result = subprocess.run(
            [
                "kubectl",
                "get",
                "deployment",
                "demo-target-service",
                "-n",
                "secure-devops-demo",
                "-o",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=503,
            detail="Timed out while querying Kubernetes.",
        )
    except OSError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Could not execute kubectl: {exc}",
        )

    if result.returncode != 0:
        raise HTTPException(
            status_code=503,
            detail=(
                "Kubernetes query failed. Check Minikube and kubectl. "
                + result.stderr.strip()
            ),
        )

    try:
        live = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=502,
            detail="Kubernetes returned invalid JSON.",
        )

    checks = []
    drifted_count = 0
    comparable_count = 0
    unknown_count = 0

    for name, path in SECURITY_CHECKS.items():
        expected, expected_found = get_nested_value(baseline, path)
        actual, actual_found = get_nested_value(live, path)

        if not expected_found or not actual_found:
            status = "unknown"
            unknown_count += 1
        else:
            comparable_count += 1

            if values_match(name, expected, actual):
                status = "match"
            else:
                status = "drift"
                drifted_count += 1

        checks.append({
            "check": name,
            "expected": expected if expected_found else None,
            "actual": actual if actual_found else None,
            "status": status,
        })

    drift_percent = (
        round((drifted_count / comparable_count) * 100, 2)
        if comparable_count > 0
        else None
    )

    return {
        "metric": "Security Drift Percentage (SDP)",
        "formula": "(drifted_checks / comparable_checks) * 100",
        "namespace": "secure-devops-demo",
        "deployment": "demo-target-service",
        "drifted_checks": drifted_count,
        "comparable_checks": comparable_count,
        "unknown_checks": unknown_count,
        "security_drift_percent": drift_percent,
        "metric_status": (
            "calculated" if comparable_count > 0 else "unavailable"
        ),
        "checks": checks,
    }
