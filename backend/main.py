from collections import Counter
from typing import List

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

import crud
import models
import schemas
from database import engine, get_db
from slack_alert import send_slack_alert

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Container & Kubernetes Security Scanner — Backend",
    description="Ingestion API for Trivy scan results, Falco runtime events, "
                "and Isolation Forest anomaly scores.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # local demo only — restrict in a real deployment
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok"}


# ---------------------- Pre-deployment: Trivy scan results ----------------------

@app.post("/scan-results", response_model=schemas.ScanResultOut)
def create_scan_result(item: schemas.ScanResultIn, db: Session = Depends(get_db)):
    row = crud.create_scan_result(db, item)
    if not row.passed:
        send_slack_alert(
            f"🛑 Security gate FAILED for {row.target} ({row.scan_type} scan): "
            f"{row.critical_count} CRITICAL / {row.high_count} HIGH findings."
        )
    return row


@app.post("/ingest/trivy-report", response_model=schemas.ScanResultOut)
def ingest_trivy_report(payload: dict, scan_type: str = "image", target: str = "unknown", db: Session = Depends(get_db)):
    """Accepts a raw `trivy image ... --format json` / `trivy config ... --format json`
    document straight from the Jenkins pipeline and converts it into a ScanResult row.
    """
    counts = Counter()
    for result in payload.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            counts[vuln.get("Severity", "UNKNOWN")] += 1
        for mis in result.get("Misconfigurations", []) or []:
            counts[mis.get("Severity", "UNKNOWN")] += 1

    passed = counts.get("CRITICAL", 0) == 0 and counts.get("HIGH", 0) == 0

    item = schemas.ScanResultIn(
        scan_type=scan_type,
        target=target,
        critical_count=counts.get("CRITICAL", 0),
        high_count=counts.get("HIGH", 0),
        medium_count=counts.get("MEDIUM", 0),
        low_count=counts.get("LOW", 0),
        passed=passed,
        raw_report=str(payload)[:20000],  # cap stored size for the SQLite demo db
    )
    row = crud.create_scan_result(db, item)
    if not row.passed:
        send_slack_alert(
            f"🛑 Security gate FAILED for {target} ({scan_type} scan): "
            f"{row.critical_count} CRITICAL / {row.high_count} HIGH findings."
        )
    return row


@app.get("/scan-results", response_model=List[schemas.ScanResultOut])
def get_scan_results(limit: int = 100, db: Session = Depends(get_db)):
    return crud.list_scan_results(db, limit)


# ---------------------- Post-deployment: Falco runtime events ----------------------

@app.post("/runtime-events", response_model=schemas.RuntimeEventOut)
def create_runtime_event(item: schemas.RuntimeEventIn, db: Session = Depends(get_db)):
    row = crud.create_runtime_event(db, item)
    if row.priority in ("CRITICAL", "EMERGENCY", "ALERT"):
        send_slack_alert(f"🚨 Falco alert [{row.priority}] {row.rule}: {row.output}")
    return row


@app.get("/runtime-events", response_model=List[schemas.RuntimeEventOut])
def get_runtime_events(limit: int = 100, db: Session = Depends(get_db)):
    return crud.list_runtime_events(db, limit)


# ---------------------- AI layer: Isolation Forest anomaly scores ----------------------

@app.post("/anomaly-scores", response_model=schemas.AnomalyScoreOut)
def create_anomaly_score(item: schemas.AnomalyScoreIn, db: Session = Depends(get_db)):
    row = crud.create_anomaly_score(db, item)
    if row.is_anomalous:
        send_slack_alert(
            f"⚠️ AI anomaly detected (score={row.anomaly_score:.3f}) in window "
            f"{row.window_start} → {row.window_end}."
        )
    return row


@app.get("/anomaly-scores", response_model=List[schemas.AnomalyScoreOut])
def get_anomaly_scores(limit: int = 200, db: Session = Depends(get_db)):
    return crud.list_anomaly_scores(db, limit)
