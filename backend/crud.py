from sqlalchemy.orm import Session
from sqlalchemy import desc
import models
import schemas


def create_scan_result(db: Session, item: schemas.ScanResultIn) -> models.ScanResult:
    row = models.ScanResult(**item.model_dump())
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_scan_results(db: Session, limit: int = 100):
    return db.query(models.ScanResult).order_by(desc(models.ScanResult.created_at)).limit(limit).all()


def create_runtime_event(db: Session, item: schemas.RuntimeEventIn) -> models.RuntimeEvent:
    row = models.RuntimeEvent(**item.model_dump())
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_runtime_events(db: Session, limit: int = 100):
    return db.query(models.RuntimeEvent).order_by(desc(models.RuntimeEvent.created_at)).limit(limit).all()


def create_anomaly_score(db: Session, item: schemas.AnomalyScoreIn) -> models.AnomalyScore:
    row = models.AnomalyScore(**item.model_dump())
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_anomaly_scores(db: Session, limit: int = 200):
    return db.query(models.AnomalyScore).order_by(desc(models.AnomalyScore.created_at)).limit(limit).all()
