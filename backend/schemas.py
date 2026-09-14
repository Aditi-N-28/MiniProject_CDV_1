from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class ScanResultIn(BaseModel):
    scan_type: str
    target: str
    severity_threshold: str = "CRITICAL,HIGH"
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    passed: bool = True
    raw_report: Optional[str] = None


class ScanResultOut(ScanResultIn):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime


class RuntimeEventIn(BaseModel):
    rule: str
    priority: str
    output: str
    pod_name: Optional[str] = None
    container_name: Optional[str] = None
    raw_event: Optional[str] = None


class RuntimeEventOut(RuntimeEventIn):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime


class AnomalyScoreIn(BaseModel):
    window_start: datetime
    window_end: datetime
    process_count: float
    network_conn_count: float
    file_op_count: float
    cpu_usage_pct: float
    mem_usage_pct: float
    anomaly_score: float
    is_anomalous: bool = False


class AnomalyScoreOut(AnomalyScoreIn):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime
