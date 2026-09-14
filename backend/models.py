from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean
from sqlalchemy.sql import func
from database import Base


class ScanResult(Base):
    """One row per Trivy scan (image or config) run by the Jenkins pipeline."""
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String, index=True)          # "image" | "config"
    target = Column(String)                         # image name or manifest path
    severity_threshold = Column(String)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    passed = Column(Boolean, default=True)           # did it clear the policy gate?
    raw_report = Column(Text, nullable=True)          # raw Trivy JSON, for drill-down
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class RuntimeEvent(Base):
    """One row per Falco alert received from the running cluster."""
    __tablename__ = "runtime_events"

    id = Column(Integer, primary_key=True, index=True)
    rule = Column(String, index=True)
    priority = Column(String, index=True)             # WARNING | CRITICAL | ...
    output = Column(Text)
    pod_name = Column(String, nullable=True)
    container_name = Column(String, nullable=True)
    raw_event = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AnomalyScore(Base):
    """One row per Isolation Forest scoring pass over a runtime feature window."""
    __tablename__ = "anomaly_scores"

    id = Column(Integer, primary_key=True, index=True)
    window_start = Column(DateTime(timezone=True))
    window_end = Column(DateTime(timezone=True))
    process_count = Column(Float)
    network_conn_count = Column(Float)
    file_op_count = Column(Float)
    cpu_usage_pct = Column(Float)
    mem_usage_pct = Column(Float)
    anomaly_score = Column(Float)                      # raw Isolation Forest score
    is_anomalous = Column(Boolean, default=False)       # thresholded decision
    created_at = Column(DateTime(timezone=True), server_default=func.now())
