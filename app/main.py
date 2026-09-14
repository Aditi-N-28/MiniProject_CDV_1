"""
Demo target application for the Container & Kubernetes Security Scanner project.

This is deliberately a small, simple service — its only purpose is to be the
thing that Jenkins builds into a Docker image, that Trivy scans, and that gets
deployed to Minikube so Falco has something real to watch at runtime. It is
NOT the security tooling itself (that lives in backend/, ml/, dashboard/).
"""
from fastapi import FastAPI
from datetime import datetime

app = FastAPI(title="Demo Target Service", version="1.0.0")


@app.get("/")
def root():
    return {
        "service": "demo-target-service",
        "status": "running",
        "time": datetime.utcnow().isoformat(),
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/work")
def do_work():
    # Simulates a small bit of "normal" application behaviour
    # (harmless file read) so Falco has non-trivial syscalls to observe.
    with open("/etc/hostname") as f:
        hostname = f.read().strip()
    return {"processed_on": hostname}
