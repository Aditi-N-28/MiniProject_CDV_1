#!/usr/bin/env bash
# Scans Kubernetes manifests / IaC files for misconfigurations
# (privileged containers, missing resource limits, running as root, etc.)
set -euo pipefail

TARGET_DIR="${1:-./k8s}"
SEVERITY="${TRIVY_SEVERITY:-CRITICAL,HIGH}"
REPORT_DIR="${TRIVY_REPORT_DIR:-./trivy-reports}"

mkdir -p "$REPORT_DIR"

echo "== Trivy config/IaC scan: $TARGET_DIR (severity threshold: $SEVERITY) =="

trivy config \
  --exit-code 1 \
  --severity "$SEVERITY" \
  --format table \
  "$TARGET_DIR" | tee "$REPORT_DIR/config-scan-report.txt"

trivy config \
  --severity "$SEVERITY" \
  --format json \
  --output "$REPORT_DIR/config-scan-report.json" \
  "$TARGET_DIR" || true

echo "== Trivy config scan passed: no $SEVERITY misconfigurations found =="
