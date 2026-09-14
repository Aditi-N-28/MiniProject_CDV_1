#!/usr/bin/env bash
# Scans the built Docker image for known CVEs.
# Exit code 1 means the configured severity threshold was breached, which
# Jenkins will read as a failed stage and use to block deployment.
set -euo pipefail

IMAGE_NAME="${1:-demo-target-service:latest}"
SEVERITY="${TRIVY_SEVERITY:-CRITICAL,HIGH}"
REPORT_DIR="${TRIVY_REPORT_DIR:-./trivy-reports}"

mkdir -p "$REPORT_DIR"

echo "== Trivy image scan: $IMAGE_NAME (severity threshold: $SEVERITY) =="

trivy image \
  --exit-code 1 \
  --severity "$SEVERITY" \
  --ignore-unfixed \
  --format table \
  "$IMAGE_NAME" | tee "$REPORT_DIR/image-scan-report.txt"

# Also emit a JSON report for the FastAPI backend to ingest.
trivy image \
  --severity "$SEVERITY" \
  --format json \
  --output "$REPORT_DIR/image-scan-report.json" \
  "$IMAGE_NAME" || true

echo "== Trivy image scan passed: no $SEVERITY vulnerabilities found =="
