# NOTE: base image and pinned dependency versions are intentionally a little
# dated so that Trivy has genuine CVEs to report during the Review 2 demo.
# For a production deployment, always use the latest patched base image.
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# Runs as root by default in this base image — flagged deliberately by
# Trivy/kube-bench style checks as a misconfiguration to fix in Review 2.
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
