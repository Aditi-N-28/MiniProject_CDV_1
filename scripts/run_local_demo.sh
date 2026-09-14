#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if command -v python3 >/dev/null 2>&1 && python3 --version >/dev/null 2>&1; then
	PY_CMD="python3"
elif command -v python >/dev/null 2>&1 && python --version >/dev/null 2>&1; then
	PY_CMD="python"
else
	echo "ERROR: no working Python found."
	exit 1
fi

echo "Using Python: $PY_CMD ($($PY_CMD --version))"
echo "== 1/5: Installing backend dependencies =="
"$PY_CMD" -m pip install -q -r "$ROOT_DIR/backend/requirements.txt"

echo "== 2/5: Starting FastAPI backend on :8000 =="
cd "$ROOT_DIR/backend"
rm -f security_scanner.db
nohup "$PY_CMD" -m uvicorn main:app --host 0.0.0.0 --port 8000 > backend.log 2>&1 &
BACKEND_PID=$!
echo "Backend PID: $BACKEND_PID"
sleep 3

echo "== 3/5: Generating telemetry and training model =="
cd "$ROOT_DIR/ml"
"$PY_CMD" -m pip install -q -r requirements.txt
"$PY_CMD" simulate_telemetry.py
"$PY_CMD" train_isolation_forest.py

echo "== 4/5: Scoring and publishing to backend =="
"$PY_CMD" score_runtime_window.py --backend-url http://localhost:8000

echo "== 5/5: Launching dashboard on :8501 =="
cd "$ROOT_DIR/dashboard"
"$PY_CMD" -m pip install -q -r requirements.txt
BACKEND_URL=http://localhost:8000 "$PY_CMD" -m streamlit run streamlit_app.py &
DASHBOARD_PID=$!

echo "Backend: http://localhost:8000/docs"
echo "Dashboard: http://localhost:8501"
echo "To stop: kill $BACKEND_PID $DASHBOARD_PID"
waitcd