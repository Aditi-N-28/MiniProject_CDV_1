import json
import subprocess
import requests

FASTAPI_URL = "http://localhost:8000/runtime-events"
FALCO_POD = "falco-bwv7h"


def send_event(event):
    output_fields = event.get("output_fields", {})

    payload = {
        "rule": event.get("rule", "Unknown"),
        "priority": event.get("priority", "INFO").upper(),
        "output": event.get("output", ""),
        "pod_name": output_fields.get("k8s.pod.name"),
        "container_name": output_fields.get("container.name"),
        "raw_event": json.dumps(event),
    }

    try:
        response = requests.post(
            FASTAPI_URL,
            json=payload,
            timeout=5
        )

        if response.status_code == 200:
            print(
                f"[OK] {payload['priority']} | "
                f"{payload['rule']} | "
                f"pod={payload['pod_name']}",
                flush=True
            )
        else:
            print(
                f"[ERROR] FastAPI {response.status_code}: "
                f"{response.text}",
                flush=True
            )

    except requests.RequestException as e:
        print(f"[ERROR] FastAPI connection: {e}", flush=True)


print("[INFO] Starting Falco log collector...", flush=True)

process = subprocess.Popen(
    [
        "kubectl",
        "logs",
        "-n",
        "falco",
        "-f",
        FALCO_POD,
        "-c",
        "falco",
        "--since=5s"
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1
)

for line in process.stdout:
    line = line.strip()

    if not line:
        continue

    if not line.startswith("{"):
        continue

    try:
        event = json.loads(line)

        if "rule" in event and "priority" in event:
            send_event(event)

    except json.JSONDecodeError:
        continue