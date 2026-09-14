# Container & Kubernetes Security Scanner

A DevSecOps system that gates a CI/CD pipeline with automated container/Kubernetes
vulnerability scanning (Trivy) and adds AI-assisted runtime anomaly detection
(Falco + eBPF + Isolation Forest) after deployment. See
`Container_Kubernetes_Security_Scanner_Report.docx` for the full write-up,
literature survey and architecture diagrams — this README is about running
the actual code.

## What's in here

```
app/            Demo target service (FastAPI) that gets built, scanned, deployed
ci-cd/          Jenkinsfile + Trivy scan scripts + security policy config
k8s/            Kubernetes manifests (namespace, hardened deployment, service,
                and one intentionally-insecure manifest for the config-scan demo)
falco/          Falco config + custom runtime detection rules for this project
backend/        FastAPI + SQLite — ingests scan results, Falco alerts, AI scores
ml/             Isolation Forest training + scoring pipeline for runtime anomalies
dashboard/      Streamlit dashboard visualising everything above
scripts/        Orchestration script for the parts you can run without a cluster
.env.example    Config template (Slack webhook, backend URL, DB path)
```

## Two ways to run this

### Option A — Backend + AI + Dashboard only (no Docker/Minikube/Jenkins needed)

This is the fastest way to see the system work end-to-end right now, using
synthetic runtime telemetry standing in for a live Falco feed.

```bash
git clone <this-repo> && cd container-k8s-security-scanner
chmod +x scripts/run_local_demo.sh
./scripts/run_local_demo.sh
```

This will: install dependencies, start the FastAPI backend on `:8000`,
generate synthetic telemetry, train the Isolation Forest, score the telemetry
and publish results to the backend, then launch the Streamlit dashboard on
`:8501`. Open **http://localhost:8501** and check the "AI Anomaly Detection"
tab — you should see ~500 scored windows with a handful flagged anomalous.

### Option B — The full pipeline (Docker, Minikube, Jenkins, Falco required)

This is what actually demonstrates the CI/CD security gate and runtime
monitoring described in the project report. You'll need these installed
locally: Docker, Minikube, kubectl, Jenkins (with Docker/Trivy/kubectl
available to its agent), Trivy CLI, and Falco (via the official Helm chart).

1. **Start Minikube and create the namespace**
   ```bash
   minikube start
   kubectl apply -f k8s/namespace.yaml
   ```

2. **Install Falco with this project's config and rules**
   ```bash
   helm repo add falcosecurity https://falcosecurity.github.io/charts
   helm install falco falcosecurity/falco -n falco --create-namespace \
     --set-file falco.yaml=falco/falco.yaml \
     --set-file customRules."falco_rules\.local\.yaml"=falco/falco_rules.local.yaml
   ```

3. **Point Jenkins at this repo** and create a Pipeline job using
   `ci-cd/Jenkinsfile`. Add a Slack Incoming Webhook credential named
   `slack-webhook-url` (see `.env.example` for where to generate one).

4. **Run the backend and dashboard** (as in Option A, steps 2 and 5 of
   `run_local_demo.sh` — you can run just those two if you want the pipeline
   to publish into a live backend instead of the synthetic demo).

5. **Trigger the Jenkins build.** It will build the demo image, run Trivy
   against the image and the `k8s/` manifests, block deployment and post to
   Slack if CRITICAL/HIGH findings exist, or deploy to Minikube if the gate
   passes.

6. **Watch runtime alerts arrive.** Once deployed, generate some traffic
   against the demo service (`kubectl port-forward` + `curl`), then try
   triggering one of the custom Falco rules — e.g. `kubectl exec` into the
   pod and run `sh` to trigger the "Shell Spawned" rule. Falco will POST the
   alert to the backend's `/runtime-events` endpoint automatically per the
   `falco/falco.yaml` config, and it'll show up on the dashboard.

7. **Feed real telemetry to the AI model.** Once you have real Falco JSON
   logs (`falco/falco.yaml` writes them to `/var/log/falco/events.log`),
   use `ml/feature_extraction.py` to convert them into the same feature
   schema `simulate_telemetry.py` produces, then retrain with
   `ml/train_isolation_forest.py` on real data instead of synthetic.

## How this maps to your review stages

| Review | What to demo | Where it lives |
|---|---|---|
| Review 1 | Architecture, literature survey, planning | `Container_Kubernetes_Security_Scanner_Report.docx` |
| Review 2 | Jenkins pipeline + Trivy gating | `ci-cd/`, `app/` |
| Review 3 | Minikube deployment + Falco runtime monitoring | `k8s/`, `falco/` |
| Review 4 | Isolation Forest anomaly detection | `ml/`, `backend/` |
| Final Review | End-to-end demo + dashboard | `dashboard/`, `scripts/run_local_demo.sh` |

## Troubleshooting

- **`pip install` fails on your machine**: use a virtualenv per component
  (`python3 -m venv .venv && source .venv/bin/activate`) to avoid conflicting
  with system packages.
- **Dashboard shows "Could not reach backend"**: make sure `uvicorn main:app`
  is running in `backend/` first, and that `BACKEND_URL` matches (defaults to
  `http://localhost:8000`).
- **Trivy scan passes locally but you want to see it fail on purpose**: pin
  an older package in `app/requirements.txt` (it already has slightly dated
  versions) or lower `TRIVY_SEVERITY` to include `MEDIUM` in
  `ci-cd/trivy/trivy-policy.yaml`.
- **Falco Helm install fails**: eBPF requires a reasonably recent kernel;
  Minikube's default driver usually handles this fine, but if not, add
  `--set driver.kind=modern-ebpf` to the Helm install command.

## Notes on what's simulated vs. real

Everything in `backend/`, `ml/`, and `dashboard/` is fully functional Python
that was built and tested end-to-end (SQLite persistence, Isolation Forest
training/scoring, and the Streamlit UI all confirmed working). `app/`,
`k8s/`, `ci-cd/`, and `falco/` are complete, correct configuration and
pipeline code, but need Docker/Minikube/Jenkins/Falco actually installed on
your machine to run — that infrastructure isn't available in the environment
this project was built in. `ml/simulate_telemetry.py` generates realistic
synthetic runtime data so you can validate the AI pipeline today; swap it
for `ml/feature_extraction.py` once Falco is live on your cluster.
