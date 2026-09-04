# SRE Agent (`sre.kubebee.com`)

An intelligent, proactive Kubernetes SRE Agent written in Go that autonomously detects cluster anomalies, triages root causes using external LLMs or agent harnesses (Claude, Codex/GPT-4o, DeepSeek, or CLI agent harness), and proposes safe remediations that execute **strictly with explicit human permission**.

---

## Key Highlights

- **Proactive Cluster Telemetry Scanning:**
  Continuously monitors Kubernetes workloads for anomalies:
  - `CrashLoopBackOff` & high restart frequency
  - `OOMKilled` (exit code 137 / cgroup memory limits)
  - `ImagePullBackOff` & `ErrImagePull`
  - Container configuration errors & probe failures
  - Unschedulable / Pending pods & PVC volume claims
  - Node conditions & resource pressures (`DiskPressure`, `MemoryPressure`, `PIDPressure`)
  - Services with 0 ready endpoints
  - Warning events and tail log capture

- **Multi-Model Triage Engine (No Ollama):**
  - **Claude** (Anthropic `claude-3-7-sonnet`, `claude-3-5-sonnet`)
  - **Codex / OpenAI** (`gpt-4o`, `o1`, `gpt-4-turbo`)
  - **DeepSeek** (`deepseek-chat`, `deepseek-reasoner` V3/R1)
  - **External Agent Harness** (Executes modular CLI harnesses like Claude Code or DeepSeek CLI)
  - **Rule-Based SRE Engine** (Offline, zero-API fallback with deterministic diagnoses)

- **Strict Permission-Gated Remediation:**
  - **Zero blind mutations**: All diagnoses start in `PENDING_APPROVAL` status.
  - Remediation actions (pod restart, node cordon, pod cleanup, gitops PR proposals) are **blocked** until an SRE approves them via the Web Dashboard or REST API.
  - Full audit trail of approvals, rejections, timestamps, and execution output.

- **Automated Credential Sanitizer:**
  Logs, events, and configuration snippets are scrubbed before sending to LLM APIs. Automatically redacts:
  - Private keys (`-----BEGIN RSA PRIVATE KEY-----`)
  - Bearer tokens and JWTs
  - Passwords, API keys, and auth secrets (`token=`, `password=`, `api_key=`)
  - Sensitive environment variables (`*SECRET*`, `*KEY*`, `*PASSWORD*`)

- **Built-in Web Dashboard & Notification Webhooks:**
  - Embedded responsive dark-mode Tailwind UI served directly from the single binary.
  - Real-time cluster health summary, anomaly browser, pod log inspector, and pending approval action center.
  - Dispatches Slack/Discord notifications with direct approval links on critical incidents.

---

## Architecture

```
                    ┌─────────────────────────┐
                    │   Kubernetes Cluster    │
                    │ (Pods, Nodes, Logs, Ev) │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │   Telemetry Scanner     │
                    │  (Deterministic Rules)  │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │   Sensitive Sanitizer   │
                    │ (Redact Keys, Tokens)   │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │    LLM Triage Engine    │
                    │ Claude / Codex / DS /   │
                    │ External Agent Harness  │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │  Remediation Engine     │
                    │ (Status: PENDING_APPR)  │
                    └────────────┬────────────┘
                                 │
         ┌───────────────────────┴───────────────────────┐
         ▼                                               ▼
┌─────────────────────────┐                     ┌─────────────────────────┐
│ Webhook (Slack/Discord) │                     │  Web UI & Approval API  │
│  "Incident Detected!"   │                     │  (sre.kubebee.com)      │
└─────────────────────────┘                     └────────────┬────────────┘
                                                             │
                                                    [Approve / Reject]
                                                             │
                                                             ▼
                                                ┌─────────────────────────┐
                                                │   Permission-Gated      │
                                                │    Action Executor      │
                                                └─────────────────────────┘
```

---

## Configuration

| Flag | Environment Variable | Default | Description |
|---|---|---|---|
| `-llm-provider` | `LLM_PROVIDER` | `claude` | LLM provider: `claude`, `codex`, `deepseek`, `harness`, `rule-based` |
| `-llm-api-key` | `LLM_API_KEY` | `""` | API key for Anthropic, OpenAI, or DeepSeek |
| `-llm-model` | `LLM_MODEL` | `""` | Model override (e.g. `claude-3-7-sonnet`, `gpt-4o`, `deepseek-chat`) |
| `-llm-base-url` | `LLM_BASE_URL` | `""` | Custom API endpoint for OpenAI or DeepSeek compatible endpoints |
| `-harness-command` | `HARNESS_COMMAND` | `""` | CLI command path when using external agent harness |
| `-scan-interval` | `SCAN_INTERVAL` | `2m` | Interval between proactive cluster scans |
| `-namespace` | `SCAN_NAMESPACE` | `""` | Target namespace (empty for all namespaces) |
| `-public-url` | `PUBLIC_URL` | `https://sre.kubebee.com` | Public URL for approval action links in alerts |
| `-webhook-url` | `WEBHOOK_URL` | `""` | Slack or Discord incoming webhook URL |
| `-port` | `PORT` | `8080` | HTTP dashboard and API server port |
| `-kubeconfig` | `KUBECONFIG` | `""` | Kubeconfig file path (empty for in-cluster ServiceAccount) |

---

## Getting Started

### Local Development

```bash
# Build binary
make build

# Run unit tests
make test

# Run locally with offline rule-based triage
./bin/sre-agent -kubeconfig ~/.kube/config -llm-provider rule-based -port 8080

# Run locally with Claude 3.7 Sonnet
export LLM_API_KEY="sk-ant-..."
./bin/sre-agent -kubeconfig ~/.kube/config -llm-provider claude -llm-model claude-3-7-sonnet-20250219
```

Access the dashboard at `http://localhost:8080`.

---

## Deployment to Kubernetes

Manifests are provided under `deploy/k8s/`:

```bash
# 1. Create secrets with your LLM API Key
kubectl create secret generic sre-agent-secrets -n sre \
  --from-literal=LLM_API_KEY="sk-..." \
  --from-literal=WEBHOOK_URL="https://hooks.slack.com/services/..."

# 2. Deploy all resources via Kustomize
kubectl apply -k deploy/k8s/
```

This sets up:
- Dedicated `sre` namespace
- Least-privilege RBAC `ServiceAccount`, `ClusterRole`, and `ClusterRoleBinding`
- `Deployment` with non-root security context and resource bounds
- `Service` & `Ingress` with automatic Let's Encrypt TLS for `sre.kubebee.com`

---

## API Endpoints

- `GET /api/status`: System status, active provider, scan timestamps, and pending approval count.
- `GET /api/issues`: List of active cluster anomalies detected in latest scan.
- `GET /api/proposals`: List of triage diagnoses and remediation proposals.
- `POST /api/proposals/{id}/approve`: Explicitly authorize and trigger execution of remediation.
- `POST /api/proposals/{id}/reject`: Reject proposal and record rationale.
- `POST /api/scan`: Trigger an on-demand cluster telemetry scan.