# SRE Agent (`sre.kubebee.com`)

An intelligent, proactive Kubernetes SRE Agent written in Go that provides full **K8sGPT-compatible anomaly scanning & analyzers**, **cluster hygiene & error pod clean up**, **multi-LLM triage** (Claude, Codex/GPT-4o, DeepSeek, or CLI agent harness), an **interactive dark-mode Web UI**, and **rich notifications with approval actions for Slack, Discord, and Microsoft Teams**.

All remediation actions execute **strictly with explicit human permission**.

---

## Complete Feature Matrix

### 1. K8sGPT-Compatible Analyzers

| Analyzer | Resource | Failure Modes Detected |
|---|---|---|
| **`PodAnalyzer`** | Pod | `CrashLoopBackOff`, `OOMKilled` (exit 137), `ImagePullBackOff`, `CreateContainerConfigError`, `Evicted`, `StuckTerminating` (> 5m), High Restarts (> 5), probe failures, and unschedulable pending states. |
| **`DeploymentAnalyzer`** | Deployment | Ready replica deficits (`status.readyReplicas < spec.replicas`), unavailable replicas, and rollout progress deadline failures. |
| **`StatefulSetAnalyzer`** | StatefulSet | Partition blocks, ready replica mismatches, and unready stateful pods. |
| **`DaemonSetAnalyzer`** | DaemonSet | Desired vs scheduled discrepancies, unready daemon pods across eligible nodes. |
| **`ReplicaSetAnalyzer`** | ReplicaSet | Failing pod templates, quota exhaustion, and stuck replica provisionings. |
| **`JobAnalyzer`** | Job | Backoff limits exceeded, active deadlines exceeded, and failed batch pods. |
| **`CronJobAnalyzer`** | CronJob | Missing or invalid cron schedule expressions, suspended cron executions. |
| **`ServiceAnalyzer`** | Service | Pod selector matching 0 ready endpoints, port/targetPort mismatches. |
| **`IngressAnalyzer`** | Ingress | Backend service not found in namespace, missing TLS secret (e.g. pending cert-manager), missing ingress class. |
| **`NetworkPolicyAnalyzer`**| NetworkPolicy | Orphaned policies matching 0 pods in target namespace. |
| **`PVCAnalyzer`** | PVC / PV | Stuck `Pending` PVCs, missing StorageClasses, `ClaimLost`, and `Failed`/`Released` PersistentVolumes. |
| **`NodeAnalyzer`** | Node | `NodeNotReady`, `DiskPressure`, `MemoryPressure`, `PIDPressure`, and network degradation. |
| **`HPAAnalyzer`** | HPA | Metrics server unavailable (`ScalingActive: False`) and `ScalingLimited: True` (maxReplicas reached). |
| **`PDBAnalyzer`** | PDB | `0` disruptions allowed blocking node maintenance, upgrades, and drains. |

---

### 2. Cluster Hygiene & Error Pod Auto-Cleaner

Integrated directly from cluster-maintainer operational patterns:
- **Evicted Pods**: Scans and cleans up pods terminated due to node disk or memory pressure (`Reason: Evicted`).
- **Failed Pods**: Cleans up failed non-restartable workloads (`Phase: Failed`).
- **Completed Batch Jobs**: Prunes legacy job pods older than 1 hour (`Phase: Succeeded`).
- **Stuck Terminating Pods**: Detects pods stuck terminating for > 5 minutes with finalizers or unreachable runtimes, supporting safe or grace-period=0 force cleanups.
- **One-Click Batch Execution**: Clean single pods or multi-select pods with dry-run support via Web UI or `POST /api/clean/pods`.

---

### 3. Multi-LLM Triage & Interactive Assistant (No Ollama)

- **Anthropic Claude**: `claude-3-7-sonnet`, `claude-3-5-sonnet`
- **OpenAI / Codex**: `gpt-4o`, `o1`, `gpt-4-turbo`
- **DeepSeek**: `deepseek-chat`, `deepseek-reasoner` (V3 / R1)
- **External Agent Harness**: Executes external CLI agent harnesses via stdin/stdout contract
- **Deterministic Rule-Based SRE Engine**: Offline, zero-API fallback with deterministic diagnoses and recommended commands
- **Interactive SRE Chat**: Interactive terminal in Web UI (`/api/chat`) where engineers can ask follow-up questions about anomalies, log traces, and remediation advice.

---

### 4. Supported Instant Messaging (IM) Integrations

Real-time alert dispatching with instant approval links:
- **Slack**: Formatted using Slack Block Kit with severity badges, root cause summary, proposed commands, and direct link to approve.
- **Discord**: Dispatches native Discord Rich Embeds with color bars (`#E53E3E` for Critical, `#DD6B20` for High), field breakdown, and one-click review button.
- **Microsoft Teams**: Dispatches Adaptive MessageCards with action buttons.
- **Test Alert Verification**: One-click webhook test ping directly from the Web UI (`POST /api/notify/test`).

---

### 5. Permission-Gated Remediation Workflow

- **Status starts in `PENDING_APPROVAL`**: Zero mutations occur autonomously.
- **Remediation Actions Supported**:
  - `RestartPod`: Safe deletion allowing controllers to restart container cleanly.
  - `RolloutRestart`: Strategic merge patch (`kubectl.kubernetes.io/restartedAt`) triggering zero-downtime rolling update of Deployments.
  - `CordonNode`: Safely marks degraded nodes as unschedulable.
  - `DeleteFailedPod`: Removes dead or stuck terminating pods.
  - `GitOpsPR`: Emits declarative YAML modifications (e.g. bumping memory limits for OOMKilled workloads) to avoid cluster drift.
  - `Manual`: Action plan with exact troubleshooting kubectl commands.

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
                    │   14+ K8sGPT Analyzers  │
                    │   + Pod Cleaner Engine  │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │   Sensitive Sanitizer   │
                    │ (Redacts Keys & Tokens) │
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
                    │   Remediation Engine    │
                    │ (Status: PENDING_APPR)  │
                    └────────────┬────────────┘
                                 │
         ┌───────────────────────┴───────────────────────┐
         ▼                                               ▼
┌─────────────────────────┐                     ┌─────────────────────────┐
│ Slack / Discord / Teams │                     │  Web UI & Approval API  │
│  "Incident Detected!"   │                     │  (sre.kubebee.com)      │
└─────────────────────────┘                     └────────────┬────────────┘
                                                             │
                                                    [Approve / Reject]
                                                             │
                                                             ▼
                                                ┌─────────────────────────┐
                                                │    Permission-Gated     │
                                                │    Action Executor      │
                                                └─────────────────────────┘
```

---

## Web Dashboard Tabs (`sre.kubebee.com`)

1. **Pending Approvals**: Review triage diagnosis, AI confidence, proposed command, with **[Approve & Execute]** and **[Reject]** buttons.
2. **Cluster Anomalies**: Interactive issue browser with filter by severity, namespace, and resource kind, plus log viewer modals.
3. **Analyzers Matrix**: Health card grid of all 14 K8sGPT analyzers with real-time issue counters.
4. **Pod Hygiene & Cleanup**: Table of Evicted, Failed, and Stuck Terminating pods with batch selection and **[Clean Selected Pods]**.
5. **SRE AI Assistant (Chat)**: Conversational chat interface for SRE troubleshooting and cluster queries.
6. **Integrations & IM**: Webhook configuration for Slack, Discord, and Teams with an instant test alert trigger.

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/status` | GET | Current cluster health, active LLM provider, scan timestamps, and pending counts. |
| `/api/issues` | GET | Active cluster anomalies with severity, logs, and events. |
| `/api/proposals` | GET | Remediation proposals awaiting authorization or completed. |
| `/api/proposals/{id}/approve` | POST | Authorize and execute remediation. |
| `/api/proposals/{id}/reject` | POST | Reject proposal with reason. |
| `/api/analyzers` | GET | List all 14 analyzers with status and active issue counts. |
| `/api/clean/pods` | GET / POST | List cleanable pods / execute batch pod cleanup (with dry-run option). |
| `/api/chat` | POST | Interactive conversation with SRE AI assistant. |
| `/api/notify/test` | POST | Test webhook alert delivery (Slack, Discord, Teams). |
| `/api/config` | GET / POST | Read or update webhook URLs and runtime settings. |
| `/api/scan` | POST | Trigger on-demand cluster telemetry scan. |

---

## Deployment & Configuration

```bash
# Test & build locally
make test
make build

# Run locally with rule-based engine
./bin/sre-agent -kubeconfig ~/.kube/config -llm-provider rule-based -port 8080

# Run with Claude
export LLM_API_KEY="sk-ant-..."
./bin/sre-agent -kubeconfig ~/.kube/config -llm-provider claude -llm-model claude-3-7-sonnet-20250219

# Deploy to Kubernetes
kubectl apply -k deploy/k8s/
```