# Kubebee SRE Sandboxed AI Agent Solver (`codex` / `agy`)

Kubebee SRE supports an optional **two-phase, approval-gated AI agent remediation workflow** backed by real coding/SRE agent CLIs — **`codex` (default)** and **`agy`** — running inside isolated ephemeral Kubernetes `Job` sandboxes.

## Workflow

1. **Phase 1 — Create Solution (Read-Only Sandbox)**:
   - Triggered from the dashboard (**Anomalies -> select `codex` or `agy` -> Solve with AI**) or via `POST /api/issues/{id}/solve` with optional `{"harness":"codex"|"agy"}`.
   - Kubebee launches an ephemeral Kubernetes `Job` using the read-only `sre-agent-solver-ro` ServiceAccount (no Secrets access, no mutations):
     - `codex` (default): `codex exec --sandbox read-only ... -`
     - `agy`: `agy --print --mode plan --sandbox --output-format json --json-schema ...`
   - The agent inspects live cluster state and returns a structured JSON solution (`summary`, `root_cause`, `remediation_plan`, `proposed_commands`, `gitops_patch`, `verification_plan`, `rollback_plan`, `confidence_score`).
   - Kubebee stores the solution as a `PENDING_APPROVAL` proposal in the **Approvals** tab.

2. **Phase 2 — Human Approve / Reject**:
   - **Reject**: Marks the proposal rejected with audit log; zero mutations run.
   - **Approve & Execute**: Launches an ephemeral execution `Job` using the scoped `sre-agent-solver-exec` ServiceAccount (still no Secrets/ClusterRoleBindings) and optional `GITOPS_TOKEN` Secret:
     - `codex`: `codex exec --sandbox workspace-write ... -`
     - `agy`: `agy --print --mode accept-edits --sandbox --output-format json ...`
   - Output is bounded, secret-redacted, recorded in the proposal audit trail, and verified.

## Isolation Model: Pod vs gVisor vs MicroVM (Kata/Firecracker)

| Runtime | Isolation Boundary | Hardware Requirement | Recommendation |
| :--- | :--- | :--- | :--- |
| Plain Pod (`runc`) | Shared host Linux kernel | Any node | **Not sufficient alone** for agents executing arbitrary shell/CLI commands |
| **gVisor (`runsc`)** | User-space syscall kernel (`runtimeClassName: gvisor`) | Any Linux node (including cloud ARM64 VMs without nested KVM) | **Default** (`SRE_AGENT_SOLVER_RUNTIME_CLASS=gvisor`) — strong kernel-escape protection with fast startup and full ARM64 VM compatibility |
| MicroVM (**Kata Containers / Firecracker**) | Dedicated guest Linux kernel per pod (`runtimeClassName: kata`) | Bare-metal or nested KVM (`/dev/kvm`) | **Pluggable drop-in** via `SRE_AGENT_SOLVER_RUNTIME_CLASS=kata` on KVM-capable nodes |

In addition to `RuntimeClassName`, every solver `Job` enforces:
- `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]`, `seccompProfile: RuntimeDefault`
- Separate read-only (`sre-agent-solver-ro`) vs approval-gated execution (`sre-agent-solver-exec`) ServiceAccounts
- Bounded `emptyDir` scratch mounts (`/tmp`, `/workspace`), `activeDeadlineSeconds`, `backoffLimit: 0`, `ttlSecondsAfterFinished`
- Default-deny `NetworkPolicy` blocking pod-to-pod lateral movement and cloud metadata (`169.254.169.254`)

## Configuration

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `SRE_AGENT_SOLVER_ENABLED` | `false` | Enable the AI agent solver API & executor |
| `SRE_AGENT_SOLVER_HARNESS` | `codex` | Default harness (`codex` or `agy`) |
| `SRE_AGENT_SOLVER_MODE` | `k8s-job` | `k8s-job` (in-cluster sandboxed Job) or `local` (dev subprocess) |
| `SRE_AGENT_SOLVER_RUNTIME_CLASS` | `gvisor` | Kubernetes `RuntimeClassName` (`gvisor`, `kata`, or empty) |
| `SRE_AGENT_SOLVER_IMAGE` | `ghcr.io/kubebee-com/sre-agent-sandbox:latest` | Sandbox image built from `deploy/Dockerfile.sandbox` |
| `SRE_AGENT_SOLVER_NAMESPACE` | `sre` | Namespace for ephemeral solver Jobs |
| `SRE_AGENT_SOLVER_PLAN_SA` | `sre-agent-solver-ro` | Phase 1 read-only ServiceAccount |
| `SRE_AGENT_SOLVER_APPLY_SA` | `sre-agent-solver-exec` | Phase 2 approved execution ServiceAccount |
| `SRE_AGENT_SOLVER_OPENAI_SECRET` | `sre-openai-secrets` | Secret providing `OPENAI_API_KEY` |
| `SRE_AGENT_SOLVER_GITOPS_REPO` | *(empty)* | Optional GitOps repository URL |
| `SRE_AGENT_SOLVER_GITOPS_SECRET` | *(empty)* | Optional Secret providing `GITOPS_TOKEN` (Phase 2 only) |
| `SRE_AGENT_SOLVER_TIMEOUT` | `10m` | Per-Job execution timeout |
