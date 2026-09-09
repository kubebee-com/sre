# Unified SRE architecture — proposed design

Status: approved for implementation on 2026-09-08.

## Objective

Replace the standalone/enterprise product split with one SRE system: an HA
`sre-orchestrator` and one `sre-agent` binary. The agent runs inside a cluster or
on a workstation/bootstrap host with network access to the Kubernetes API.
Collection, diagnosis, debugging, and approved execution use shared code across
deployment locations. There is one central UI and one authorization model.

## Approach

Consolidate incrementally around the existing enterprise authorization, evidence,
and persistence services and the existing scanner/provider implementations.
A rename-only change would retain competing runtime behavior. A new implementation
from scratch would duplicate or discard existing tested boundaries.

Execution placement is agent-side diagnosis/debugging. The orchestrator validates
results and retains durable coordination; the agent executes the shared diagnostic
loop using local provider credentials.

## Responsibilities

`sre-orchestrator` owns the browser UI/API, OIDC sessions, application scopes,
enrollment, provider policy, incident state, scheduling, approvals, notifications,
reviewed knowledge, audit, and recovery records. It holds no kubeconfig or
Kubernetes workload credentials.

`sre-agent` owns collection, local resource identity mapping, the diagnostic loop,
bounded read-only debugging tools, action preparation, and approved execution.
It reports projected evidence and results to the orchestrator. Execution is an
explicit capability, disabled by default; enabling collection or diagnosis does
not enable mutation. The orchestrator validates results and approvals independently
of the agent's diagnostic conclusions.

Consolidating into one process means an execution-enabled agent can access both
read and write credentials. This changes the current collector/executor process
isolation. Keep capability checks and approval validation explicit, and document
this deployment trust boundary. Do not claim that one process preserves separate
OS-level identities.

## Connection and jobs

Agents establish outbound authenticated HTTPS connections to the orchestrator;
local agents need no inbound listener. Enrollment binds an agent to explicit
organization, cluster, application, namespaces, and verified cluster UID.

Support `--in-cluster` for ServiceAccount credentials and `--kubeconfig` or standard
`KUBECONFIG` for external operation. Accept `KUBE_CONFIG` as a compatibility alias
for the user's requested spelling. Explicit flags take precedence; conflicting
credential modes fail clearly. Never silently switch clusters when loading fails.

Use persisted jobs with agent capability requirements, scoped authority, expiry,
attempt identity, and bounded input/output. Claims have leases and fencing tokens;
heartbeats renew ownership. Late results from expired owners cannot overwrite
current state. Cancellation is durable and visible across orchestrator replicas.

Retry eligible read-only work after lease expiry. Never automatically replay a
cluster mutation after an uncertain outcome. Retain the action journal, exact
target/precondition checks, approval binding, and ambiguous-outcome reconciliation.

## Shared diagnosis and providers

Extract reusable runtime services from command entry points. Reuse `pkg/scanner`,
`pkg/triage`, and existing evidence validation rather than implement a second
diagnostic engine. Extract the investigation loop from PostgreSQL/HTTP lifecycle
dependencies so the agent can execute it through bounded interfaces.

The orchestrator distributes authorized provider profile metadata, not long-lived
provider secrets in job payloads. Proposed default: agent-side provider adapters
resolve credentials from local environment/Secrets or workload identity. The
orchestrator retains profile governance and records the exact profile version.
Any future central credential gateway remains a transport adapter, not another
diagnostic loop.

Maintain explicit projection/redaction before outbound provider requests and
orchestrator reports. Moving the loop onto the agent does not authorize sending
raw cluster data to a remote model. Local CLI entry points use the same runtime;
the old independent dashboard and approval authority are retired.

## Interactive CLI, messaging, and UI

Preserve the approval and notification workflows as shared orchestrator services.
Interaction channel and Kubernetes credential source are independent: a local agent
may run unattended, and interactive operation uses the same agent runtime.

`sre-agent --interactive` attaches a terminal conversation to its orchestrator
session: show progress, ask clarification questions, display exact proposed actions,
and accept explicit approve/reject decisions. Authenticate the human separately
from the enrolled agent; Kubernetes credentials or possession of an agent token
do not confer human approval authority. Terminal decisions call the same scoped
orchestrator APIs as the UI. Interactive mode does not create a local approval
bypass or a second incident store.

Without `--interactive`, never wait for terminal input. Persist requests for human
input and route them to configured messaging destinations (including Slack) and/or
the owned UI through the orchestrator API. Interactive mode can still emit configured
notifications. Terminal disconnects leave requests pending for later CLI reattachment
or response through another authorized channel; absence of a response never means
approval. Expired requests require fresh validation before execution.

Represent clarification, notification acknowledgement, and action approval as
distinct typed operations. Each request has a stable ID, scope, incident/job link,
version, status, and expiry. Approval binds the exact action hash, target, evidence,
and preconditions. Responses carry verified human identity and are committed
atomically so concurrent CLI/UI/messaging responses cannot authorize duplicate
execution. A generic chat reply such as "yes" is not mutation authorization.

Retain durable notification outbox, retry, deduplication, acknowledgement, and
escalation. Add channel adapters around that service rather than independent
approval engines. Existing standalone Slack formatting only links to dashboard
approval, and current enterprise delivery is a generic webhook; native Slack
responses are new work. A Slack adapter must verify incoming requests, map the
responding workspace/user to an authorized human principal, and bind structured
responses to the exact pending request. If that identity binding is unavailable,
link to authenticated UI approval rather than treating a webhook as authority.

The owned UI consumes the same request/status/response APIs as the terminal.
Pending requests and responses survive orchestrator failover and remain auditable
regardless of the originating channel.

## High availability

Use PostgreSQL as shared durable state. Move login challenges and browser sessions
out of process memory, with atomic one-time challenge consumption and shared
logout/revocation. Requests must work across replicas without sticky sessions.

Replace startup-wide interruption of runs/jobs with lease-expiry recovery.
Persist cancellation and coordinate concurrency limits across replicas. Coordinate
maintenance, notification dispatch, enrollment/credential changes, and schema
migration so replica starts do not invalidate live work or duplicate effects.

Run multiple orchestrator replicas with rolling updates, readiness checks, graceful
drain, disruption budget, and topology spread. PostgreSQL availability remains an
external deployment dependency; chart replica count is not database HA.

## Packaging and migration

Provide a unified chart with independently enabled orchestrator and agent sections.
Install the orchestrator centrally and agent-only releases in workload clusters.
External agents run the same binary with kubeconfig. Keep one agent image rather
than separate collector/executor implementations.

Migrate existing enterprise PostgreSQL state with versioned migrations. Preserve
audit and identity lineage. Treat standalone file proposals as historical exports;
do not silently import them as executable authorization in the new system.
Old command/chart names may forward temporarily with deprecation guidance, but
must not retain a separate implementation or authentication path.

## Delivery sequence

1. Shared cluster connection and agent runtime, capability model, and bounded
   agent-job protocol, including migration of collection/execution entry points.
2. Shared agent-side diagnosis/debugging loop, provider resolution, and centrally
   validated evidence/results; retire the standalone application runtime.
3. Shared sessions, leased job ownership, durable cancellation, coordinated
   recovery/maintenance, and multi-replica orchestrator packaging.
4. Shared human-input APIs, interactive terminal adapter, messaging adapters,
   and UI integration with preserved approval/notification behavior.
5. Unified chart, naming, migration documentation, and end-to-end acceptance.

Each stage needs its own implementation plan; the complete requested outcome
requires all five stages.

## Acceptance evidence

- The same agent handles an in-cluster ServiceAccount and external kubeconfig
  against a test cluster, with equivalent diagnostic results and scope enforcement.
- Observe-only agents cannot execute actions; stale or mismatched approvals fail.
- Duplicate claims/results and worker loss do not cause duplicate mutations.
- Two orchestrator replicas support login/callback/API/logout across replicas.
- Killing a replica during diagnosis permits bounded recovery; cancellation reaches
  an agent regardless of which replica received the request.
- Rolling restarts preserve unrelated live work, enrollment, and audit records.
- Central and agent-only chart installations render and run; legacy entry points
  cannot expose a second independent UI or approval path.
- Report/provider payload tests retain the existing privacy contract.
- CLI, UI, and messaging responses use identical scope/approval checks and audit;
  concurrent responses cannot cause duplicate execution.
- Interactive disconnects preserve pending requests; unattended agents do not read
  stdin, and absent/expired responses cannot approve an action.
- Notification retries/escalation survive replica failure; notification
  acknowledgement and conversational answers cannot substitute for approval.

## Review findings motivating HA work

`pkg/orchestrator/auth.go` stores sessions and login challenges in maps.
`pkg/investigation/queue.go` keeps cancellation functions in a local map.
`cmd/sre-control-plane/main.go` interrupts runs/jobs during startup.
`pkg/investigation/service.go` uses process-local concurrency slots.
These require behavioral changes before supporting multiple replicas.
