# Unified SRE implementation plan

> For agentic workers: use subagent-driven-development for bounded implementation
> and review tasks. Root integrates packaging and validates the complete system.

**Goal:** Migrate to one orchestrator/agent product with shared approvals and
notifications, agent-side diagnostics, and multi-replica coordination.

**Architecture:** Preserve PostgreSQL as the scoped authority. Agent connections
are outbound and use leased jobs. Existing provider/scanner and approval services
remain authoritative implementations rather than being copied into new binaries.

**Tech stack:** Go, PostgreSQL/pgx, Kubernetes client-go, Helm, HTML/JavaScript.

## Global constraints

- Preserve scope, explicit approval, privacy projection, audit and no-replay semantics.
- Local and in-cluster agents use the same runtime and diagnostic loop.
- Shared orchestrator state must work without sticky sessions.
- Legacy command names may forward but cannot retain independent product behavior.
- Run targeted failing tests before behavior changes, then package/integration tests.
- Work on feat/unified-sre; do not overwrite unrelated work or publish/deploy externally.

## Task 1: Shared authentication and authority generation

Files: pkg/orchestrator/auth.go, server.go; new postgres auth storage and migration 017;
pkg/fleet/service.go and corresponding tests.

- [ ] Add cross-replica challenge/session/logout and stable-generation regression tests.
- [ ] Run `go test ./pkg/orchestrator ./pkg/fleet ./pkg/storage/postgres` and verify failures.
- [ ] Persist auth through a bounded shared store with atomic challenge consumption;
      production uses PostgreSQL, tests can inject a shared memory implementation.
- [ ] Derive fleet epoch from configured generation rather than random process ID.
- [ ] Verify old generation credentials cannot resume after explicit generation change.
- [ ] Run targeted tests and cross-instance PostgreSQL tests; review scope/security.

## Task 2: Unified runtime and remote diagnosis

Files: pkg/investigation, pkg/agent/collection, pkg/agent/executor, new pkg/agent;
new remote diagnostic storage and migration 018; agent HTTP handlers;
cmd/sre-agent, cmd/sre-collector, cmd/sre-executor.

- [ ] Add tests for local/in-cluster source resolution and capability enforcement.
- [ ] Add leased claim/heartbeat/cancellation/late-result tests for agent diagnostics.
- [ ] Extract the existing diagnostic rounds into a transport-neutral shared API.
- [ ] Dispatch versioned evidence/profile work; authenticate scoped agents on claim,
      collection and result; independently validate results and source lineage.
- [ ] Execute shared rounds on agent with local provider credentials; reuse collection
      and execution runtimes in one process. Keep mutations disabled by default.
- [ ] Replace process-local startup interruption with fenced lease recovery and
      persistent cancellation. Coordinate global job concurrency in shared storage.
- [ ] Replace old agent server default with managed runtime and compatibility forwarding.
- [ ] Run package, race and real PostgreSQL lifecycle tests including duplicate completion.

## Task 3: Human interaction channels

Files: new pkg/interaction and shared storage migration 019; enterprise interaction
handlers/UI; CLI adapter and Slack channel adapter.

- [ ] Add tests for response identity, exact action binding, concurrent answers,
      expiration, CLI EOF, and Slack request signature/replay validation.
- [ ] Persist typed clarification requests; use existing action approvals and notification
      acknowledgements as distinct operations rather than a generic approve boolean.
- [ ] Provide shared scoped request/response APIs and UI presentation.
- [ ] Implement interactive terminal adapter using a human token, separate from agent
      credentials; leave pending work intact on EOF. Unattended mode never reads stdin.
- [ ] Route notifications through existing durable delivery with native Slack formatting
      and signed callbacks or authenticated UI fallback where human identity is unbound.
- [ ] Test adapters, authorization and retry/duplicate behavior.

## Task 4: Orchestrator and unified chart

Files: cmd/sre-orchestrator; shared orchestrator startup; deploy/helm/sre;
Dockerfiles, Makefile, README, migration documentation and CI scripts.

- [ ] Add build/Helm tests for the new names, central/agent-only topology and HA values.
- [ ] Extract reusable orchestrator startup and forward old command name.
- [ ] Build two primary binaries/images; unified chart exposes replicas, rolling strategy,
      PDB, spread, external PostgreSQL/OIDC and scoped agent enrollment configuration.
- [ ] Retire independent standalone HTTP entry path; document immutable legacy proposal
      exports and do not import historical authorization as executable approvals.
- [ ] Run `go test ./...`, targeted `-race`, `make build`, Helm rendering and available
      PostgreSQL integration suites. Exercise failover across two server instances.
- [ ] Perform spec and code review; fix findings before claiming migration complete.

## Progress and verification

Implemented: shared auth and stable generation; shared authority encryption key;
agent-side leased diagnostics with centralized validation; unified managed agent
and orchestrator binaries; preserved action/notification authority; interactive
CLI including diagnosis dispatch; enum-only clarification UI/API; Slack review
links; unified HA chart and image/release targets; package and migration naming.

Verification completed during implementation:

- `go test -p 1 ./...` passed after package migration.
- Real disposable PostgreSQL suite passed for agent, orchestrator, investigation,
  storage, fleet, execution, delivery and interaction packages.
- PostgreSQL-backed `-race` suite passed for the changed runtime/storage packages.
- `go vet -p 1 ./...`, `make build`, Helm lint and central/agent-only chart tests passed.
- Product dependency inspection confirms neither binary imports the historical
  standalone server/CLI archive.

No production deployment, real model calls, real Slack delivery, or live-cluster
acceptance was performed. Existing cluster/browser fixture tests remain available
through the disposable Kind integration target. Native Slack approval callbacks
remain intentionally unavailable until a verified human identity binding is configured;
Slack notifications link to authenticated UI review. The database must have its own
HA deployment. Historical standalone test code is archived internally, not linked
into product binaries. Diagnostic concurrency is serialized per application in the
shared database; aggregate capacity follows deployed agents rather than replica-local
worker slots.
