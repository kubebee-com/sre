# Isolated Enterprise Collection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans or superpowers:subagent-driven-development. Verify with synthetic identities and disposable Kubernetes only.

**Goal:** Make the observe-only control plane usable with separately deployed, explicitly scoped cluster collectors.

**Architecture:** An administrator issues a single-use collector enrollment secret bound to one application scope, expected cluster UID, collector audience, and authority epoch. The collector exchanges it once for a time-limited credential. Only typed strict observations enter the control plane; cluster credentials and names remain local. Enterprise mutation endpoints remain absent until the executor release gate passes.

**Tech Stack:** Go, existing scanner/client-go, PostgreSQL, HTTPS collector transport, Kubernetes read-only RBAC.

## Global constraints

- Tokens carry separate collector role and audience; no collector credential authorizes a mutation, execution claim, or receipt.
- Enrollment and credential verification occur in scope-bound transactions. Bootstrap consumption is atomic and credentials expire; revoked generations cannot submit reports.
- The authority epoch comes from an external deployment secret and changes for restore/re-enrollment. A restored installation starts collection/authorization locked until fresh administrator enrollment.
- Strict reports contain opaque resource handles and fixed observation enums/numbers, never raw names/logs/specs/customer strings.
- Successful empty scans report coverage; they do not independently establish recovery.

## Task 1: Durable collector enrollment

**Files:** Create `pkg/fleet/types.go`, `service.go`, `service_test.go`; add core schema migration and scoped agent repository methods.

- [ ] Test unauthorized enrollment, one-use bootstrap race, wrong scope/role/audience/epoch, expired credentials, revoked generation, and restart persistence against real PostgreSQL.
- [ ] Admin setup permission issues a 10-minute bootstrap secret with a configured expected Kubernetes cluster UID. Exchanging it consumes that exact secret and creates a 30-minute collector credential; raw token values appear only in the authorized enrollment response. Store only hashes.
- [ ] Verify current role/audience/epoch/generation before accepting every report. Issue rotation credentials atomically and reject replaced credentials. No fallback to shared operator identity.

## Task 2: Strict collector report ingestion

**Files:** Create `pkg/collector/report.go`, `report_test.go`; add `pkg/enterprise/collector_handlers.go`.

- [ ] Test malformed/oversized reports, customer text injection, cross-scope and mismatched cluster reports, duplicate report IDs, and expired evidence.
- [ ] Authenticate collector before persistence, validate every observation through the strict projection, and atomically write incident evidence plus a deduplicated incident-created outbox event. Record failed/partial coverage as unknown. Never resolve all incidents because a report is empty.
- [ ] Keep observation provenance (collector ID, generation, epoch, source report ID and observed time) inside the immutable evidence envelope. UI must display freshness and source separately from hypotheses.

## Task 3: Separate collector process and deployment

**Files:** Create `cmd/sre-collector/main.go`, local configuration and identity-registry helpers, observe-only Helm chart/process manifests, and deployment documentation.

- [ ] Require explicit control-plane URL, application scope, expected cluster UID, namespace list, local identity key, and enrollment secret/credential file. Verify the local cluster identity before enrollment and every resumed run.
- [ ] Use only bounded scanner reads. Project findings locally; raw snippets never enter central requests. Persist opaque resource mappings encrypted locally with atomic writes and restrictive file permissions.
- [ ] Deploy the collector with get/list/watch permissions only, scoped to reviewed namespaces/resources. Deploy the control plane with service-account automount disabled and no customer-resource RBAC. No executor is installed in the observe-only deployment.
- [ ] Run real database HTTP report/feedback tests, executable UI tests, rendered RBAC inspection and disposable-cluster collector validation. Never run against the operator's existing kubeconfig implicitly.
