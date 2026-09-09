# Scoped Enterprise State Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Complete the test/review cycle for each task.

**Goal:** Establish one PostgreSQL authority for scoped immutable diagnostic evidence and transactional state changes.

**Architecture:** Every repository transaction is bound to an explicit organization, cluster, and application. Immutable item versions form an append-only dependency graph; mutable eligibility is checked recursively in the same serialization boundary used by action submission. Legacy playbook storage remains an import source.

**Tech Stack:** Go 1.25, existing pgx/v5, PostgreSQL, disposable Docker database.

## Global constraints

- No cluster credentials, inference, or mutation is introduced in this workstream.
- Application scope is mandatory; platform incidents use a separately registered platform application ID.
- Raw Kubernetes names and customer text do not belong in the core resource identity.
- Database errors return stable public errors without SQL, parameters, or credentials.
- Scope-qualified compound foreign keys enforce reference isolation, including same-looking IDs.
- No local-file fallback, implicit schema downgrade, or legacy executable approval import.

## Task 1: Scope and immutable diagnostic contracts

**Files:** Create `pkg/identity/scope.go`, `pkg/identity/scope_test.go`, `pkg/incident/types.go`, `pkg/incident/evidence.go`, `pkg/incident/evidence_test.go`.

**Interfaces:** `identity.Scope{OrganizationID, ClusterID, ApplicationID string}` with `Validate() error` and `Key() string`; IDs must be 1–128 ASCII alphanumeric, underscore, or hyphen. `incident.ItemRef{ID string, Version int64}`. `incident.Item{Scope identity.Scope, IncidentID string, ID string, Version int64, Kind ItemKind, Body json.RawMessage, ObservedAt time.Time, ValidUntil time.Time, Parents []ItemRef, Hash string}`. Kinds are EVIDENCE and CLAIM. `incident.Incident{Scope identity.Scope, ID string, Version int64, State string, OpenedAt time.Time}`. `incident.ResourceIdentity` contains scope, API group/kind, opaque resource handle, UID, exact-target commitment, authority epoch, enrollment generation; no namespace/name fields.

- [ ] Write/run failing tests for missing scope parts, delimiter ambiguity, invalid IDs, invalid/oversized JSON, duplicate parents, missing observation time, invalid freshness interval, and stable item hash under JSON object key reordering. Example assertion:

```go
if (identity.Scope{OrganizationID:"org", ClusterID:"cluster"}).Validate() == nil {
    t.Fatal("application-less scope accepted")
}
```

- [ ] Implement `Item.Seal() error`: validate IDs/scope/kind/version (positive), <=64 KiB valid JSON object, <=64 unique parents with positive versions, nonzero UTC observation time, later validity time; normalize object encoding and parent order before SHA-256 hashing the immutable envelope (excluding Hash). Never mutate parent items. Implement deep-copy behavior at repository serialization boundaries.
- [ ] Run `go test -race ./pkg/identity ./pkg/incident`; commit the contract and test files.

## Task 2: Scoped transactional repository

**Files:** Create `pkg/storage/postgres/store.go`, `transaction.go`, `items.go`, `outbox.go`, `migrations/001_enterprise_core.sql`, `contract_test.go`.

**Interfaces:** `Open(ctx context.Context, dsn string) (*Store,error)`, `Close()`, `Transact(ctx context.Context, scope identity.Scope, fn func(*Tx) error) error`. `Tx.CreateIncident(incident.Incident) error`, `Tx.Incident(id string) (incident.Incident,error)`, `Tx.UpdateIncident(id string, expectedVersion int64, state string) error`, `Tx.PutItem(incident.Item) error`, `Tx.Item(ref incident.ItemRef) (incident.Item,error)`, `Tx.Items(incidentID string, afterID string, limit int) ([]incident.Item,error)`, `Tx.Quarantine(ref incident.ItemRef) error`, `Tx.Eligible(ref incident.ItemRef, at time.Time) (bool,error)`, `Tx.Enqueue(key, kind string, payload json.RawMessage) error`. Public errors: `ErrUnavailable`, `ErrConflict`, `ErrNotFound`, `ErrInvalid`.

- [ ] First run real-database failing contracts against an isolated database: cross-scope parent rejection; immutable version overwrite rejection; orphan incident/item rejection; rollback leaves neither item nor outbox event; concurrent expected-version updates yield one winner; repeated migration preserves data; ancestor quarantine makes descendants ineligible immediately; expired evidence is ineligible; bounded pagination; outbox unique scope/key deduplication.
- [ ] Create schema `enterprise_core`, migration ledger with checksum, composite primary/foreign keys, item-parent relation, separate eligibility state, incident versions, and scoped outbox unique key. Serialize each scope using a transaction advisory lock and bound each transaction to a timeout. Existing parent versions must precede a new child insertion, preventing cycles. Item version collisions are errors; callers cannot overwrite evidence.
- [ ] Embed migrations and apply once under a migration advisory lock; reject unknown future versions or altered checksums. Use scoped SQL parameters everywhere, including recursive lineage and outbox operations. Resolve no cross-scope reference through an unscoped ID lookup.
- [ ] Enforce fresh evidence and all ancestor eligibility inside `Tx.Eligible`, including the item itself. Quarantine is synchronous; outbox is projection/delivery support only. `Tx.Enqueue` permits a duplicate key only for exactly matching kind/payload; otherwise return conflict.
- [ ] Run `SRE_ENTERPRISE_TEST_DATABASE_URL=... go test -race ./pkg/storage/postgres -count=1` against real PostgreSQL; no database means tests explicitly skip, never a claimed acceptance pass. Commit only repository files.

## Task 3: Legacy migration report and operator verification

**Files:** Create `pkg/incident/import.go`, `pkg/incident/import_test.go`, `scripts/ci/enterprise-postgres.sh`, `docs/enterprise-storage.md`; modify CI to provision a disposable PostgreSQL service.

- [ ] Add a dry-run import report accepting legacy bytes and an explicit verified binding. Report SHA-256 source digest, record count, quarantined counts, and reasons. Reject missing binding. Never copy actor strings or historical approval status into executable authorization. Imported observations remain untrusted pending fresh collection/review.
- [ ] Test malformed input, missing binding, repeated identical source hash, and old approved records remaining non-executable. Keep report generation side-effect free.
- [ ] Add an isolated Docker verification script with task-specific container name, loopback-only ephemeral port, random generated database password, bounded readiness polling, trap cleanup of only its own container, and environment injection without logging credentials. Run the repository suite and legacy playbook PostgreSQL suite against that database.
- [ ] Document schema ownership, explicit no-JSON-fallback behavior, retention as immutable archival with dependency preservation, and backup/restore lockout requirements. A restore must supply a fresh external authority generation; W2/W4/W7 enforce activation and revoke prior authority before accepting agents or actions.
- [ ] Run the real DB script, `go test -race ./pkg/identity ./pkg/incident ./pkg/storage/postgres`, `git diff --check`; obtain spec and code review. Do not claim W1 production integration before the enterprise runtime wires the repository.

## Contract review refinements

Canonical output, as well as input, must fit the 64 KiB body limit; repeated
sealing must succeed without changing the hash. The hash field is omitted from
the hash preimage. Duplicate JSON keys are rejected recursively, and JSON
numbers retain their exact representation. These refinements were exercised as
failing regressions before being implemented in `ba27625`.
