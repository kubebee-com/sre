# Enterprise Access, Privacy, and Feedback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Use behavioral failing tests and independent reviews for each deliverable.

**Goal:** Deliver authenticated application-scoped investigations with safe evidence projection and per-item engineer feedback.

**Architecture:** Add a separate control-plane process with no Kubernetes client or mounted service-account token. Trusted deployment configuration maps verified OIDC groups to explicit application scopes and roles. Every service operation authorizes before opening a scope-bound PostgreSQL transaction. Evidence, claims, feedback, and knowledge remain distinct records.

**Tech Stack:** Go, PostgreSQL/pgx, coreos go-oidc v3.21.0 (Go 1.25), existing provider task adapters, embedded HTML/JavaScript.

## Global constraints

- No actor headers, shared API token identity, implicit wildcard scope, or operator-edited security floor.
- Enterprise runtime exposes only explicitly registered enterprise routes; legacy mutation, process harness, and catalog learning routes are absent.
- Strict privacy projects fixed codes, numeric observations, and opaque handles; arbitrary customer strings are excluded before storage/inference.
- False feedback quarantines the exact item in the same transaction as its attributed assessment. True is feedback, not corroboration or automatic knowledge promotion.
- A fresh run consumes fresh eligible observations and reviewed knowledge, never earlier unverified conclusions.
- Mutation is disabled until the separate executor and recovery gates pass.

## Task 1: Verified principals and application permissions

**Files:** Create `pkg/identity/oidc.go`, `oidc_test.go`, `pkg/authorization/policy.go`, `policy_test.go`, `pkg/ownership/registry.go`.

**Interfaces:** `identity.Principal{ID, Issuer string, Groups []string, IssuedAt, ExpiresAt time.Time}`; `identity.NewOIDCVerifier(ctx,issuer,audience string) (*OIDCVerifier,error)` and `Verify(ctx,rawToken string) (Principal,error)`. `authorization.Binding{Scope identity.Scope, Group string, Role Role}`; `authorization.NewPolicy(bindings []Binding) (*Policy,error)`; `Policy.Authorize(principal,scope,permission) error`; `Policy.Scopes(principal) []identity.Scope`; `Policy.Version() string`.

- [ ] Write signed-token fixtures for issuer/audience/signature/expiry/nbf, missing subject, multi-audience authorized-party mismatch, and token age. Use an isolated HTTPS discovery/JWKS test server. Reject HTTP production issuers, redirects, and invalid issuer metadata.
- [ ] Pin coreos go-oidc v3.21.0; configure issuer, client ID, allowed RS256/ES256 algorithms without any skip-verification options. Hash issuer plus subject into a stable internal ID; do not use email as identity. Require issued-at and a maximum 15-minute token age; revocation through group changes becomes effective no later than this bound. Refresh/re-authentication is required afterward.
- [ ] Test a full role/permission matrix and identical application IDs in two clusters. Exact trusted group bindings define Viewer (read), Investigator (read/investigate/feedback), Owner (those plus approve), Approver (read/approve), Steward (read/feedback/adjudicate/knowledge-review), Administrator (setup without implicit application evidence access), SecurityAdministrator (privacy/provider policy without application evidence access). Unknown operations and missing scope are denied. No runtime endpoint accepts caller-declared role/group ownership.
- [ ] Build an immutable versioned registry from trusted bindings. Validate duplicate/conflicting application ownership configuration; return independent scope copies and deterministic policy version hashes. Run `go test -race ./pkg/identity ./pkg/authorization ./pkg/ownership`.

## Task 2: Strict privacy projections and bounded investigation contracts

**Files:** Create `pkg/privacy/projection.go`, `projection_test.go`, `pkg/investigation/types.go`, `service.go`, `scenarios_test.go`, `rubric.go`; extend `pkg/triage/task.go` through its existing schema framework.

- [ ] Test that raw names, log content, environment variables, annotation values, customer email, and malicious instruction text cannot appear in projected evidence. Only fixed diagnostic codes, numeric metrics, approved status enums, opaque handles, timestamps, and bounded dependency handles enter strict evidence. Unknown fields are rejected or omitted; privacy is a typed projection, not a prompt instruction or regex-only masking claim.
- [ ] Define evidence payloads and claim payloads with cited exact item versions, alternatives, tested discriminators, and explicit NEEDS_EVIDENCE/INCONCLUSIVE/HYPOTHESIS status. Enforce budgets, current scope, and eligible evidence at each run. Provider results never grant CORROBORATED themselves.
- [ ] Deliver rubric `diagnostic-rubric/v1` and frozen positive/negative fixtures before any knowledge promotion. Only authorized steward assessment with current evidence, discriminating tests, and no unresolved contradiction can corroborate. Test downstream failure/root cause separation and contradictory/stale evidence abstention.
- [ ] Provider selection uses trusted named profiles and a deployment-approved provider factory. Operator choices select an existing profile ID; they cannot submit endpoints, credentials, headers, privacy settings, or arbitrary subprocesses. Persist profile/prompt/privacy/rubric versions with each run.

## Task 3: Append-only feedback and synchronous invalidation

**Files:** Create `pkg/feedback/types.go`, `service.go`, `service_test.go`; create `pkg/storage/postgres/migrations/002_feedback.sql` and repository feedback methods. Expand the single migration runner to an ordered checksum-verified sequence.

**Interfaces:** `feedback.Assessment` is TRUE/FALSE/CANNOT_VERIFY. Requests carry incident ID, exact item ref/hash, idempotency key, optional bounded correction code, and optional existing visible evidence refs. Append-only events have authenticated actor ID and server time. Requests may supersede only that actor's earlier event on the same item.

- [ ] Run real-database tests for idempotent same request, conflicting key, stale version/hash, unauthorized reviewer, cross-scope ref, False quarantine and outbox atomic rollback, contradictory reviewers, and retrieval immediately after feedback commit. User text stays out of strict mode; optional corrections use approved diagnostic reason codes with evidence refs.
- [ ] Write feedback event, dispute projection, and outbox event in one transaction. Do not erase an observation or previous assessment. A later True does not automatically lift quarantine. Steward adjudication distinguishes FACTUAL_ERROR/NOT_APPLICABLE/STALE/CONFIRMED/UNRESOLVED and preserves historical labels.
- [ ] Expose feedback history and eligibility next to each item. Knowledge retrieval and action submission call the same current lineage eligibility query; caches are not an authority.

## Task 4: Control-plane API and engineer UI

**Files:** Create `cmd/sre-control-plane/main.go`, `pkg/enterprise/server.go`, `handlers.go`, `static/index.html`, `static/app.js`, API/UI tests, and deployment configuration docs.

- [ ] Require database, HTTPS OIDC issuer/audience, and trusted configuration path at startup. Open no Kubernetes client, mount no service-account token, and start no legacy remediation engine. Add bounded HTTP requests/responses, timeouts, same-origin policy, CSP, secure session handling, and graceful shutdown.
- [ ] Register scoped incident/item/investigation/feedback endpoints through shared services; every request resolves a verified principal and exact scope. Unknown routes/actions fail closed. Authenticated scope selection controls all lists and detail fetches.
- [ ] Render evidence and conclusion cards separately with timestamps, exact version, citations, uncertainty, and eligibility. Add keyboard-accessible True/False/Cannot verify controls with no default choice, saved/error state, and feedback history. Clear stale selections when switching scope or refreshing fails. Do not use innerHTML for untrusted text.
- [ ] Run executable UI tests and full real-database HTTP tests proving Team A cannot list/fetch/assess Team B items. Verify the control-plane deployment contains no Kubernetes token or customer mutation RBAC.

## Sources

Use the verifier's documented signature/issuer/audience/expiry checks and reuse its remote key cache: [coreos OIDC API](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc). Version and Go floor were verified from [v3.21.0 source](https://github.com/coreos/go-oidc/tree/v3.21.0).
