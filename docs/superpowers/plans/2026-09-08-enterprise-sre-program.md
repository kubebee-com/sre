# Enterprise SRE Program Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement an approved workstream task-by-task. Use subagent-driven-development only when parallel agent execution is explicitly selected. Steps use checkbox syntax for tracking.

**Goal:** Deliver a customer-hosted, multi-cluster SRE system with evidence-driven diagnosis, application ownership, enforceable privacy, owner-approved recovery, granular engineer feedback, and evaluated learning.

**Architecture:** Keep Go domain services modular behind shared authorization and privacy boundaries. Deploy scoped collectors and optional isolated executors per cluster, a customer-owned control plane without cluster credentials, and PostgreSQL for durable scoped state. AI providers analyze authorized sanitized evidence; deterministic services own policy, approval, execution, verification, and knowledge promotion.

**Tech Stack:** Existing Go/Kubernetes clients, HTTP/gRPC/MCP surfaces, embedded UI, provider adapters, Helm/Kustomize, and Prometheus. Introduce PostgreSQL with pgx/v5 and a maintained OIDC implementation after checking supported versions at implementation time; no graph database, online model training, or workflow platform dependency is required initially.

**Design:** [Enterprise direction and contracts](../specs/2026-09-08-enterprise-sre-direction-design.md).

**Status:** Implementation authorized on 2026-09-08; delivered R1–R10 capabilities, verification and supported limits are tracked in [the release evidence](../../enterprise-release-evidence.md). This is a sequence of bounded workstreams with files, contracts, acceptance scenarios, and release gates. Before coding a workstream, turn its approved contracts into a focused implementation plan with concrete test/code steps; do not treat this broad program as one unattended implementation batch. The user subsequently requested comprehensive review and implementation; see the review amendments and execution plan.

## Global constraints

- Default deployment is observe-only: install no customer-resource mutation roles or executor.
- The diagnostic process receives sanitized evidence and has no Kubernetes credentials.
- No response is not approval.
- Successful API calls do not by themselves establish recovery or causation.
- Unknown actions are denied; unavailable approval/policy state blocks new mutations.
- Raw customer content is excluded by default.
- Revoked knowledge is excluded at retrieval time.
- Learning never changes permissions or activates itself.
- Preserve unrelated current worktree changes; isolate implementation work and commit only its reviewed files.
- All new entities, queries, cache keys, references, and audit events carry organization and cluster scope; application scope is mandatory for application-owned data.
- Models cannot select recipients, ownership, execution permissions, privacy exemptions, or arbitrary provider endpoints.
- No enterprise readiness claim before the applicable real-database, cluster, security, and failure-recovery gates pass.

## Delivery order and dependencies

| Workstream | Depends on | Independently useful deliverable |
|---|---|---|
| W0: Correct current incident semantics | Existing implementation | Targeted scans and UI cannot falsely report recovery. |
| W1: Scoped durable domain state | W0 | Reliable organization/cluster/application identity, evidence, and execution records. |
| W2: Identity, ownership, and delivery | W1 | Owners can securely access and receive their applications' results. |
| W3: Privacy and provider governance | W1; integrate authorization from W2 | Safe, selectable AI inference with no conversational disclosure bypass. |
| W4: Fleet setup and isolated collection | W1-W3 | Verified multi-cluster onboarding and scoped sanitized collection. |
| W5: Evidence-driven investigations | W0-W4 | Bounded read-only investigations with tested hypotheses and explicit uncertainty. |
| W6: Granular engineer feedback | W2, W3, W5 | True/False/Cannot verify assessment per evidence item and conclusion. |
| W7: Owner-approved executor | W1-W6 | Exact typed actions enforced outside AI with owner approval and revocation. |
| W8: Independent recovery verification | W4, W5, W7 | Measured recovery distinct from applied actions and mitigation. |
| W9: Golden cases, learning, and evaluation | W5, W6, W8 | Reviewed knowledge releases and honest quality metrics. |
| W10: Enterprise operations and release | All applicable workstreams | Supported deployment, backup/recovery, security and scale evidence. |

W2 and the pure privacy/provider contracts in W3 can be developed independently after W1; integrate access checks before either is exposed. W7 can be tested in disposable environments before W8, but customer production mutation remains disabled until W8 and the mutation release gate pass. All capabilities must be wired through shared services across UI/HTTP/gRPC/MCP/CLI before their gate is passed.

## W0: Correct current incident semantics

**Existing files:** pkg/scanner/history.go, pkg/scanner/contract.go, pkg/scanner/types.go, pkg/server/server.go, pkg/server/handlers.go, pkg/server/static/app.js, cmd/sre-agent/main.go, deploy/helm/sre-agent/templates/servicemonitor.yaml, deploy/helm/sre-agent/templates/_helpers.tpl.

**New focused tests:** pkg/scanner/history_scope_test.go, pkg/server/incident_state_test.go, pkg/server/cleanup_ui_test.go, plus Helm rendering assertions in scripts/ci/check-helm.sh.

**Consumes:** Current scan plans, analyzer records, history and proposal APIs.

**Produces:** Coverage-aware scan reconciliation, honest UI/API state, and a safe supported single-writer deployment baseline.

- [ ] Preserve findings outside the effective successful scan coverage, including namespace, kind, analyzer, name, and selector restrictions. Failed/forbidden/timed-out coverage cannot resolve previous findings. Make evidence time and coverage explicit.
- [ ] Reconcile dashboard active state from scoped incident state rather than replacing all findings with the newest targeted scan. Distinguish stale/unobserved from healthy.
- [ ] Fix cleanup UI to display proposed cleanup, preserve namespace/name identity, link pending proposals, and retain execution progress. Remove the implication that no pending approvals means no incidents.
- [ ] Configure authenticated ServiceMonitor scraping and prohibit unsupported multi-writer file-store deployments, including overlapping rollout writers. Document the temporary availability tradeoff of a single-writer rollout.
- [ ] Preserve terminal persistence errors as visible operational failures; do not silently claim a recorded completion. Notification creation must distinguish a new proposal from a reused one.

**Acceptance:** Scan unhealthy applications A and B, then scan A only: B remains unresolved. Fail A's analyzer: neither application becomes healthy. Create cleanup proposals: UI states pending approval and never claims deletion. Render default authenticated monitoring: scraper credentials are configured without printing their values. Attempt two file-backed writers: deployment/startup guard rejects unsupported topology.

**Verification:** go test -race ./pkg/scanner ./pkg/server ./pkg/remediation ./cmd/sre-agent; run browser workflow assertions and scripts/ci/check-helm.sh. Snapshot the isolated reproductions from the review as regressions; a source-string test alone is insufficient for the UI behavior.

## W1: Scoped durable domain state

**Create:** pkg/identity/scope.go, pkg/incident/types.go, pkg/incident/evidence.go, pkg/incident/store.go, pkg/storage/postgres/store.go, pkg/storage/postgres/migrations/001_enterprise_core.sql, pkg/storage/postgres/contract_test.go.

**Modify:** pkg/scanner/types.go, pkg/scanner/history.go, pkg/remediation/store.go, pkg/remediation/engine.go, pkg/cache/cache.go, pkg/config/config.go, cmd/sre-agent/main.go, go.mod, go.sum.

**Consumes:** W0 scope and coverage semantics.

**Produces:** Versioned Scope, ResourceIdentity, EvidenceItem, Incident, InvestigationRun, Claim, ApprovalRecord, ExecutionAttempt, and OutboxEvent contracts plus repositories requiring explicit Scope. An application scope may be absent only for an authorized platform-owned incident.

- [ ] Define immutable organization/cluster/application IDs and compound resource identity including API group/kind and UID. Claims reference evidence IDs and immutable versions; separate hypothesis and observation types.
- [ ] Introduce scoped repositories with transactions, constrained references/foreign keys, immutable evidence, optimistic versions, bounded pagination, and explicit retention. Ensure joins and reference resolution cannot cross an authorized scope. Evaluate PostgreSQL row-level security as additional defense, not a substitute for scoped service methods.
- [ ] Store approvals, action claims, transitions, and outbox records transactionally. Design ambiguous external-action outcomes for reconciliation; do not promise exactly-once Kubernetes effects.
- [ ] Establish one core migration sequence used by incident, remediation, feedback, and later playbook adapters. Avoid separate conflicting findings/approval tables under pkg/playbook.
- [ ] Add a dry-run migration report for legacy data. Require administrator binding to a verified cluster and preserve source hashes; quarantine unmapped records. Do not carry old shared-token approvals into executable enterprise approvals.
- [ ] Implement backup/restore and upgrade compatibility checks. Enterprise DB outages block new mutations; no executable fallback to local JSON.

**Acceptance:** Identical namespace/name values in two clusters never collide. Cross-organization evidence references fail. Two workers claim one execution once. A crash after an external effect is represented as ambiguous and reconciled. Migration does not invent cluster ownership or valid owner approvals. Restored data retains lineage and revocation state.

**Verification:** go test -race ./pkg/identity ./pkg/incident ./pkg/storage/postgres ./pkg/remediation ./pkg/cache. Run the PostgreSQL contract suite against a disposable real database in CI, including concurrent claims, rollback, restart, and migration replay; fakes alone do not satisfy this gate.

## W2: Identity, ownership, and notification delivery

**Create:** pkg/identity/oidc.go, pkg/ownership/registry.go, pkg/authorization/policy.go, pkg/notifier/outbox.go, pkg/server/ownership_handlers.go, pkg/authorization/cross_surface_test.go.

**Modify:** pkg/server/auth.go, pkg/server/chat_sessions.go, pkg/server/mcp.go, pkg/grpcapi/server.go, pkg/notifier/webhook.go, pkg/server/static/app.js, pkg/server/static/index.html, cmd/sre-agent/main.go.

**Consumes:** W1 Scope and immutable IDs/repositories.

**Produces:** Authenticated Principal, versioned OwnershipBinding, access decisions, approver delegation, and authorized state-transition notification delivery.

- [ ] Validate OIDC issuer, audience, signature, expiry, and group mapping; define revocation/session behavior and scoped service credentials. Reject asserted caller identity headers as an alternative identity path.
- [ ] Implement application owner, designated approver, platform steward, investigator, viewer, and administrative permissions. Owners cannot edit the organization security floor. Operators cannot grant themselves ownership/approval authority.
- [ ] Support reviewed resource mappings, namespace defaults, ownership conflicts, shared infrastructure ownership, and on-call delegation. Treat labels as discovery hints only.
- [ ] Enforce permissions on every API/tool/query/cache/export/feedback path through shared services. Chat session ownership becomes individual/scoped rather than a shared token actor.
- [ ] Route only sanitized, authorized impact summaries to registered destinations. Add durable state-transition deduplication, retries, acknowledgement/escalation, recovery delivery, and reauthorization at send time.

**Acceptance:** Team A cannot list, fetch by guessed ID, query, export, or receive Team B's private evidence. Changing a label or supplying X-User-Email cannot claim ownership. A queued notification is blocked after recipient access is revoked. Unchanged scans do not generate new incident-created notifications. Notification receipt does not authorize execution.

**Verification:** go test -race ./pkg/identity ./pkg/ownership ./pkg/authorization ./pkg/server ./pkg/grpcapi ./pkg/notifier. Add browser tests for owner-scoped views, expired sessions, denied direct links, and delivery/approval distinctions.

## W3: Privacy and provider governance

**Create:** pkg/privacy/policy.go, pkg/privacy/projection.go, pkg/privacy/pseudonym.go, pkg/privacy/sinks_test.go, pkg/triage/governance.go, pkg/triage/governance_test.go, pkg/server/provider_handlers.go.

**Modify:** pkg/sanitizer/sanitizer.go, pkg/scanner/query.go, pkg/triage/profile.go, pkg/triage/cached.go, pkg/triage/harness.go, pkg/config/profile.go, pkg/server/supportbundle.go, pkg/notifier/webhook.go, pkg/supportbundle/bundle.go, pkg/metrics/metrics.go.

**Consumes:** W1 scoped evidence and W2 access decisions.

**Produces:** Versioned PrivacyPolicy, SourceProjection, SanitizedEvidence, DisclosureDecision, and ApprovedProviderProfile. Provider requests accept sanitized authorized projections, not arbitrary internal scanner objects.

- [ ] Implement STRICT_METADATA default, explicit SANITIZED_DIAGNOSTICS sources, and LOCAL_RESTRICTED routing. Apply the strictest organization/application/destination policy, with administrative audit for policy changes.
- [ ] Implement allowlisted structural projections, configurable sensitive field maps and bounded PII detection. Exclude raw free text by default. Reject uncertain or unsupported payload encodings; do not use the existing opaque-byte passthrough as a privacy boundary.
- [ ] Add keyed scoped pseudonyms for correlation, with no model-accessible key/mapping or reveal tool. Minimize before central persistence and before inference.
- [ ] Apply disclosure policy to model/user/tool input and every sink, including feedback corrections, errors, logs, notifications, cache hits, metrics, support bundles, imports, and output buffering. Scope authorization applies before retrieving content for inference.
- [ ] Expose administrator-approved provider profiles and owner-selectable eligible profiles. Snapshot profile versions, budgets, allowed data classes, schema support, and permitted fallback chains per run. Never silently fall back from local-only to remote.
- [ ] Disable subprocess harness use in enterprise mode until a separate worker passes credential/environment/filesystem/socket/egress isolation tests. Provider errors remain incomplete outcomes.
- [ ] Implement configured retention, erasure and invalidation for derived data; document backup expiry and data already sent to approved external destinations.

**Acceptance:** Planted customer email, phone, payment/account identifiers, and secret values do not reach unauthorized sinks under the test policy. Prompt requests to reveal/encode/translate them cannot weaken policy. Unknown text sources are excluded. A local-only request cannot invoke a remote fallback. A revoked provider cannot be selected through REST, chat, or stored profiles. Harness workers cannot read kubeconfig, service-account tokens, host sockets, or inherited cloud credentials.

**Verification:** go test -race ./pkg/privacy ./pkg/sanitizer ./pkg/triage ./pkg/cache ./pkg/server ./pkg/supportbundle ./pkg/notifier. Run a centralized sink/canary matrix with malicious documents and provider responses. Use synthetic PII only; report test coverage rather than claiming perfect recognition of arbitrary text.

## W4: Multi-cluster setup and isolated collection

**Create:** pkg/fleet/registry.go, pkg/fleet/enrollment.go, pkg/fleet/context.go, pkg/collector/broker.go, cmd/sre-collector/main.go, pkg/server/fleet_handlers.go, pkg/fleet/enrollment_test.go.

**Modify:** pkg/config/config.go, pkg/scanner/scope.go, pkg/scanner/query.go, pkg/scheduler/kube_trigger.go, cmd/sre-agent/main.go, api/v1/sre.proto and generated bindings, deploy/helm/sre-agent/values.yaml and templates, deploy/k8s/rbac.yaml.

**Consumes:** W1 identities, W2 ownership, W3 source/privacy/provider policies.

**Produces:** Authenticated ClusterEnrollment, versioned ClusterContext and ApplicationContext, capability reports, and a scoped read-only EvidenceRequest/EvidenceResponse protocol.

- [ ] Implement verified enrollment, short-lived agent credentials, rotation, revocation, explicit reconnect behavior, and cluster identity bound to authenticated transport.
- [ ] Build setup for discovery plus administrator-authored architecture context, dependencies, deployment sources, health profiles, privacy/provider choices, ownership, notification routes, and execution mode. Narrative descriptions remain unverified context, not permissions.
- [ ] Restrict collectors to reviewed resources and data projections; scope Lease bookkeeping separately. Remove Kubernetes credentials from the diagnostic/control-plane deployment. Keep additional evidence requests typed and bounded.
- [ ] Add explicit cluster/environment selectors and health/coverage indicators in UI and API. Access changes/profile versions invalidate affected approvals and caches.
- [ ] Support one-cluster and multiple-cluster customer-owned topologies without distributing cluster-admin kubeconfigs to the control plane. Add agent queue bounds and scan API-load controls.

**Acceptance:** Two clusters with identical resource names remain separate throughout findings, chat, notification, feedback, and cache. A renamed context cannot redirect an action. Revoked agents cannot send accepted evidence or receive execution commands. Missing CRDs/integrations are unknown/absent, not healthy. The diagnostic workload cannot directly call the Kubernetes API using mounted credentials.

**Verification:** go test -race ./pkg/fleet ./pkg/collector ./pkg/scanner ./pkg/scheduler ./pkg/server ./pkg/grpcapi ./cmd/.... Add two disposable cluster enrollment tests and inspect rendered RBAC/token mounts. Update protobufs from source; do not edit generated bindings by hand.

## W5: Evidence-driven investigations

**Create:** pkg/investigation/types.go, pkg/investigation/service.go, pkg/investigation/hypotheses.go, pkg/investigation/knowledge.go, pkg/investigation/scenarios_test.go, pkg/triage/task.go, pkg/server/investigation_handlers.go.

**Modify:** pkg/triage/types.go, pkg/triage/provider.go and supported provider adapters, pkg/triage/cached.go, pkg/scanner/types.go, cmd/sre-agent/main.go, pkg/server/static/app.js, pkg/server/static/index.html.

**Consumes:** Scoped evidence snapshots, environment profiles, authorized collector queries, approved provider profiles, and explicit reviewed knowledge releases.

**Produces:** InvestigationRun, atomic EvidenceItem/Claim versions, hypothesis assessment records, evidence citations, uncertainty reasons, and typed non-executing recovery proposals.

- [ ] Split observations from assertions and diagnoses. Record evidence source/time/coverage and parent/dependency relations in a queryable incident timeline.
- [ ] Implement the bounded collect/hypothesize/test/contradict/reassess loop. Stop on no new information, budget exhaustion, missing permissions, or unresolved uncertainty; do not simply repeat the same provider prompt.
- [ ] Require evidence references for conclusions; reject nonexistent/cross-scope citations. Preserve alternatives and explicitly label mitigation versus cause correction.
- [ ] Introduce a diagnosis queue separate from scan timeouts with bounded concurrency, fair per-scope budgets, deduplication, cancellation, and visible failures. Provider adapters share schema and error semantics.
- [ ] Start a fresh run from current evidence plus eligible reviewed knowledge. Snapshot environment/provider/privacy/prompt/knowledge versions; invalidate caches and dependent claims through explicit lineage.
- [ ] Deliver an incident page with atomic evidence and conclusions, scope/freshness, impact, tested alternatives, and an honest next step when inconclusive.

**Acceptance scenario suite:** Downstream connection failures caused by a network-policy change; repeated pod restarts caused by a missing dependency; resource exhaustion caused by deployment/configuration drift; unrelated simultaneous failures; stale evidence after resource recreation; a model that repeatedly insists on a contradicted hypothesis; missing log access; a misleading imported runbook. Assert required evidence and abstention, not exact prose. The service must not label a temporary restart success as root-cause confirmation.

**Verification:** go test -race ./pkg/investigation ./pkg/triage ./pkg/server ./cmd/sre-agent. Use deterministic provider/collector fakes for contract assertions and a separately versioned held-out suite for optional governed real-provider evaluation.

## W6: Per-item engineer feedback and corrections

**Create:** pkg/feedback/types.go, pkg/feedback/service.go, pkg/feedback/adjudication.go, pkg/feedback/service_test.go, pkg/server/feedback_handlers.go, pkg/storage/postgres/migrations/002_feedback.sql.

**Modify:** pkg/investigation/service.go, pkg/investigation/knowledge.go, pkg/triage/cached.go, pkg/server/static/app.js, pkg/server/static/index.html, pkg/metrics/metrics.go.

**Consumes:** W5 atomic evidence/claim IDs and immutable versions, W2 Principal/access policies, W3 sanitization, and W1 lineage/outbox storage.

**Produces:** Append-only FeedbackEvent and AdjudicationEvent records, disputed/invalidated claim state, descendant invalidation events, and reviewed correction candidates. Assessment values are TRUE, FALSE, and CANNOT_VERIFY.

- [ ] Add True/False/Cannot verify controls to every evidence item and conclusion; optional reason/correction/evidence reference, keyboard operation, saved/error states, revision history, and no default positive assessment.
- [ ] Define feedback endpoints under scoped investigation items. Require item version/hash and idempotency key. Validate reviewer permission and evidence-reference visibility; sanitize correction text before persistence or inference.
- [ ] On False, immediately dispute/quarantine the affected conclusion, invalidate dependent cached conclusions, and publish a durable event to block pending dependent execution. Retain original evidence and prior assessments unchanged.
- [ ] Support revised assessments as superseding events, stale-version conflicts, and steward adjudication of conflicting reviewers. Preserve True as attributed confirmation until independent corroboration.
- [ ] Enable an explicit fresh investigation using remaining evidence and attributed corrections. Feedback never grants mutation approval or raw-data access.
- [ ] Add review coverage, false/unknown rates, dispute latency, and adjudicated outcomes with denominators. Generate regression-case candidates only after correction review, with no direct knowledge activation.

**Acceptance:** An owner marks evidence E false and conclusion C depends on E: C is quarantined, cached C is ineligible, and its pending action is blocked. Unrelated claims remain available. A request for an already edited claim returns a version conflict. Duplicate submissions create one event. Team A cannot assess Team B's item. Conflicting True/False assessments do not silently overwrite each other. A comment containing synthetic PII is sanitized. A False click without a correction is accepted and reduces trust; it does not fabricate a replacement fact.

**Verification:** go test -race ./pkg/feedback ./pkg/investigation ./pkg/server ./pkg/metrics ./pkg/storage/postgres. Browser acceptance must exercise all three selections, optional correction, failed saves, retry/idempotency, keyboard interaction, conflicting reviews, and refresh after a stale-version response. Verify execution invalidation again when W7 is integrated.

## W7: Owner-approved isolated executor

**Create:** pkg/action/registry.go, pkg/approval/service.go, pkg/executor/service.go, cmd/sre-executor/main.go, pkg/executor/bypass_test.go, pkg/storage/postgres/migrations/003_execution_claims.sql.

**Modify:** pkg/remediation/engine.go, pkg/remediation/executor.go, pkg/remediation/store.go, pkg/server/handlers.go, pkg/server/mcp.go, pkg/grpcapi/server.go, deploy/overlays/remediation/remediation-rbac-patch.yaml, Helm executor/RBAC templates.

**Consumes:** W1 durable claims and approval records, W2 owner policies, W4 verified cluster identities, W5 typed plans, W6 invalidation events.

**Produces:** Versioned ActionDefinition, canonical PlanHash, ApprovalRecord, ExecutionClaim, ExecutionAttempt, and immutable per-step audit transitions. AI gets propose capability only; execution submission is a separate authenticated service operation.

- [ ] Inventory all Kubernetes verbs/subresources and indirect effects. Maintain a deny-by-default typed registry; disallow shell, generic apply/patch, wildcard/bulk deletion, exec/tunnels, privilege changes, arbitrary CRD mutations, and unrestricted GitOps/cloud operations.
- [ ] Deploy optional isolated executors with action-specific least privilege and explicit cluster/resource scope. Keep collectors and provider workers unable to obtain these credentials.
- [ ] Bind authenticated owner approval to exact plan/version/hash, scope, target UID/resourceVersion, ownership/policy version, expiry, and co-approval rules. Acknowledgements, model output, owner labels, and knowledge activation do not grant execution permission.
- [ ] Revalidate live identity, ownership, policy, disputed evidence, impact, health/disruption checks, and dry-run before each typed mutation. Restrict scaling, maintenance windows, protected resources, and shared infrastructure actions.
- [ ] Implement transactional action claims, stop controls, approval revocation, crash reconciliation, terminal-write error handling, and no blind retries of ambiguous mutations. On database/policy outage, block new mutations.
- [ ] Treat rollback and external GitOps changes as writes. Support only exact approved contingencies or new approvals. Keep unsupported operations manual; do not mark a message as a created PR.

**Acceptance:** Prompt injection cannot access a write tool or credentials. An altered plan, wrong cluster, changed target, expired/replayed approval, revoked owner, disputed conclusion, or unavailable policy store results in zero submitted mutations. Two workers cannot concurrently submit the same claimed action. Cancellation after submission reports uncertainty accurately. A live-pod action respects disruption policy. RBAC denies all forbidden subresources even if an API route is mistakenly exposed.

**Verification:** go test -race ./pkg/action ./pkg/approval ./pkg/executor ./pkg/remediation ./pkg/server ./pkg/grpcapi. In a disposable cluster, inspect actual Kubernetes audit events and effective service-account permissions for allowed and denied paths; static YAML checks are not sufficient. Production execution remains disabled until W8's gate passes.

## W8: Independent recovery verification

**Create:** pkg/verification/types.go, pkg/verification/service.go, pkg/verification/health.go, pkg/verification/recovery_test.go.

**Modify:** pkg/remediation/engine.go, pkg/remediation/store.go, pkg/incident/types.go, pkg/notifier/outbox.go, pkg/server/static/app.js, pkg/metrics/metrics.go.

**Consumes:** Exact approved action postconditions, administrator/owner-reviewed application health profiles, fresh collector evidence, execution attempts, and external-intervention records.

**Produces:** Versioned VerificationResult and OutcomeAssessment distinguishing applied action, recovered service, temporary mitigation, failure, and unknown; separate diagnostic-correctness assessment.

- [ ] Predeclare health and observation/follow-up windows in the plan. Use permitted health sources independent of the model's success message. Invalid/missing health profiles block a verified-recovery claim.
- [ ] Verify target-operation postconditions and sustained application health separately. Observe recurrence and known manual/environment interventions. Do not credit an unrelated manual repair to the AI action.
- [ ] Record pending windows, timeouts, ambiguous responses, stale targets, missing dependencies, and partial multi-step outcomes explicitly. Do not silently turn verification failures into success.
- [ ] Publish outcome transitions to UI/owners and the learning eligibility service through the outbox. Preserve stable incident denominators across retries.

**Acceptance:** Pod deletion succeeds but replacement crashes: action applied, recovery failed. Error rate briefly improves then returns: mitigation/recurrence, not golden correction. No health access: unknown. Approved scaling restores declared health over the window: recovered, but cause remains separately assessed. A manual intervention prevents false AI recovery attribution.

**Verification:** go test -race ./pkg/verification ./pkg/remediation ./pkg/incident ./pkg/notifier ./pkg/metrics. Use deterministic clocks for windows plus disposable-cluster failure scenarios with independently collected health signals. Complete this gate before enabling owner-approved production actions.

## W9: Golden cases, reviewed learning, and quality reporting

**Create:** pkg/knowledge/case.go, pkg/knowledge/release.go, pkg/knowledge/lineage.go, pkg/evaluation/cohort.go, pkg/evaluation/metrics.go, pkg/evaluation/runner.go, pkg/server/quality_handlers.go, docs/evaluation-rubric.md, testdata/evaluation/manifest.json.

**Adapt from existing playbook plan:** pkg/playbook domain/canonicalization/import/matching services and shared structured provider tasks. Use W1's core repositories/migrations instead of a parallel authoritative findings/approval schema.

**Consumes:** W5 evidence/hypotheses, W6 adjudicated feedback and corrections, W8 recovery/intervention assessments, versioned environment/provider/knowledge profiles.

**Produces:** Reviewed GoldenCase, negative regression case, immutable KnowledgeRelease, eligibility/lineage decisions, held-out EvaluationRun, and authorized quality cohorts.

- [ ] Require corroborated diagnosis or explicitly labeled mitigation, scoped provenance, reviewed corrections, observed outcomes, applicability, and recurrence information for candidate knowledge. Include valid read-only diagnostic cases through independent review.
- [ ] Implement opt-in candidate generation and CANDIDATE/REVIEW/EVALUATION/APPROVED_RELEASE/RETIRED/REVOKED lifecycle. Human review is mandatory for every initial enterprise knowledge promotion.
- [ ] Reject knowledge that attempts to alter tools, privacy, owner policy, approvals, provider restrictions, or evaluation rules. Retain unsafe imports as rejected provenance only; do not execute their commands.
- [ ] Track invalidation descendants and enforce eligibility at retrieval/cache lookup, then clean up stored derivatives asynchronously. Disputed evidence blocks promotion; revoked releases stop being retrieved immediately.
- [ ] Build versioned held-out scenarios with family/time/source separation and both positive and negative/adversarial cases. Pair provider/prompt/knowledge comparisons on the same dataset. Prevent newly learned and near-duplicate cases from contaminating evaluation labels.
- [ ] Implement all quality formulas in the design: coverage, assessed correctness, verified yield, recovery, recurrence, invalidation, abstention, safety, cost/latency, and feedback coverage. Expose sample sizes, pending windows, unavailable data, and uncertainty intervals.
- [ ] Shadow-evaluate releases read-only, approve rollout, and support rollback of knowledge independently from application execution. No autonomous online model training or cross-customer corpus sharing.

**Acceptance:** API success or a True click alone cannot produce a golden case. A reviewed False correction produces a regression candidate, not an active rule. Conflicting reviews block promotion. Invalidating a source excludes descendants from the next diagnostic run. A frozen benchmark improvement is distinguishable from a changing production case mix. The same incident retried five times does not become five successful incidents.

**Verification:** go test -race ./pkg/knowledge ./pkg/playbook ./pkg/evaluation ./pkg/feedback ./pkg/verification ./pkg/metrics ./pkg/server. Run offline evaluation with deterministic fixtures in CI; governed provider evaluations record exact profiles, dataset/release hashes, budgets, counts, and uncertainty. Do not advertise a numerical improvement until measured results satisfy the review criteria.

## W10: Enterprise operations, UX, and release evidence

**Create:** docs/enterprise-deployment.md, docs/enterprise-security-boundaries.md, docs/enterprise-operations.md, docs/enterprise-release-evidence.md, scripts/ci/enterprise-acceptance.sh, browser workflow tests in tests/browser/.

**Modify:** Helm/Kustomize assets, .github/workflows/ci.yaml, pkg/metrics/metrics.go, README.md, docs/deployment.md, embedded UI assets.

**Consumes:** All delivered workstream contracts and acceptance evidence.

**Produces:** Supported release profiles, operational runbooks, user-visible workflow completeness, and reproducible release evidence.

- [ ] Ship customer-hosted single-cluster and fleet configuration examples with external Secret references, TLS/rotation, governed egress, database recovery, retention, and optional executor installation. Self-host UI assets for restricted networks.
- [ ] Document supported scale and load-test at that scale: resource count, clusters, concurrent investigators, evidence size, scan/API QPS, provider budgets, storage growth, and notification backlog. Establish measured limits before choosing HA replica defaults.
- [ ] Test database unavailability, executor restart after an ambiguous write, lost leadership, disconnected/revoked agents, expired credentials, restored backups, and upgrades with schema compatibility. Preserve stop/revocation state across restores.
- [ ] Add missing observability for coverage/freshness, investigation queues, policy decisions, outbox delivery, action/verification states, and quality metrics. Keep customer identifiers out of general metrics labels.
- [ ] Browser-test setup, My Applications, incident evidence/claims, per-item feedback, scope isolation, approval diff, execution/verification progress, correction history, and knowledge/quality views. Include keyboard accessibility, failures, stale data, empty states, and direct-link authorization.
- [ ] Run dependency/image scanning, signed artifact verification, privacy/execution abuse tests, and independent security review before enterprise mutation release. Publish limitations alongside evidence.

**Verification:** go test -race ./...; go vet ./...; make check; real PostgreSQL contracts; disposable multi-cluster acceptance; browser workflow/accessibility tests; controlled load and failure-recovery tests. Record exact commands/tool versions/results in docs/enterprise-release-evidence.md. Skipped environment-dependent checks must be reported as not validated, not passed.

## Release gates

| Gate | Required evidence | Customer-visible scope |
|---|---|---|
| G0: Trustworthy observation | W0 regressions and supported single-writer behavior | Existing read-only pilot with explicit limitations. |
| G1: Owned private investigations | W1-W6 plus applicable W10 access/privacy/operations checks | Customer-hosted fleet investigation, selectable approved providers, owner delivery, and granular feedback; no production mutations. |
| G2: Controlled recovery | G1 plus W7-W8 and real-cluster/failure/security checks | Opt-in supported typed actions with exact owner approval and independent verification. |
| G3: Reviewed improvement | G2 plus W9 held-out evaluation and lineage/revocation checks | Reviewed golden knowledge and honest quality trends; no automatic permission expansion. |

For each gate: zero unauthorized mutations and zero cross-scope/canary disclosures in the required acceptance suite; no unresolved high-severity boundary defects; all claimed capabilities wired into supported deployment paths. These are release criteria, not a universal guarantee against all future failures. Quality targets beyond safety must be set against a recorded baseline, not invented in advance.

## Requirement traceability

| Requirement | Delivery | Critical proof |
|---|---|---|
| R1: Root-cause depth | W0, W5, W8 | Symptom/causal-chain scenarios; recovery does not imply cause. |
| R2: No diagnostic contamination | W1, W5, W6, W9 | False claim invalidation and descendant/cache exclusion. |
| R3: Ownership and routing | W2, W4 | Cross-team access denial and authorized outbox routing. |
| R4: PII protection | W3, W6, W10 | Source exclusion and adversarial multi-sink disclosure tests. |
| R5: Owner-approved writes | W2, W7, W8 | Isolated credentials, exact approvals, API/RBAC bypass tests. |
| R6: Cluster-specific setup | W1, W4 | Two clusters with identical names; verified profiles/enrollment. |
| R7: Golden learning | W6, W8, W9 | No unverified/self-promoted knowledge; reviewed release rollback. |
| R8: Improvement metrics | W6, W8, W9 | Fixed denominators, held-out cohorts, sample sizes, recurrence. |
| R9: Provider choice | W3, W5 | Eligible selection and no privacy-breaking fallback. |
| R10: Engineer feedback UI | W5, W6, W9 | Atomic True/False/Cannot verify, attribution, conflicts, regression candidates. |

## First implementation unit

Start with W0's coverage-aware reconciliation and its UI state contract. It is bounded, immediately useful, and prevents the enterprise investigation/learning layers from inheriting false resolution labels. Then implement W1's scoped identities and durable evidence contracts, with W2-W3 access/privacy boundaries before exposing fleet investigations.

Do not start with autonomous learning or additional mutation actions. The earlier 2026-09-07 playbook plan must be revised against this design's persistence, verification, privacy, and human-reviewed promotion contracts before its implementation resumes.

## Planning verification

- [x] Confirm all R1-R10 requirements have a delivery workstream and observable acceptance proof.
- [x] Confirm positive engineer feedback, successful API calls, recovery, and diagnostic correctness remain separate labels in every workstream.
- [x] Confirm data collection and owner access/privacy controls precede broader AI investigation and fleet exposure.
- [x] Confirm invalidation blocks pending execution and learning, with ambiguous in-flight actions reconciled.
- [x] Confirm every production mutation release depends on real database/cluster tests and independent verification.
- [x] Validate local Markdown links, document consistency, whitespace, and the existing documentation checks. No application tests are needed solely for creating these planning documents.

## Binding comprehensive-review changes

The eight amendments in the enterprise direction design and the [review record](../specs/2026-09-08-enterprise-plan-review.md) govern implementation. W1/W10 include restore lockout and an externally renewed authority epoch; W4 includes role/audience/capability-bound agent enrollment and local opaque identity mapping; W6/W7 enforce synchronous dispute eligibility rather than relying on the outbox; W5/G1 include the diagnostic rubric and frozen negative baseline; W7 initially permits one mutation per approval with fresh approval for rollback; W6/W9 separate factual errors from stale/not-applicable feedback. Existing playbook services are reused only through the explicitly reviewed inventory and enterprise gates.
