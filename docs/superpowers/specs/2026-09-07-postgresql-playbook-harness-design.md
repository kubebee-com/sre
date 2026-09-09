# PostgreSQL Playbook Digest, Normalization, And Guarded Resolution

## Status

Design approved by the user on 2026-09-07. This document defines the next
implementation unit for the SRE agent. The prior feature-gap closure remains a
separate workstream; this design integrates with its scanner, triage, metrics,
dashboard, and remediation boundaries.

## Goal

Build a durable playbook catalog that can ingest user-authored and external
runbooks, use the existing LLM harness to digest and normalize them, resolve
Kubernetes findings into typed remediation proposals, and learn new playbook
candidates from verified outcomes without silently creating executable behavior.

PostgreSQL is the source of truth for playbook content, provenance, findings,
resolution runs, approvals, feedback, and graph-ready relationships. The LLM
harness is an analysis and planning component. It is never a Kubernetes client
and never executes an arbitrary command.

## Scope And Boundaries

### In scope

- Markdown, YAML, and JSON playbook import with source provenance and checksums.
- Semantic LLM digestion of imported material and sanitized cluster evidence.
- Deterministic normalization into a versioned canonical playbook model.
- Guardrail evaluation before a playbook is activated or a plan is executed.
- Finding-to-playbook matching and LLM-assisted, typed resolution plans.
- Integration with the existing approval-gated remediation engine.
- Verified-outcome learning that creates reviewable draft playbooks.
- PostgreSQL repositories and migrations for the catalog and audit trail.
- Dashboard views for catalog state, resolution outcomes, guardrail decisions,
  and LLM token usage, plus settings for learning and execution policy.
- Unit and contract tests that use a fake harness; Kind remains deferred.

### Out of scope for this implementation unit

- Arbitrary shell, unrestricted `kubectl`, Ansible execution, or remote code
  execution.
- Automatic activation of mutating playbooks.
- Replacing the existing Kubernetes remediation executor.
- A dedicated graph database or a workflow platform dependency.
- Treating raw LLM output as a source of truth.
- Claiming that successful model output proves a remediation is correct without
  postcondition verification.

## Design Decisions

### Recommended approach: in-process engine with PostgreSQL

The agent will add a `pkg/playbook` domain package and a PostgreSQL adapter.
The package will depend on a narrow structured LLM harness interface and the
existing `pkg/remediation` action registry. It will not depend on a second API
client or a workflow server.

This keeps digesting, normalization, policy decisions, and unit testing close
to the current Go service. PostgreSQL provides durable shared state for future
replicas and enables relational queries, JSONB storage, full-text search, and
stable relation identifiers.

### Deferred alternatives

Argo Workflows is a possible later execution backend for long-running DAGs,
retries, and suspend/resume steps, but it would add a Kubernetes workflow
dependency to the first implementation. Temporal is a possible later backend
for durable cross-service workflows and human signals, but it requires a
separate service and operational model. StackStorm, Rundeck, and Robusta are
useful import and approval-pattern references rather than runtime dependencies.
Kyverno and Gatekeeper remain suitable cluster-side policy enforcement layers,
not replacements for this catalog and resolver.

References: [Argo Workflows](https://argo-workflows.readthedocs.io/en/latest/),
[Temporal workflows](https://docs.temporal.io/workflows),
[StackStorm](https://docs.stackstorm.com/),
[Rundeck workflows](https://docs.rundeck.com/docs/manual/jobs/job-workflows.html),
[Kyverno](https://kyverno.io/docs/), and
[Gatekeeper](https://open-policy-agent.github.io/gatekeeper/website/docs/).

## System Architecture

The pipeline has separate immutable, canonical, and execution-specific
representations:

```text
source document or Kubernetes finding
        |
        v
bounded parser + secret/redaction boundary
        |
        v
LLM harness: semantic digest with schema validation
        |
        v
deterministic normalizer: canonical playbook and content hash
        |
        v
guardrail engine: provenance, scope, action, and safety policy
        |
        v
PostgreSQL catalog: draft/review/active versions and relations
        |
        v
LLM harness: finding-specific resolution plan
        |
        v
guarded proposal: approval + UID/RV preconditions + dry-run
        |
        v
existing typed remediation executor + postcondition verification
        |
        v
verified outcome -> learning digest -> new draft candidate
```

The internal “playbook skill” is a set of versioned harness tasks, prompts,
schemas, and output validators:

- `digest`: extract semantic intent, triggers, evidence, prerequisites,
  actions, expected outcomes, rollback, and unknowns.
- `normalize`: propose canonical fields while the deterministic normalizer
  chooses defaults, maps action names, and rejects unsupported content.
- `resolve`: select an active version and produce a finding-specific plan with
  evidence references, exact target identity, typed actions, approvals, and
  postconditions.
- `learn`: summarize a verified run and propose a new or revised playbook
  candidate with explicit lineage and confidence.

The harness adapter will reuse the existing provider configuration, endpoint
allowlist, request bounds, cancellation, prompt-injection boundary, and token
observers. The test profile selects `gpt-5.5` through environment variables;
credentials remain host-provided and are never committed or persisted in
playbook content.

## Domain Contracts

### Source artifact

An imported artifact contains a source ID, source kind, origin URI or user
label, media type, content checksum, parser version, provenance, and sanitized
content. The original input is never executable. Command blocks are retained
only as descriptive evidence unless a known typed-action adapter can map them.
Unknown commands become manual steps that require review.

### Playbook digest

A digest is immutable structured output from the harness. It contains:

- title, summary, source and lineage references;
- failure categories and trigger conditions;
- evidence requirements and evidence references;
- root-cause hypotheses and confidence;
- prerequisites, candidate typed actions, and unknowns;
- expected postconditions, rollback intent, and approval intent;
- model/task/prompt schema metadata and a redacted content hash.

The digest describes meaning. It does not grant permission to execute an
action, select an unrestricted target, or bypass approval.

### Normalized playbook

A normalized playbook is the canonical version stored in PostgreSQL. It has a
stable logical ID, immutable version, status, source lineage, trigger bindings,
applicability constraints, evidence requirements, typed steps, preconditions,
postconditions, rollback behavior, guardrail references, approval policy,
confidence, and canonical content hash.

Every step references an action from the existing remediation action registry.
The initial registry includes the current typed actions such as pod restart,
safe failed-pod deletion, workload scaling, rollout restart, node cordon,
cleanup, GitOps proposal, and manual review. There is no free-form command
execution path.

### Resolution plan

A resolution plan is scoped to one finding and one live target snapshot. It
contains the selected playbook/version, evidence references, concise rationale,
typed actions, target UID/resourceVersion, required approval, confidence,
blocking uncertainties, and verification criteria. The plan becomes a normal
remediation proposal; the existing engine owns approval and execution.

### Learning candidate

A learning candidate is a normalized draft derived from a verified resolution
run. It records the before/after evidence identity, executed steps, verified
postconditions, user feedback, model/task metadata, source playbook lineage,
and the user policy in force. A candidate cannot be used for resolution until
it is explicitly activated.

## PostgreSQL Persistence

Use `pgx/v5` and versioned embedded SQL migrations. A configured
`SRE_DATABASE_URL` enables the durable catalog. Unit tests use repository fakes
and SQL contract tests; a PostgreSQL integration suite runs only when an
explicit test database URL is supplied.

The initial schema contains:

- `playbook_sources`: source metadata, checksum, parser result, trust, and
  license/provenance fields;
- `playbook_digests`: immutable sanitized digest JSONB, task metadata, and
  evidence/source references;
- `playbooks`: logical ID, version, lifecycle state, canonical JSONB, hash,
  confidence, origin, and approval metadata;
- `playbook_steps` and `playbook_bindings`: typed actions, constraints, and
  failure/resource matching fields;
- `findings` and `evidence_snapshots`: sanitized finding identity and bounded
  evidence references;
- `resolution_runs`, `resolution_steps`, `approvals`, and `feedback`: full
  proposal lifecycle and verified outcome history;
- `relations`: typed edges between sources, digests, playbooks, rules,
  findings, actions, and runs.

Use relational columns for lookup-critical fields and JSONB for versioned
payloads. Add indexes for logical playbook ID/version, lifecycle state,
failure category, resource identity, canonical hash, source checksum, and
full-text search over sanitized title/summary/content. Stable IDs and explicit
relations allow a later projection to Apache AGE, Neo4j, or another graph
system without redesigning the catalog.

References: [PostgreSQL JSON types](https://www.postgresql.org/docs/current/datatype-json.html)
and [PostgreSQL full-text search](https://www.postgresql.org/docs/current/textsearch-intro.html).

## Guardrail Model

Guardrails are cumulative and fail closed:

1. **Input boundary:** bound document, log, event, and model sizes; redact
   secrets; label imported and cluster data as untrusted; preserve provenance.
2. **Harness boundary:** require schema-valid JSON, strict enums, bounded
   confidence, evidence references, and explicit unknowns. Invalid or
   injection-shaped output is rejected.
3. **Catalog boundary:** validate source trust, parser support, action mapping,
   namespace/resource scope, blast radius, and required approvals before a
   playbook can become active.
4. **Execution boundary:** re-fetch targets, require UID/resourceVersion
   preconditions, perform server-side dry-run where supported, apply timeouts,
   idempotency, rate limits, and approval checks, then verify postconditions.
5. **Learning boundary:** only verified successful runs can create candidates;
   failed, stale, ambiguous, manually overridden, or unverified runs cannot
   teach executable behavior.

Cluster-admin changes, control-plane operations,
credential/key/certificate changes, storage destruction, upgrades, unrestricted
selectors, and unknown actions are permanently approval/manual-review classes
in the first version. User settings can narrow policy and choose
draft/approval behavior, but cannot remove the hard safety floor.

## Import And Lifecycle

Import adapters will cover Markdown, YAML, and JSON first, with an adapter
interface for StackStorm, Rundeck, Ansible, and other documented formats.
Every adapter produces the same untrusted source artifact and passes through
digest, normalization, and guardrails. An imported playbook is never active
merely because its source format is recognized.

Lifecycle states are explicit:

```text
RECEIVED -> DIGESTED -> NORMALIZED -> REVIEW -> ACTIVE
                                      \-> REJECTED
ACTIVE -> RETIRED
```

Duplicate canonical hashes link to the existing version rather than creating
multiple executable entries. Revisions create new immutable versions and
preserve lineage.

## Self-Evolution Policy

The default learning mode is `AUTO_DRAFT`. A verified run creates at most one
deduplicated candidate per learning event. User settings may disable learning,
restrict candidate action types, require a confidence threshold, limit source
and namespace scope, and require an approval class. Observe-only candidates
may optionally be auto-activated; mutating candidates require explicit review.

The candidate stores what was actually observed and verified, not merely what
the model predicted. User accept/edit/reject feedback is retained as a
first-class relation and is included in later learning context only after
sanitization.

## Dashboard And Settings

Extend the existing authenticated dashboard with:

- playbook counts by lifecycle state and origin;
- digest, normalization, guardrail rejection, resolution, and learning error
  counts;
- resolution success/failure/verification rates;
- token usage grouped by harness task and provider, with unavailable usage
  shown explicitly;
- recent drafts, approvals, rejected candidates, and source provenance.

Settings expose the LLM profile/model, import source allowlist, learning mode,
confidence threshold, action/resource/namespace allowlists, approval policy,
and retention. Secrets, API keys, private headers, raw source credentials, and
unredacted evidence are never rendered or returned by the dashboard.

## Failure Handling

- Harness timeout, rate limit, provider error, invalid JSON, or schema mismatch:
  retain the finding, record a bounded task error, and create no proposal.
- Normalization or guardrail rejection: persist the digest and rejection reason
  as review data; do not discard the source lineage.
- PostgreSQL outage: continue observation where possible, but disable new
  activation, learning, and mutating execution. An already-approved proposal
  may continue only when its complete state is durably available in the
  existing remediation store and the executor can still enforce its original
  preconditions.
- Target changed or verification fails: mark the run stale/failed and do not
  generate a learning candidate.
- Duplicate or concurrent learning events: use a canonical hash and
  idempotency key to produce one candidate.

All errors and metrics use low-cardinality sanitized labels. Raw prompts,
secrets, and unbounded cluster output are excluded from logs and audit rows.

## Testing And Acceptance

Unit tests are the first verification layer and must cover:

- digest schema validation and prompt-injection/redaction boundaries;
- normalization defaults, unsupported action rejection, canonical ordering,
  stable hashes, and idempotency;
- guardrail decisions across action, scope, approval, confidence, and source
  trust combinations;
- resolution-plan conversion into existing remediation proposals;
- stale UID/resourceVersion and failed-postcondition handling;
- learning state transitions, deduplication, feedback, and policy changes;
- PostgreSQL repository queries using fakes or SQL mocks without a live server;
- dashboard/API redaction and metric projections.

Harness contract tests will feed valid, malformed, overlong, ambiguous,
prompt-injected, and unsafe outputs. A real provider smoke test remains
environment-gated and uses `gpt-5.5` through env configuration; no API secret
is stored in the repository. Kind and full cluster failure simulation remain
deferred until the host has sufficient resources.

Acceptance requires that an imported playbook reaches `REVIEW`, an approved
canonical playbook can produce only a typed guarded proposal, a verified run
creates one draft candidate, and no failed or unverified run changes the active
catalog.

## Implementation Decomposition

The later implementation plan will split work into disjoint areas:

- playbook domain types, digest/normalizer, and pure guardrails;
- PostgreSQL migrations and repositories;
- harness task adapter and resolution integration;
- remediation outcome and self-evolution pipeline;
- import adapters and provenance handling;
- API/dashboard/settings and metrics;
- focused unit/contract tests and documentation.

Shared interfaces and schema changes will be integrated centrally. No worker
may weaken authentication, redaction, approval, target preconditions, or the
read-only default to make a test pass.
