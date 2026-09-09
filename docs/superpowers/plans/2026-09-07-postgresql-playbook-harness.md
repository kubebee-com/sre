# PostgreSQL Playbook Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a PostgreSQL-backed playbook catalog that digests and normalizes untrusted runbooks with the existing LLM harness, produces guarded typed remediation proposals, and creates reviewable playbook drafts from verified outcomes.

**Architecture:** Add a focused `pkg/playbook` domain layer with immutable source/digest records, deterministic canonicalization, policy guardrails, import/resolve/learn services, and repository interfaces. Extend `pkg/triage` with a structured task runner so Codex, harness, and compatible providers share the existing bounds, redaction, endpoint, and token-observation behavior. Persist catalog/audit state in PostgreSQL, while the existing remediation engine remains the only Kubernetes mutation executor.

**Tech Stack:** Go 1.25, `pgx/v5`/`pgxpool`, embedded SQL migrations, Kubernetes typed clients, existing sanitizer/metrics/remediation packages, JSON/YAML parsing, authenticated embedded dashboard, and unit/contract tests without Kind.

---

## Resume Status — 2026-09-08

Recovered session `01a076e9-f602-7383-954a-af6aa59444aa` after interrupted
workers. Integration continues on `codex/playbook-integration` in
`.worktrees/playbook-integration`. The original main checkout remains intact;
its uncommitted event-scanner/parity changes were copied into integration
commit `700133a` after the complete baseline unit suite passed.

- [x] Recover original task, user approvals, worker commits, and partial fixes.
- [x] Repair and review configuration/CLI dispatch and help-secret boundaries.
- [x] Integrate configuration with event scanning; focused config/CLI tests pass.
- [x] Complete domain guardrail review and integrate Tasks 1–2.
- [x] Complete structured-runner and remediation verification review.
- [x] Implement and review PostgreSQL catalog/migrations (Task 4).
- [x] Implement and review import, resolution, and learning services (Tasks 5–6).
- [x] Wire service startup and scanner behavior (Task 7 runtime portion).
- [x] Add authenticated API, dashboard, settings, and metrics (Task 8).
- [x] Complete documentation and integration verification (Task 9).

Kind remains deferred per the user's explicit resource constraint. Use
`GOMAXPROCS=2` and `go test -p 2` for local checks. Database integration and
real-provider tests are separate, explicit evidence gates; passing mocks must
not be represented as live PostgreSQL or provider verification.

Final integration evidence: full unit and race suites, `go vet`, documentation,
manifest/image metadata, shell syntax, JavaScript syntax, and dashboard DOM
security tests pass. The authorized `gpt-5.5` Responses structured smoke test
passes (46 input / 38 output / 84 total tokens). Live PostgreSQL was skipped
because `SRE_TEST_DATABASE_URL` was unset. See `docs/playbooks.md` for operational
limits, including exact single-action resolution and best-effort outcome audits.

## File Map And Ownership

The implementation must keep these write sets disjoint during parallel work:

- `pkg/playbook/types.go`, `pkg/playbook/errors.go`, `pkg/playbook/canonical.go`,
  and their tests own the domain contracts and
  pure safety logic.
- `pkg/triage/task.go`, provider adapters, and task tests own structured LLM
  execution. No playbook package files are changed in this lane.
- `pkg/playbook/store.go`, `pkg/playbook/postgres.go`,
  `pkg/playbook/migrations/001_playbooks.sql`, and repository tests own the
  PostgreSQL adapter. Only this lane changes `go.mod`/`go.sum` for `pgx`.
- `pkg/playbook/ingest.go`, `pkg/playbook/resolve.go`, and `pkg/playbook/learn.go`
  own the pipeline after the domain and repository contracts are integrated.
- `pkg/remediation/engine.go`, `pkg/remediation/executor.go`, and focused
  remediation tests own verification/outcome callbacks.
- `pkg/config/config.go`, `pkg/config/profile.go`, `cmd/sre-agent/main.go`, and
  startup/config tests own runtime wiring and environment settings.
- `pkg/server/server.go`, `pkg/server/handlers.go`, `pkg/metrics/metrics.go`,
  dashboard assets, and tests own API/UI/metrics projections.
- `README.md`, `docs/deployment.md`, and playbook documentation own operator
  setup and test instructions.

The integration worker coordinates shared interfaces, runs formatting and the
full test suite, and does not revert unrelated existing worktree changes.

## Task 1: Define Playbook Domain Contracts

**Files:**

- Create: `pkg/playbook/types.go`
- Create: `pkg/playbook/errors.go`
- Create: `pkg/playbook/canonical.go`
- Test: `pkg/playbook/types_test.go`
- Test: `pkg/playbook/canonical_test.go`

- [x] **Step 1: Write failing contract tests.** Cover lifecycle values,
  required source fields, action parsing, digest-to-playbook copies, stable
  canonical hashes, sorted trigger/step ordering, and clone isolation. The
  canonical hash test must use two values with different input ordering and
  assert equal hashes.

  ```go
  func TestCanonicalHashIsStableAcrossInputOrdering(t *testing.T) {
      first := NormalizedPlaybook{ID: "pod-crash", Version: 1, Steps: []NormalizedStep{
          {ID: "b", Action: "Manual", Description: "inspect"},
          {ID: "a", Action: "RestartPod", Description: "restart"},
      }}
      second := NormalizedPlaybook{ID: "pod-crash", Version: 1, Steps: []NormalizedStep{
          {ID: "a", Action: "RestartPod", Description: "restart"},
          {ID: "b", Action: "Manual", Description: "inspect"},
      }}
      left, err := CanonicalHash(first)
      if err != nil { t.Fatal(err) }
      right, err := CanonicalHash(second)
      if err != nil { t.Fatal(err) }
      if left != right { t.Fatalf("hashes differ: %q != %q", left, right) }
  }
  ```

- [x] **Step 2: Run the focused tests and verify they fail** because the
  domain types and hash function do not exist.

  ```text
  go test ./pkg/playbook -run 'TestCanonicalHashIsStableAcrossInputOrdering|TestLifecycle' -count=1
  Expected: compilation failure for missing package symbols.
  ```

- [x] **Step 3: Implement the contracts.** Define `LifecycleState` values
  `RECEIVED`, `DIGESTED`, `NORMALIZED`, `REVIEW`, `ACTIVE`, `REJECTED`, and
  `RETIRED`; `SourceArtifact`; `EvidenceRef`; `DigestStep`; `PlaybookDigest`;
  `NormalizedStep`; `NormalizedPlaybook`; `ResolutionPlan`; `LearningCandidate`;
  `LearningOutcome`; `MatchQuery`; and `CatalogStats`. Keep imported action names as strings until guardrail
  validation maps them to `triage.ActionType`. Add validation methods that
  reject blank IDs, invalid confidence outside `[0,1]`, oversized text, and
  unknown lifecycle values. `CanonicalHash` must copy and sort all orderless
  slices, marshal a dedicated canonical value, and return a lowercase
  SHA-256 hex digest.

- [x] **Step 4: Run focused tests and verify they pass.**

  ```text
  go test ./pkg/playbook -run 'TestCanonicalHashIsStableAcrossInputOrdering|TestLifecycle' -count=1
  Expected: PASS.
  ```

- [x] **Step 5: Commit the isolated domain change.**

  ```text
  git add pkg/playbook
  git commit -m "feat: define playbook domain contracts"
  ```

## Task 2: Implement Deterministic Normalization And Guardrails

**Files:**

- Create: `pkg/playbook/normalize.go`
- Create: `pkg/playbook/guardrails.go`
- Test: `pkg/playbook/normalize_test.go`
- Test: `pkg/playbook/guardrails_test.go`

- [x] **Step 1: Write failing normalization and policy tests.** Assert that
  normalization maps only supported actions, assigns deterministic IDs to
  missing steps, canonicalizes namespace/kind selectors, preserves unknowns,
  and is idempotent. Assert guardrails reject arbitrary shell, wildcard
  selectors, missing evidence, low confidence, out-of-scope namespaces,
  excessive steps, unknown actions, and mutating plans without approval.

  ```go
  func TestGuardrailsRejectUnknownAndUnsafeActions(t *testing.T) {
      playbook := NormalizedPlaybook{
          ID: "unsafe", Confidence: 0.95,
          Steps: []NormalizedStep{{ID: "one", Action: "kubectl exec", Command: "rm -rf /"}},
      }
      decision := EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7}, playbook)
      if decision.Allowed || len(decision.Reasons) == 0 { t.Fatal("unsafe playbook was allowed") }
  }
  ```

- [x] **Step 2: Run the tests and verify they fail** for absent normalizer and
  guardrail functions.

  ```text
  go test ./pkg/playbook -run 'TestGuardrails|TestNormalize' -count=1
  Expected: compilation failure for missing implementation.
  ```

- [x] **Step 3: Implement `NormalizeDigest` and `EvaluateGuardrails`.** Use a
  fixed action map for the existing typed remediation actions. Preserve an
  unsupported action as a reason, never coerce it to a mutating action. Set
  `RequiresApproval` for all mutation actions and keep observe/manual content
  non-executable. Validate target kind, namespace, maximum steps, confidence,
  evidence references, and pre/postconditions. Return all bounded reasons in
  stable order. Call `CanonicalHash` only after normalization succeeds.

- [x] **Step 4: Run focused tests and verify they pass.**

  ```text
  go test ./pkg/playbook -run 'TestGuardrails|TestNormalize' -count=1
  Expected: PASS.
  ```

- [x] **Step 5: Commit the pure pipeline logic.**

  ```text
  git add pkg/playbook
  git commit -m "feat: normalize and guard playbooks"
  ```

## Task 3: Add Structured LLM Harness Tasks

**Files:**

- Create: `pkg/triage/task.go`
- Modify: `pkg/triage/harness.go`
- Modify: `pkg/triage/codex.go`
- Modify: `pkg/triage/openai_compatible.go`
- Modify: `pkg/triage/claude.go`
- Modify: `pkg/triage/cloud_provider.go`
- Modify: `pkg/triage/deepseek.go`
- Modify: `pkg/triage/cached.go`
- Modify: `pkg/triage/profile.go`
- Test: `pkg/triage/task_test.go`
- Test: `pkg/triage/codex_test.go`

- [x] **Step 1: Write failing runner contract tests.** Define tests for a
  structured Codex Responses request, a shell harness request, response-size
  rejection, context cancellation, redaction of configured secrets, token
  observer propagation, and delegation through the cached/deadline wrappers.

  ```go
  func TestStructuredTaskRunnerBoundsAndRedactsOutput(t *testing.T) {
      runner := NewFakeStructuredTaskRunner(`{"secret":"api-key","ok":true}`)
      result, err := runner.RunStructured(context.Background(), StructuredTask{
          Operation: "playbook.digest", SystemPrompt: "system", UserPrompt: "user",
      })
      if err != nil { t.Fatal(err) }
      if strings.Contains(result.Text, "api-key") { t.Fatal("secret was returned") }
      if !json.Valid([]byte(result.Text)) { t.Fatal("structured output is not JSON") }
  }
  ```

- [x] **Step 2: Run the focused tests and verify they fail** because the task
  interface and provider methods do not exist.

  ```text
  go test ./pkg/triage -run 'TestStructuredTask|TestCodexStructured' -count=1
  Expected: compilation failure for missing task runner symbols.
  ```

- [x] **Step 3: Implement the shared task contract.** Add:

  ```go
  type StructuredTask struct {
      Operation       string
      SystemPrompt    string
      UserPrompt      string
      MaxOutputBytes  int
  }

  type StructuredTaskResult struct {
      Text  string
      Usage ProviderTokenUsage
  }

  type StructuredTaskRunner interface {
      RunStructured(context.Context, StructuredTask) (StructuredTaskResult, error)
  }
  ```

  Bound operation names, prompt sizes, output sizes, and cancellation in one
  helper. Implement the method by reusing each provider’s existing structured
  request path and response parser. `HarnessProvider` must run the configured
  command with bounded buffers and sanitized prompts. Unsupported providers
  return a typed error; they do not silently call `Diagnose` or fabricate
  output. Cached/deadline wrappers delegate without caching a new task type
  until a task-specific cache key exists.

- [x] **Step 4: Run focused tests and verify they pass.**

  ```text
  go test ./pkg/triage -run 'TestStructuredTask|TestCodexStructured' -count=1
  Expected: PASS.
  ```

- [x] **Step 5: Commit the harness change.**

  ```text
  git add pkg/triage
  git commit -m "feat: expose bounded structured harness tasks"
  ```

## Task 4: Add PostgreSQL Catalog And Migrations

**Files:**

- Create: `pkg/playbook/store.go`
- Create: `pkg/playbook/postgres.go`
- Create: `pkg/playbook/migrations/001_playbooks.sql`
- Test: `pkg/playbook/postgres_test.go`
- Modify: `go.mod`
- Modify: `go.sum`

- [x] **Step 1: Write repository contract tests** against an in-memory fake
  implementing the same `Catalog` interface. Cover source checksum
  deduplication, immutable digest/playbook versions, lifecycle transitions,
  active-playbook matching, one learning candidate per idempotency key, and
  relation insertion.

  ```go
  type Catalog interface {
      SaveSource(context.Context, SourceArtifact) error
      SaveDigest(context.Context, PlaybookDigest) error
      SavePlaybook(context.Context, NormalizedPlaybook) error
      ListActive(context.Context, MatchQuery) ([]NormalizedPlaybook, error)
      Transition(context.Context, string, int, LifecycleState, string) error
      RecordLearningCandidate(context.Context, LearningCandidate) error
      Stats(context.Context) (CatalogStats, error)
  }
  ```

- [x] **Step 2: Run the repository tests and verify they fail** for absent
  interfaces and storage implementation.

  ```text
  go test ./pkg/playbook -run 'TestCatalog|TestPostgres' -count=1
  Expected: compilation failure for missing repository symbols.
  ```

- [x] **Step 3: Add `pgx/v5` and implement the adapter.** Use a pool created
  from `SRE_DATABASE_URL`, bounded acquire/ping contexts, and embedded ordered
  migrations. The migration must create `playbook_sources`,
  `playbook_digests`, `playbooks`, `playbook_steps`, `playbook_bindings`,
  `findings`, `evidence_snapshots`, `resolution_runs`, `resolution_steps`,
  `approvals`, `feedback`, `relations`, and a unique idempotency key for
  learning candidates. Store canonical payloads in JSONB, use typed columns for
  state/category/kind/namespace/hash, and add indexes for state, hash,
  checksum, bindings, and search text. All writes must use transactions and
  preserve immutable digest/version rows. Never store API keys or raw secret
  values.

- [x] **Step 4: Run repository tests without a live server.** Use the fake for
  behavior tests and a SQL mock or query-contract layer for PostgreSQL SQL
  statements. Add an integration test that skips unless
  `SRE_TEST_DATABASE_URL` is explicitly set.

  ```text
  go test ./pkg/playbook -run 'TestCatalog|TestPostgres' -count=1
  Expected: PASS; live integration is skipped when the env var is absent.
  ```

- [x] **Step 5: Commit the storage lane.**

  ```text
  git add go.mod go.sum pkg/playbook
  git commit -m "feat: add postgres playbook catalog"
  ```

## Task 5: Implement Import, Digest, And Normalization Services

**Files:**

- Create: `pkg/playbook/ingest.go`
- Create: `pkg/playbook/ingest_test.go`
- [x] **Step 1: Write failing ingestion tests.** Cover Markdown/YAML/JSON
  media detection, malformed structured documents, bounded content, secret
  redaction, prompt-boundary escaping, provider schema errors, unsupported
  commands becoming manual steps, and successful state progression through
  `RECEIVED`, `DIGESTED`, `NORMALIZED`, and `REVIEW`.

- [x] **Step 2: Run focused ingestion tests and verify they fail.**

  ```text
  go test ./pkg/playbook -run 'TestIngest|TestImport' -count=1
  Expected: compilation failure for missing ingestion service.
  ```

- [x] **Step 3: Implement `Ingestor`.** Parse Markdown as bounded text and
  YAML/JSON with `yaml.v3`/`encoding/json` validation. Redact before constructing
  a prompt and wrap source content in an untrusted boundary that treats all
  embedded instructions as data. Call `StructuredTaskRunner` with operation
  `playbook.digest`, decode strict JSON into `PlaybookDigest`, validate it,
  normalize it deterministically, evaluate guardrails, and persist each
  immutable stage. Persist a rejected digest with bounded reasons rather than
  dropping provenance. Commands that do not map to typed actions must be
  represented as `Manual`/review-only content.

- [x] **Step 4: Run focused ingestion tests and verify they pass.**

  ```text
  go test ./pkg/playbook -run 'TestIngest|TestImport' -count=1
  Expected: PASS.
  ```

- [x] **Step 5: Commit the ingestion lane.**

  ```text
  git add pkg/playbook pkg/sanitizer
  git commit -m "feat: digest and normalize imported playbooks"
  ```

## Task 6: Add Guarded Resolution And Verified Self-Evolution

**Files:**

- Create: `pkg/playbook/resolve.go`
- Create: `pkg/playbook/learn.go`
- Test: `pkg/playbook/resolve_test.go`
- Test: `pkg/playbook/learn_test.go`
- Modify: `pkg/remediation/engine.go`
- Modify: `pkg/remediation/executor.go`
- Test: `pkg/remediation/verification_test.go`

- [x] **Step 1: Write failing resolution/learning tests.** Cover active
  playbook matching, sanitized finding prompts, plan issue-ID mismatch,
  unknown action rejection, target UID/resourceVersion mismatch, proposal
  creation with a safe playbook reference command, failed execution producing
  no candidate, unverified execution producing no candidate, verified success
  producing one `DRAFT`, duplicate learning idempotency, and user rejection.

- [x] **Step 2: Run focused tests and verify they fail** because the resolver,
  verification callback, and learning service do not exist.

  ```text
  go test ./pkg/playbook ./pkg/remediation -run 'TestResolve|TestLearn|TestVerification' -count=1
  Expected: compilation failure for missing services and callback types.
  ```

- [x] **Step 3: Implement the resolver.** Query only `ACTIVE` versions whose
  bindings match the sanitized finding. Call the harness with operation
  `playbook.resolve`; require a structured plan containing the exact finding
  ID, selected playbook/version, evidence references, one or more registered
  action types, target identity, approval requirement, and verification
  criteria. Re-run normalization and guardrails on the selected plan, convert
  it to the existing `triage.Diagnosis`, and call
  `CreateProposalForActor`. Use a safe comment-form reference such as
  `# playbook:<id>:<version>` for `ProposedCommand`; never place raw model text
  there.

- [x] **Step 4: Add explicit remediation verification and outcome callbacks.**
  Add `ProposalVerifier` and `OutcomeObserver` interfaces to the remediation
  engine. Extend proposal state with bounded verification status/error fields.
  The Kubernetes executor must verify typed outcomes: deletion observes the
  target gone, scale observes the requested replica count, cordon observes
  `Unschedulable`, and rollout observes a changed target revision. Manual and
  GitOps actions remain unverified. The engine calls the observer only after a
  successful verification; stale, failed, or unavailable verification becomes
  a non-learning outcome.

- [x] **Step 5: Implement the learning service.** On a verified outcome,
  sanitize the before/after evidence and call operation `playbook.learn`.
  Normalize and guard the candidate, force `DRAFT`/`REVIEW` state for
  mutating content, attach lineage to the source playbook/finding/run, and
  persist with an idempotency key plus canonical hash. User feedback changes
  only candidate state and metadata; it cannot alter an active version in
  place.

- [x] **Step 6: Run focused tests and verify they pass.**

  ```text
  go test ./pkg/playbook ./pkg/remediation -run 'TestResolve|TestLearn|TestVerification' -count=1
  Expected: PASS.
  ```

- [x] **Step 7: Commit the resolution lane.**

  ```text
  git add pkg/playbook pkg/remediation
  git commit -m "feat: resolve incidents and learn verified playbooks"
  ```

## Task 7: Add Configuration And Process Wiring

**Files:**

- Modify: `pkg/config/config.go`
- Modify: `pkg/config/profile.go`
- Test: `pkg/config/config_test.go`
- Test: `pkg/config/profile_test.go`
- Modify: `cmd/sre-agent/main.go`
- Test: `cmd/sre-agent/main_test.go`

- [x] **Step 1: Write failing configuration tests.** Assert that
  `SRE_DATABASE_URL` is never printed or persisted as a secret-bearing value,
  playbooks remain disabled when no database is configured, explicit enablement
  without a database fails validation, default learning mode is `AUTO_DRAFT`,
  action/namespace allowlists are bounded, and profile round-trips retain
  non-secret playbook settings.

- [x] **Step 2: Run focused config tests and verify they fail** for missing
  fields and validation.

  ```text
  go test ./pkg/config ./cmd/sre-agent -run 'Test.*Playbook|Test.*Database' -count=1
  Expected: compilation failure for missing configuration fields.
  ```

- [x] **Step 3: Add configuration fields and env mappings.** Add
  `SRE_PLAYBOOK_ENABLED`, `SRE_DATABASE_URL`, `SRE_PLAYBOOK_LEARNING_MODE`,
  `SRE_PLAYBOOK_MIN_CONFIDENCE`, `SRE_PLAYBOOK_ALLOWED_ACTIONS`,
  `SRE_PLAYBOOK_ALLOWED_NAMESPACES`, `SRE_PLAYBOOK_ALLOWED_KINDS`, and bounded
  step/source limits. Persist only safe policy values in `UserSettings`; keep
  credentials and database URLs out of the user config file. Validate
  `AUTO_DRAFT`, `OBSERVE_ONLY`, and `DISABLED`, with mutation auto-promotion
  rejected regardless of user setting.

- [x] **Step 4: Wire startup.** When enabled, create the PostgreSQL catalog,
  construct the playbook service with the structured runner exposed by the
  selected provider, register the remediation outcome observer, and pass the
  service to the scanner loop/server. If disabled, preserve all existing
  memory/file behavior. If enabled but the provider cannot run structured
  tasks, keep observation available and expose a clear unavailable state
  without creating mutating proposals.

- [x] **Step 5: Run focused tests and verify they pass.**

  ```text
  go test ./pkg/config ./cmd/sre-agent -run 'Test.*Playbook|Test.*Database' -count=1
  Expected: PASS.
  ```

- [x] **Step 6: Commit configuration/wiring.**

  ```text
  git add pkg/config cmd/sre-agent
  git commit -m "feat: wire postgres playbook settings"
  ```

## Task 8: Add API, Metrics, Dashboard, And Settings

**Files:**

- Modify: `pkg/server/server.go`
- Modify: `pkg/server/handlers.go`
- Test: `pkg/server/playbook_handlers_test.go`
- Modify: `pkg/metrics/metrics.go`
- Test: `pkg/metrics/metrics_test.go`
- Modify: `pkg/server/static/index.html`
- Modify: `pkg/server/static/app.js`
- Modify: `pkg/server/dashboard_security_test.go`

- [x] **Step 1: Write failing API/metrics/security tests.** Cover authenticated
  listing/import/state transition endpoints, bounded import bodies, invalid
  lifecycle transitions, dashboard projections, task-level token counters,
  and redaction of API keys, database URLs, source credentials, raw evidence,
  and malicious HTML/script content.

- [x] **Step 2: Run focused server tests and verify they fail** for missing
  routes and projections.

  ```text
  go test ./pkg/server ./pkg/metrics -run 'TestPlaybook|TestDashboard|Test.*Token' -count=1
  Expected: compilation failure for missing playbook server interfaces.
  ```

- [x] **Step 3: Add the optional server surface.** Extend `ServerOptions` with
  a narrow playbook service interface and register authenticated routes:
  `/api/v1/playbooks`, `/api/v1/playbooks/import`,
  `/api/v1/playbooks/{id}/approve`, `/api/v1/playbooks/{id}/reject`, and
  `/api/v1/playbooks/{id}/retire`. Enforce existing body/rate/auth limits,
  sanitize all responses, and return structured errors. Add catalog counts,
  guardrail decisions, resolution/learning outcomes, and task/provider token
  usage to the status projection with explicit unavailable values.

- [x] **Step 4: Extend the dashboard.** Add usable authenticated views for
  catalog state, draft review, provenance, resolution outcomes, guardrail
  rejection counts, and settings for learning mode, thresholds, allowlists,
  and provider task configuration. Keep endpoint displays host-safe and never
  render untrusted source HTML as markup.

- [x] **Step 5: Run focused tests and verify they pass.**

  ```text
  go test ./pkg/server ./pkg/metrics -run 'TestPlaybook|TestDashboard|Test.*Token' -count=1
  Expected: PASS.
  ```

- [x] **Step 6: Commit the API/UI lane.**

  ```text
  git add pkg/server pkg/metrics
  git commit -m "feat: expose playbook dashboard and metrics"
  ```

## Task 9: Documentation And Integration Verification

**Files:**

- Modify: `README.md`
- Modify: `docs/deployment.md`
- Create: `docs/playbooks.md`
- Test: `scripts/ci/check-docs.sh` only if the documentation checker needs a
  focused assertion

- [x] **Step 1: Document operator behavior.** Describe PostgreSQL setup,
  migrations, environment variables, import lifecycle, supported typed
  actions, guardrail floors, approval workflow, learning policy, dashboard
  fields, and the optional `SRE_TEST_DATABASE_URL` integration test. State
  clearly that Kind verification is deferred and arbitrary commands are never
  executed.

- [x] **Step 2: Run formatting and focused security checks.**

  ```text
  git diff --name-only --diff-filter=ACMR -z -- '*.go' | xargs -0 -r gofmt -w
  git diff --check
  ./scripts/ci/check-docs.sh
  Expected: PASS.
  ```

- [x] **Step 3: Run the complete unit and static verification suite.**

  ```text
  go test -count=1 -timeout=240s ./...
  go test -race -count=1 -timeout=300s ./...
  go vet ./...
  ./scripts/ci/check-manifests.sh
  ./scripts/ci/check-image-metadata.sh
  bash -n scripts/ci/*.sh
  Expected: all commands pass. Do not run Kind in this phase.
  ```

- [x] **Step 4: Run the environment-gated real provider smoke test** only when
  host credentials are already present. Set `LLM_PROVIDER=codex`,
  `LLM_MODEL=gpt-5.5`, `LLM_WIRE_API=responses`, endpoint allowlist, and the
  host API key through environment variables. Never print the key or write it
  into configuration, fixtures, PostgreSQL, or logs.

- [x] **Step 5: Commit documentation and test evidence.**

  ```text
  git add README.md docs/deployment.md docs/playbooks.md
  git commit -m "docs: document guarded playbook operations"
  ```

## Integration Order And Review Gates

1. Dispatch Tasks 1, 3, and 4 in parallel because their write sets are
   disjoint. Task 2 follows Task 1 and may run in the same batch only after the
   domain types are available.
2. Integrate and review those commits before dispatching Tasks 5 and 6.
3. Dispatch Tasks 7 and 8 after the service interfaces are stable; they may run
   in parallel because configuration and HTTP/UI files are disjoint.
4. Run Task 9 centrally after all workers return. Review every worker diff for
   authentication, redaction, approval, UID/resourceVersion, and fail-closed
   regressions before running the full suite.

The completion bar is an imported playbook reaching `REVIEW`, an approved
canonical playbook producing only a typed guarded proposal, a verified
successful run producing exactly one draft candidate, and failed/unverified
runs leaving the active catalog unchanged.
