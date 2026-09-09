# Enterprise SRE Execution Plan

> **For agentic workers:** Use executing-plans for this implementation. Each task follows test-driven-development and receives spec and code review before completion.

**Goal:** Implement the approved enterprise program with verified observation, scoped identity and durable state, private provider-backed investigations, engineer feedback, owner-approved execution, and reviewed learning.

**Architecture:** Reuse the existing playbook integration through explicit adapters. Separate observation, hypotheses, engineer assessment, recovery, and trusted knowledge. Enforce authorization/privacy outside AI, and isolate cluster credentials from the control plane.

**Tech stack:** Go, Kubernetes client-go, PostgreSQL/pgx, OIDC, existing HTTP/gRPC/MCP and provider adapters, embedded browser UI, Helm, disposable Docker/Kind test infrastructure.

## Global constraints

- Default deployment is observe-only: install no customer-resource mutation roles or executor.
- The diagnostic process receives sanitized evidence and has no Kubernetes credentials.
- No response is not approval.
- Successful API calls do not by themselves establish recovery or causation.
- Unknown actions are denied; unavailable approval/policy state blocks new mutations.
- Raw customer content is excluded by default.
- Revoked knowledge is excluded at retrieval time.
- Learning never changes permissions or activates itself.
- Implement in `/home/kevin/sre/.worktrees/enterprise-sre`; preserve the original checkout.
- Commit only task files. No production deployment, external notifications, or customer-data/provider smoke requests are part of local verification.

Implementation evidence and supported capability boundaries are recorded in [the release record](../../enterprise-release-evidence.md). The detailed historical steps below retain their original sequencing; the release record is authoritative for executed checks.

## Implementation sequence

The comprehensive review record and program plan govern all tasks. Detailed workstream plans are added before their implementation as interfaces become concrete; this avoids inventing incompatible signatures across the whole program.

- [x] Review and reconcile architecture, including existing playbook implementation.
- [x] Integrate reusable existing playbook/provider work; establish a passing baseline.
- [ ] Task 1: W0 scanner reconciliation and active-state correctness.
- [ ] Task 2: W0 operator workflow, monitoring, writer safety, and persistence errors.
- [ ] Task 3: W1 scoped durable domain and PostgreSQL contracts.
- [ ] Task 4: W2 identity, ownership, authorization, and outbox.
- [ ] Task 5: W3 privacy and approved provider profiles.
- [ ] Task 6: W4 fleet setup and collector isolation.
- [ ] Task 7: W5 evidence-driven investigation service and UI.
- [ ] Task 8: W6 granular engineer feedback and invalidation.
- [ ] Task 9: W7 exact owner approvals and isolated executor.
- [ ] Task 10: W8 sustained recovery verification.
- [ ] Task 11: W9 reviewed knowledge and quality reporting.
- [ ] Task 12: W10 integrated deployment, failure, browser, and security validation.

## Task 1: Coverage-aware history and current findings

**Files:** Modify `pkg/scanner/history.go`, `pkg/scanner/contract.go`, `pkg/scanner/dynamic_scanner.go`, `pkg/scanner/dynamic_analyzers.go`, `pkg/scanner/types.go`, `pkg/scanner/sanitized.go`, and `pkg/server/server.go`. Add `pkg/scanner/history_scope_test.go` and `pkg/server/incident_state_test.go`. Update relevant scanner/dynamic/server contracts without weakening existing security tests.

**Interfaces:** Retain the existing `HistoryStore.Record([]*Issue) error` compatibility API. Introduce `ReportHistoryStore` with `RecordReport(*ScanReport) error` for runtime reconciliation. Add `AnalyzerNames []string` to Issue/SanitizedIssue and preserve copies through serialization/deduplication. Runtime scans always use the report-aware path. Legacy custom stores without it receive a conservative merged unresolved snapshot rather than a partial result that deletes unrelated history.

- [ ] Add table-driven tests for full scan, one-namespace scan, one-analyzer scan, failed analyzer, excluded namespace, name filter, label selector, canceled scan, repeated report, and resource recreation. Run `go test ./pkg/scanner -run 'TestHistoryScope|TestHistoryCoverage' -count=1`; demonstrate the current false-resolution failure before implementation.

The core behavioral regression is:

```go
func TestHistoryScopePreservesUnscannedNamespace(t *testing.T) {
    store := NewMemoryHistoryStore()
    first := &ScanReport{Scope: scanplan.Default().EffectiveScope(),
        Analyzers: []AnalyzerRun{{Info: AnalyzerInfo{Name: "Probe", Resource: "Pod"}}},
        Issues: []*Issue{
            {ID: "a", Namespace: "team-a", Kind: "Pod", Name: "broken", AnalyzerNames: []string{"Probe"}},
            {ID: "b", Namespace: "team-b", Kind: "Pod", Name: "broken", AnalyzerNames: []string{"Probe"}},
        }}
    if err := store.RecordReport(first); err != nil { t.Fatal(err) }
    plan := scanplan.Default()
    plan.IncludeNamespaces = []string{"team-a"}
    second := &ScanReport{Scope: plan.EffectiveScope(), Analyzers: first.Analyzers}
    if err := store.RecordReport(second); err != nil { t.Fatal(err) }
    entries, err := store.List()
    if err != nil { t.Fatal(err) }
    for _, entry := range entries {
        if entry.Issue.Namespace == "team-b" && entry.Resolved {
            t.Fatal("unscanned namespace was resolved")
        }
    }
}
```

- [ ] Attach source analyzer names before aggregation; union provenance when findings deduplicate. Preserve source names across sanitization and history restart.
- [ ] Reconcile only absence proven by successful source-analyzer coverage and the effective scope. If source provenance is unknown or label membership cannot be established, retain the finding as unresolved. Never infer label membership from a missing result. Failed/canceled coverage cannot resolve findings.
- [ ] Record the combined typed/dynamic report exactly once. Suppress intermediate typed persistence through an internal execution option, not by swapping a shared store on the scanner. Preserve dynamic unavailable/forbidden information and report timestamps.
- [ ] Prevent out-of-order completed reports from overwriting newer evidence or resurrecting already-resolved findings. Track observation/report times and duplicate report identity; define compatibility behavior for legacy callers without timestamps.
- [ ] File persistence builds a new state, writes it atomically, and publishes it in memory only after success. Readers receive independent copies.
- [ ] Make active findings derive from reconciled history when available; retain explicit fallback behavior for simple embedded scanners. A targeted nonempty result cannot hide other unresolved findings. Show coverage/freshness separately from the incident count.
- [ ] Run `go test -race ./pkg/scanner ./pkg/server ./cmd/sre-agent`; add dynamic combined-report and restart regressions. Commit only Task 1 files with `fix: reconcile findings within successful scan coverage`.

## Task 2: Correct operator workflow and deployment baseline

**Files:** Modify `pkg/server/static/app.js`, `pkg/server/static/index.html`, `pkg/server/handlers.go`, `pkg/remediation/engine.go`, `pkg/remediation/store.go`, `cmd/sre-agent/main.go`, Helm ServiceMonitor/deployment/values/helpers templates, base deployment, and associated tests. Add executable Node/browser contract fixtures and writer-lock tests.

**Interfaces:** Cleanup returns HTTP 202 with `proposals`, never a completed-deletion count. A cleanup selection is namespace plus name. Proposal status/history remains visible after approval. Proposal creation exposes whether a new record was created so unchanged scans do not send duplicate created events. Terminal persistence failures remain observable and retryable/reconcilable without replaying cluster effects.

- [ ] Reproduce the cleanup mismatch with an executable JavaScript test using a 202 proposal response. Assert the displayed text contains pending approval and contains neither `undefined` nor a successful-deletion claim. Cover identical names in different namespaces.
- [ ] Render all proposal lifecycle states with status filters and a safe detail link; do not display "all clear" based solely on pending approval count. Show explicit request errors and stale-data indicators.
- [ ] Render authenticated ServiceMonitor credentials from a Secret reference whenever API authentication is enabled. Validate the reference configuration; never render secret values in monitoring configuration.
- [ ] Enforce one file-backed writer through an OS-level lock and disallow multiple chart replicas with local file persistence. Use a non-overlapping rollout strategy. Document the availability tradeoff until shared storage is implemented.
- [ ] Inject a store transition failure after executor success. Assert failure is observable and the external action is not submitted again. Do not convert storage errors into an absent proposal or a successful recorded completion.
- [ ] Assert reused proposals do not trigger a new creation notification. Keep bounded transport retries separate from incident-state deduplication.
- [ ] Run `go test -race ./pkg/server ./pkg/remediation ./cmd/sre-agent`, executable frontend fixtures, `scripts/ci/check-helm.sh`, `make check`, and `git diff --check`; commit `fix: align operator workflows with durable proposal state`.

## Test and review protocol

For every task: write behavioral failing tests, run them to demonstrate the defect/missing contract, implement the minimal coherent change, run focused tests, run spec review, address findings, then run code-quality review. Broaden tests when changes affect shared contracts. Do not call a workstream finished because its package compiles if its supported API/process/deployment wiring is missing.

No production credentials are needed for deterministic fixtures. Disposable database/cluster resources must have task-specific names and be cleaned up only when created by this work. A skipped integration check remains an explicit release limitation.
