# SRE Feature-Gap Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all locally implementable partial K8sGPT capability slices, preserve KubeBee SRE safety guarantees, and prove end-to-end diagnosis and deterministic remediation in a disposable Kind cluster.

**Architecture:** Keep the existing scanner, triage, cache, server, remediation, plugin, integration, and deployment boundaries. Workers implement disjoint subsystem contracts with focused tests; the integration workspace coordinates shared configuration, dependency, and documentation changes. The background scanner uses client-go shared informers for Pod and core Event changes, a bounded/debounced latest-state trigger queue for targeted scans, and the existing periodic full scan as a correctness backstop. Kind runs the real binary against fixture resources and observes authenticated issue/proposal projections. It defaults to the host's Codex/OpenAI-compatible Responses API through environment-only configuration, with an explicit `SRE_KIND_LLM_PROVIDER=rule-based` offline mode.

For resource-constrained development hosts, verification proceeds through unit,
fake-client, race, vet, manifest, and shell-contract tests first. The Kind
acceptance remains a separate final gate and is not required for the local
event-trigger implementation loop when the host cannot safely run a cluster.

**Tech Stack:** Go 1.25, client-go typed/dynamic clients, Kubernetes fake clients and envtest fixtures, `net/http`, gRPC, AES-GCM, Prometheus metrics, Kustomize, Helm, Docker, Kind, `kubectl`, `curl`, and `jq`.

---

## Coverage Map

| Workstream | Gap slices | Disjoint write scope |
|---|---|---|
| Analyzer parity | `KG-ANL-01` through `KG-ANL-12` | `pkg/scanner`, scanner tests, dynamic analyzer fixtures |
| Provider/cache/privacy | `KG-CLI-06`, `KG-AI-02`, `KG-AI-03`, `KG-AI-05` through `KG-AI-08`, `KG-CACHE-01` through `KG-CACHE-03`, `KG-PRIV-01` | `pkg/triage`, `pkg/cache`, `pkg/sanitizer`, triage/cache tests |
| API/lifecycle/integrations | `KG-API-01`, `KG-API-02`, `KG-API-04`, `KG-EXT-01`, `KG-EXT-02`, `KG-INT-02`, `KG-INT-03`, `KG-OPS-03` | `pkg/server`, `pkg/remediation`, `pkg/plugin`, `pkg/integration`, API tests and deployment RBAC |
| Kind and delivery | `KG-OPS-04` evidence plus acceptance for every implemented slice | `deploy/fixtures/kind`, `deploy/overlays/kind`, `scripts/ci`, `Makefile`, CI checks |
| Dashboard observability | Authenticated error/token metrics and sanitized runtime settings | `pkg/metrics`, `pkg/server`, `pkg/server/static`, dashboard contract tests |

`KG-INT-01`, `KG-OPS-01`, and `KG-OPS-02` are already covered by current
contract/manifests; final verification must keep those checks passing. External
cloud identity, OIDC, ingress TLS, and distributed failover remain explicit
deployment evidence boundaries rather than false local claims.

## Parallel Execution Rules

- Before dispatch, record the current clean baseline and create one worker per disjoint write scope.
- Analyzer, provider/cache/privacy, API/lifecycle/integration, and Kind/delivery workers run concurrently in isolated forks.
- Workers must use TDD: add one failing test, run it and record the expected failure, implement the smallest fix, run the focused suite, then run `gofmt`.
- Workers must not edit `go.mod`, `go.sum`, `pkg/config`, `cmd/sre-agent/main.go`, the central feature-gap matrix, or generated protobuf files without reporting the required change to the integration workspace.
- The integration workspace applies shared changes, resolves dependency conflicts, reviews every worker diff, and runs the full verification sequence.

### Task 1: Analyzer Contract And Kubernetes Semantic Parity

**Worker:** analyzer-parity

**Files:**
- Modify: `pkg/scanner/scanner.go`, `pkg/scanner/types.go`, `pkg/scanner/contract.go`, `pkg/scanner/analyzers_workloads.go`, `pkg/scanner/analyzers_networking.go`, `pkg/scanner/analyzers_policy.go`, `pkg/scanner/analyzers_extended.go`, `pkg/scanner/query.go`.
- Modify: `pkg/scanner/dynamic_analyzers.go`, `pkg/scanner/dynamic_scanner.go`.
- Create/modify tests: `pkg/scanner/analyzer_parity_test.go`, `pkg/scanner/analyzer_semantics_test.go`, `pkg/scanner/dynamic_conformance_test.go`, `pkg/scanner/analyzers_networking_endpoint_test.go`.

- [ ] **Step 1: Add a failing category coverage test.** Build a table of every supported `IssueCategory` with a fixture object and assert that `ScanWithPlan` returns the expected category, stable kind/name, bounded details, and a nonempty docs URL. Include at least Pod, workload, Service, Ingress, NetworkPolicy, storage, HPA, PDB, webhook, ConfigMap, node, security, Gateway, OLM, KEDA, Kyverno, and Prometheus cases.

```go
func TestAnalyzerParityProducesStableEvidence(t *testing.T) {
	for _, tc := range parityCases() {
		t.Run(tc.Name, func(t *testing.T) {
			report, err := tc.Scanner.ScanWithPlan(context.Background(), tc.Plan)
			if err != nil { t.Fatal(err) }
			issue := findCategory(report.Issues, tc.Category)
			if issue == nil || issue.Name != tc.Name || issue.DocsURL == "" {
				t.Fatalf("missing stable finding: %#v", report.Issues)
			}
			if len(issue.Details) > maxIssueDetailsBytes { t.Fatal("details unbounded") }
		})
	}
}
```

- [ ] **Step 2: Run the test and verify a real missing-semantic failure.** Run `go test ./pkg/scanner -run TestAnalyzerParityProducesStableEvidence -count=1 -v`; expected: FAIL because at least one fixture is not emitted or loses selector/parent evidence.
- [ ] **Step 3: Implement shared scan semantics.** Propagate `scanplan.Plan.ListOptions()` to every typed and dynamic list operation; use namespace include/exclude and resource-name filtering consistently; classify forbidden and unsupported API errors in `AnalyzerRun.Error`; keep independent analyzers running after one error; deduplicate findings by versioned fingerprint; sort analyzers and issues deterministically.
- [ ] **Step 4: Complete typed analyzer behavior.** Add multiple findings per Pod including init/ephemeral/previous-log evidence; owner/template/selector/progress/deadline/retry/missed-schedule checks for all workload kinds; EndpointSlice with legacy fallback and ready/serving/terminating handling; Service target-port/headless/ExternalName validation; Ingress class/path/backend/status/TLS validation; NetworkPolicy empty/match-expression/namespace selector semantics; StorageClass/PV/PVC phases, capacity, defaults, and missing classes; HPA target/metric semantics; PDB selector intent; webhook CA/service/port/URL/failure-policy/timeout validation; ConfigMap reference/size/empty/dynamic-sidecar handling; and ClusterRole/ClusterRoleBinding plus init/ephemeral security paths.
- [ ] **Step 5: Complete dynamic capability behavior.** Make GatewayClass/Gateway/HTTPRoute/ReferenceGrant, seven OLM resource families, and KEDA/Kyverno/Prometheus families use capability discovery, plan selectors, optional-field guards, and explicit absent/forbidden/unavailable states. Enforce Gateway listener attachment, `sectionName`, backend group/kind/namespace, cross-namespace ReferenceGrant, and parent acceptance semantics.
- [ ] **Step 6: Run focused green verification.** Run `gofmt -w pkg/scanner/*.go`, `go test ./pkg/scanner ./pkg/scanplan -count=1`, and `go vet ./pkg/scanner ./pkg/scanplan`; expected: all focused tests pass with no panic or ignored permission errors.
- [ ] **Step 7: Commit the worker change.** Commit only scanner files and tests as `feat: complete analyzer parity semantics` and report the commit plus test output.

### Task 2: Provider, Cache, Privacy, And Deterministic Solutions

**Worker:** provider-cache-parity

**Files:**
- Modify: `pkg/triage/provider.go`, `pkg/triage/fallback.go`, `pkg/triage/claude.go`, `pkg/triage/codex.go`, `pkg/triage/deepseek.go`, `pkg/triage/cloud_provider.go`, `pkg/triage/aws_provider.go`, `pkg/triage/openai_compatible.go`, `pkg/triage/cached.go`, `pkg/triage/profile.go`.
- Modify: `pkg/cache/cache.go`, `pkg/cache/file.go`, `pkg/cache/remote.go`, `pkg/cache/blobstore.go`, `pkg/cache/observe.go`, `pkg/sanitizer/sanitizer.go`.
- Create/modify tests: `pkg/triage/provider_parity_test.go`, `pkg/triage/fallback_coverage_test.go`, `pkg/triage/cloud_contract_test.go`, `pkg/cache/semantic_key_test.go`, `pkg/cache/provider_contract_test.go`, `pkg/sanitizer/sink_matrix_test.go`.

- [ ] **Step 1: Add failing provider and category tests.** Assert unknown providers return an error, each named provider rejects invalid configuration without process exit, empty successful responses return typed errors, and every scanner category receives a nonempty safe diagnosis.

```go
func TestRuleProviderCoversEverySupportedCategory(t *testing.T) {
	for _, category := range scanner.AllIssueCategories() {
		diagnosis, err := NewRuleBasedProvider("fixture-token").Diagnose(context.Background(), &scanner.Issue{
			ID: "fixture/" + string(category), Kind: "Pod", Name: "fixture", Namespace: "sre-fixtures", Category: category,
			Severity: scanner.SeverityMedium, Details: "fixture details",
		})
		if err != nil || diagnosis.Summary == "" || diagnosis.RootCause == "" || diagnosis.RemediationPlan == "" || diagnosis.ActionType == "" {
			t.Fatalf("category %s has no complete solution: %#v %v", category, diagnosis, err)
		}
	}
}
```

- [ ] **Step 2: Run focused tests and verify red.** Run `go test ./pkg/triage ./pkg/cache ./pkg/sanitizer -run 'TestRuleProviderCoversEverySupportedCategory|TestUnknownProvider|TestSemanticCache' -count=1 -v`; expected: FAIL on uncovered categories, unknown-provider fallback, or cache-key collisions.
- [ ] **Step 3: Fail closed and isolate provider state.** Validate canonical provider names and aliases before construction; return typed errors for unknown names and malformed endpoints; construct request-scoped adapters or immutable profiles; pass contexts/deadlines through every provider; bound response bodies and handle empty choices/parts for Azure, OpenAI-compatible, Bedrock, SageMaker, Gemini, Vertex, OCI, IBM, Cohere, Hugging Face, Claude, and custom modes. Add `ProviderProfile.WireAPI` and `LLM_WIRE_API` with only `chat` and `responses`; implement the Codex/OpenAI Responses request and response envelope used by the host configuration, including `output_text` extraction and strict response validation.
- [ ] **Step 4: Expand deterministic diagnosis.** Add explicit mappings for every supported `IssueCategory`, including networking, storage, policy, webhook, ConfigMap, security, dynamic, and integration findings. Each mapping must set issue ID, summary, root cause, remediation plan, confidence in `[0,1]`, an allow-listed action, and a redacted command. Unsupported future categories return a visible `Manual` diagnosis instead of an empty solution.
- [ ] **Step 5: Close privacy and cache gaps.** Redact configured literals, structured secret fields, bearer/JWT/private-key values, logs/events/spec snippets, provider errors, prompts, webhook payloads, and cached bytes. Exclude raw mappings from JSON/YAML. Include operation, provider, model, endpoint, prompt schema, redaction schema, and evidence digest in cache keys. Return setup/transport errors from cloud and remote cache backends; never call `log.Fatal`, use insecure TLS, or use uncancellable background operations.
- [ ] **Step 6: Run green verification.** Run `gofmt -w pkg/triage/*.go pkg/cache/*.go pkg/sanitizer/*.go`, `go test ./pkg/triage ./pkg/cache ./pkg/cache/remote ./pkg/sanitizer -count=1`, and `go vet ./pkg/triage ./pkg/cache ./pkg/sanitizer`; expected: provider matrix, cache concurrency/corruption, and sink matrix pass.
- [ ] **Step 7: Commit the worker change.** Commit only provider/cache/privacy files and tests as `feat: close provider cache and privacy gaps` and report the commit plus test output.

### Task 3: API, Remediation, Plugin, And Integration Lifecycle

**Worker:** api-lifecycle-parity

**Files:**
- Modify: `pkg/server/server.go`, `pkg/server/handlers.go`, `pkg/server/chat_sessions.go`, `pkg/server/mcp.go`, `pkg/server/supportbundle.go`.
- Modify: `pkg/remediation/engine.go`, `pkg/remediation/executor.go`, `pkg/remediation/store.go`, `pkg/scanner/cleaner.go`.
- Modify: `pkg/plugin/client.go`, `pkg/plugin/registry.go`, `pkg/plugin/supervisor.go`, `pkg/integration/registry.go`, `pkg/integration/aws.go`.
- Modify: `pkg/grpcapi/server.go`, `api/v1/sre.proto`, `api/v1/plugin.proto` only if a contract field is required; regenerate generated files with the repository's protobuf command and report the exact command.
- Modify: `deploy/k8s/rbac.yaml`, `deploy/overlays/remediation/remediation-rbac-patch.yaml` only for verified verbs.
- Create/modify tests: `pkg/server/lifecycle_contract_test.go`, `pkg/server/mcp_bounds_test.go`, `pkg/remediation/lifecycle_test.go`, `pkg/plugin/discovery_test.go`, `pkg/integration/lifecycle_test.go`, `pkg/grpcapi/compatibility_test.go`.

- [ ] **Step 1: Add failing boundary tests.** Cover structured 400/401/403/413/429/499 behavior, gRPC malformed/nil messages and deadlines, MCP negative bounds and log limits, durable proposal restart recovery, stale UID/resourceVersion rejection, cleanup eligibility/approval, plugin discovery/close/cancellation, and integration ownership rollback.
- [ ] **Step 2: Run focused tests and verify red.** Run `go test ./pkg/server ./pkg/remediation ./pkg/plugin ./pkg/integration ./pkg/grpcapi -run 'TestLifecycle|TestBounds|TestStale|TestDiscovery' -count=1 -v`; expected: FAIL on at least one unbounded input, lost state transition, or missing lifecycle contract.
- [ ] **Step 3: Complete authenticated API lifecycle.** Ensure all non-health routes and gRPC services require verified bearer identity, reject caller-controlled actor headers, propagate request context, bound request/response bodies, serialize configuration writes, keep metrics labels low-cardinality, and make MCP start/close explicit with no fatal asynchronous bind path. Keep query resources allow-listed and reject Secret reads.
- [ ] **Step 4: Complete mutation and cleanup lifecycle.** Route cleanup through proposal approval; re-check candidate eligibility immediately before deletion; enforce protected labels/namespaces, UID/resourceVersion preconditions, dry-run semantics, action policy, idempotency, postcondition checks, and audited force deletion only when explicitly authorized. Preserve durable file-store transitions and execution logs across restart.
- [ ] **Step 5: Complete extension/integration lifecycle.** Add authenticated plugin discovery/metadata validation, TLS/loopback policy, close ownership, quotas, cancellation, and optional signature enforcement. Make integration activation/deactivation explicit, ownership-scoped, failure-propagating, rollback-aware, and non-destructive for unrelated namespaces; preserve read-only default RBAC.
- [ ] **Step 6: Run green verification.** Run `gofmt -w` on changed Go files, `go test ./pkg/server ./pkg/remediation ./pkg/plugin ./pkg/integration ./pkg/grpcapi -count=1`, and `go vet` on those packages; expected: no panic, process exit, broad deletion, or unbounded response.
- [ ] **Step 7: Commit the worker change.** Commit the API/lifecycle files as `feat: close API remediation and extension gaps` and report the commit plus test output.

### Task 4: Kind Failure Fixtures And Controller Observation

**Worker:** kind-acceptance

**Files:**
- Create: `deploy/fixtures/kind/namespace.yaml`, `deploy/fixtures/kind/pods.yaml`, `deploy/fixtures/kind/workloads.yaml`, `deploy/fixtures/kind/networking.yaml`, `deploy/fixtures/kind/policy.yaml`, `deploy/fixtures/kind/storage.yaml`, `deploy/fixtures/kind/security.yaml`, `deploy/fixtures/kind/webhooks.yaml`, `deploy/fixtures/kind/dynamic-crds.yaml`, `deploy/fixtures/kind/dynamic-resources.yaml`.
- Create: `scripts/ci/kind-fixtures.sh` and `scripts/ci/kind-assertions.sh`.
- Modify: `scripts/ci/kind-integration.sh`, `deploy/overlays/kind/configmap-patch.yaml`, `deploy/overlays/kind/kustomization.yaml`, `Makefile`.
- Create/modify tests: `scripts/ci/kind-fixtures_test.sh` or a shellcheck-compatible assertion test under `scripts/ci`.

- [ ] **Step 1: Add failing fixture/assertion checks.** Validate fixture files contain expected scenario names and that the assertion helper fails when one expected category or proposal field is absent. Require `kind`, `docker`, `kubectl`, `curl`, and `jq` with an explicit skip only when Kind itself is unavailable.
- [ ] **Step 2: Run the fixture checks and verify red.** Run `bash -n scripts/ci/kind-fixtures.sh scripts/ci/kind-assertions.sh scripts/ci/kind-integration.sh` and the fixture assertion test; expected: FAIL until all scenario IDs and response predicates exist.
- [ ] **Step 3: Create safe Kubernetes fixtures.** Add one named fixture per supported typed category: pending scheduling, invalid image, crash loop, exit-137/OOM-shaped failure, failed/evicted/terminating pod, log error and previous-log restart, degraded Deployment/StatefulSet/DaemonSet/ReplicaSet/Job/CronJob, selectorless/empty Service and EndpointSlice mismatch, invalid Ingress class/backend/port/TLS, empty/wide/orphan NetworkPolicy, invalid HPA/PDB, pending PVC and failed/released PV/storage class, empty/unused/large ConfigMap, missing webhook service/target, unschedulable/tainted/failing synthetic Node, and privileged ClusterRoleBinding/init-container cases. Use fixture labels and a shared token string so assertions can prove redaction.
- [ ] **Step 4: Add optional dynamic fixtures.** Install minimal CRDs for Gateway API, OLM, KEDA, Kyverno, and Prometheus only where the dynamic scanner has a supported GVR; apply failing condition objects and record absent/forbidden capability output when a fixture is intentionally unavailable. Never grant the agent mutation verbs just to create fixtures; the test harness uses the operator kubeconfig separately.
- [ ] **Step 5: Expand the Kind integration flow.** Set `SCAN_INTERVAL=5s`, `SRE_SCAN_JITTER=0s`, temporary data storage, and the fixture namespace. Default `LLM_PROVIDER=codex`, `LLM_MODE=remote`, `LLM_WIRE_API=responses`, `LLM_API_KEY` from `SRE_KIND_LLM_API_KEY` or host `CODEX_*`/`OPENAI_*` variables, `LLM_BASE_URL` from `SRE_KIND_LLM_BASE_URL` or the host Codex/OpenAI endpoint, and `LLM_MODEL` from `SRE_KIND_LLM_MODEL` or the host model. Pass the key only through a temporary Secret and never echo it. Require complete structured Codex diagnoses by default; allow `SRE_KIND_LLM_PROVIDER=rule-based` as the explicit offline override and label the output accordingly. After rollout/readiness, apply fixtures, poll authenticated `/api/v1/issues` until all expected category IDs appear, reject any response containing the API token or fixture secret, then poll `/api/proposals` until each issue has a complete provider diagnosis and supported action. Call `/api/v1/scan` once with JSON output and assert deterministic ordering and effective scope. Save response artifacts on failure and always delete only the uniquely created cluster.
- [ ] **Step 6: Run the acceptance test.** Run `make kind-test`; expected output includes cluster name, health/readiness status, unauthenticated `401`, authenticated `200`, expected fixture count, expected category count, expected proposal count, and cleanup success. If Kind/Docker are unavailable, report the exact skip; do not convert an available-but-failing Kind run into a skip.
- [ ] **Step 7: Commit the worker change.** Commit fixtures and scripts as `test: exercise diagnosis and solutions in Kind` and report the scenario/category/proposal counts.

### Task 5: Shared Integration And Configuration Wiring

**Owner:** integration workspace after Tasks 1-4 return

**Files:**
- Modify: `cmd/sre-agent/main.go`, `cmd/sre-agent/cli.go`, `pkg/config/config.go`, `pkg/config/profile.go`, `go.mod`, `go.sum` only for dependencies proven necessary by worker changes.
- Modify: `deploy/k8s/configmap.yaml`, `deploy/k8s/deployment.yaml`, `deploy/k8s/service.yaml`, `deploy/k8s/pdb.yaml`, `deploy/k8s/networkpolicy.yaml`, `deploy/helm/sre-agent/values.yaml` and affected Helm templates.
- Regenerate: protobuf outputs only when Task 3 changes a `.proto` contract.

- [ ] **Step 1: Review worker reports and diffs.** Confirm each worker changed only its declared paths, inspect all tests and error handling, and list shared symbols/dependencies before applying changes.
- [ ] **Step 2: Add failing wiring tests.** Extend `cmd/sre-agent/main_test.go`, `cmd/sre-agent/cli_test.go`, and `pkg/config/config_test.go` to assert the Kind settings, provider aliases, fixture scan interval, persisted data directory, and any new analyzer/provider registration reach the running process.
- [ ] **Step 3: Wire shared contracts.** Resolve central category catalog/config fields, add `Config.LLMWireAPI` from `LLM_WIRE_API`, ensure `providerProfileFromConfig` passes it into `triage.ProviderProfile`, ensure the background scanner uses the same validated `ScanPlan` and configured provider as CLI/REST, pass redaction secrets from configuration to every sink, and preserve read-only base RBAC with remediation overlay separation. The Kind script must select `codex` and `responses` by default from `SRE_KIND_LLM_*` or host `CODEX_*`/`OPENAI_*` environment values, inject only the key through a temporary Secret, and require `rule-based` to be explicitly selected for offline runs.
- [ ] **Step 4: Align build/deployment dependencies.** Keep Go/toolchain versions aligned, fix image build arguments/OCI metadata, add any required CRD fixture dependencies without making production startup depend on optional CRDs, and ensure Helm/Kustomize selectors are release-scoped.
- [ ] **Step 5: Run integration tests.** Run `gofmt -w` on all changed Go files, `go test ./... -count=1`, `go vet ./...`, `./scripts/ci/check-manifests.sh`, `./scripts/ci/check-image-metadata.sh`, `./scripts/ci/check-helm.sh`, and `bash -n scripts/ci/*.sh`; expected: all exit 0 before documentation claims change.

### Task 6: Documentation, Evidence, And Closure Ledger

**Owner:** integration workspace after implementation evidence exists

**Files:**
- Modify: `docs/kubebee-sre-k8sgpt-feature-gap.md`, `docs/kubebee-sre-k8sgpt-evidence.md`, `docs/kubebee-sre-k8sgpt-roadmap.md`, `README.md`, `docs/deployment.md`, `deploy/helm/sre-agent/README.md`.
- Modify: `scripts/ci/check-docs.sh` and add `scripts/ci/check-feature-gap-ledger.sh`.

- [ ] **Step 1: Add failing ledger checks.** Verify every `KG-*` ID is unique, every `Partial`/`Missing` row has a concrete missing slice, every closure row cites a test/fixture/script, analyzer/provider counts match source registration, and every cited path exists.
- [ ] **Step 2: Run the checks and verify red against the old matrix.** Run `./scripts/ci/check-feature-gap-ledger.sh`; expected: FAIL because the old 14 Covered/31 Partial counts and evidence references do not describe the new acceptance artifacts.
- [ ] **Step 3: Update claims from evidence.** Move only verified locally implementable rows to `Covered` or an explicitly tested safer equivalent; keep external cloud/OIDC/failover rows `Partial` with their exact deployment evidence boundary. Document the Kind fixture matrix, rule-based solution contract, optional CRD behavior, auth requirements, retention/redaction policy, RBAC profiles, and migration/upgrade behavior.
- [ ] **Step 4: Add executable documentation checks.** Make CI run representative `version`, `scan --output json`, `analyzers`, cache/profile commands, manifest rendering, and `make kind-test` when prerequisites exist. Reject stale claims such as full upstream parity without conformance evidence, direct cleanup bypass, or unauthenticated routes.
- [ ] **Step 5: Run docs verification.** Run `./scripts/ci/check-docs.sh`, `./scripts/ci/check-feature-gap-ledger.sh`, `git diff --check`, and inspect generated/current counts; expected: no stale claim, missing path, duplicate ID, or unsupported completion claim.

### Task 7: Final Verification And Independent Review

**Owner:** integration workspace

- [ ] **Step 1: Run the complete local suite.** Run `go test -count=1 ./...`, `go test -race -count=1 ./...`, and `go vet ./...`; record exit status and package counts.
- [ ] **Step 2: Run delivery checks.** Run `./scripts/ci/check-docs.sh`, `./scripts/ci/check-feature-gap-ledger.sh`, `./scripts/ci/check-manifests.sh`, `./scripts/ci/check-image-metadata.sh`, `./scripts/ci/check-helm.sh`, `bash -n scripts/ci/*.sh`, `git diff --check`, and a clean `make build && make version`.
- [ ] **Step 3: Run Kind from a clean image build.** Run `make kind-test` with no reused cluster, retain failure artifacts if it fails, and verify the output includes all fixture/category/proposal counts and authenticated status checks.
- [ ] **Step 4: Review security invariants.** Search changed files for wildcard CORS, raw secret fields, caller-controlled actors, `log.Fatal`/`os.Exit` in libraries, insecure provider/cache transport, force-delete fallback, floating image tags, unbounded `io.ReadAll`, and unauthenticated mutation routes. Fix any finding before claiming completion.
- [ ] **Step 5: Request final code review.** Have an independent reviewer compare the implementation against this plan and the design spec, especially the Kind assertion path and every changed feature-gap row. Resolve all Critical/Important findings, rerun affected tests, and only then update the evidence ledger.

### Task 8: Dashboard Metrics And Settings

**Owner:** integration workspace, with provider/API workers contributing shared
metrics hooks

**Files:**
- Modify: `pkg/metrics/metrics.go`, `pkg/server/handlers.go`, `pkg/server/server.go` only if a sanitized dashboard projection route is required.
- Modify: `pkg/server/static/index.html`, `pkg/server/static/app.js`.
- Create/modify tests: `pkg/metrics/metrics_test.go`, `pkg/server/dashboard_security_test.go`, and the relevant authenticated handler tests.

- [ ] **Step 1: Add failing contract tests.** Assert the authenticated dashboard projection exposes bounded error and token-usage fields plus masked runtime settings, while rejecting unauthenticated access and excluding API keys, custom header values, cache encryption keys, fixture secrets, and raw webhook URLs.
- [ ] **Step 2: Implement observability projection.** Record provider usage when a response reports prompt/completion/total tokens, expose low-cardinality error counters, and return a read-only JSON projection suitable for the dashboard. Keep Prometheus metrics available for machine consumers and return an explicit unavailable state when usage is not reported.
- [ ] **Step 3: Implement the UI.** Add a Metrics tab with error count, scan/analyzer/provider error totals, token usage, last refresh, and unavailable/error states. Expand Settings with provider/wire API/model, scan cadence, cache state, webhook status, and safe actions. Use the existing authenticated fetch path and escape all server data before rendering.
- [ ] **Step 4: Verify responsive/security behavior.** Run static dashboard security tests, authenticated handler tests, and browser-compatible syntax checks; inspect desktop/mobile layout for overflow or secret leakage.
- [ ] **Step 5: Include dashboard assertions in Kind.** Poll the authenticated metrics/settings endpoints after fixture diagnosis and assert that error count and provider usage are visible or explicitly unavailable, while sensitive values remain absent.

### Task 9: Event-Driven Scan Coordination

**Owner:** integration workspace after the scheduler contract is available

**Files:**
- Create: `pkg/scheduler/trigger.go`, `pkg/scheduler/kube_trigger.go`.
- Modify: `pkg/scheduler/scheduler.go`, `cmd/sre-agent/main.go`, `pkg/config/config.go`, `pkg/config/profile.go`, `pkg/server/server.go`, `pkg/server/handlers.go`, and the embedded dashboard settings.
- Create/modify tests: `pkg/scheduler/trigger_test.go`, `pkg/scheduler/kube_trigger_test.go`, configuration/status/dashboard contract tests.

- [ ] **Step 1: Add failing queue and informer contracts.** Cover latest-state coalescing, bounded overflow, debounce, cancellation, Pod add/update/delete, warning Event filtering and involved-object targeting, namespace filtering, and shared periodic/event overlap protection.
- [ ] **Step 2: Implement the hybrid coordinator.** Use client-go informers rather than an admission webhook for kubelet/controller-generated state, filter callbacks against the configured plan, preserve dependency kinds for targeted analysis, run only in the active leader term, and retain periodic full scans for recovery.
- [ ] **Step 3: Expose safe event settings.** Add environment/flag/profile values for event mode, queue capacity, and debounce; include sanitized values in status, gRPC config, and the dashboard settings page.
- [ ] **Step 4: Run local verification first.** Run `go test ./pkg/scheduler ./pkg/config ./pkg/server ./cmd/sre-agent`, the corresponding race/vet checks, the full Go suite, and delivery contract checks. Defer `make kind-test` when the host is resource-constrained and record that evidence boundary.

## Final Acceptance

The work is complete only when the full test suite, delivery checks, and Kind
acceptance pass; every locally implementable gap row has matching evidence; all
rule-based proposals are complete and safe; optional capabilities fail closed;
and remaining cloud/OIDC/distributed-topology limitations are clearly stated
instead of represented as verified parity.
