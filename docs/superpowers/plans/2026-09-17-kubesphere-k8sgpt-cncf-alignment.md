# KubeBee SRE KubeSphere, K8sGPT, And Cloud-Native Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the approved KubeSphere-inspired dashboard into the production authenticated dashboard, close the K8sGPT-compatible scan and AI triage contracts around the existing scanner, and make the deployed artifact satisfy an explicit CNCF cloud-native operational checklist. The Resource Logs modal must contain the selected issue's sanitized logs and must open and close correctly from mouse, keyboard, and backdrop interaction.

**Architecture:** Keep the existing two-process boundary. `sre-orchestrator` owns the authenticated UI/API, scope selection, approvals, audit, and durable coordination. `sre-agent` owns Kubernetes collection, analyzers, sanitization, provider calls, and optional execution. Extend `pkg/scanplan`, `pkg/scanner`, `pkg/triage`, and the existing versioned HTTP/gRPC/MCP surfaces instead of creating a parallel K8sGPT implementation. Preserve read-only behavior by default and require an exact, scoped, resource-version-aware approval before any mutation. Ship one immutable, signed multi-architecture image through CI and update the existing Flux source with its digest.

**Tech Stack:** Go 1.26.6, Kubernetes client-go, protobuf/gRPC, embedded HTML/CSS/JavaScript, Playwright 1.56.1, PostgreSQL/pgx, Helm/Kustomize, Flux, OCI images, SBOM/provenance/signing, Prometheus metrics, and the existing sanitizer/provider/analyzer test harnesses.

**Reference spec:** [2026-09-17 KubeSphere, K8sGPT, and CNCF alignment design](/home/kevin/sre/docs/superpowers/specs/2026-09-17-kubesphere-k8sgpt-cncf-alignment-design.md).

---

## Working-tree and release constraints

- Work in the existing `/home/kevin/sre` checkout. It already contains user changes in scanner, triage, Helm, Falco, and server files; inspect overlapping hunks before editing and never discard them.
- Treat `/home/kevin/myk3s` as a separate Flux source checkout. Its existing dirty changes are user-owned. Prepare a clean temporary worktree from `origin/main` for the single deployment promotion commit, then apply that commit to the Flux source only after the application image digest is available.
- Do not deploy `.superpowers/` browser companions. They are review artifacts only.
- Do not put credentials in source, manifests, browser screenshots, shell history, command output, or the plan. Read the production API token into an environment variable only when invoking the browser and unset it immediately afterward.
- Never promote a mutable image tag. Production evidence must show an immutable `@sha256:` image reference, the running pod's image ID, and the Flux applied revision.
- Use `GOTOOLCHAIN=local` for local diagnostics first. The repository's `go.mod` requires Go 1.26.6; when the local toolchain is older or the toolchain download is unavailable, report that exact limitation and rely on CI's pinned Go setup rather than changing the module floor.

## File map

UI and browser acceptance:

- Modify `internal/legacyserver/static/index.html` and `internal/legacyserver/static/app.js`.
- Extend `internal/legacyserver/dashboard_security_test.go` and `internal/legacyserver/auth_test.go`.
- Add `scripts/ci/legacy-dashboard-browser.cjs` and a `legacy-browser-test` Make target.
- Keep `internal/legacyserver/static/bootstrap.html` as the public unauthenticated entry point and update only its protected-dashboard handoff when the new shell changes the required marker contract.

K8sGPT-aligned contracts:

- Extend `pkg/scanplan/plan.go` and `pkg/scanplan/plan_test.go` for validated scope, output, explain, documentation, deadlines, and cancellation policy.
- Extend `pkg/scanner/types.go`, `pkg/scanner/contract.go`, `pkg/scanner/contract_test.go`, `pkg/scanner/analyzer_parity_test.go`, and the existing analyzer files for stable finding identity, default analyzer metadata, bounded evidence, and deterministic report ordering.
- Extend `internal/legacyserver/compatibility.go`, `internal/legacyserver/handlers.go`, `internal/legacyserver/server.go`, and their tests for scan output, named filters, capabilities, provider-safe explanation, and bounded errors.
- Extend `api/v1/sre.proto`, regenerate `api/v1/sre.pb.go` and `api/v1/sre_grpc.pb.go` with the repository's pinned protobuf toolchain, and update `pkg/grpcapi/server.go` and `pkg/grpcapi/server_test.go`.
- Extend `pkg/triage/types.go`, `pkg/triage/provider.go`, provider adapters, and provider tests for sanitized model metadata, latency, confidence, usage, fallback, endpoint policy, and cancellation.
- Extend `internal/legacyserver/mcp.go` and `internal/legacyserver/mcp_test.go` for the same read-only scope and capability contract.

Cloud-native evidence and delivery:

- Add `docs/kubebee-sre-k8sgpt-cncf-checklist.md` and update `docs/kubebee-sre-k8sgpt-feature-gap.md` plus `docs/kubebee-sre-k8sgpt-roadmap.md` with implementation status and evidence links.
- Modify `deploy/helm/sre/values.yaml`, `deploy/helm/sre/templates/orchestrator.yaml`, `deploy/helm/sre/templates/agent.yaml`, `deploy/helm/sre/templates/rbac.yaml`, `deploy/helm/sre/templates/networkpolicy.yaml`, and `deploy/helm/sre/templates/pdb.yaml` for digest-first images, least privilege, resource policy, availability, and bounded egress.
- Modify `deploy/k8s/deployment.yaml`, `deploy/k8s/rbac.yaml`, `deploy/k8s/networkpolicy.yaml`, and `deploy/k8s/kustomization.yaml` where the raw portable manifests are missing the Helm guarantees.
- Extend `scripts/ci/check-manifests.sh`, `scripts/ci/check-image-metadata.sh`, `scripts/ci/unified-chart_test.py`, `scripts/ci/deployment_contract_test.sh`, and `.github/workflows/ci.yaml` for the new release evidence.
- Promote only `apps/sre/base/deployment.yaml` in the Flux source checkout under `/home/kevin/myk3s` after CI, registry, and digest verification.

## Task 1: Reproduce and lock the dashboard failure before changing the UI

**Files:** Modify `internal/legacyserver/dashboard_security_test.go`; add `scripts/ci/legacy-dashboard-browser.cjs`; add the `legacy-browser-test` target to `Makefile`.

- [ ] Add a failing static regression test that reads the embedded `static/index.html`, finds `#modal-backdrop`, and asserts the selector-specific rule `#modal-backdrop.hidden` appears after the generic `.flex` rule. Assert that the modal has `role="dialog"`, `aria-modal="true"`, an `aria-labelledby` target, a close button, and a log content target. Assert that the dashboard contains the global navigation, grouped left navigation, cluster context, triage queue, issue detail, evidence, approval, metrics, settings, playbook, and audit markers while retaining existing compatibility IDs such as `stat-issues`, `section-approvals`, `tab-metrics`, `section-metrics`, and `settings-provider`.
- [ ] Add a Playwright runner that accepts one JSON config argument with `url`, `module`, `chromium`, and optional `artifacts`, creates a browser context with `Authorization: Bearer ${SRE_UI_TOKEN}`, and never prints the token. Check the authenticated page for three global links, grouped left navigation, non-empty issue rows, and no page errors. Open the first issue's Resource Logs action, assert the selected issue name is visible and log text length is greater than zero, close with the button, reopen and close with Escape, reopen and close by clicking the backdrop, and assert both `aria-hidden="true"` and computed `display: none` after every close. Capture desktop and 390px mobile screenshots when `artifacts` is set.
- [ ] Add `legacy-browser-test` to run the browser runner only when `SRE_LEGACY_DASHBOARD_URL` and `SRE_UI_TOKEN` are present, using `SRE_PLAYWRIGHT_MODULE` and `/snap/bin/chromium` defaults locally. With no URL, fail with a clear configuration message rather than silently claiming browser coverage.
- [ ] Run `go test ./internal/legacyserver -run TestDashboard -count=1` and the new browser test against the current deployment before the fix. Record the expected pre-fix browser failure: the modal has `hidden` in its class list but computed display remains `flex` because `.flex` follows `.hidden` in the cascade, and initial modal content is empty until an issue is selected.

**Expected result:** A reproducible failing contract exists for the actual production bug and for the approved dashboard structure.

## Task 2: Build the KubeSphere-style AI triage shell and fix Resource Logs

**Files:** Modify `internal/legacyserver/static/index.html`, `internal/legacyserver/static/app.js`, `internal/legacyserver/dashboard_security_test.go`, and `internal/legacyserver/auth_test.go`.

- [ ] Replace the old tab-first shell with the approved light enterprise layout: top navigation for Triage Center, Clusters, and AI Operations; a production/kubebee cluster context selector; a grouped left pane for Triage, Evidence, Automation, and Governance; a dense overview with live severity counts, cluster health posture, AI priority queue, AI briefing, review workload, and issue list. Use local CSS and existing icon conventions; do not add a remote font or icon dependency. Make the visual hierarchy quiet and operational, with compact panels and table-like rows rather than marketing cards.
- [ ] Preserve every existing production workflow and compatibility marker while relocating it into the new shell: active anomalies, proposals/approvals, cleanable pods, chat, scan history, analyzers, metrics, settings, playbooks, audit, and support bundle. Navigation actions must switch the visible section without losing the selected cluster or re-running mutation-capable operations.
- [ ] Keep all untrusted issue, log, event, diagnosis, provider, and playbook content out of HTML interpolation. Continue using `escapeHtml` only for trusted display fragments and use `textContent` or DOM node creation for untrusted text. Remove remaining inline event-handler attributes from the shell and route actions through the existing delegated listener.
- [ ] Fix the modal with a selector-specific rule placed after the utility declarations: `#modal-backdrop.hidden { display: none; }`. Keep the visible state explicit with `aria-hidden="false"`, restore `aria-hidden="true"` on close, and toggle the body scroll lock only while open. `showLogsModal(issueId)` must locate the selected issue, render its safe `logs_snippet` or a clear “No sanitized logs were collected” state, set the title/resource label, and focus the close button. `closeModal()` must be idempotent. Close on the close button, Escape, and backdrop click while ignoring clicks inside the dialog.
- [ ] Add an issue assessment modal with severity, category, analyzer, resource, evidence, confidence, and the existing approval/log actions. The assessment modal and Resource Logs modal share the same keyboard and backdrop contract but maintain separate content and labels.
- [ ] Add responsive constraints so the shell has no horizontal overflow at 390px, the sidebar can collapse without changing the selected issue, table rows wrap long resource names, and modal content remains within the viewport. Use stable dimensions for controls and `min-width: 0` on grid/flex children.
- [ ] Update static/auth tests for the new protected markers while preserving the public bootstrap boundary. Add a Node DOM security assertion covering a malicious `logs_snippet` and `details` payload; it must remain text and must not create a script or inline handler.
- [ ] Run `gofmt` on Go changes, `go test ./internal/legacyserver -run 'TestDashboard|TestAuthenticatedBoundary' -count=1`, `node --check internal/legacyserver/static/app.js`, and the local Playwright runner against a server built from this checkout. The browser run must report zero page errors, non-empty logs, keyboard close, backdrop close, and computed `display: none`.

**Expected result:** The authenticated production page is the approved KubeSphere-inspired issue-triage dashboard, and Resource Logs is populated and closable through every supported interaction.

## Task 3: Complete the validated K8sGPT scan contract

**Files:** Modify `pkg/scanplan/plan.go`, `pkg/scanplan/plan_test.go`, `internal/legacyserver/compatibility.go`, `internal/legacyserver/handlers.go`, `internal/legacyserver/server.go`, `internal/legacyserver/compatibility_test.go`, and `internal/legacyserver/lifecycle_contract_test.go`.

- [ ] Extend the existing `scan/v1` plan with explicit fields for named filter identity, output format (`json`, `yaml`, `table`, and `raw`), explain mode, documentation inclusion, and bounded evidence/log collection. Normalize and validate all fields before touching the Kubernetes client. Reject unknown output formats, invalid durations, conflicting namespace include/exclude values, unsupported analyzers, unbounded lists, and attempts to request mutation tools.
- [ ] Add a `pkg/scanfilter` package with `Filter{SchemaVersion, Name, Description, Plan, Default}` and a `Store` interface with `List`, `Get`, `Put`, and `Delete`. Implement a deterministic memory store for the legacy server and a PostgreSQL-backed store in the existing enterprise storage boundary with a versioned migration. Names must be DNS-like identifiers, plan fields are validated through `scanplan.Plan.Validate`, updates use an expected version, and the default filter cannot be deleted. Expose authenticated `GET/POST/PUT/DELETE /api/v1/filters` routes with scope validation and bounded request/response sizes.
- [ ] Make `POST /api/v1/scan` return a stable report envelope with schema version, effective scope, deterministic issue ordering, issue count, analyzer runs, start/finish/duration, forbidden/timeout/canceled analyzer states, and a stable request ID. `table` is a bounded human-readable projection; `json` and `yaml` preserve the versioned report; `raw` is only available for sanitized resource evidence and never returns Secrets or provider credentials. Set `Content-Type` consistently and return structured errors without raw Kubernetes/provider error text.
- [ ] Add cancellation tests that cancel the request context while an analyzer is blocked and verify all analyzer goroutines stop before the handler returns. Add deadline tests for analyzer and provider calls, bounded concurrency tests, deterministic ordering tests, filter conflict tests, and forbidden-resource tests.
- [ ] Run `go test ./pkg/scanplan ./pkg/scanfilter ./internal/legacyserver -run 'Scan|Filter|History|Lifecycle' -count=1` and use fake clientsets to prove namespace, label, kind, name, and analyzer filters are applied before issue projection.

**Expected result:** The existing versioned HTTP surface provides the useful K8sGPT scan workflows without unsafe default access or nondeterministic output.

## Task 4: Lock analyzer parity and stable finding identity

**Files:** Modify `pkg/scanner/types.go`, `pkg/scanner/contract.go`, `pkg/scanner/scanner.go`, the existing analyzer implementation files, `pkg/scanner/contract_test.go`, `pkg/scanner/analyzer_parity_test.go`, `pkg/scanner/analyzer_semantics_test.go`, `pkg/grpcapi/server.go`, `pkg/grpcapi/server_test.go`, `api/v1/sre.proto`, and generated protobuf files.

- [ ] Add an explicit `Fingerprint` field to `scanner.Issue` and the versioned API projection. Generate it from a versioned tuple of analyzer, category, namespace, kind, name, parent identity, and bounded discriminator. Keep the existing issue ID for compatibility, but make fingerprints the deduplication and UI identity key. Add tests proving the same finding is stable across analyzer order, scan time, and process restart, while distinct parent/resource/category findings do not collide.
- [ ] Make the default analyzer catalog expose the K8sGPT core set with accurate metadata and capability state: Pods with current/previous/init/ephemeral evidence; PVC/PV/storage; Deployment/StatefulSet/DaemonSet/ReplicaSet/Job/CronJob; Service/EndpointSlice/Ingress; warning Events; Nodes; ConfigMaps; and mutating/validating admission webhooks. The catalog must identify optional HPA/PDB/NetworkPolicy/Gateway/log/storage/security/OLM/integration analyzers as enabled, disabled, or unavailable with a bounded reason rather than silently omitting them.
- [ ] Ensure analyzers accept the validated plan scope, use bounded client calls, preserve Kubernetes Forbidden and NotFound semantics as safe analyzer-run states, and emit parent references where a finding belongs to a workload/controller. Add tests for current/previous/init/ephemeral containers, standalone warning events, endpoint slices, admission webhook targets, storage phases, and workload parent relationships.
- [ ] Add report counts and analyzer timing to JSON and protobuf projections. Update generated protobuf code through the pinned generation command and verify `buf`/`protoc` output is clean; do not hand-edit generated code except to resolve a deterministic generator version mismatch documented in the plan's implementation commit.
- [ ] Run `go test ./pkg/scanner ./pkg/grpcapi -run 'Contract|Parity|Semantics|Analyzer|Scan|Resource' -count=1` and verify gRPC `Scan`, `Analyze`, `ListAnalyzers`, and `GetResource` return the same sanitized findings and effective scope as HTTP.

**Expected result:** Operators receive K8sGPT-like core analyzer coverage, stable identities, parent context, timing, and explicit capability state over both HTTP and gRPC.

## Task 5: Make AI explanation provider-neutral, bounded, and auditable

**Files:** Modify `pkg/triage/provider.go`, `pkg/triage/types.go`, `pkg/triage/fallback.go`, provider adapters under `pkg/triage`, `internal/legacyserver/handlers.go`, `internal/legacyserver/server.go`, `internal/legacyserver/mcp.go`, and their tests.

- [ ] Extend the sanitized diagnosis projection with `provider`, `model`, `confidence`, `latency_ms`, `input_tokens`, `output_tokens`, `fallback`, and `policy_version`. Do not include API keys, authorization headers, endpoint credentials, raw provider response bodies, or unsanitized cluster content. Keep token counts bounded and low-cardinality in metrics.
- [ ] Implement provider-neutral explanation through the existing `TriageProvider` boundary for OpenAI-compatible, Claude, Bedrock/cloud, local, rule-based, and no-op modes. All provider calls receive a deadline, cancellation, response-size limit, retry budget, and schema-validation pass. A malformed, timed-out, or unavailable provider response deterministically falls back to the rule engine and records the bounded fallback reason.
- [ ] Preserve the existing untrusted-evidence prompt boundary and sanitizer. Add tests for prompt-injection strings in summaries, logs, events, and resource snippets; endpoint allowlists and loopback policy; secret redaction in prompts/errors/metrics; malformed provider JSON; provider cancellation; and retry exhaustion.
- [ ] Expose authenticated read-only `explain` and bounded chat tools through HTTP and MCP. Tool names, arguments, resource kinds, namespaces, and result sizes are allow-listed. MCP initialization and scan calls must return the same capabilities and read-only claim as HTTP. No caller-supplied actor, provider endpoint, shell command, or mutation action is accepted.
- [ ] Run `go test ./pkg/triage ./internal/legacyserver -run 'Provider|Triage|Chat|MCP|Sanit|Safety' -count=1` and inspect metrics output for credentials and unbounded labels.

**Expected result:** AI improves issue triage while remaining provider-neutral, privacy-preserving, read-only by default, and operationally observable.

## Task 6: Add the CNCF cloud-native evidence matrix and close runtime gaps

**Files:** Add `docs/kubebee-sre-k8sgpt-cncf-checklist.md`; update `docs/kubebee-sre-k8sgpt-feature-gap.md`, `docs/kubebee-sre-k8sgpt-roadmap.md`, Helm/raw manifests, and deployment contract tests.

- [ ] Write the checklist as evidence, not a certification claim. Each row must name the requirement, implementation status (`covered`, `partial`, or `not-started`), exact repository evidence, exact automated test, and the remaining risk. Cover standard Kubernetes APIs/versioned contracts, Helm/Kustomize portability, immutable OCI supply chain, non-root/read-only/seccomp/capability drop/resources, read versus mutation RBAC, authentication/scoped access, secrets/TLS/mTLS, audit/agent identity, redaction, health/readiness, Prometheus/structured logs/correlation, OpenTelemetry extension points, bounded timeouts/retries/cancellation/shutdown, lease overlap prevention, Postgres restart semantics, PDB/topology, idempotency/stale resourceVersion verification, and AI evaluation/HITL success criteria.
- [ ] Make image references digest-first in `deploy/helm/sre/values.yaml` and templates. Permit a tag only for local development; production values must render `image@sha256:digest`. Add validation that the digest is immutable and the two containers do not silently use different source revisions.
- [ ] Ensure orchestrator and agent pods run non-root with RuntimeDefault seccomp, no privilege escalation, all capabilities dropped, read-only filesystems, explicit CPU/memory requests and limits, bounded termination grace, readiness/liveness probes, topology spread, and a PDB appropriate to replica count. Keep orchestrator service accounts tokenless unless a concrete Kubernetes API permission is required.
- [ ] Keep collector RBAC read-only and executor RBAC separate. Mutation verbs must be absent when execution is disabled; when enabled, only the approved namespace/resource verbs are rendered. Add tests for no wildcard resources/verbs and no protected namespace mutation.
- [ ] Render default-deny network policy with explicit DNS, Kubernetes API, PostgreSQL, provider, ingress, and Falco egress/ingress paths. Make TLS CA configuration explicit and keep provider secrets sourced from Kubernetes Secrets or the configured external-secret boundary.
- [ ] Add bounded Prometheus labels, correlation IDs in structured logs, public health/readiness behavior, audit events for scan/explain/approval/execution, lease/lock overlap tests, shutdown cancellation tests, stale resource-version rejection, post-action verification, and idempotency tests to the existing deployment and enterprise contract suites.
- [ ] Run `make check-manifests check-image-metadata check-helm unified-chart-test`, `bash scripts/ci/deployment_contract_test.sh`, and `git diff --check`. Update the checklist only with evidence produced by these commands or already present in the repository.

**Expected result:** The deployable artifact has a reviewable cloud-native security, reliability, observability, and AI-governance baseline with automated evidence.

## Task 7: Build, sign, publish, and promote one immutable release

**Files:** Modify `.github/workflows/ci.yaml`, `scripts/ci/enterprise-images.sh`, and the Flux source file `/home/kevin/myk3s/apps/sre/base/deployment.yaml` in a clean temporary worktree based on `origin/main`. Do not stage the user's unrelated dirty myk3s files.

- [ ] Run the full CI-equivalent local gates that are available: `GOTOOLCHAIN=local go test -race ./...`, `go vet ./...`, `make check`, `make build`, `make enterprise-build`, `make enterprise-evaluate`, and `go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...`. Record any Go-toolchain or network limitation verbatim.
- [ ] Build multi-architecture orchestrator and agent images from the verified commit with immutable revision labels, SBOM, provenance, vulnerability scan, and Cosign signature/attestation. Push to the configured registry under a commit-specific tag, then resolve both manifest-list digests without exposing registry credentials.
- [ ] Verify the image's OCI labels, platforms, SBOM, vulnerability result, provenance, and signature. Confirm the digest contains the Resource Logs selector-specific fix and dashboard asset hashes from the checkout.
- [ ] Create a temporary clean myk3s worktree from `origin/main`, modify only `apps/sre/base/deployment.yaml` to the verified immutable image digest, run the myk3s repository's manifest tests, and commit that one deployment promotion. Push to the configured Flux source branch through the normal repository workflow; preserve the user's existing dirty checkout untouched.
- [ ] Reconcile the Flux source and kustomization using the existing `/home/kevin/myk3s/data/.kube/config` context and namespace `sre`. Watch the rollout, verify the running pod image ID equals the promoted digest, verify `/healthz` and `/readyz`, and verify the Ingress remains `https://sre.infra.kubeb.com/`.
- [ ] If the registry, GitHub, Flux, or cluster rejects the release, stop at the failed boundary with the command output and do not substitute a mutable tag or claim deployment success.

**Expected result:** The cluster runs the verified signed digest and Flux reports the same source revision and applied revision.

## Task 8: Perform live Playwright inspection and close the release ledger

**Files:** Modify `scripts/ci/legacy-dashboard-browser.cjs`, `docs/kubebee-sre-k8sgpt-cncf-checklist.md`, `docs/kubebee-sre-k8sgpt-feature-gap.md`, and `docs/kubebee-sre-k8sgpt-roadmap.md` with observed evidence only.

- [ ] Fetch the production API token without printing it: `token="$(KUBECONFIG=/home/kevin/myk3s/data/.kube/config kubectl -n sre get secret sre-agent-secrets -o jsonpath='{.data.SRE_API_TOKEN}' | base64 -d)"`; run the Playwright browser against `https://sre.infra.kubeb.com/`; unset the token immediately after the command. Check top navigation, cluster context, category pane, live counts, AI queue, issue details, sanitized evidence, approvals, metrics, and Resource Logs.
- [ ] Run the same browser contract against the LAN demo/server URL when available, using a separate non-production fixture token. At desktop and 390px mobile viewports, confirm no horizontal overflow, no page errors, readable issue rows, and modal focus/close behavior. Save screenshots to a temporary artifact directory outside the repository unless a release artifact is explicitly required.
- [ ] Query the live API with the authenticated browser context and verify that Resource Logs content is non-empty for issues that have sanitized log evidence, empty states are explicit for issues without logs, and no raw secrets/customer strings appear in issue details, logs, events, provider responses, HTML, or screenshots.
- [ ] Run the full available verification set again after deployment: `go test ./...`, `go test -race ./...`, `make check`, `make unified-kind-test` when Kind/Postgres/browser prerequisites are available, the Playwright browser runner, `git diff --check`, and the myk3s manifest/deployment checks.
- [ ] Update the parity ledger with each covered/partial/not-started row, a link to the exact code/test evidence, and the live digest/revision. The final report must distinguish local/CI evidence from live-cluster evidence and must call out any blocked checks.

**Expected result:** The browser review covers the whole dashboard and the release record proves the UI fix, K8sGPT core behavior, cloud-native controls, and live deployment state.

## Completion review

- [ ] Use the requesting-code-review skill against the final diff, prioritizing regressions in authentication, scope isolation, sanitizer boundaries, mutation authorization, Kubernetes permissions, image immutability, and browser accessibility.
- [ ] Use the verification-before-completion skill before reporting completion. No final claim may say “deployed,” “fixed,” or “passing” without the corresponding command output, live cluster evidence, or an explicitly stated unavailable prerequisite.
- [ ] Preserve unrelated user changes in both repositories and report them as pre-existing when they affect overlapping files or release risk.
