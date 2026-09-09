# KubeBee SRE K8sGPT Parity Roadmap

This roadmap turns the [feature-gap table](kubebee-sre-k8sgpt-feature-gap.md) into dependency-ordered implementation work. It is deliberately safety-first: KubeBee SRE's approval gate, deterministic fallback, and sanitized evidence remain requirements while parity is added. A package is closed only when its acceptance evidence is linked from the [evidence index](kubebee-sre-k8sgpt-evidence.md) and the corresponding `KG-*` rows can move to `Covered` or an explicitly tested safer equivalent.

## Closure Gate

The 100% gate has three conditions:

1. Every one of the 45 `KG-*` slices in the table is `Covered`, or has a written supersession decision that demonstrates the same upstream user outcome plus stronger KubeBee SRE safety/operability.
2. Every `Partial` row's missing-slice list has a named test, fixture, API contract, or deployment check that passes in CI.
3. No P0 safety exception remains: network identity, authorization, mutation approval, redaction, secret handling, release credentials, and dependency readiness are enforced at runtime and tested at their boundaries.

## Dependency Graph

```text
WP-P0-01 identity and transport
       |
       +--> WP-P0-02 mutation and audit
       |          |
       |          +--> WP-P1-04 analyzer/API compatibility
       |
       +--> WP-P0-03 privacy and sink boundary
       |
       +--> WP-P0-04 supply chain and deployment baseline
                    |
                    +--> WP-P1-01 scan-plan and analyzer SDK
                               |
                               +--> WP-P1-02 core analyzer parity
                               +--> WP-P1-03 AI/chat/cache parity
                                          |
                                          +--> WP-P2-01 cloud providers/caches
                                          +--> WP-P2-02 extensions/integrations
                                                     |
                                                     +--> WP-P3-01 docs/governance
```

## P0 Safety And Release Blockers

### WP-P0-01: Identity, Transport, And Request Boundaries

**Closes or enables:** `KG-API-01`, `KG-API-02`, `KG-API-03`, `KG-API-04`, `KG-OPS-03`; hardens `KB-API-001`, `KB-REM-002`, `KB-HYG-002`, `KB-NOT-002`.

**Affected areas:** `pkg/server/server.go` (`corsMiddleware`), `pkg/server/handlers.go`, `pkg/server/static`, `pkg/config/config.go`, `deploy/k8s/ingress.yaml`, `deploy/k8s/service.yaml`, `deploy/k8s/rbac.yaml`.

**Prerequisites:** threat model and route inventory; decide whether REST is the primary API and whether gRPC compatibility is required. Keep the service internal until the gate passes.

**Behavior to add:**

- TLS or an authenticated ingress identity boundary with per-route authorization; no wildcard CORS, anonymous config, chat, cleanup, scan, or approval calls.
- Server-side approver identity from verified identity claims, never a caller-controlled `X-User-Email` fallback.
- CSRF protection for browser mutation routes, request-size/rate/deadline limits, structured errors, and bounded log/event responses.
- Versioned REST schemas plus authenticated gRPC/gateway compatibility and controlled reflection if `KG-API-01` is retained.
- Separate liveness/readiness and metrics endpoints, with dependency readiness and graceful shutdown.
- Route-level audit fields for scans, config changes, cleanup, approvals, rejections, and notifications.

**Acceptance evidence:** HTTP/gRPC integration tests send anonymous, unauthorized, malformed, oversized, expired, and canceled requests; verify 401/403/400 status behavior, no panic, no CORS bypass, verified actor attribution, bounded responses, and shutdown. Rendered ingress/service/RBAC tests prove no public unauthenticated path and NetworkPolicy limits reachability.

### WP-P0-02: Mutation Safety, Approval, And Durable Audit

**Closes or enables:** safer closure for `KG-API-02`, `KG-EXT-02`, `KG-OPS-03`; hardens `KB-HYG-002`, `KB-REM-001`, `KB-REM-002`, `KB-REM-003`, `KB-DEP-002`.

**Affected areas:** `pkg/remediation/engine.go`, `pkg/remediation/executor.go`, `pkg/scanner/cleaner.go`, `pkg/server/handlers.go`, `pkg/scanner/types.go`, `deploy/k8s/rbac.yaml`.

**Prerequisites:** WP-P0-01 identity and route authorization; define action policy classes and required Kubernetes verbs.

**Behavior to add:**

- Put pod cleanup behind the same proposal/approval policy as remediation, with explicit dry-run and eligibility lookup.
- Persist proposals, state transitions, actors, evidence fingerprint, resourceVersion preconditions, execution logs, TTL, and reconciliation across restarts.
- Make force deletion a separately authorized action; never fall back to grace-period zero for any delete error.
- Verify rollout/cordon outcomes, support cancellation/timeouts, and reject stale or changed resources.
- Split read-only and mutation ServiceAccounts/RBAC; add policy hooks by namespace, kind, severity, and action.

**Acceptance evidence:** fake-client and restart tests prove no mutation before approval, unauthorized approval/cleanup fails, stale resourceVersion is rejected, dry-run never mutates, force delete needs policy, execution is idempotent/audited, and proposal state survives a process restart.

### WP-P0-03: End-To-End Privacy And Data-Sink Contract

**Closes or enables:** `KG-PRIV-01`, `KG-AI-08`, `KG-CACHE-01`, `KG-CACHE-03`; hardens `KB-SEC-001`, `KB-AI-001`, `KB-AI-003`, `KB-NOT-001`, `KB-UI-001`.

**Affected areas:** `pkg/sanitizer/sanitizer.go`, `pkg/scanner/types.go`, `pkg/scanner/scanner.go`, `pkg/triage/provider.go`, `pkg/notifier/webhook.go`, `pkg/server/handlers.go`, `pkg/server/static`, new cache package, dump/export code when added.

**Prerequisites:** define data classes and retention policy; identify original versus sanitized fields in `Issue` and proposal objects.

**Behavior to add:**

- Introduce a typed `SanitizedFinding`/redaction report accepted by AI, cache, webhook, API, UI, chat, and dump sinks.
- Use literal replacement and structured secret detection; omit originals from JSON/YAML/logs and keep them only in an authorization-scoped in-memory object.
- Redact specs, events, logs, environment/config references, model errors, webhook payloads, and arbitrary chat prompts.
- Add prompt injection boundaries, model output validation, and cache keys that include redaction/schema/model state.

**Acceptance evidence:** property/fuzz tests cover regex metacharacters, Unicode, structured secrets, raw event/log/spec fields, provider payloads, cache bytes, webhook JSON, browser responses, and errors. A sink matrix test fails if any original token appears outside the authorized local object.

### WP-P0-04: Supply Chain And Deployment Baseline

**Closes or enables:** `KG-OPS-01`, `KG-OPS-02`; hardens `KB-DEP-001`, `KB-DEP-002`, `KB-DEP-003`, `KB-DEP-004`.

**Affected areas:** `.github/workflows/ci.yaml`, `deploy/Dockerfile`, `deploy/k8s/{deployment,rbac,service,ingress,kustomization}.yaml`, `go.mod`, `Makefile`, image/release configuration.

**Prerequisites:** choose supported Go version and immutable image/version policy; coordinate with WP-P0-01 RBAC/auth decisions.

**Behavior to add:**

- Align CI, Docker, and module Go versions; fix build/linker metadata and all Make targets.
- Remove registry/build secrets from PR-controlled builds; publish only from trusted events/environments.
- Add SBOM, vulnerability scan, keyless signature/provenance attestations, digest-pinned actions/images, and reproducible version/hash/date smoke tests.
- Add NetworkPolicy, PDB, topology/multi-replica policy, per-release selectors, least-privilege RBAC profiles, and externally managed Secrets.
- Keep non-root/read-only runtime and add authenticated ingress/security headers.

**Acceptance evidence:** CI policy tests inspect workflow events/secrets; clean checkout runs all Make targets, builds and prints version/hash/date, verifies SBOM/signature/provenance, and renders/lints singleton/multi-release manifests with selector/RBAC/security assertions.

## P1 Parity-Critical Work

### WP-P1-01: Scan Plan, Discovery, And Analyzer SDK

**Closes:** `KG-CLI-01`, `KG-CLI-02`, `KG-CLI-03`, `KG-CLI-04`, `KG-CLI-07`, `KG-ANL-12`, and part of `KG-OPS-03`.

**Affected areas:** `pkg/config/config.go`, `cmd/sre-agent/main.go`, `pkg/scanner/scanner.go`, `pkg/scanner/types.go`, new scan-plan/analyzer-contract packages, `pkg/server/handlers.go`.

**Prerequisites:** WP-P0-01 identity and WP-P0-03 sanitized finding schema.

**Behavior to add:**

- Library-first configuration with explicit precedence, persisted profiles/migration, namespace/label/name/resource filters, and analyzer enablement.
- Discovery-aware typed/dynamic/controller-runtime clients with request contexts, retries, API rate budgets, and explicit forbidden/unsupported states.
- A versioned analyzer SDK exposing `Analyze`, ListOptions, parent/docs/pre-analysis, evidence, bounded concurrency, cancellation, and execution metrics.
- Durable scan history, jitter/leader election or a lease, overlap prevention, issue fingerprints/resolution state, and visible effective scope.

**Acceptance evidence:** fake typed/dynamic clients run every registered analyzer under selectors and cancellation; contract tests assert schema/docs/parents/metrics; multi-replica ticker tests prove one active scan and deterministic results.

### WP-P1-02: Core Resource And Policy Analyzer Parity

**Closes:** `KG-ANL-01` through `KG-ANL-07`, `KG-ANL-09`; strengthens the existing `KB-ANL-*` entries.

**Affected areas:** `pkg/scanner/scanner.go`, `pkg/scanner/analyzers_workloads.go`, `pkg/scanner/analyzers_networking.go`, `pkg/scanner/analyzers_policy.go`, new analyzer files for webhooks/configmaps/security/storage.

**Prerequisites:** WP-P1-01 analyzer SDK and selector propagation; WP-P0-03 evidence model.

**Behavior to add:**

- Emit multiple ranked pod findings with init/ephemeral/previous logs/events and configurable thresholds.
- Complete workload graph analysis for Deployment, ReplicaSet, StatefulSet, DaemonSet, Job, and CronJob including owner/template/selector drift, progress/deadline/retry/missed schedule semantics, and child-pod/quota evidence.
- Add EndpointSlice, Service ports/targetPort/headless/ExternalName, Ingress class/path/status/TLS, cross-namespace rules, and API error classification.
- Add webhook target/CA/DNS/timeout checks and ConfigMap hygiene checks for unused, empty, over-1 MiB, dynamic-sidecar, and opt-out cases; optionally extend this with reference/key analysis.
- Add upstream StorageClass default/deprecated-provisioner, PV phase/capacity, PVC phase/capacity/missing-StorageClass, and node network/taint/cordon analysis. Treat volume attachment as an explicitly labeled improvement.
- Implement HPA metric/target semantics, PDB selector/intent, the upstream NetworkPolicy empty-selector/matching-pod behavior, and optional matchExpressions/namespace/rule conformance; add missing security privilege paths including ClusterRole bindings and init/ephemeral containers.

**Acceptance evidence:** fake-client/envtest conformance suites cover healthy/failing matrices, all selectors, API versions, permission errors, optional fields, and false-positive boundaries. Each analyzer reports its exact evidence and stable category/severity.

### WP-P1-03: AI, Chat, And Local Cache Parity

**Closes:** `KG-CLI-06`, `KG-AI-01`, `KG-AI-03`, `KG-AI-04`, `KG-AI-08`, `KG-AI-09`, `KG-CACHE-01`, `KG-CACHE-03`; hardens `KB-AI-002`, `KB-AI-003`, `KB-AI-005`.

**Affected areas:** `pkg/triage/{provider,claude,codex,deepseek,harness,fallback}.go`, `pkg/config/config.go`, new provider profile/cache packages, `pkg/server/handlers.go`, `pkg/server/static`.

**Prerequisites:** WP-P0-03 redaction/sink contract; WP-P1-01 scan/evidence schema.

**Behavior to add:**

- Strictly validate provider names and configuration; support OpenAI-compatible options, Claude contract/error behavior, local/self-hosted named profiles, and explicit rule/NoOp modes.
- Add language/docs-aware prompts, schema-validated model output, token/retry/deadline policy, confidence bounds, and provider health.
- Add authenticated short-lived chat sessions with bounded history, expiry, cancellation, and explicit cluster-query tools.
- Add opt-in encrypted local cache with hit/miss/no-cache/list/remove/purge, TTL, 0600 permissions, semantic versioned keys, and no sensitive durable defaults.

**Acceptance evidence:** mocked provider matrix and HTTP contract tests cover each option/backend, unknown provider, malformed output, cancellation, chat session lifecycle, redaction, and cache hit/miss/key separation/corruption/concurrency.

### WP-P1-04: Compatibility API And External Analyzer Boundary

**Closes:** `KG-API-01`, `KG-API-02`, `KG-API-03`, `KG-EXT-01`; preserves WP-P0 security controls.

**Affected areas:** `pkg/server`, protobuf/generated API definitions, new compatibility gateway, new plugin SDK/sidecar, `deploy/k8s`.

**Prerequisites:** WP-P0-01 identity/authorization, WP-P1-01 analyzer SDK, WP-P0-03 redaction.

**Behavior to add:**

- Versioned authenticated gRPC Config/Analyzer/Query services and REST compatibility endpoints, with request context/deadlines, structured errors, and controlled reflection.
- Narrow allow-listed query resources and custom-analyzer CRUD/health; no arbitrary object reads or mutations.
- Versioned external analyzer protocol with mTLS, endpoint identity, close ownership, quotas, response validation, and sensitive metadata.
- Authenticated health/metrics with low-cardinality labels and dependency readiness.

**Acceptance evidence:** protocol tests and fuzzers cover nil/malformed messages, deadlines, authz, reflection policy, plugin cancellation/close/nil responses, query allowlists, metrics bounds, and process stability.

## P2 Important Capability Families

### WP-P2-01: Cloud Providers And Remote Caches

**Closes:** `KG-AI-02`, `KG-AI-05`, `KG-AI-06`, `KG-AI-07`, `KG-CACHE-02`.

**Affected areas:** new provider adapters under `pkg/triage/providers`, cache backends under `pkg/cache`, `pkg/config`, deployment secret references and KMS configuration.

**Prerequisites:** WP-P1-03 provider interface/redaction/cache key schema; WP-P0-04 supply-chain baseline.

**Behavior to add:**

- Azure OpenAI, AWS Bedrock/Converse/SageMaker/Mantle, Gemini/Vertex, OCI, IBM, Cohere, Hugging Face, and explicit NoOp adapters with common validation/deadline/error contracts.
- S3, GCS, Azure Blob, and Interplex cache backends with TLS-by-default, scoped prefixes, KMS envelope encryption, retention, precise error classification, and non-fatal setup.
- Cloud identity/region/project allowlists and secret-safe health diagnostics.

**Acceptance evidence:** mocked SDK/HTTP tests cover each adapter/backend, credentials/region/project selection, TLS, retries/deadlines, malformed responses, retention/delete safety, and no process exit on setup errors.

### WP-P2-02: Plugin And Cluster Integrations

**Closes:** `KG-ANL-08`, `KG-ANL-10`, `KG-ANL-11`, `KG-EXT-02`, `KG-INT-01`, `KG-INT-02`, `KG-INT-03`.

**Affected areas:** new Gateway API/OLM analyzers, `pkg/integration`, plugin registry/sidecars, CRD discovery, deployment RBAC.

**Prerequisites:** WP-P1-01 analyzer SDK and WP-P1-04 extension protocol; WP-P0-02 mutation/ownership policy.

**Behavior to add:**

- GatewayClass/Gateway/HTTPRoute conformance semantics including listeners, parents, sectionName, backends, cross-namespace policy, and optional fields; add ReferenceGrant handling as a KubeBee improvement because it is not present in the frozen upstream commit.
- Discovery-gated OLM analyzers for all seven upstream resource families with absent-CRD and malformed-field handling.
- Signed/allow-listed activation for AWS/EKS, Prometheus, Kyverno, and KEDA analyzers; read-only by default.
- Dry-run, ownership labels, namespace scope, transactional rollback, idempotency, and failure propagation for any integration install/uninstall.

**Acceptance evidence:** Gateway conformance fixtures, fake dynamic OLM clients, integration activation matrices, absent-CRD tests, and ownership-scoped lifecycle tests run without cluster-wide accidental deletion.

### WP-P2-03: Diagnostic Export And Support Workflows

**Closes:** `KG-CLI-05`; strengthens `KB-UI-001`, `KB-HYG-001`, `KB-NOT-001`.

**Affected areas:** new CLI/admin commands, `pkg/server/handlers.go`, `pkg/notifier/webhook.go`, `pkg/scanner/cleaner.go`, support-bundle package, UI.

**Prerequisites:** WP-P0-01 authz and WP-P0-03 sink redaction; WP-P0-02 approval policy for cleanup.

**Behavior to add:**

- Authenticated, bounded support-bundle export with manifest, 0600 local permissions, safe defaults, and no raw Secrets.
- Provider key-generation/help links without shell/browser injection.
- Notification destination validation/signing, SSRF prevention, retries/backoff/queue/deduplication, response diagnostics, and redacted payloads.
- Cleanup UI/API shows eligibility and approval status before mutation.

**Acceptance evidence:** fixture bundle inspection, destination allowlist/SSRF tests, signed webhook contract tests, retry/dedup tests, and browser/API tests proving cleanup cannot bypass approval.

## P3 Documentation And Governance

### WP-P3-01: Generated Documentation, Examples, And Upgrade Contract

**Closes:** `KG-OPS-04`; completes documentation evidence for every other row.

**Affected areas:** `README.md`, new `docs/`, generated API/analyzer/provider inventories, `.github/workflows/ci.yaml`, release notes and migration files.

**Prerequisites:** implementation packages above expose versioned schemas and registration metadata.

**Behavior to add:**

- Document K8sGPT-compatible CLI/API/MCP/provider/analyzer behavior and all intentional safety differences.
- Generate analyzer/provider/API tables from source registrations; add executable examples against fake fixtures.
- Publish security model, RBAC profiles, data-retention/redaction policy, upgrade/migration notes, runbooks, and compatibility versioning.
- Make CI validate URLs, versions, commands, manifests, and README claims.

**Acceptance evidence:** docs CI executes representative commands, compares generated lists to source, renders deployment examples, validates links/versions, and fails stale feature claims.

## Coverage Ledger

Every upstream ID is assigned to at least one package. IDs with multiple packages have a dependency relationship described above.

| Package | Assigned upstream IDs |
|---|---|
| WP-P0-01 | `KG-API-01`, `KG-API-02`, `KG-API-03`, `KG-API-04`, `KG-OPS-03` |
| WP-P0-02 | `KG-API-02`, `KG-EXT-02`, `KG-OPS-03` |
| WP-P0-03 | `KG-PRIV-01`, `KG-AI-08`, `KG-CACHE-01`, `KG-CACHE-03` |
| WP-P0-04 | `KG-OPS-01`, `KG-OPS-02` |
| WP-P1-01 | `KG-CLI-01`, `KG-CLI-02`, `KG-CLI-03`, `KG-CLI-04`, `KG-CLI-07`, `KG-ANL-12`, `KG-OPS-03` |
| WP-P1-02 | `KG-ANL-01`, `KG-ANL-02`, `KG-ANL-03`, `KG-ANL-04`, `KG-ANL-05`, `KG-ANL-06`, `KG-ANL-07`, `KG-ANL-09` |
| WP-P1-03 | `KG-CLI-06`, `KG-AI-01`, `KG-AI-03`, `KG-AI-04`, `KG-AI-08`, `KG-AI-09`, `KG-CACHE-01`, `KG-CACHE-03` |
| WP-P1-04 | `KG-API-01`, `KG-API-02`, `KG-API-03`, `KG-EXT-01` |
| WP-P2-01 | `KG-AI-02`, `KG-AI-05`, `KG-AI-06`, `KG-AI-07`, `KG-CACHE-02` |
| WP-P2-02 | `KG-ANL-08`, `KG-ANL-10`, `KG-ANL-11`, `KG-EXT-02`, `KG-INT-01`, `KG-INT-02`, `KG-INT-03` |
| WP-P2-03 | `KG-CLI-05` |
| WP-P3-01 | `KG-OPS-04` |

`KG-AI-08`/`KG-AI-09` and cache IDs are shared across privacy, AI, and cache packages. This ledger is checked mechanically against the feature table before a release claim.

## Stronger-Feature Preservation Checklist

- Periodic scans remain enabled and become durable/leader-elected rather than being reduced to a one-shot CLI.
- Rule-based triage remains an explicit offline mode and is never silently replaced by an unknown remote provider.
- Approval is required for every mutation, including pod cleanup, integration uninstall, and future MCP mutation tools.
- Slack/Discord/Teams notifications remain available but use signed, validated, redacted, queued delivery.
- Dashboard/chat remain first-class workflows with identity, authorization, session limits, and accessible state.
- Sanitization occurs before every external or durable sink, including cache and support bundles.
