# P0 Safety Baseline Implementation Plan

> **For the implementation agent:** REQUIRED SUB-SKILL: Use `subagent-driven-development` to execute this plan task by task. Each task must be test-first, reviewed for specification compliance, and reviewed for code quality before the next task begins.

**Goal:** Close the highest-risk gaps identified by the KubeBee SRE and K8sGPT inventories: authenticated API boundaries, bounded request handling, end-to-end redaction, durable approval/audit, remediation preconditions, cleanup authorization, and a reproducible deployment supply chain.

**Architecture:** Preserve the existing Go packages and HTTP API shape where practical. Add explicit boundary types and constructor options rather than spreading security decisions through handlers. Keep the in-memory implementations usable for tests, while production startup requires an API token and a durable proposal store. Route every mutating action through the same authenticated actor and approval/audit path.

**Tech stack:** Go 1.25, `net/http`, Kubernetes client-go, `golang.org/x/time/rate`, YAML manifests, GitHub Actions, shell-based CI checks.

## Task 1: Authenticated REST Boundary and Lifecycle

**Files:**
- Create `pkg/server/auth.go` and `pkg/server/auth_test.go`.
- Modify `pkg/server/server.go`, `pkg/server/handlers.go`, and any server tests.
- Modify `pkg/config/config.go`, `cmd/sre-agent/main.go`, `README.md`, and the dashboard client under `web/` if present.

**Steps:**
1. Write failing tests for bearer-token authentication, constant-time token comparison, public health endpoints, exact allowed-origin CORS, request body limits, rate limiting, actor propagation, and rejection of the legacy `X-User-Email` identity header.
2. Add server options for API token, allowed origins, maximum request bytes, request rate/burst, and readiness state. Use a SHA-256 token hash or equivalent constant-time comparison; do not log or expose the raw token. Keep `/healthz` public and make `/readyz` public but return failure until dependencies and the HTTP lifecycle are ready. Protect all other API and static dashboard routes when authentication is enabled.
3. Apply `http.MaxBytesReader`, JSON decoder size checks, content-type validation for JSON mutation endpoints, and a per-client limiter. CORS must echo only configured origins and must not use `*` when credentials or authentication are enabled.
4. Replace caller-controlled `X-User-Email` approval identity with the authenticated actor. Make the server lifecycle context-aware, set read/write/idle timeouts, and make shutdown idempotent. Update configuration loading so production can receive `SRE_API_TOKEN`, `SRE_ALLOWED_ORIGINS`, `SRE_MAX_BODY_BYTES`, `SRE_REQUESTS_PER_MINUTE`, and `SRE_REQUEST_BURST` without breaking existing local defaults.
5. Update the dashboard to send the configured bearer token from session storage and show unauthorized responses as an actionable login state. Update docs and examples to describe the authenticated contract.
6. Run focused server/config tests, `go test ./...`, and `gofmt`; commit as `feat: secure REST boundary and lifecycle`.

## Task 2: End-to-End Redaction and Sink Contract

**Files:**
- Create `pkg/scanner/sanitized.go` and `pkg/scanner/sanitized_test.go`.
- Modify `pkg/sanitizer/sanitizer.go` and its tests.
- Modify `pkg/triage/provider.go`, `pkg/triage/types.go`, `pkg/notifier/webhook.go`, `pkg/server/handlers.go`, and related tests.

**Steps:**
1. Write failing tests covering bearer/API keys, JWTs, private keys, common secret field names, known configured secret values, nested maps, issue logs/events/spec, diagnosis evidence/commands, chat responses, webhook payloads, API responses, and error strings. Assert raw secrets never cross a notification or HTTP response boundary.
2. Add typed sanitized output (`SanitizedIssue` and a redaction report) so scanners sanitize before triage, triage sanitizes model prompts and parsed diagnosis fields, and notifier/API serializers accept only sanitized values. Redact configured literal values in addition to pattern matches, preserve useful structure, and avoid returning raw model output in parse errors.
3. Validate parsed diagnosis enums, score bounds, and action fields before they can become proposals. Keep the original issue available internally only where required for Kubernetes identity and execution; expose sanitized projections at all user and sink boundaries.
4. Add tests for all sink paths and run focused sanitizer/triage/notifier/server tests plus `go test ./...`; run `gofmt`; commit as `feat: enforce redaction at all sinks`.

## Task 3: Durable Approval, Preconditions, and Cleanup Authorization

**Files:**
- Create `pkg/remediation/store.go`, `pkg/remediation/store_test.go`, and `pkg/remediation/audit_test.go` as needed.
- Modify `pkg/remediation/engine.go`, `pkg/remediation/executor.go`, and their tests.
- Modify `pkg/scanner/cleaner.go`, `pkg/scanner/types.go`, `pkg/server/handlers.go`, `pkg/server/server.go`, and `cmd/sre-agent/main.go`.

**Steps:**
1. Write failing tests for atomic durable proposal persistence, restart recovery, monotonic state transitions, audit records, duplicate proposals, approval/rejection reasons, authenticated actors, resource UID/resourceVersion preconditions, dry-run behavior, and cleanup authorization.
2. Define a `ProposalStore` interface and a file-backed implementation using a private directory, atomic temp-file replacement, restrictive permissions, and explicit schema/version fields. Persist proposal identity, action type, target UID/resourceVersion, sanitized diagnosis, actor, timestamps, status, rejection reason, execution result, and audit events. Keep an in-memory store for unit tests.
3. Change engine approval and rejection to require an authenticated actor and an explicit approval record. Re-load the target and verify UID/resourceVersion before mutation. Do not fall back to force deletion on arbitrary errors. Permit force deletion only through an explicit, separately audited policy decision; verify postconditions where the Kubernetes API permits it.
4. Route stale-pod cleanup through a proposal/approval path, re-check eligibility immediately before deletion, honor protected labels and namespaces, and make dry-run report candidates without claiming deletion. Add PVC cleanup only with an explicit policy and ownership/age checks.
5. Update handlers and startup wiring for the store and actor context. Run remediation/scanner/server focused tests and `go test ./...`; run `gofmt`; commit as `feat: make remediation approvals durable and conditional`.

## Task 4: Supply Chain and Deployment Baseline

**Files:**
- Modify `.github/workflows/ci.yaml`, `deploy/Dockerfile`, `Makefile`, and version/build metadata in `cmd/sre-agent/main.go` or a small existing package.
- Modify `deploy/k8s/deployment.yaml`, `deploy/k8s/service.yaml`, `deploy/k8s/ingress.yaml`, `deploy/k8s/rbac.yaml`, `deploy/k8s/kustomization.yaml`, and add narrowly scoped manifests for NetworkPolicy, PDB, PVC, and Secret as required.
- Add `scripts/ci/check-manifests.sh`, `scripts/ci/check-image-metadata.sh`, `scripts/ci/kind-integration.sh`, and focused tests or Make targets for these checks.
- Update `README.md` and deployment documentation.

**Steps:**
1. Write failing shell/config checks for pinned toolchain/action/image inputs, non-floating application image references, required OCI labels, non-root execution, read-only filesystem, and manifest selectors/probes.
2. Align the declared Go versions across `go.mod`, CI, and the builder image. Add reproducible version/commit/build-date linker metadata and expose it from status or `--version`. Build a static, minimal runtime image with OCI source/revision/version labels.
3. Scope CI permissions per job, keep tests unable to access publish credentials, pin actions to immutable refs where practical, and add SBOM/provenance, vulnerability scanning, and image signing/verification steps for release artifacts. Ensure pull requests do not publish or receive release credentials.
4. Replace `latest` deployment references with digest-oriented release configuration, add required labels/selectors, separate service-account token behavior, tighten RBAC to the actual operations, add NetworkPolicy/PDB, correct ingress/auth assumptions, and add durable-store configuration/secrets. Keep health probes aligned with the public health contract.
5. Add a disposable Kind integration script and `make kind-test` target. The script must create a pinned Kind node image cluster, build the application image, load it into Kind, create a temporary non-empty API-token Secret, apply the rendered manifests, wait for the Deployment rollout and `/readyz`, and smoke-test `/healthz`, `/readyz`, unauthenticated `/api/status` rejection, authenticated `/api/status` success, and clean teardown. It must use a trap for cleanup, avoid real registry credentials, and skip only when Kind is explicitly unavailable locally; CI must run it in a dedicated job with no publish permissions.
6. Run shell checks, manifest validation where tools are available, the Kind integration test, `go test ./...`, and `gofmt`; commit as `ci: harden build and deployment baseline`.

## Integration Verification

1. From the worktree root run `go test ./...`, `go vet ./...`, and the repository’s race-enabled test target.
2. Run the CI and manifest checks directly, build the binary and container, and inspect the resulting image metadata if the local toolchain is available.
3. Run `make kind-test` or `scripts/ci/kind-integration.sh` against a disposable Kind cluster. Capture rollout, health, readiness, auth rejection, and authenticated status evidence; do not treat kustomize rendering alone as deployment verification.
4. Review `git diff --check`, scan for wildcard CORS, legacy actor headers, raw secret fields, force-delete fallbacks, floating image tags, and unauthenticated mutation paths.
5. Start the service with a test token and exercise health, readiness, authenticated status, rejected unauthenticated mutation, approval/audit persistence, and restart recovery.
