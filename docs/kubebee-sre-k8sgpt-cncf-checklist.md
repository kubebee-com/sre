# KubeBee SRE Cloud-Native Evidence Checklist

This checklist records cloud-native operational evidence for the KubeBee SRE
agent and its K8sGPT-compatible triage surface. It is an engineering review
matrix, not a CNCF certification or a claim that the project is a CNCF
conformance test suite. `covered` means repository evidence and an automated
check exist; `partial` means a material deployment, provider, or live-cluster
boundary remains; `not-started` means no implementation is claimed.

## Evidence Matrix

| Requirement | Status | Repository evidence | Automated evidence | Remaining risk |
|---|---|---|---|---|
| Versioned Kubernetes APIs and stable application contracts | covered | `api/v1/sre.proto`, `pkg/scanplan`, `pkg/output`, `pkg/scanner`, and versioned REST routes in `pkg/server` | `go test ./pkg/scanplan ./pkg/output ./pkg/grpcapi ./pkg/server -count=1` | Kubernetes API behavior still depends on the target cluster version and permissions. |
| Helm and Kustomize portability | covered | `deploy/helm/sre`, `deploy/k8s`, `deploy/overlays/kind`, and `deploy/overlays/remediation` | `scripts/ci/check-manifests.sh`, `scripts/ci/check-helm.sh`, `scripts/ci/unified-chart_test.py` | A live install on every supported distribution is not proven by render tests. |
| Immutable OCI image and supply-chain evidence | partial | Pinned Docker bases and OCI labels in `deploy/Dockerfile` and `deploy/Dockerfile.unified`; SBOM, provenance, vulnerability scan, and Cosign workflow in `.github/workflows/ci.yaml` | `scripts/ci/check-image-metadata.sh`; CI build-and-sign job | Registry publication, signature verification, and the promoted digest require the release workflow and live registry. |
| Non-root, read-only runtime, seccomp, dropped capabilities, and resource bounds | covered | Security contexts and resource requests/limits in `deploy/k8s/deployment.yaml` and `deploy/helm/sre/templates/{agent,orchestrator}.yaml` | `scripts/ci/check-manifests.sh`, `scripts/ci/check-helm.sh`, `scripts/ci/check-image-metadata.sh` | The init container intentionally has narrowly scoped ownership capabilities for the data volume. |
| Read versus mutation RBAC separation | covered | Read-only base in `deploy/k8s/rbac.yaml`; explicit mutation overlay in `deploy/overlays/remediation` | `scripts/ci/check-manifests.sh`, `pkg/remediation/safety_test.go` | The optional mutation overlay still requires an operator policy review before activation. |
| Authentication and scoped access | covered | Bearer authentication, route boundaries, namespace/label/kind/name scope, and sanitized projections in `pkg/server` and `pkg/scanplan` | `pkg/server/auth_test.go`, `internal/legacyserver/auth_test.go`, `go test ./pkg/server ./pkg/scanplan -count=1` | Production identity federation and ingress policy remain cluster configuration. |
| Secrets, TLS, and mTLS boundaries | partial | Secret references and optional CA mounts in `deploy/k8s/deployment.yaml`; TLS/mTLS configuration in `pkg/grpcapi` and `pkg/server` | `pkg/grpcapi/server_test.go`, `pkg/server/auth_test.go`, manifest checks | Production certificate rotation, external-secret integration, and ingress TLS need live-cluster evidence. |
| Audit events and verified agent identity | covered | Audit persistence and identity handling in `internal/legacyserver`, `pkg/audit`, and `pkg/server` | `internal/legacyserver/cleanup_test.go`, `internal/legacyserver/lifecycle_contract_test.go`, `pkg/server/*test.go` | Multi-replica audit durability depends on the configured storage backend. |
| Redaction at API, provider, webhook, bundle, and UI sinks | covered | `pkg/sanitizer`, `pkg/scanner/sanitized.go`, provider adapters, support bundles, and the dashboard DOM boundary | `internal/legacyserver/safety_test.go`, `internal/legacyserver/chat_sessions_test.go`, `pkg/supportbundle/bundle_test.go`, `internal/legacyserver/dashboard_security_test.go` | Sanitization is not a formal information-flow type system for arbitrary future extensions. |
| Health, readiness, and graceful shutdown | covered | `/healthz`, `/readyz`, readiness wiring, and cancellation-aware server lifecycle in `pkg/server` and `cmd/sre-agent` | `pkg/server/server_test.go`, `pkg/scheduler/*test.go`, manifest probe checks | Dependency readiness and rollout behavior still require a live deployment check. |
| Prometheus metrics, structured logs, and correlation | partial | `pkg/metrics`, bounded labels, audit events, and request IDs in `pkg/server` and `internal/legacyserver` | `pkg/metrics/metrics_test.go`, `internal/legacyserver/lifecycle_contract_test.go` | A complete organization-wide log pipeline and trace correlation backend are deployment concerns. |
| OpenTelemetry extension point | not-started | No OpenTelemetry exporter or SDK is claimed in the current release | No automated evidence | Add tracing context propagation and an opt-in exporter only after the privacy and cardinality contract is defined. |
| Bounded timeouts, retries, cancellation, and shutdown | covered | Scan plans, provider limits, HTTP body limits, scheduler cancellation, and bounded plugin supervision in `pkg/scanplan`, `pkg/triage`, `pkg/scheduler`, and `pkg/plugin` | `pkg/scanplan/plan_test.go`, provider cancellation tests, scheduler tests, plugin tests | External provider behavior and network retry quality still depend on deployment conditions. |
| Lease overlap prevention and scan scheduling | covered | Client-go Lease election, overlap guard, jitter, and event-trigger debounce in `pkg/scheduler` | `pkg/scheduler/scheduler_test.go`, `pkg/scheduler/kube_trigger_test.go` | Live multi-replica Lease renewal and failover are not established locally. |
| PostgreSQL restart and durable state semantics | partial | Enterprise storage, migrations, and restart-aware audit/proposal paths under `pkg/storage`, `pkg/audit`, and `internal/legacyserver` | `scripts/ci/enterprise-postgres_test.sh`, enterprise contract tests | A production PostgreSQL HA/failover exercise is still required. |
| PDB, topology, probes, and availability policy | covered | PDB, topology spread, rolling update, probes, and termination bounds in Helm/raw deployment templates | `scripts/ci/check-manifests.sh`, `scripts/ci/check-helm.sh`, `scripts/ci/deployment_contract_test.sh` | Scheduling constraints and actual replica placement depend on cluster capacity. |
| Idempotency, stale resourceVersion checks, and post-action verification | covered | Approval preconditions, action fingerprints, idempotency, and verification in `pkg/remediation` and `pkg/audit` | `pkg/remediation/safety_test.go`, lifecycle and cleanup tests | Live failure injection across a rollout is not covered by unit tests. |
| AI evaluation and human-in-the-loop success criteria | partial | Rule fallback, provider-neutral diagnosis metadata, sanitized evidence, approvals, and audit in `pkg/triage`, `internal/legacyserver`, and `pkg/remediation` | Provider/safety tests plus the Playwright dashboard contract in `scripts/ci/legacy-dashboard-browser.cjs` | Model quality, false-positive rate, operator task time, and production approval outcomes require a defined evaluation dataset and live review. |

## Release Boundary

The following commands are the local evidence recorded for this review:

```text
make check-manifests check-image-metadata check-helm unified-chart-test
bash scripts/ci/deployment_contract_test.sh
```

The Go test gate must run with the repository's required Go 1.26.6 toolchain.
On hosts where the local binary reports Go 1.26.0, `GOTOOLCHAIN=local` fails
closed at the module requirement; `GOTOOLCHAIN=auto` is the supported local
fallback when the pinned toolchain is available for download. This distinction
is recorded rather than hidden behind a changed module version.

The release is not considered promoted until the running pod image is an
immutable `registry.kubeb.com/sre/agent@sha256:...` reference, the pod image
ID matches that digest, Flux reports the corresponding applied revision, and
the authenticated Playwright contract passes against the production ingress.
