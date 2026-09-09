# KubeBee SRE Verification Evidence

This record describes checks run against the current worktree and the scope of
what each check proves. It supports the status labels in the
[feature-gap table](kubebee-sre-k8sgpt-feature-gap.md); source similarity alone
is not treated as feature evidence.

## Implementation Evidence

| Area | Source and tests | What is covered |
|---|---|---|
| Cobra CLI and config | [`cmd/sre-agent/cli.go`](../cmd/sre-agent/cli.go), [`cmd/sre-agent/cli_test.go`](../cmd/sre-agent/cli_test.go), [`pkg/config/config.go`](../pkg/config/config.go), [`pkg/config/profile.go`](../pkg/config/profile.go), [`pkg/config/profile_test.go`](../pkg/config/profile_test.go) | Independent Cobra command trees, command dispatch, config precedence, legacy migration, secret-free profile/filter CRUD, defaults, bounded interactive explain with request-level cache bypass, analyzer documentation links, local MCP stdio, explicit cache lifecycle commands, and validated transient provider organization/proxy/custom-header settings. Header values are excluded from persisted/runtime config projections and included in redaction coverage. |
| Scan plans and output | [`pkg/scanplan/plan.go`](../pkg/scanplan/plan.go), [`pkg/scanplan/plan_test.go`](../pkg/scanplan/plan_test.go), [`pkg/output/output.go`](../pkg/output/output.go), [`pkg/output/output_test.go`](../pkg/output/output_test.go) | `scan/v1` scope validation, namespace/kind/name/analyzer selection, concurrency/timeout limits, deterministic scope, and `output/v1` JSON/YAML/table/raw rendering with redaction. |
| Typed and dynamic analyzers | [`pkg/scanner/contract.go`](../pkg/scanner/contract.go), [`pkg/scanner/contract_test.go`](../pkg/scanner/contract_test.go), [`pkg/scanner/analyzers_extended.go`](../pkg/scanner/analyzers_extended.go), [`pkg/scanner/dynamic_analyzers.go`](../pkg/scanner/dynamic_analyzers.go), [`pkg/scanner/dynamic_analyzers_test.go`](../pkg/scanner/dynamic_analyzers_test.go) | Built-in analyzer contracts, per-run records, parent/docs metadata, optional Gateway API/OLM/integration capability states, dynamic family gating, and fake-client behavior. |
| Support bundles | [`pkg/supportbundle/bundle.go`](../pkg/supportbundle/bundle.go), [`pkg/supportbundle/bundle_test.go`](../pkg/supportbundle/bundle_test.go), [`pkg/server/supportbundle.go`](../pkg/server/supportbundle.go) | `support-bundle/v1` ZIP manifest, SHA-256 members, bounded counts/sizes, atomic 0600 local creation, resource opt-in, path safety, Secret rejection, and redaction. |
| Providers | [`pkg/triage/profile.go`](../pkg/triage/profile.go), [`pkg/triage/openai_compatible.go`](../pkg/triage/openai_compatible.go), [`pkg/triage/aws_provider.go`](../pkg/triage/aws_provider.go), [`pkg/triage/cloud_provider.go`](../pkg/triage/cloud_provider.go), provider tests and [`pkg/triage/providers/catalog.go`](../pkg/triage/providers/catalog.go) | Named profiles and aliases, OpenAI-compatible controls, Claude/DeepSeek/harness/rule/no-op modes, bounded named cloud HTTP adapters, explicit native AWS SDK v2 Bedrock/SageMaker mode, endpoint policy including explicit custom-endpoint allowlists, bounded requests/responses, cancellation, and secret-safe errors. |
| Cache | [`pkg/cache/file.go`](../pkg/cache/file.go), [`pkg/cache/remote.go`](../pkg/cache/remote.go), [`pkg/cache/blobstore.go`](../pkg/cache/blobstore.go), [`pkg/cache/observe.go`](../pkg/cache/observe.go), [`pkg/cache/blobstore_test.go`](../pkg/cache/blobstore_test.go), [`pkg/cache/cache_test.go`](../pkg/cache/cache_test.go), [`pkg/cache/file_test.go`](../pkg/cache/file_test.go), [`pkg/cache/remote_test.go`](../pkg/cache/remote_test.go), [`pkg/triage/cached.go`](../pkg/triage/cached.go), [`pkg/triage/cached_test.go`](../pkg/triage/cached_test.go) | Opt-in AES-GCM local cache, semantic keys, TTL/count/value bounds, atomic owner-only files, corruption removal, encrypted `ObjectStore` cache, memory backend, maintained `gocloud.dev/blob` `BlobObjectStore` for S3/GCS/Azure Blob schemes, secure URL validation, bounded operation counters, lifecycle CLI commands, provider-result caching for diagnosis/explanation, and tested request-level bypass. |
| Chat and MCP | [`pkg/triage/profile.go`](../pkg/triage/profile.go), [`pkg/server/chat_sessions.go`](../pkg/server/chat_sessions.go), [`pkg/server/chat_sessions_test.go`](../pkg/server/chat_sessions_test.go), [`pkg/server/mcp.go`](../pkg/server/mcp.go), [`pkg/server/mcp_test.go`](../pkg/server/mcp_test.go) | Authenticated session ownership, bounded history/expiry, cancellation, official MCP Go SDK Streamable HTTP and stdio transports, four exposed read-only MCP tools, prompts, and point-in-time resources. |
| REST and gRPC | [`pkg/server/server.go`](../pkg/server/server.go), [`pkg/server/compatibility.go`](../pkg/server/compatibility.go), [`pkg/grpcapi/server.go`](../pkg/grpcapi/server.go), [`pkg/grpcapi/server_test.go`](../pkg/grpcapi/server_test.go), [`api/v1/sre.proto`](../api/v1/sre.proto) | Versioned REST routes, health/readiness, authenticated metrics, gRPC Analyzer/Query/Config services, bearer metadata auth, request limits, deadlines, sanitized projections, optional TLS/mTLS, and controlled reflection. |
| Plugins and integrations | [`pkg/plugin/client.go`](../pkg/plugin/client.go), [`pkg/plugin/client_test.go`](../pkg/plugin/client_test.go), [`pkg/plugin/registry.go`](../pkg/plugin/registry.go), [`pkg/plugin/registry_test.go`](../pkg/plugin/registry_test.go), [`pkg/plugin/supervisor.go`](../pkg/plugin/supervisor.go), [`pkg/plugin/supervisor_test.go`](../pkg/plugin/supervisor_test.go), [`pkg/integration/registry.go`](../pkg/integration/registry.go), [`pkg/integration/registry_test.go`](../pkg/integration/registry_test.go), [`pkg/integration/aws.go`](../pkg/integration/aws.go), [`pkg/integration/aws_test.go`](../pkg/integration/aws_test.go) | TLS-by-default external analyzer protocol, response validation, cancellation, optional signature verification, explicit lifecycle, shell-free bounded process supervision, metadata validation, activation rollback, ownership-aware deactivation, and opt-in read-only AWS/EKS health analysis using the maintained AWS SDK. |
| Security and remediation | [`pkg/server/auth.go`](../pkg/server/auth.go), [`pkg/server/auth_test.go`](../pkg/server/auth_test.go), [`pkg/scanner/sanitized.go`](../pkg/scanner/sanitized.go), [`pkg/remediation/engine.go`](../pkg/remediation/engine.go), [`pkg/remediation/safety_test.go`](../pkg/remediation/safety_test.go), [`deploy/k8s/rbac.yaml`](../deploy/k8s/rbac.yaml), [`deploy/overlays/remediation`](../deploy/overlays/remediation) | Bearer auth, exact CORS, body/rate limits, caller identity-header rejection, sanitized API/provider/webhook/bundle boundaries, approval/audit/precondition checks, supported-action validation, and read-only-by-default Kustomize RBAC with an explicit remediation overlay. |
| Scheduling and metrics | [`pkg/scheduler/scheduler.go`](../pkg/scheduler/scheduler.go), [`pkg/scheduler/scheduler_test.go`](../pkg/scheduler/scheduler_test.go), [`pkg/scheduler/trigger.go`](../pkg/scheduler/trigger.go), [`pkg/scheduler/trigger_test.go`](../pkg/scheduler/trigger_test.go), [`pkg/scheduler/kube_trigger.go`](../pkg/scheduler/kube_trigger.go), [`pkg/scheduler/kube_trigger_test.go`](../pkg/scheduler/kube_trigger_test.go), [`pkg/metrics/metrics.go`](../pkg/metrics/metrics.go), [`pkg/metrics/metrics_test.go`](../pkg/metrics/metrics_test.go), [`cmd/sre-agent/main.go`](../cmd/sre-agent/main.go) | Immediate and periodic scans, jitter, shared overlap prevention, client-go Lease election, graceful cancellation, readiness wiring, Pod/Event informer triggers, warning-Event target fan-out, bounded coalescing/debounce, targeted plan scoping, and low-cardinality Prometheus scan/analyzer/cache operation metrics. |

## Verification Commands

These results are for this worktree. A passing local test does not establish
cloud credentials, production cloud, ingress, or multi-replica behavior.

| Command | Result | Evidence boundary |
|---|---|---|
| `go test ./... -count=1` | Passed | All Go packages compile and their unit/fake-client tests pass. |
| `go test -race ./...` | Passed | Race detector coverage for tested in-process state; no live-cluster or failover proof. |
| `go vet ./...` | Passed | No Go vet diagnostics. |
| `./scripts/ci/check-docs.sh` | Passed | Required docs/source anchors, matrix accounting, current routes/schemas, and stale-claim rejection. |
| `./scripts/ci/check-manifests.sh` | Passed | Kustomize base/Kind rendering and required security/deployment markers. |
| `./scripts/ci/check-image-metadata.sh` | Passed | Pinned Docker bases, non-root runtime, OCI metadata, and build-argument contract. |
| `./scripts/ci/check-helm.sh` | Passed | Helm lint/template security and fixed image validation. |
| `bash -n scripts/ci/*.sh` | Passed | Shell syntax for CI and deployment scripts. |
| Real Codex Responses smoke | Passed | The rebuilt CLI used the host-configured `SUB2API_API_KEY` through `LLM_API_KEY`, the configured Responses endpoint plus `LLM_ENDPOINT_ALLOWLIST`, and explicitly selected model `gpt-5.5`; `explain --no-cache` returned the fixed marker `GPT55_LIVE_OK` with exit status 0. The host config currently selects `gpt-5.6-luna`; this evidence records the exact `gpt-5.5` test rather than substituting that model. |
| `make kind-test` | Not rerun for the event-trigger change | The disposable Kind procedure remains available for authenticated deployment and fixture diagnosis acceptance, but this change was verified with focused unit/fake-client tests because the host is resource-constrained. |

The last recorded baseline Kind run, from before the event-trigger change, was:

```text
Kind integration passed: cluster=sre-agent-kind-1427690 health=200 ready=200 unauthenticated_status=401 authenticated_status=200
```

## Deliberate Non-Claims

The following are not proven by the commands above and remain `Partial` or
`Missing` in the matrix:

- Full K8sGPT edge-semantic parity for every analyzer, including controller,
  EndpointSlice, Gateway API, OLM, webhook, storage, security, and policy
  behavior.
- Google workload identity, IBM/OCI native auth, cloud discovery, provider
  quality, external model availability, or production retry policy. The
  native AWS triage adapters still require an AWS credential/configuration
  chain and live model access for operational proof.
- An Interplex cache client. The Go Cloud adapters, lifecycle CLI, and opt-in
  local cache are not proof of live cloud credentials, endpoint access,
  provider retention, or production retry behavior.
- Live AWS credentials, EKS control-plane access, and cloud failure behavior;
  the AWS/EKS analyzer is covered with paginated fake-client and kubeconfig
  matching tests only.
- OIDC identity, grpc-gateway, and public exposure safety. The main binary has
  optional TLS/mTLS and authenticated reflection, but production identity and
  gateway policy remain deployment concerns.
- MCP resource subscriptions, SSE, or streaming. The current product exposes
  authenticated Streamable HTTP and explicit local stdio with four read-only
  tools, prompts, and point-in-time resources.
- Operator-managed plugin discovery and required signature policy. The process
  supervisor is shell-free and bounded; signature verification is an explicit
  registry option.
- Shared proposal/history state, storage consistency, and leader-election
  failover under multiple replicas. `SRE_DATA_DIR` provides durable local
  files; it is not a distributed store.

## Kind Procedure

`make kind-test` uses [`scripts/ci/kind-integration.sh`](../scripts/ci/kind-integration.sh).
It creates a unique cluster with a pinned Kind node image, builds the local
image without registry credentials, loads it into that cluster, creates a
temporary non-empty API token Secret, applies
[`deploy/overlays/kind`](../deploy/overlays/kind), and always tears down its
own cluster through a shell trap. It does not reuse an existing cluster.
For Codex mode, set `SRE_KIND_LLM_MODEL` to a model available to the selected
endpoint; otherwise the harness uses the host Codex config model as its
environment-only default.
