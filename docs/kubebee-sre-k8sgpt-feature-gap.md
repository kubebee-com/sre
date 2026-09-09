# KubeBee SRE and K8sGPT Feature Gap

This is the current implementation matrix for the 45 capability IDs created
by the original K8sGPT audit. It describes this worktree as of 2026-09-07; it
does not describe a release promise or imply that KubeBee SRE is a drop-in
replacement for K8sGPT. The upstream source audit remains in
[k8sgpt-analysis/REPORT.md](k8sgpt-analysis/REPORT.md).

## Status Rules

`Covered` means KubeBee has a reachable, tested equivalent for the capability
slice. It does not mean that K8sGPT's implementation, transport, or defaults
were copied. `Partial` means an equivalent exists but a material behavior or
operational guarantee remains. `Missing` means there is no current KubeBee
equivalent. The matrix currently contains 14 `Covered`, 31 `Partial`, and 0 `Missing` slices.

Security improvements are part of the status decision. In particular,
authenticated REST/gRPC, read-only query allowlists, secret-safe projections,
and opt-in mutation are not downgraded to match an unsafe upstream default.

## Current Matrix

### CLI And Analysis

| ID | Status | Current KubeBee implementation | Remaining limitation | Evidence |
|---|---|---|---|---|
| KG-CLI-01 | Covered | Cobra root tree with `serve`, `scan`, `explain`, `analyzers`, `docs`, `mcp`, `config`, `filters`, `support-bundle`, `cache`, and `generate`; versioned user config and legacy migration. | No Viper dependency or upstream `auth` command; provider credentials remain environment/flag inputs. | [cli.go](../cmd/sre-agent/cli.go), [profile.go](../pkg/config/profile.go) |
| KG-CLI-02 | Covered | `scan`, one-shot and bounded interactive `explain`, `docs`, cancellation, shared output rendering, and transient repeatable provider headers through `--llm-headers`/`LLM_CUSTOM_HEADERS`. | Header values are runtime-only and are never persisted in user profiles; provider-specific features beyond the common transport remain outside this slice. | [cli.go](../cmd/sre-agent/cli.go), [config.go](../pkg/config/config.go), [output.go](../pkg/output/output.go) |
| KG-CLI-03 | Covered | `scan/v1` plans support namespace include/exclude, label selector, kind/name/analyzer selection, bounded concurrency, timeout, and deterministic ordering. | Names are an allowlisted selection filter, not a full upstream resource graph selector; only one label selector is accepted. | [plan.go](../pkg/scanplan/plan.go), [contract.go](../pkg/scanner/contract.go) |
| KG-CLI-04 | Covered | `output/v1` renders JSON, YAML, table, and raw forms with effective scope, findings, parent references, docs URLs, analyzer runs, timing, and counts. | The table is intentionally compact and does not expose every structured field. | [output.go](../pkg/output/output.go), [types.go](../pkg/scanner/types.go) |
| KG-CLI-05 | Covered | `support-bundle` and `dump` create a bounded, manifest-based, sanitized ZIP; `generate` returns only an explicit HTTPS key-help allowlist. | The bundle contains collected findings/history and explicitly requested resources; it is not a live cluster snapshot or browser integration. | [bundle.go](../pkg/supportbundle/bundle.go), [provider.go](../pkg/supportbundle/provider.go) |
| KG-CLI-06 | Partial | Persisted provider profiles have CRUD/default commands, validation, aliases, and secret-free listing. | There is no credential-management or secret-manager rotation command; keys are never persisted by the profile store. | [profile.go](../pkg/config/profile.go), [catalog.go](../pkg/triage/providers/catalog.go) |
| KG-CLI-07 | Covered | Named filters have add/list/delete/default commands and are applied through the same scan-plan validation path. | Filters are local configuration objects and have no multi-user ownership or remote synchronization. | [cli.go](../cmd/sre-agent/cli.go), [profile.go](../pkg/config/profile.go) |

### Kubernetes Analyzers

| ID | Status | Current KubeBee implementation | Remaining limitation | Evidence |
|---|---|---|---|---|
| KG-ANL-01 | Partial | Pod and log analyzers cover common pending, image, crash, OOM, eviction, restart, termination, event, current-log, and previous-log cases with bounded output. | Findings and container coverage are not a one-for-one implementation of every upstream pod/log edge case or threshold. | [scanner.go](../pkg/scanner/scanner.go), [analyzers_extended.go](../pkg/scanner/analyzers_extended.go), [sanitized.go](../pkg/scanner/sanitized.go) |
| KG-ANL-02 | Partial | Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob, workload graph, and CronJob semantic analyzers are registered. | Controller-specific owner, quota, child-pod, rollout, schedule, and duplicate-suppression semantics remain narrower than the upstream matrix. | [analyzers_workloads.go](../pkg/scanner/analyzers_workloads.go), [analyzers_extended.go](../pkg/scanner/analyzers_extended.go) |
| KG-ANL-03 | Partial | Service, Ingress, and Ingress semantic checks cover selectors/endpoints, classes, backends, ports, and TLS references. | EndpointSlice behavior, controller status, path edge cases, and all cross-namespace rules are not complete upstream parity. | [analyzers_networking.go](../pkg/scanner/analyzers_networking.go) |
| KG-ANL-04 | Partial | `AdmissionWebhookAnalyzer` checks webhook service targets and backing pods through cluster-scoped typed APIs. | It does not actively probe admission endpoints or provide complete CA, DNS, failure-policy, timeout, and controller semantics. | [analyzers_extended.go](../pkg/scanner/analyzers_extended.go) |
| KG-ANL-05 | Partial | `ConfigMapAnalyzer` checks empty/large/unused objects and common workload references, with bounded resource handling. | It is not a complete upstream reference/key analyzer and does not infer all dynamic sidecar usage patterns. | [analyzers_extended.go](../pkg/scanner/analyzers_extended.go) |
| KG-ANL-06 | Partial | Node, PVC, PV, and StorageClass checks cover readiness/pressure, binding phases, capacity, and common storage configuration issues. | Volume attachments, every deprecated provisioner/defaulting edge, and all upstream capacity semantics are not covered. | [analyzers_extended.go](../pkg/scanner/analyzers_extended.go), [scanner.go](../pkg/scanner/scanner.go) |
| KG-ANL-07 | Partial | HPA, PDB, PDB selector, and NetworkPolicy analyzers cover status, scaling limits, disruption budget, selector, and matching-workload conditions. | Network traffic reachability and full selector/rule conformance are outside the current analyzer contract. | [analyzers_policy.go](../pkg/scanner/analyzers_policy.go), [analyzers_networking.go](../pkg/scanner/analyzers_networking.go) |
| KG-ANL-08 | Partial | Dynamic Gateway API analyzers cover GatewayClass, Gateway, HTTPRoute, ReferenceGrant, listener/parent/backend checks, and API capability states. | Gateway versions, controller-specific attachment behavior, and conformance-level edge cases still require cluster fixtures; ReferenceGrant support is an extension. | [dynamic_analyzers.go](../pkg/scanner/dynamic_analyzers.go), [dynamic_scanner.go](../pkg/scanner/dynamic_scanner.go) |
| KG-ANL-09 | Partial | `SecurityAnalyzer` reports selected privileged workload and cluster-admin paths with a read-only policy surface. | It is not an admission-grade policy engine and does not resolve every effective Role/ClusterRole privilege or security policy. | [analyzers_extended.go](../pkg/scanner/analyzers_extended.go) |
| KG-ANL-10 | Partial | Dynamic OLM analyzers cover ClusterCatalog, ClusterExtension, CSV, Subscription, InstallPlan, CatalogSource, and OperatorGroup conditions. | OLM CRDs, versions, permissions, and field shapes remain cluster-dependent; this is capability-gated condition analysis, not complete OLM lifecycle parity. | [dynamic_analyzers.go](../pkg/scanner/dynamic_analyzers.go) |
| KG-ANL-11 | Partial | Dynamic KEDA, Kyverno, and Prometheus Operator analyzers are cataloged; optional families have explicit enable/disable state, and the read-only AWS/EKS integration is available through explicit activation. | Integration analyzers are not enabled by default, and there is no controller installer or complete controller-specific semantic engine. | [dynamic_analyzers.go](../pkg/scanner/dynamic_analyzers.go), [integration registry](../pkg/integration/registry.go), [aws.go](../pkg/integration/aws.go) |
| KG-ANL-12 | Partial | Typed analyzer interface, parent/doc metadata, per-run execution records, cancellation, and low-cardinality Prometheus metrics exist. | There is no separate upstream-style pre-analysis hook, and custom analyzers may expose less semantic metadata than built-ins. | [contract.go](../pkg/scanner/contract.go), [metrics.go](../pkg/metrics/metrics.go), [types.go](../pkg/scanner/types.go) |

### Providers, Privacy, And Cache

| ID | Status | Current KubeBee implementation | Remaining limitation | Evidence |
|---|---|---|---|---|
| KG-AI-01 | Covered | OpenAI-compatible profiles support model, endpoint, proxy, organization, headers, sampling, stop sequences, limits, cancellation, and endpoint policy. | This is a hardened common transport, not a claim of every provider SDK-specific option. | [openai_compatible.go](../pkg/triage/openai_compatible.go), [profile.go](../pkg/triage/profile.go) |
| KG-AI-02 | Partial | Named Azure OpenAI adapter sends a bounded `/chat/completions` request with Azure API-key handling. | Azure deployment/API-version configuration and native Azure identity are not modeled as a cloud SDK. | [cloud_provider.go](../pkg/triage/cloud_provider.go), [catalog.go](../pkg/triage/providers/catalog.go) |
| KG-AI-03 | Partial | Claude/Anthropic message provider supports diagnosis, explanation, bounded HTTP, cancellation, and redacted errors. | Provider-native conversation features, exhaustive options, and external credential lifecycle remain outside the adapter. | [claude.go](../pkg/triage/claude.go), [provider.go](../pkg/triage/provider.go) |
| KG-AI-04 | Covered | Named `localai`, `ollama`, `litellm`, `groq`, and `custom` profiles use the common OpenAI-compatible contract with local endpoint policy. | Operators must supply and secure the endpoint; there is no provider-specific server lifecycle or health discovery. | [openai_compatible.go](../pkg/triage/openai_compatible.go), [catalog.go](../pkg/triage/providers/catalog.go) |
| KG-AI-05 | Partial | Named Bedrock and SageMaker adapters support bounded provider-specific payload/response extraction over HTTP, and explicit `ProviderModeAWS` uses the maintained AWS SDK v2 Runtime clients with region/configuration injection. | AWS credentials, model/endpoint access, and live cloud failure/retry behavior remain deployment prerequisites; the other named cloud adapters remain HTTP-based. | [aws_provider.go](../pkg/triage/aws_provider.go), [cloud_provider.go](../pkg/triage/cloud_provider.go), [profile.go](../pkg/triage/profile.go) |
| KG-AI-06 | Partial | Named Gemini and Vertex adapters have bounded content-generation payloads and endpoint policy. | Google project/region/workload identity and provider-native SDK behavior are external prerequisites. | [cloud_provider.go](../pkg/triage/cloud_provider.go) |
| KG-AI-07 | Partial | Named Cohere, Hugging Face, IBM watsonx.ai, OCI Generative AI, and explicit `noop` profiles are discoverable and constructible. | Cloud authentication, endpoint-specific schemas, and native SDK semantics are intentionally not claimed; `noop` suppresses explanations by design. | [cloud_provider.go](../pkg/triage/cloud_provider.go), [catalog.go](../pkg/triage/providers/catalog.go) |
| KG-AI-08 | Partial | Structured prompts mark cluster data as untrusted; scanner, provider, notification, API, chat, and bundle boundaries apply redaction. | There is no universal mapping/restoration contract for every custom analyzer field, language-specific prompt registry, or proof against every embedding sink. | [provider.go](../pkg/triage/provider.go), [sanitizer.go](../pkg/sanitizer/sanitizer.go) |
| KG-AI-09 | Covered | CLI interactive explain and authenticated HTTP chat sessions support bounded history, expiry, ownership, cancellation, and one read-only resource tool. | There is no streaming provider conversation or provider-native session persistence. | [chat_sessions.go](../pkg/server/chat_sessions.go), [profile.go](../pkg/triage/profile.go) |
| KG-CACHE-01 | Partial | AES-GCM encrypted local file cache has semantic keys, TTL, bounds, atomic owner-only files, list/remove/purge, corruption handling, counters, opt-in service/CLI configuration, and `explain --no-cache` request bypass. | The encryption key remains an environment/Secret input; cache bypass is currently exposed on `explain`, not as a general scan-plan field. | [file.go](../pkg/cache/file.go), [cache.go](../pkg/cache/cache.go), [cached.go](../pkg/triage/cached.go), [cli.go](../cmd/sre-agent/cli.go) |
| KG-CACHE-02 | Partial | Encrypted remote cache uses an injected `ObjectStore` with scoped prefixes, TTL/bounds, list/remove/purge, a memory implementation, and a maintained Go Cloud `BlobObjectStore` for `s3://`, `gs://`, and `azblob://`. | The Interplex driver is not included; remote cache is library-configured rather than the default deployment backend, and live credentials, endpoint access, retries, and retention remain selected-driver/deployment concerns. | [remote.go](../pkg/cache/remote.go), [blobstore.go](../pkg/cache/blobstore.go), [remote.go](../pkg/cache/remote/remote.go) |
| KG-CACHE-03 | Partial | Versioned cache keys hash prompt content and include provider, model, endpoint, prompt schema, and redaction-independent digest material; `CachedProvider` caches diagnosis and explanation results separately in the default wiring when enabled, and bounded operation counters expose hit/miss/error status. | Eviction-specific telemetry and cache policy remain opt-in rather than an unconditional default. | [cache.go](../pkg/cache/cache.go), [cached.go](../pkg/triage/cached.go), [observe.go](../pkg/cache/observe.go), [metrics.go](../pkg/metrics/metrics.go) |
| KG-PRIV-01 | Partial | External projections use sanitized issue/analyzer/config/resource data; Secret resources are rejected; tokens and configured secrets are redacted from outputs. | Sanitization is not a formal information-flow type system. Raw internal objects and unrecognized sensitive values remain the embedding application's responsibility. | [sanitized.go](../pkg/scanner/sanitized.go), [sanitizer.go](../pkg/sanitizer/sanitizer.go), [supportbundle.go](../pkg/server/supportbundle.go) |

### API, Transport, And Extensions

| ID | Status | Current KubeBee implementation | Remaining limitation | Evidence |
|---|---|---|---|---|
| KG-API-01 | Partial | Versioned REST, token-authenticated gRPC services, public health probes, authenticated metrics, optional gRPC TLS/mTLS, and controlled reflection are implemented. | There is no h2c grpc-gateway or OIDC identity layer; public deployments still need a reviewed proxy/identity boundary. | [server.go](../pkg/server/server.go), [grpcapi/server.go](../pkg/grpcapi/server.go), [sre.proto](../api/v1/sre.proto) |
| KG-API-02 | Partial | REST and gRPC expose scan/analyzer/query/config/status/history/capability/support-bundle behavior with bounded requests and structured version fields. | There is no custom-analyzer CRUD API, arbitrary resource query, or full upstream config mutation surface. | [compatibility.go](../pkg/server/compatibility.go), [grpcapi/server.go](../pkg/grpcapi/server.go) |
| KG-API-03 | Covered | `/healthz`, `/readyz`, and authenticated `/metrics` are separated from the API; scan/analyzer counters and duration histograms use bounded labels. | Metrics are process-local and do not prove dependency health beyond the configured readiness callback. | [server.go](../pkg/server/server.go), [metrics.go](../pkg/metrics/metrics.go) |
| KG-API-04 | Partial | Maintained MCP Go SDK serves authenticated Streamable HTTP and local stdio transports with read-only scan, query, analyzers, and history tools, plus prompts and point-in-time resources. | Resource subscriptions, SSE transport, and configuration/filter mutation tools are intentionally not exposed. | [mcp.go](../pkg/server/mcp.go), [mcp_test.go](../pkg/server/mcp_test.go), [cli.go](../cmd/sre-agent/cli.go) |
| KG-EXT-01 | Partial | External analyzer gRPC protocol has generated types, TLS-by-default client, bounds, response validation, cancellation, health/metadata, explicit registry lifecycle, and a shell-free plugin process supervisor with bounded startup/stop. | There is no discovery protocol, default mandatory signature policy, or CLI plugin management command. | [plugin.proto](../api/v1/plugin.proto), [client.go](../pkg/plugin/client.go), [registry.go](../pkg/plugin/registry.go), [supervisor.go](../pkg/plugin/supervisor.go) |
| KG-EXT-02 | Partial | In-process integration registry validates metadata, activates/deactivates owned analyzers, rolls back partial registration, and exposes state. | It does not deploy or uninstall third-party controllers and does not provide an operator-wide activation store. | [registry.go](../pkg/integration/registry.go) |

### Integrations, Operations, And Delivery

| ID | Status | Current KubeBee implementation | Remaining limitation | Evidence |
|---|---|---|---|---|
| KG-INT-01 | Covered | `AWSFactory` uses the maintained AWS SDK for Go v2, discovers a cluster by exact kubeconfig context/ARN path or explicit name, paginates EKS clusters, and reports read-only control-plane status/health issues through the integration registry. | The analyzer requires AWS credentials and a selected cluster context/name; it does not install controllers, mutate AWS/Kubernetes resources, or prove live cloud behavior without an AWS test account. | [aws.go](../pkg/integration/aws.go), [aws_test.go](../pkg/integration/aws_test.go), [registry.go](../pkg/integration/registry.go) |
| KG-INT-02 | Partial | Prometheus Operator CRD health/condition analysis is capability-gated and can be activated through the dynamic family. | Prometheus endpoint discovery, scrape configuration parsing, and relabel-specific analyzers are not implemented. | [dynamic_analyzers.go](../pkg/scanner/dynamic_analyzers.go), [registry.go](../pkg/integration/registry.go) |
| KG-INT-03 | Partial | KEDA and Kyverno resource/report condition analyzers are available in the optional integration family. | There is no controller installation lifecycle and no complete policy/scaler semantic engine. | [dynamic_analyzers.go](../pkg/scanner/dynamic_analyzers.go) |
| KG-OPS-01 | Covered | Kustomize base and Helm package non-root/read-only deployment, external-secret default, probes, PVC, PDB, NetworkPolicy, observation RBAC, explicit optional remediation RBAC, gRPC, ingress, and ServiceMonitor. | MCP is an HTTP route rather than a separate chart-managed process; gRPC TLS remains an ingress/host concern. | [deploy/k8s](../deploy/k8s), [remediation overlay](../deploy/overlays/remediation), [Helm chart](../deploy/helm/sre-agent) |
| KG-OPS-02 | Covered | CI runs Go tests/race/vet, manifest/image checks, pinned action checks, container build, SBOM/provenance/signing, vulnerability scan, and Kind integration. | Release publication and external registry availability are not proven by local checks. | [ci.yaml](../.github/workflows/ci.yaml), [Makefile](../Makefile), [kind-integration.sh](../scripts/ci/kind-integration.sh) |
| KG-OPS-03 | Partial | Background scans run immediately and periodically with jitter, plus bounded/debounced client-go Pod/Event triggers for targeted scans; both paths share overlap protection, optional client-go Lease election, graceful shutdown, durable local history/proposals, and readiness. | Multi-replica failover, shared storage consistency, production Lease behavior, and live informer recovery require a live cluster; the periodic scan remains the correctness backstop and proposal state is in memory without `SRE_DATA_DIR`. | [scheduler.go](../pkg/scheduler/scheduler.go), [trigger.go](../pkg/scheduler/trigger.go), [kube_trigger.go](../pkg/scheduler/kube_trigger.go), [main.go](../cmd/sre-agent/main.go), [deployment.yaml](../deploy/k8s/deployment.yaml) |
| KG-OPS-04 | Covered | README, deployment guide, Helm guide, feature matrix, evidence record, CLI examples, API/proto paths, and Kind procedure are maintained in this repository. | Generated client SDKs, a release/upgrade migration guide, and executable examples for every cloud/provider path are not included. | [README.md](../README.md), [deployment.md](deployment.md), [evidence](kubebee-sre-k8sgpt-evidence.md) |

## Remaining Work

The following items are intentionally still open rather than hidden behind a
parity label:

- Complete one-for-one analyzer semantics and add envtest or cluster fixtures
  for Gateway API, OLM, admission webhooks, storage, security, and optional
  integration CRDs.
- Extend native cloud SDK adapters only where they are needed, using maintained
  provider SDKs for signing and workload identity rather than hand-rolled
  authentication. Bedrock and SageMaker now have native AWS SDK paths; the
  remaining named cloud adapters are bounded HTTP adapters.
- Add an Interplex adapter if required; remote cache drivers remain library
  integrations and need deployment-owned encryption/key management,
  credentials, retries, and retention.
- Add an OIDC identity or grpc-gateway boundary for gRPC if it is exposed
  beyond a trusted local network; the binary now supports optional TLS/mTLS and
  authenticated reflection, but does not provide OIDC or gateway translation.
- Add resource subscriptions/SSE or streaming only if the product contract
  requires them; current MCP tools, prompts, and resources are read-only.
- Add an operator-facing plugin activation/configuration surface and discovery
  protocol if external analyzers need to be managed dynamically; the process
  supervisor and explicit registry lifecycle are present.
- Validate multi-replica durable state, ingress TLS, RBAC, external providers,
  and cloud identity in a target cluster. The local tests and Kind smoke test
  do not establish those guarantees.

See [the evidence record](kubebee-sre-k8sgpt-evidence.md) for the checks that
have actually run and the limits of each check.
