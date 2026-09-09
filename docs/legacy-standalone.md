> Historical standalone reference. These commands are retired from the unified agent.

# KubeBee SRE Agent

KubeBee SRE Agent is a Go service and CLI for read-only Kubernetes diagnosis,
sanitized triage, and explicitly approved remediation. It is informed by the
K8sGPT feature set, but it does not claim one-for-one K8sGPT parity. The
current comparison and remaining gaps are tracked in
[the feature-gap table](docs/kubebee-sre-k8sgpt-feature-gap.md) and
[the verification record](docs/kubebee-sre-k8sgpt-evidence.md).

Every cluster mutation is represented as a proposal and requires an explicit
approval. A scan, provider, plugin, or chat request does not grant mutation
authority.

## Customer-hosted enterprise deployment

Use the separate [enterprise deployment](docs/enterprise-deployment.md) for OIDC application ownership, explicit multi-cluster enrollment, strict privacy projection, evidence and conclusion feedback, governed AI providers, reviewed golden learning and optional owner-approved Pod replacement. The control plane has no Kubernetes credentials; collection and execution use separate identities. Start with observe-only installation.

See the [verification and capability record](docs/enterprise-release-evidence.md) and [measured capacity limits](docs/enterprise-capacity.md). The legacy quick start below is a separate deployment surface.

## Quick Start

Build and run the deterministic local mode:

```bash
make build
./bin/sre-agent version
./bin/sre-agent serve --llm-provider rule --port 8080
```

The service uses the current kubeconfig when `KUBECONFIG` or
`--kubeconfig` is set, and otherwise attempts in-cluster configuration. A
cluster scan requires Kubernetes credentials with the permissions described by
the [Kustomize RBAC](deploy/k8s/rbac.yaml) or [Helm values](deploy/helm/sre-agent/values.yaml).

Run a bounded scan against the current Kubernetes context:

```bash
./bin/sre-agent scan --namespace sre --output table
./bin/sre-agent scan \
  --label-selector 'app.kubernetes.io/name=sre-agent' \
  --kind Pod --concurrency 4 --timeout 90s --output json
```

The `scan` command is read-only. The command accepts `json`, `table`, `yaml`,
and `raw` output and emits the `output/v1` schema. Scan requests use the
`scan/v1` plan schema.

## CLI

The executable has a Cobra command tree. Use `--config PATH` to select a
versioned user configuration file; the default is the platform user config
directory under `sre-agent/config.yaml`.

| Command | Purpose |
|---|---|
| `version` | Print build version, revision, and date metadata. |
| `serve` | Start the HTTP service and background scanner. |
| `scan` | Execute one bounded Kubernetes scan. |
| `explain [question]` | Ask the configured provider; `--interactive` keeps a bounded local conversation and `--no-cache` bypasses cached results for the request. |
| `analyzers` | List built-in and attached analyzer metadata. |
| `docs [analyzer]` | List HTTPS Kubernetes documentation links from analyzer metadata. |
| `mcp` | Serve the read-only MCP protocol over local stdio. |
| `config show` | Print non-secret persisted configuration. |
| `config profile list\|add\|delete\|default` | Manage named provider profiles. |
| `config filters list\|add\|delete\|default` | Manage named scan filters. |
| `filters list\|add\|delete\|default` | Compatibility alias for filter management. |
| `support-bundle [path]` | Write a bounded `support-bundle/v1` sanitized ZIP; `dump` is an alias. |
| `generate PROVIDER` | Print an allowlisted provider key-help URL. It never opens a browser or constructs a URL from input. |
| `cache list\|stats\|remove\|purge` | Inspect or explicitly manage encrypted local cache entries. |

Configuration precedence is flags over environment over persisted user
settings. API tokens, LLM keys, and webhook URLs are read from flags or the
environment and are not written to the user config. Profiles and filters are
stored as `config/v1`, migrated from supported legacy documents, written
atomically, and restricted to owner permissions.

The scan plan supports included and excluded namespaces, a Kubernetes label
selector, resource kinds and names, analyzer names, maximum analyzer
concurrency, and a per-scan timeout. Named filters provide reusable scope;
explicit scan flags take precedence over the selected filter.

Provider routing can also be overridden for a process or one CLI invocation
with `--llm-organization`, `--llm-proxy-url`, and repeatable
`--llm-headers KEY:value` (the `--custom-headers` alias is supported). The
equivalent environment input is `LLM_CUSTOM_HEADERS` (with
`K8SGPT_CUSTOM_HEADERS` retained as a compatibility alias). Header values are
validated, redacted, and never persisted in user profiles or returned by the
runtime config projection.

## Analyzer Coverage

The typed scanner currently registers 25 built-in analyzers:

`PodAnalyzer`, `EventAnalyzer`, `LogAnalyzer`, `DeploymentAnalyzer`, `StatefulSetAnalyzer`,
`DaemonSetAnalyzer`, `ReplicaSetAnalyzer`, `JobAnalyzer`, `CronJobAnalyzer`,
`CronJobScheduleAnalyzer`, `ServiceAnalyzer`, `IngressAnalyzer`,
`IngressSemanticsAnalyzer`, `NetworkPolicyAnalyzer`,
`PersistentVolumeClaimAnalyzer`, `StorageAnalyzer`, `NodeAnalyzer`,
`HPAAnalyzer`, `HPATargetAnalyzer`, `PDBAnalyzer`, `PDBSelectorAnalyzer`,
`WorkloadGraphAnalyzer`, `AdmissionWebhookAnalyzer`, `ConfigMapAnalyzer`, and
`SecurityAnalyzer`.

The dynamic scanner can additionally expose capability-aware analyzers for:

- Gateway API: `GatewayClass`, `Gateway`, `HTTPRoute`, and `ReferenceGrant`.
- OLM: `ClusterCatalog`, `ClusterExtension`, `ClusterServiceVersion`,
  `Subscription`, `InstallPlan`, `CatalogSource`, and `OperatorGroup`.
- Optional integration CRDs: KEDA, Kyverno, and Prometheus Operator.

Dynamic resources are queried only when the API is available and permitted.
The capability endpoint reports `available`, `absent`, `forbidden`, or
`unavailable` instead of treating an optional CRD as a core scan failure.
Gateway API and OLM families are enabled by the dynamic facade; the generic
integration family is opt-in through the library API so activation and
ownership can be reviewed by the embedding application.

The analyzers cover common pod, workload, networking, storage, policy,
webhook, ConfigMap, HPA/PDB, node, security, Gateway API, OLM, KEDA, Kyverno,
and Prometheus Operator conditions. They are not an admission-grade policy
engine and do not claim all upstream K8sGPT edge semantics. See the
[current parity matrix](docs/kubebee-sre-k8sgpt-feature-gap.md) for the
per-family limitations.

## Triage And Providers

The triage contract is `Diagnose` plus `Explain`. Available canonical provider
profiles are:

- Remote and local OpenAI-compatible: `openai`, `custom`, `deepseek`, `groq`,
  `litellm`, `localai`, and `ollama`.
- Native message or process modes: `claude`, `harness`, `rule`, and `noop`.
- Named cloud adapters: `azureopenai`, `bedrock`, `cohere`, `gemini`,
  `huggingface`, `ibm`, `oci`, `sagemaker`, and `vertex`.

Aliases include `codex` for `openai`, `anthropic` for `claude`, `watsonx` for
`ibm`, `oracle` for `oci`, and the corresponding Azure, AWS, Vertex, local,
rule, and no-op spellings. Provider profiles validate model, endpoint, proxy,
organization, custom headers, timeouts, token limits, and endpoint policy.
Requests and responses are bounded and cancellable, and provider errors do
not include upstream response bodies.

For a non-default remote endpoint, set `LLM_ENDPOINT_ALLOWLIST` to a
comma-separated list containing the endpoint origin or path. `LLM_BASE_URL`
selects the endpoint, while the allowlist is the explicit outbound-request
trust policy; local loopback endpoints remain available to local providers.

The named cloud adapters implement provider-specific bounded HTTP payloads.
Set `LLM_MODE=aws` (or `--llm-mode aws`) with `LLM_PROVIDER=bedrock` or
`LLM_PROVIDER=sagemaker` to use the maintained AWS SDK v2 runtime clients and
the ambient AWS credential chain. Set `AWS_REGION`; for SageMaker, pass the
endpoint name through `LLM_BASE_URL`. Leave the mode empty or use `remote` for
the legacy bounded HTTP adapter.

The remaining named cloud adapters implement provider-specific bounded HTTP
payloads. Google workload identity, IBM/OCI native authentication, and
production credential discovery for those adapters remain deployment
responsibilities. `rule` is deterministic and offline; `noop` explicitly
disables explanations.

The optional `AWS/EKS` integration uses the maintained AWS SDK for Go v2. Set
`SRE_ENABLE_AWS_EKS=true` to activate its read-only control-plane health
analyzer. It resolves an explicit `SRE_EKS_CLUSTER_NAME` or matches the
current kubeconfig context to an exact EKS cluster name/ARN path, and uses the
ambient AWS credential chain. It never mutates AWS or Kubernetes resources.

## Cache And Extensions

`pkg/cache` provides an opt-in encrypted local file cache with AES-GCM,
semantic `v1` keys, TTL, entry/value bounds, atomic owner-only files, list,
remove, purge, corruption handling, and counters. `NewDisabledCache` is the
explicit no-persistence implementation. The remote cache uses the same
encrypted envelope through an injected `ObjectStore` contract and includes a
bounded in-memory object store for tests. The maintained `gocloud.dev/blob`
adapter exposes `BlobObjectStore` for `s3://`, `gs://`, and `azblob://` buckets,
using each driver's standard credential chain. Insecure driver query switches
are rejected before a bucket is opened.

The main service and CLI wire the local cache when both `SRE_CACHE_DIR` and
`SRE_CACHE_ENCRYPTION_KEY` are supplied. Cache results are encrypted, bounded,
and keyed separately for diagnosis and explanation; missing or unavailable
cache storage is non-fatal to provider requests. The `cache` CLI requires both
environment variables and only explicit `remove` or `purge` commands delete
entries. The encryption key is read from the environment/Secret only and is
never persisted or returned by the configuration API. Remote Go Cloud adapters
remain library integrations. An Interplex driver remains outside the product
binary; live cloud credentials, endpoint access, retries, and retention remain
deployment concerns of the selected driver.

`pkg/plugin` defines an external analyzer gRPC protocol in
[api/v1/plugin.proto](api/v1/plugin.proto). The client requires TLS by default,
allows insecure connections only for explicit loopback endpoints, bounds
messages/findings/strings, validates metadata and responses, and supports
signature verification through the registry option. The registry supports
explicit register, activate, deactivate, unregister, and close lifecycle
operations.

`pkg/integration` provides a separate in-process analyzer factory registry with
metadata validation, explicit activation, ownership-aware rollback, and
deactivation. It does not download, install, or manage third-party controllers.

## HTTP, gRPC, MCP, And Chat

The HTTP server exposes public health probes and protected API/static surfaces.
When token authentication is enabled, send `Authorization: Bearer TOKEN`.
JSON mutation requests also require `Content-Type: application/json`.

| Surface | Routes or services |
|---|---|
| Public health | `GET /healthz`, `GET /readyz`; `/` serves the dashboard or authenticated bootstrap page. |
| Legacy REST | `/api/status`, `/api/issues`, `/api/proposals`, `/api/proposals/{id}/approve`, `/api/proposals/{id}/reject`, `/api/audit`, `/api/scan`, `/api/analyzers`, `/api/clean/pods`, `/api/chat`, `/api/chat/sessions`, `/api/notify/test`, and `/api/config`. |
| Versioned REST | `/api/v1/status`, `/api/v1/issues`, `/api/v1/analyzers`, `/api/v1/scan`, `/api/v1/history`, `/api/v1/query`, `/api/v1/capabilities`, and `/api/v1/support-bundle`. |
| Chat sessions | `/api/v1/chat/sessions`, `/api/v1/chat/sessions/{id}`, `/messages`, and `/query`; the unversioned `/api` forms are aliases. |
| MCP | Authenticated Streamable HTTP at `POST /api/v1/mcp` or explicit local stdio via `sre-agent mcp`, using the maintained `github.com/modelcontextprotocol/go-sdk`. Tools are read-only `scan`, `query`, `analyzers`, and `history`; prompts and read-only resources are also registered. |
| Metrics | Authenticated Prometheus text at `GET /metrics` when API token authentication is enabled. |
| gRPC | Optional services in [api/v1/sre.proto](api/v1/sre.proto): `AnalyzerService`, `QueryService`, and `ConfigService`. |

The versioned REST and gRPC projections include sanitized findings, effective
scope, analyzer execution records, parent references, documentation URLs, and
schema versions. Query is limited to an explicit non-secret resource allowlist;
Secret resources are rejected. MCP chat tools use the same read-only query
boundary.

The HTTP chat endpoint remains available for one-off questions. Chat sessions
add authenticated ownership, bounded history, expiry, message limits, provider
cancellation, and one registered read-only `resource.get` tool. The MCP stdio
command is a local process boundary and does not start the HTTP listener. MCP
resources are point-in-time reads; subscription/SSE transports and configuration
or filter mutation tools are intentionally not exposed.

The gRPC service enforces bearer-token metadata, deadlines, message and item
limits, and sanitized config projection. The main binary binds it when
`SRE_GRPC_PORT` is non-zero. TLS/mTLS can be enabled with
`SRE_GRPC_TLS_CERT_FILE`, `SRE_GRPC_TLS_KEY_FILE`, and
`SRE_GRPC_TLS_CLIENT_CA_FILE`; server reflection remains disabled unless
`SRE_GRPC_REFLECTION=true`. A grpc-gateway and OIDC identity layer are not
included, so public deployments still need an authenticated proxy boundary.

## Security And Remediation

Set `SRE_REQUIRE_API_TOKEN=true` for deployed instances. Startup fails closed
when that setting is enabled without a nonblank `SRE_API_TOKEN`. The base
Kustomize deployment and Helm chart enable this mode; local development keeps
it opt-in. `/healthz` and `/readyz` remain public so Kubernetes probes work.

The HTTP boundary applies request-size and per-client rate limits, exact
allowed-origin checks, and optional trusted-proxy CIDR validation. It rejects
caller-supplied `X-User-Email` identity headers. Secrets, tokens, webhook
URLs, logs, events, specs, provider payloads, public API projections, chat
context, notifications, and support bundles pass through the available
redaction boundaries. Sanitization is not a substitute for least-privilege
RBAC or provider-side data policy; raw internal scanner objects must not be
sent to external systems by an embedding application.

If ingress-nginx terminates traffic, configure its `ingress-nginx controller ConfigMap`
according to the actual proxy chain. The application Ingress does
not set controller-wide forwarding behavior; the conservative controller
settings are `use-forwarded-headers: "false"` and
`compute-full-forwarded-for: "false"` until trusted proxy CIDRs and the
forwarding path have been reviewed. Set `SRE_TRUSTED_CLIENT_IP_HEADER` and
`SRE_TRUSTED_PROXY_CIDRS` only for that reviewed proxy boundary.

Remediation supports `RestartPod`, `DeleteFailedPod`, `CleanupPods`,
`RolloutRestart`, `ScaleWorkload`, `CordonNode`, `GitOpsPR`, and `Manual`
diagnoses. Proposals retain target UID/resource-version preconditions and
approval/audit events. With `SRE_DATA_DIR` configured, proposals, audit state,
and scan history use durable owner-only files; without it, proposal state is
in memory. A restart or multi-replica deployment therefore requires a shared
durable design outside the process-local stores.

## Guarded Playbooks

An optional PostgreSQL catalog imports Markdown, YAML, and JSON runbooks through
structured LLM tasks. Reviewed active versions can produce approval-gated typed
remediation proposals; verified outcomes can create new review drafts. See
[playbook operations](docs/playbooks.md) for setup, limits, and learning policy.

## Scheduling And Deployment

The background scanner runs immediately and then at `SCAN_INTERVAL`, with
optional bounded `SRE_SCAN_JITTER`. In addition, client-go shared informers
watch Pod and core Event changes and enqueue bounded, debounced targeted scans;
warning Events also trigger analysis of their involved object. The periodic
full scan remains the recovery/backstop path for dropped events, startup races,
and resources outside the informer set. Both paths share an atomic
in-process gate, so scans cannot overlap. Set `SRE_EVENT_DRIVEN_SCANNING=false`
to use periodic scans only; `SRE_EVENT_QUEUE_CAPACITY` and
`SRE_EVENT_DEBOUNCE` tune the bounded queue. `SRE_LEADER_ELECTION=true` adds a
Kubernetes `Lease` using client-go's maintained leader-election implementation. Configure
`SRE_LEADER_ELECTION_NAMESPACE`, `SRE_LEADER_ELECTION_ID`, and optionally
`SRE_LEADER_ELECTION_IDENTITY`; the deployment RBAC includes only the Lease
verbs needed by that feature.

Kustomize is available at [deploy/k8s](deploy/k8s), with the Kind overlay at
[deploy/overlays/kind](deploy/overlays/kind) and the explicit remediation-RBAC
overlay at [deploy/overlays/remediation](deploy/overlays/remediation). The Helm chart is at
[deploy/helm/sre-agent](deploy/helm/sre-agent). Both package non-root,
read-only containers, fixed image metadata, health probes, a PVC-backed data
directory, PDB, NetworkPolicy, least-privilege observation RBAC, optional
remediation RBAC, optional gRPC service exposure, and optional ServiceMonitor.
Secret creation is external by default. See [deployment.md](docs/deployment.md)
and the [Helm chart guide](deploy/helm/sre-agent/README.md).

Prometheus metrics use the maintained `github.com/prometheus/client_golang`
registry with low-cardinality labels for scan and analyzer status/duration.
They intentionally do not label metrics with namespace, object name, prompt,
provider key, or other unbounded cluster data.

## Verification

Run the local checks:

```bash
go test ./... -count=1
go vet ./...
./scripts/ci/check-docs.sh
./scripts/ci/check-manifests.sh
./scripts/ci/check-image-metadata.sh
helm lint deploy/helm/sre-agent
helm template sre-agent deploy/helm/sre-agent >/tmp/sre-agent-rendered.yaml
```

Run the disposable authenticated deployment check when Docker, Kind,
`kubectl`, and `curl` are available:

```bash
make kind-test
```

The Kind check builds and loads the image, applies the Kind overlay, waits for
rollout/readiness, verifies public health, verifies unauthenticated API
rejection, verifies authenticated `/api/status`, and deletes only its uniquely
named temporary cluster. It does not test cloud credentials, production
ingress/TLS, provider quality, or multi-replica failover.
