# KubeBee SRE Feature-Gap Closure And Kind Acceptance Design

## Goal

Close every locally implementable `Partial` capability in the 45-slice K8sGPT
comparison while preserving KubeBee SRE's authenticated, read-only-by-default,
approval-gated, sanitized operating model. Add a reproducible Kind acceptance
test that creates supported Kubernetes failures, observes the running agent's
findings, and verifies deterministic remediation solutions.

## Scope And Evidence Boundary

The 31 partial rows in `docs/kubebee-sre-k8sgpt-feature-gap.md` are the work
inventory. A row may move to `Covered` only after its behavior is reachable,
tested, and represented at the relevant boundary. A safer equivalent may
supersede unsafe upstream behavior, but an unrelated stronger feature does not
hide a missing parity slice.

Local code, fake-client, envtest, HTTP/gRPC contract, and Kind tests are in
scope. Live cloud credentials, OIDC identity, external model quality, ingress
TLS policy, and multi-replica shared-state failover are deployment-dependent.
The implementation will provide explicit adapters, capability/error states,
bounded failure behavior, and contract tests for those areas, without claiming
live proof that cannot be produced in this repository.

## Architecture

### Analyzer And Evidence Contract

Keep the existing `pkg/scanner` and `pkg/scanplan` library boundaries. Complete
typed analyzer semantics with shared list selectors, namespace/name filtering,
stable categories/severity, bounded evidence, and deterministic result order.
Add the missing Kubernetes relationships rather than duplicating resource
lookups: EndpointSlice with legacy Endpoints fallback, workload owners and
children, Service/Ingress ports and classes, webhook targets, ConfigMap
references, storage state, policy selectors, and complete security binding and
container paths. Dynamic Gateway API, OLM, and optional integration analyzers
must report absent/forbidden/unsupported capability states instead of failing
the entire scan.

Every analyzer remains read-only and context-aware. Optional fields, malformed
objects, API permission errors, and unsupported versions become bounded
`AnalyzerRun` errors or findings; they must not panic or silently turn an API
failure into a healthy result.

### Triage, Providers, Privacy, And Cache

Keep `pkg/triage.Provider` as the common diagnosis/explanation contract. Make
provider construction fail closed for unknown names, isolate mutable provider
state per request/profile, validate diagnosis schema and action allowlists, and
bound response sizes, retries, deadlines, and cancellation. Maintain explicit
rule and no-op modes for deterministic offline operation.

All provider, cache, notification, API, UI, chat, plugin, and support-bundle
projections use sanitized data. Cache keys include provider/model/endpoint,
prompt schema, operation, and sanitized evidence identity. Local and remote
caches remain opt-in, encrypted where configured, owner-only, bounded, and
non-fatal when unavailable. Cloud adapters use injected clients or bounded HTTP
contracts; setup errors return typed errors instead of terminating the host.

### API, Remediation, Plugins, And Integrations

Retain the versioned REST/gRPC/MCP surfaces and their authentication and
allowlists. Close remaining lifecycle gaps with structured errors, request
deadlines, bounded query/log responses, explicit plugin discovery/activation
metadata, and ownership-aware integration activation/deactivation. Every
mutation, including cleanup and integration removal, remains proposal- and
approval-gated with actor attribution, target preconditions, durable audit
state when configured, and no broad force-delete fallback.

Cloud/EKS, Prometheus, Kyverno, KEDA, Gateway, OLM, and external analyzer
activation stay explicit and read-only by default. Installation or uninstall
of third-party controllers is not inferred from analyzer registration; any
lifecycle operation must be allow-listed, ownership-scoped, idempotent, and
rollback-aware.

## Dashboard Metrics And Settings

The embedded dashboard remains the authenticated operational surface. Extend it
with a metrics view that loads a bounded, sanitized projection of runtime
health: active error count, scan/analyzer/provider error totals, and provider
token usage (prompt, completion, and total when the provider reports usage).
The UI must show an explicit unavailable state when a provider does not return
usage rather than inventing a number. Prometheus remains the machine-facing
source of truth; the dashboard projection is read-only and low-cardinality.

Add a settings view for provider name, wire API, model, scan interval/jitter,
cache state, and webhook configuration. Render endpoint values only in masked
or host-safe form, never return API keys, custom header values, cache
encryption keys, or raw webhook URLs, and keep mutations limited to the
existing authenticated, validated configuration actions. Add browser-safe
loading/error states and responsive layouts for the metrics and settings
sections.

## Event-Driven Scan Triggers

The background scanner uses a hybrid trigger model. A client-go shared
informer watches Pods and core Events, because kubelet status transitions and
controller-generated warning Events are not admission requests and therefore
cannot be reliably handled by an admission webhook. Informer callbacks emit
bounded object triggers; warning Events also emit a trigger for their involved
object so a failure can be analyzed even when the Pod update is delayed.

Triggers are coalesced by resource, namespace, and name in a bounded
latest-state queue and drained after a configurable debounce window. Targeted
scans preserve the configured namespace, selector, analyzer, timeout, and kind
scope, while retaining dependency kinds needed by the affected analyzer. A
periodic full scan remains the correctness backstop for dropped events,
startup races, resources not yet covered by informers, and informer/API
outages. Both paths share the scheduler overlap gate, and only the active
leader runs the informer and trigger consumer when leader election is enabled.

The event source requires only the existing read-only `get`, `list`, and
`watch` permissions for Pods and Events. Event-driven scanning is enabled by
default and can be disabled with `SRE_EVENT_DRIVEN_SCANNING`; queue capacity
and debounce are controlled by `SRE_EVENT_QUEUE_CAPACITY` and
`SRE_EVENT_DEBOUNCE`.

## Kind Acceptance Workflow

The existing `make kind-test` path will become a full authenticated diagnosis
acceptance test while retaining its unique-cluster and cleanup guarantees.

1. Create a uniquely named Kind cluster from the pinned node image, build and
   load the agent image, create a temporary non-empty API-token Secret, and
   apply the base/Kind manifests.
2. Configure the agent through test-only environment inputs. By default the
   harness selects the `codex` provider, reads the host-provided Codex/OpenAI
   API key, base URL, model, and `wire_api` (`responses`) without writing them
   to the repository or a persisted profile, and waits for rollout, readiness,
   and the authenticated API. `SRE_KIND_LLM_PROVIDER=rule-based` is the
   explicit offline override for environments without a host API credential.
3. Apply a fixture bundle under a dedicated namespace. The matrix covers the
   supported typed categories: pending/unschedulable, image-pull, crash-loop,
   OOM/failed/evicted/terminating pods, current and previous log evidence,
   Deployment/StatefulSet/DaemonSet/ReplicaSet/Job/CronJob failures, Service
   selector and EndpointSlice failures, Ingress class/backend/port/TLS
   failures, NetworkPolicy selector cases, HPA and PDB conditions, pending
   PVC/PV/StorageClass failures, ConfigMap hygiene, admission webhook target
   failures, node readiness/pressure/taint cases, and security binding or
   privilege findings.
4. Install minimal optional CRD fixtures where the dynamic scanner supports
   them, then create malformed or failing Gateway API, OLM, KEDA, Kyverno, and
   Prometheus Operator objects. The test must verify capability-gated results
   and must skip only a fixture whose CRD is unavailable by design, recording
   that boundary rather than treating it as a passing analyzer result.
5. Poll authenticated `/api/v1/issues` until every expected fixture category
   is present. Verify each returned issue has a stable identity, sanitized
   evidence, bounded details, and no fixture secret/token. Poll
   `/api/proposals` until the background controller has diagnosed the issues.
   For every expected proposal, verify provider name, root cause, remediation
   plan, confidence bounds, supported action, and a redacted safe command.
6. Exercise the versioned scan endpoint and CLI-compatible JSON projection,
   then assert unauthenticated requests fail, health/readiness remain public,
   and cleanup removes only the cluster and namespace owned by the test. Fetch
   the authenticated dashboard metrics/settings projections and assert they
   contain error/token/configuration fields but no API key, fixture secret,
   cache key, or raw webhook value.

The Kind run proves controller wiring, Kubernetes API semantics, scanner
observation, deterministic triage, redaction, and authenticated API behavior.
It does not claim live cloud provider credentials, OIDC, production ingress,
or multi-replica failover; those remain contract and deployment checks.

The Codex test contract uses `SRE_KIND_LLM_API_KEY`,
`SRE_KIND_LLM_BASE_URL`, `SRE_KIND_LLM_MODEL`, and
`SRE_KIND_LLM_WIRE_API` when supplied. When they are absent, the harness may
read equivalent host-only `CODEX_*`/`OPENAI_*` environment values and the
configured Codex provider endpoint; secret values are passed only through a
temporary Kubernetes Secret. The application exposes `LLM_WIRE_API` as
`chat` or `responses` and rejects unsupported values.

## Concurrent Workstreams

Workers will edit disjoint areas and return changed paths plus focused test
evidence:

- **Analyzer parity:** `pkg/scanner`, dynamic capability fixtures, and scanner
  contract/conformance tests.
- **Provider, cache, and privacy parity:** `pkg/triage`, `pkg/cache`,
  `pkg/sanitizer`, provider/cache contract tests, and safe output boundaries.
- **API, remediation, plugin, and integration closure:** `pkg/server`,
  `pkg/remediation`, `pkg/plugin`, `pkg/integration`, API contracts, and
  deployment RBAC where necessary.
- **Kind, CI, and documentation:** fixture manifests, Kind orchestration,
  CI targets/checks, generated/evidence ledgers, and user-facing docs.

Shared changes to `go.mod`, central scanner types, configuration schemas, or
generated protobufs will be coordinated through the integration workspace
after worker patches are reviewed. No worker may weaken authentication,
redaction, approval, or read-only deployment defaults to make a test pass.

## Error Handling And Observability

Analyzer and provider failures must preserve cancellation, distinguish
forbidden/unsupported/unavailable states, and expose bounded diagnostics. The
agent must continue scanning independent analyzers when one fails, record the
failed analyzer run, and keep deterministic rule-based diagnosis available
when no remote provider is configured. Metrics and logs use low-cardinality,
sanitized fields. Kind assertions inspect API responses and persisted proposal
projections rather than relying on process logs alone.

## Verification And Closure

Each workstream starts with failing focused tests, implements the smallest
behavior needed, and runs its package suite. Integration verification runs:

```text
gofmt -w <changed Go files>
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
./scripts/ci/check-docs.sh
./scripts/ci/check-manifests.sh
./scripts/ci/check-image-metadata.sh
bash -n scripts/ci/*.sh
make kind-test
```

The feature-gap matrix and evidence record are updated only after the matching
acceptance artifact passes. Remaining external-environment limitations stay
explicit in the matrix and evidence record; no row is marked covered solely
because a type, adapter, or manifest exists.
