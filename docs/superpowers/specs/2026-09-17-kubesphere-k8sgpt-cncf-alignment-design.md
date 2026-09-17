# Kubebee SRE Triage Console, K8sGPT Core, And Cloud-Native Alignment

## Goal

Turn the approved KubeSphere-style browser design into the real authenticated
Kubebee SRE dashboard, then close the core K8sGPT compatibility and cloud-native
operational gaps that affect an SRE using the product in a Kubernetes cluster.

The product remains an AI-assisted, issue-triage system. It is not a generic
Kubernetes administration console and it does not grant an AI model mutation
authority.

## Terminology And Boundary

"K8sGPT aligned" means the product provides the same core operator outcomes as
K8sGPT: scoped Kubernetes scanning, analyzer-driven findings, filters, simple
English explanations, documentation links, pluggable AI backends, structured
output, and extensibility. It does not mean that every upstream implementation
detail or unsafe default is copied.

"CNCF cloud-native aligned" means the product passes an explicit engineering
checklist derived from the CNCF Cloud Native Definition and Kubernetes-native
operational practice. CNCF does not issue a single universal application
certification for this claim, so the product must publish its evidence rather
than make a certification claim.

The existing K8sGPT capability matrix remains the source of truth for detailed
parity. This work must update that matrix as behavior moves from Partial to
Covered; it must not silently redefine Partial as complete.

## Product Shape

Keep the existing unified architecture:

- `sre-orchestrator` owns the authenticated UI/API, scoped work, approvals,
  notifications, audit history, and durable coordination state.
- `sre-agent` owns Kubernetes collection, analyzers, evidence sanitization,
  provider calls, and explicitly approved execution.
- Read-only collection and diagnosis remain the default. Execution requires an
  authorized human approval for the exact plan and resource version.

The dashboard becomes a KubeSphere-inspired operational workspace:

- Global top navigation for Triage Center, Clusters, and AI Operations.
- A cluster context selector showing organization, cluster, application scope,
  connectivity, and agent identity.
- Grouped left navigation for Triage, Evidence, Automation, and Governance.
- An overview canvas with issue counts, health posture, AI priority queue, AI
  briefing, review workload, and help information.
- Issue rows expose severity, category, evidence state, AI confidence, current
  lifecycle state, review, and Resource Logs actions.
- The UI is backed by live API data. The browser demo must not become a second
  hard-coded application or a deployment artifact.

The Resource Logs dialog must have an explicit selector-specific hidden rule,
safe text rendering, keyboard-accessible close behavior, backdrop close
behavior, and a Playwright regression that checks computed visibility rather
than only the `hidden` class or attribute.

## K8sGPT Core Compatibility

### Scan And Scope

The supported product path must provide:

- A one-shot and service-mode scan against typed Kubernetes resources.
- Namespace include and exclude scope, label selector, kind, name, and analyzer
  selection with an explicit effective-scope response.
- Named filters with list, add, remove, and default behavior.
- Bounded concurrency, request deadlines, cancellation, deterministic analyzer
  ordering, and explicit forbidden or unsupported API states.
- Structured JSON, YAML, table, and raw output with schema version, findings,
  parent references, docs URLs, analyzer runs, timing, and counts.

The current scan-plan and analyzer contracts should be reused and strengthened;
new parallel contracts are not allowed unless an existing one cannot express a
required K8sGPT behavior.

### Default Analyzer Set

The default compatibility set must cover the K8sGPT core resource families:

- Pods and bounded current, previous, init, and ephemeral container evidence.
- PVCs and storage binding state.
- ReplicaSets, Deployments, StatefulSets, Jobs, and CronJobs.
- Services, EndpointSlices, Ingresses, and admission webhooks.
- Warning events and resource-linked event evidence.
- Nodes and node pressure, taints, scheduling, and readiness signals.
- ConfigMaps and safe usage or size hygiene checks.

Optional analyzer families must be capability-gated and visible in the analyzer
catalog rather than failing an entire scan when their CRDs are absent:

- HPA, PDB, NetworkPolicy, Gateway API, logs, storage, and security.
- OLM, KEDA, Kyverno, Prometheus Operator, AWS/EKS, Falco, and other owned
  integrations.

Every finding must have stable identity/fingerprint, kind, namespace/name when
applicable, severity, category, summary, root-cause evidence, analyzer name,
docs URL when available, parent reference when applicable, and a clear state
for active, resolved, suppressed, or unsupported.

### Explanation And Providers

The provider boundary must support the K8sGPT core workflow:

- Explain a finding using sanitized evidence and optional Kubernetes docs.
- Use a provider-neutral interface with OpenAI-compatible, Claude, cloud, local,
  rule-based, and no-op modes where currently supported.
- Validate provider configuration strictly, enforce endpoint policy, deadlines,
  cancellation, bounded retries, response-size limits, and schema-validated
  diagnosis output.
- Mark model-derived text as advisory and preserve deterministic fallback when
  a provider is unavailable.
- Expose provider, model, confidence, latency, token/cost usage when available,
  and unavailable-usage states without exposing credentials.
- Support authenticated bounded chat sessions and read-only query tools.
- Preserve redaction and prompt-injection boundaries at every model, cache,
  notification, API, bundle, and UI sink.

### Extension And Integration Surface

The product must retain a versioned external analyzer boundary and MCP support.
Analyzer metadata, health, capability, cancellation, quotas, and response
validation must be explicit. Integrations must be read-only by default,
allow-listed, capability-gated, and visible in status and audit output.

## Cloud-Native Alignment Checklist

### Kubernetes And Portability

- Use standard Kubernetes APIs and versioned REST/gRPC contracts.
- Ship declarative Helm and Kustomize deployment paths with configuration
  separated from images and secrets externally managed.
- Use OCI images with multi-architecture builds, immutable digest promotion,
  provenance, SBOM, vulnerability scanning, and signature verification policy.
- Keep the application portable across Kubernetes distributions; provider- or
  vendor-specific integrations remain optional extensions.
- Keep production deployment GitOps-compatible with Flux and ensure manifests
  select the digest of the reviewed image.

### Security And Trust Boundaries

- Run containers as non-root with read-only root filesystems, dropped
  capabilities, seccomp defaults, resource requests/limits, and explicit
  service accounts.
- Separate read-only agent permissions from optional execution permissions.
- Use authenticated browser/API routes, verified human identity for approvals,
  scoped cluster and namespace access, bounded query allowlists, and no caller-
  supplied actor identity for mutations.
- Use NetworkPolicy to restrict ingress and egress, external secret references,
  TLS or mTLS for service boundaries, and short-lived or rotated credentials
  where the deployment supports them.
- Give each agent instance a traceable workload identity and record the agent,
  human actor, scope, plan hash, resource version, and result for every action.
- Redact secrets, credentials, raw sensitive fields, and untrusted text before
  sending data to AI providers or durable external sinks.

### Observability And Explainability

- Keep public `/healthz` and `/readyz` separate from authenticated API routes.
- Expose Prometheus metrics with bounded label cardinality for scans, analyzers,
  providers, cache, queue, approvals, execution, and errors.
- Emit structured logs with request, scan, finding, trace, actor, and agent
  correlation identifiers while excluding secrets.
- Add optional OpenTelemetry trace propagation/export for HTTP, gRPC, scans,
  analyzer runs, provider calls, and execution; no exporter must be required
  for local operation.
- Preserve an evidence trail connecting an issue to observations, model input,
  explanation, proposal, approval, and execution result.
- Define data retention and aggregation behavior for findings, logs, traces,
  cache entries, and audit records.

### Availability And Fault Tolerance

- Keep bounded timeouts, retries, cancellation, graceful shutdown, readiness
  dependency checks, and deterministic fallback behavior.
- Prevent overlapping scans and coordinate periodic/event-driven work with a
  lease or equivalent leader-election boundary when multiple replicas run.
- Persist orchestrator state and audit transitions in PostgreSQL; keep agent
  local state bounded and restart-safe.
- Ship PDB, topology spread or anti-affinity where replica count permits,
  resource limits, and a documented single-replica fallback for small clusters.
- Make operations idempotent, reject stale resource versions, and verify the
  post-action state rather than treating an API request as recovery.

### AI Governance

- Define success criteria for triage quality, evidence completeness, safe-action
  precision, false-positive rate, latency, token/cost usage, and human review
  burden.
- Maintain deterministic synthetic fixtures and evaluation datasets for common
  Kubernetes failure modes, adversarial input, provider failure, and stale
  resource state.
- Evaluate full investigation trajectories, not only final text: collection,
  analyzer selection, evidence selection, provider call, explanation, proposal,
  approval, execution, and verification.
- Make no model output sufficient to authorize a write action. Every mutation
  remains policy-checked, human-approved, scoped, audited, and verifiable.

## Implementation Phases

1. **Dashboard foundation.** Replace the legacy dark tab composition with the
   approved KubeSphere-style layout, preserving existing API routes and auth,
   wiring all live data, and fixing the Resource Logs lifecycle. Add desktop,
   mobile, DOM-security, and Playwright coverage.
2. **Core K8sGPT contract.** Close the default analyzer, scan-plan, filters,
   output, provider, explain/docs, cache, MCP, and external analyzer behaviors
   required by the core workflow. Update the capability matrix with evidence.
3. **Cloud-native baseline.** Add or verify OpenTelemetry boundaries, workload
   identity and audit correlation, production-ready resilience manifests,
   digest/provenance policy, and the security/observability checks above.
4. **Integration and delivery.** Build the reviewed multi-architecture image,
   update only the intended Flux deployment manifest to its immutable digest,
   reconcile the `sre` workload, and validate the live HTTPS dashboard and
   Resource Logs workflow with Playwright.
5. **Parity ledger.** Continue closing non-core K8sGPT partial rows and publish
   exact remaining gaps; do not claim full parity until the 45-row matrix is
   closed or has a tested supersession decision.

## Acceptance Evidence

- Unit and contract tests for scan scope, analyzer metadata, stable findings,
  provider errors, redaction, cache keys, MCP, plugin lifecycle, and API auth.
- Fake-client or envtest matrices for healthy/failing core resources, optional
  CRD absence, forbidden access, cancellation, timeouts, and stale resources.
- Browser tests for authentication, sidebar navigation, live counts, issue
  review, logs content, computed modal visibility, responsive layout, and safe
  rendering of malicious issue data.
- Manifest tests for non-root/read-only execution, RBAC separation, probes,
  NetworkPolicy, PDB/topology, resources, digest image references, and external
  secrets.
- CI evidence for `go test -race`, `go vet`, static checks, image SBOM,
  vulnerability scan, provenance/signature, multi-architecture image metadata,
  and Kind acceptance.
- Deployment evidence that Flux reports the intended Git revision and the
  running Pod reports the intended immutable image digest.
- Updated K8sGPT matrix and a cloud-native alignment checklist with links to
  each passing test, manifest check, or operational runbook.

## Non-Goals

- Claiming CNCF membership, certification, or project maturity from this work.
- Copying KubeSphere branding, assets, or resource-management breadth that does
  not improve issue triage.
- Giving the model unrestricted Kubernetes write access.
- Treating the visual companion demo as production application code.
- Declaring all 45 K8sGPT capability slices complete in the first phase.

## References

- K8sGPT README: https://github.com/k8sgpt-ai/k8sgpt/blob/main/README.md
- K8sGPT technical review: https://github.com/k8sgpt-ai/k8sgpt/blob/main/GENERAL_TECHNICAL_REVIEW.md
- CNCF Cloud Native Definition: https://www.cncf.io/about/who-we-are/
- CNCF cloud-native agentic standards: https://www.cncf.io/blog/2026/03/23/cloud-native-agentic-standards/
- Existing KubeBee K8sGPT matrix: `docs/kubebee-sre-k8sgpt-feature-gap.md`
- Existing KubeBee parity roadmap: `docs/kubebee-sre-k8sgpt-roadmap.md`
