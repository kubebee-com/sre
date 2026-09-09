# KubeBee SRE K8sGPT Feature-Gap Analysis Design

## Goal

Create an evidence-backed feature-gap table that lets KubeBee SRE reach complete K8sGPT capability parity while preserving and extending KubeBee SRE's stronger remediation approval, deterministic fallback, notification, and security workflows.

## Baseline

- **KubeBee SRE:** the current working tree at `/home/kevin/sre`, product name **KubeBee SRE**.
- **K8sGPT:** the shallow clone at `/home/kevin/sre/k8sgpt`, commit `731a6c90749e8e62b9325e41712c39c0d72510c4`, reviewed on 2026-09-04.
- README claims are not accepted as implementation evidence until checked against source, tests, configuration, and deployment manifests.

## Status Semantics

| Status | Meaning | Required treatment |
|---|---|---|
| **Covered** | KubeBee SRE provides the capability end to end for the same user-facing outcome, with implementation evidence. | Cite the SRE entrypoint, implementation, and tests or runtime configuration where applicable. |
| **Partial** | KubeBee SRE provides a meaningful subset or equivalent, but one or more K8sGPT behaviors, resource kinds, transports, providers, controls, or lifecycle guarantees are absent. | Name every material missing slice in the table. A row may not say only “partial.” |
| **Missing** | No usable KubeBee SRE implementation or equivalent exists. | State the K8sGPT behavior and the concrete SRE work required. |
| **KubeBee SRE stronger** | A parity capability is covered and SRE adds a materially stronger property. | Record the stronger property separately; it never hides a missing K8sGPT slice. |

A capability is not Covered merely because a similarly named type exists. It must be reachable in the product path and have the relevant inputs, outputs, errors, security controls, and lifecycle behavior.

## Capability Taxonomy

The inventory will normalize K8sGPT features into rows across these families:

1. **Cluster and resource discovery:** in-cluster/out-of-cluster clients, namespaces, selectors, resource-name selection, typed/dynamic/controller-runtime clients, OpenAPI documentation.
2. **Built-in analyzers:** every core/additional K8sGPT analyzer and the exact failure modes it detects, including Pod, Deployment, ReplicaSet, StatefulSet, DaemonSet, Job, CronJob, Service, Ingress, Node, PVC/PV, ConfigMap, HPA, PDB, NetworkPolicy, webhooks, logs/events, Gateway API, OLM, and Security.
3. **Analyzer mechanics:** filter catalog, analyzer activation, integration-provided analyzers, concurrency, metrics, parent ownership, docs, event/log evidence, and selector/namespace semantics.
4. **AI and explanations:** all K8sGPT providers, provider configuration/authentication, prompt templates, language handling, custom headers/proxies, interactive mode, response/error handling, model defaults, and custom REST/agent integrations.
5. **Privacy and caching:** anonymization, sensitive mapping behavior, event/log coverage, cache backends, cache disable/list/remove/purge, cache-key semantics, encryption/transport, and cache lifecycle.
6. **Outputs and interfaces:** text/JSON output, statistics, CLI commands/flags, gRPC, grpc-gateway, MCP stdio/HTTP, prompts/resources/tools, health and metrics.
7. **Integrations and extensions:** AWS/EKS, KEDA, Kyverno, Prometheus, custom analyzers, extension/configuration contracts, and external schema compatibility.
8. **Operations and delivery:** Helm, RBAC, service exposure, container image, release artifacts, SBOM/provenance/signing, CI, configuration persistence, and upgrade/migration behavior.
9. **KubeBee SRE differentiators:** proactive scan loop, deterministic rule-based triage, multi-LLM triage, remediation proposals, explicit approval/rejection, GitOps PR action, pod cleanup, Slack/Discord/Teams notifications, web dashboard, and chat.

Rows will be split when one broad feature contains materially different missing slices. For example, AI support is separated by provider family and by request/lifecycle behavior; analyzer parity is separated by resource kind/failure family rather than one “analyzers” row.

## Table Schema

The main table will use these columns:

| Column | Content |
|---|---|
| ID | Stable gap identifier for roadmap tracking. |
| Family | One taxonomy family above. |
| Capability | Normalized user-facing capability. |
| K8sGPT behavior | What K8sGPT actually does at the frozen commit. |
| K8sGPT evidence | Exact source paths, symbols, tests, or manifests. |
| KubeBee SRE behavior | What current SRE actually does, including limits. |
| KubeBee SRE evidence | Exact source paths, symbols, tests, or manifests. |
| Status | Covered, Partial, or Missing. |
| Missing slice | Required for every Partial and Missing row; explicit behaviors/resources/controls absent. |
| Better KubeBee solution | Design that reaches parity and improves safety/operability without unnecessary compatibility debt. |
| Priority | P0 safety/blocker, P1 parity-critical, P2 important, P3 polish. |
| Acceptance evidence | Test, fixture, API contract, or deployment check that will prove closure. |

Evidence will use repository-relative paths and line/symbol references. Findings derived from documentation alone will be labeled as claims and downgraded until implementation evidence exists.

## Deliverables

1. `docs/kubebee-sre-k8sgpt-feature-gap.md`: executive summary, complete table, parity totals, SRE-stronger capabilities, and links to evidence.
2. `docs/kubebee-sre-k8sgpt-roadmap.md`: dependency-ordered implementation work packages with acceptance criteria, preserving the table's stable IDs.
3. `docs/kubebee-sre-k8sgpt-evidence.md`: source/test/manifests inventory and unresolved evidence questions where behavior cannot be verified without a live cluster or provider.
4. `docs/superpowers/plans/2026-09-04-kubebee-sre-k8sgpt-feature-gap.md`: executable plan for producing the analysis artifacts.

The existing per-file K8sGPT appendices remain the source evidence for the K8sGPT side; the new evidence file will add the KubeBee SRE side and cross-reference both.

## Analysis Method

- Inventory K8sGPT capabilities from its reviewed appendices and verify high-impact rows against source.
- Inventory KubeBee SRE behavior from executable code, tests, HTTP routes, CLI/configuration, and deployment manifests.
- Normalize names and split rows until each status has an unambiguous meaning.
- Mark `Partial` only with an explicit missing-slice list; do not treat a stronger SRE feature as parity for an absent K8sGPT capability.
- Assign priorities based on safety/reachability first, then parity value and implementation dependencies.
- Write acceptance evidence before recommending closure: unit tests for pure logic, fake-client tests for Kubernetes behavior, HTTP contract tests for APIs, provider contract tests, and Helm/render/RBAC checks.
- Validate the final table mechanically: stable unique IDs, no blank status/missing-slice fields, every K8sGPT capability mapped to one or more rows, every SRE-only differentiator listed, and all cited paths exist.

## Non-Goals

- Do not copy K8sGPT's insecure behavior merely for parity; the “better solution” column must preserve authenticated, least-privilege, approval-gated operation.
- Do not implement production feature work as part of the gap-analysis artifact task.
- Do not claim live-cluster/provider compatibility without a runnable test or an explicit evidence limitation.
- Do not collapse KubeBee SRE remediation/notification features into K8sGPT rows; they are tracked as differentiators.

## Completion Criteria

The analysis is complete when:

- Every normalized K8sGPT capability at the frozen commit appears in the table.
- Every `Partial` row names its concrete missing slices.
- Every row has source evidence for both repositories or an explicit unavailable-evidence note.
- The table has stable IDs and maps one-to-one to roadmap work packages or an explicit Covered rationale.
- The report identifies where KubeBee SRE is safer/better and where it still lacks parity.
- Independent inventory and quality reviews find no Critical or Important coverage/evidence defects.
