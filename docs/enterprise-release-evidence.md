# Enterprise capability and verification record

Implementation date: 2026-09-08. Branch: `codex/enterprise-sre`. This record describes the customer-hosted enterprise entry points; it is not certification or a guarantee of error-free diagnosis. The legacy HTTP/gRPC/MCP deployment is excluded from the enterprise trust boundary.

## Requested capabilities

| Requirement | Delivered behavior | Evidence |
| --- | --- | --- |
| Root-cause depth | Three bounded hypothesis/challenge/reassessment rounds, causal-code rubric, timing/dependency/alternative checks, fresh typed collection, explicit abstention; independent steward corroboration | `pkg/investigation` causal scenarios, refresh-isolation tests; `pkg/stewardship` real-database tests |
| No contamination | New runs consume eligible observations rather than previous claims; False and source revocation invalidate descendants synchronously, including historical golden dependencies | Feedback, quality lineage and knowledge PostgreSQL tests; browser False invalidation |
| Owners and notifications | OIDC groups, exact organization/cluster/application grants, owner inbox, durable authorized webhook delivery, acknowledgement and escalation | Identity/authorization/enterprise tests; delivery PostgreSQL tests; two-cluster owner isolation |
| Privacy outside AI | Strict source projection, opaque resource identities, encrypted local mapping, bounded typed corrections/provider output; no prompt-controlled raw-data exception | Projection/canary tests; actual collector integration excludes private names; browser rendering tests |
| Owner-approved writes | Observe-only default, separate executor identity/RBAC, one unhealthy controller-owned Pod replacement, exact hash/UID/RV/epoch/expiry, dry-run, no mutation retry, durable receipt/reconciliation | Real PostgreSQL concurrent claim; executor HTTP/client-go tests; actual Kind RBAC and approval-before-delete |
| Multi-cluster setup | Explicit scopes, verified cluster UID, namespace allowlists, role-bound enrollment, typed environment/dependency context, setup UI and CLI | Two disposable clusters with identical app namespace; administrator browser onboarding; fleet tests |
| Reviewed learning | Attributed corrections/adjudication, independent causal corroboration, sustained recovery, two-person evaluated golden publication, retirement and source invalidation | Stewardship/knowledge/recovery real PostgreSQL tests and fixed guidance evaluation |
| Honest improvement metrics | Unique incident denominator, attempt ledger, assessed coverage/correctness, verified diagnostic yield, invalidation, abstention, failure counts and 95% intervals by day/profile/prompt/rubric; independent health counts | Deterministic quality tests and real source-revocation tests; quality UI; [paired offline evaluation](evaluation-rubric.md) |
| Provider choice | Per-scope trusted, versioned provider profiles; selectable UI/CLI profile; bounded structured stateless calls and no unauthorized fallback | `pkg/triage` governance/adapters and enterprise profile authorization tests; no live paid provider calls |
| Engineer feedback | True/False/Cannot verify on each immutable observation/conclusion, exact hash/version, idempotency, attributed history, immediate quarantine on False, explicit steward corrections | Real PostgreSQL transaction/race tests; actual Chromium desktop/mobile workflows |

## Verification commands and observed results

- `go test -race ./...`: passed across the repository, including existing legacy behavior. Environment-dependent database/cluster/capacity tests are separately run below rather than counted as passing when skipped.
- `go vet ./...`, `PATH=/home/kevin/.local/bin:$PATH make check enterprise-build`: passed. Chart checks render control-plane, collector-only and optional executor configurations and assert identity/RBAC/volume isolation.
- `scripts/ci/enterprise-postgres.sh`: passed all selected domain packages with the race detector against uniquely created PostgreSQL 17 containers. Includes concurrent claims, revocation, owner reconciliation, historical lineage, recovery sample windows, escalation pagination/activation, transient retention and scope isolation.
- `scripts/ci/enterprise-kind.sh` with Playwright 1.56.1 and Chromium: passed actual two-cluster/ServiceAccount, exact owner approval, independent sustained recovery, browser onboarding/feedback and private PVC restart checks in 96.855 seconds. Only disposable clusters were mutated. Later receipt/escalation corrections have dedicated unit/real-database regressions.
- `go run ./cmd/sre-evaluate --max-calls 26`: thirteen fixed synthetic cases, paired baseline and candidate evaluation with dataset/recording hashes, explicit budget, errors in denominator and unknown cost/usage preserved. The deterministic 13/13 reference versus 7/13 abstention reference tests the mechanism; it does not demonstrate real AI improvement.
- `scripts/ci/enterprise-capacity.sh`: passed 1,001 incidents/runs across two scopes. Method and local results are recorded in [capacity evidence](enterprise-capacity.md); this is serial storage measurement, not fleet throughput.
- `go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...`: no reachable vulnerabilities; one unused required-module advisory remains.
- `scripts/ci/enterprise-images.sh` using Trivy 0.74.0: all four isolated component images built, no high/critical findings, full JSON reports and CycloneDX SBOMs produced. Control-plane has one unused OpenPGP module advisory; other component reports have zero findings. Artifacts are local/CI outputs, not committed binary assets.

Toolchain: Go 1.26.6, Helm 3.20.2, PostgreSQL 17 and Kind Kubernetes v1.35.0. Source/build dependencies and container bases are pinned. CI repeats domain, chart, cluster/browser and image checks and preserves security artifacts. Production image publication/signature verification and customer IdP/provider contracts were not exercised locally.

## Review findings resolved

Independent specification and quality reviews covered source identity/registry isolation, scanner coverage, executor mutation semantics, learning lineage, recovery, operations and delivery. Final reviews identified and verified fixes for refreshed snapshots retaining tentative causes, revoked evidence inflating valid success counts, unacknowledged reconciled receipts blocking executor progress, and new escalation routes replaying old history. Regression tests accompany each correction. Review approval is bounded to inspected code and is separate from test results.

## Supported scope and explicit limits

The deployment is a single control plane with a read-only collector and optional executor per application/cluster scope. Every restart creates a fresh authority epoch: old credentials, queued authority and pending approvals become unusable; agents need explicit reenrollment. This favors restore safety over availability. HA and uninterrupted rolling upgrades are not supported.

Collection uses typed Kubernetes workload/endpoint observations. It excludes raw logs, customer strings and arbitrary tools. Missing evidence produces uncertainty; supported observation codes do not imply comprehensive network/cloud/database root-cause coverage. The only cluster mutation is one approved unhealthy Pod replacement. A successful mutation never establishes recovery or causal attribution. Independent Deployment health is sampled over a declared window.

Quality reports measure assessed diagnostic outcomes; they do not fabricate unobserved monetary cost, operator effort or action-caused recovery. Historical recovery-status buckets may overlap. No live-provider accuracy improvement is claimed without a controlled measured comparison. Scope-specific authorization is supported through enterprise HTTP/UI/CLI and dedicated agent endpoints; legacy tool surfaces are not alternative enterprise APIs.

Retention prunes bounded transient records while preserving immutable evidence and security lineage. Historical erasure, backup storage expiry, external webhook relay operation, production PKI/IdP setup and registry signing belong to the customer's deployment process. See [deployment and operations](enterprise-deployment.md). Broad roadmap examples such as additional repair kinds, native Slack/email adapters, arbitrary logs, autonomous training and HA are not silently enabled by this implementation.
