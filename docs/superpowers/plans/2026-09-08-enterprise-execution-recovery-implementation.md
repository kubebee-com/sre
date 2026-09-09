# Enterprise owner-approved execution, recovery, and reviewed learning

This extends the approved enterprise program. Execution remains opt-in, in a separate process and ServiceAccount. Default installation observes only.

## Exact single action

Implement a typed `REPLACE_POD` action only. The planner may propose one deletion of an unhealthy controller-owned Pod; the owning controller performs replacement. No shell, arbitrary patch, exec, create, RBAC, namespace-wide operation, or force deletion is accepted. Protected namespaces and standalone/static Pods are denied locally. Approval describes this as mitigation, never proven root-cause repair.

A persisted action binds application scope, incident, exact evidence reference/hash, opaque target handle/commitment, source collector generation and authority epoch, executor ID/generation, action kind, policy version, and expiry. Operator proposal and owner/approver approval are distinct authenticated events. Approvals bind canonical action hash and cannot amend the payload. Permission is checked again at the database submission boundary. All supporting evidence lineage must remain eligible; old authority epochs cannot execute after restart or restore.

Claim transitions APPROVED to SUBMITTED once, with a unique receipt token hash. Submission is the last transactional authority boundary before Kubernetes. The executor resolves the encrypted local target and validates UID/resourceVersion, namespace, ownership, and dry-run before a single Delete with UID/resourceVersion preconditions. No retry after a submitted attempt; missing receipts are AMBIGUOUS and require reconciliation/new approval. APPLIED records operation effect only. Rollback/replacement actions require new approval.

Tests: no self-authorized investigator write; exact hash/expiry/policy/source/target/generation binding; revoked/wrong-role credentials; concurrent claim once; False feedback ordering; lost result no replay; live precondition failure; static/protected target denial; read-only default RBAC.

## Independent recovery

Collector health observations are independent of executor receipts. A configured versioned profile requires fresh complete samples, stable source identity and resource identity, desired availability, minimum sample count and sustained window. Partial/missing observations yield UNKNOWN; regressions reset the window. Record recovery assessment separately and allow sustained HEALTHY without asserting the action caused it. Distinguish mitigation, external repair, and reviewed causal correction. Reopening starts a new incident episode.

## Steward adjudication and golden cases

Record immutable adjudications against exact feedback/item versions, reason codes CONFIRMED, FACTUAL_ERROR, NOT_APPLICABLE, STALE, or UNRESOLVED. Ordinary True feedback does not remove quarantine or promote knowledge. A steward can publish a new reviewed claim with exact evidence parents after deterministic rubric checks, independent causal assessment, and resolution of material contradictions. Disputed source versions stay immutable/quarantined.

Golden candidates require a reviewed corroborated claim and independently sustained recovery. A second explicit steward publication creates an immutable scoped knowledge release. Retrieval checks every source lineage synchronously for dispute/revocation, separately from historic freshness so historical verified knowledge remains useful only as guidance requiring current evidence. Candidate knowledge cannot authorize tools or permissions. Releases can be retired; no automatic self-promotion.

## Honest quality reporting

Persist all accepted investigation runs, including provider failures, abstentions, cancellation, and completion. Report denominators, reviewed coverage, factual correctness, recovery outcomes, abstention/provider failure rates, sample sizes and Wilson intervals, grouped by time/profile/provider/prompt/rubric/knowledge release. Unreviewed outcomes are unknown, never successes. Factual-error adjudications alter correctness; contextual non-applicability does not rewrite historical truth. Frozen baseline scenarios and held-out evaluations gate new knowledge release publication.

## Operator surfaces

Use shared application services from authenticated HTTP/UI and supported CLI adapters. UI shows exact action and owner acknowledgment, operation status separately from sustained recovery, feedback/adjudication lineage, golden release review, and quality-over-time with sample counts. Unsupported legacy mutation surfaces remain absent from the enterprise control plane.
