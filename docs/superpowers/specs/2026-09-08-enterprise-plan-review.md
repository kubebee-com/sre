# Enterprise Plan Comprehensive Review

Date: 2026-09-08. Reviewed with the Superpowers requesting-code-review workflow and a separate existing-code reuse review. Scope: all R1-R10 requirements, architecture boundaries, delivery sequencing, test gates, and existing playbook implementation. Reviewers made no code changes.

## Findings and dispositions

| Priority | Finding | Resolution |
|---|---|---|
| P1 | Restored backups can resurrect consumed approvals/revocations | Recovery lockout, fresh external authority epoch, credential/approval revocation, policy restoration, reconciliation; stale-backup replay acceptance test. |
| P1 | Cluster identity alone does not distinguish collector/executor authority | Role/audience/capability/epoch/generation-bound identities and single-use administrator enrollment. |
| P1 | Async invalidation permits feedback/action races | Transactional dispute state and synchronous ancestor eligibility at retrieval/submission authorization; explicit in-flight boundary. |
| P1 | G1 corroboration precedes rubric/evaluation | Move minimal rubric, steward/deterministic corroboration authority, and frozen negative baseline to W5/G1. |
| P1 | Raw resource names may be PII yet execution needs exact targets | Local encrypted identity mapping and opaque handle/exact-target commitment; policy-approved owner projection. |
| P2 | Future resourceVersions make multi-step/rollback approval ambiguous | First release permits one mutation per approval; rollback requires a new approval. |
| P2 | Stale/relevance feedback can corrupt historical correctness | Distinct adjudication outcomes; only factual error changes correctness metrics. |
| P2 | Prior implementation is substantial and has conflicting authority contracts | Explicit reuse inventory and enterprise-mode gates; no duplicate provider runner or authoritative schemas. |

## Existing implementation inventory

Enterprise baseline f7f934a contains the same application snapshot as playbook commit 700133a plus the new enterprise documents. The existing integration branch is codex/playbook-integration at 92dd5dc; its merge-base is 7ef4783. Integration preserves its implementation history but does not certify it for enterprise use.

| Existing component | Disposition | Required adaptation |
|---|---|---|
| pkg/triage/task.go and provider wire adapters | Reuse | Add governed investigation operations and strict task-schema validation. |
| pkg/triage/responses_stream.go, bounded cancellation, token accounting | Reuse | Preserve current limits; add scope/privacy/provider version context. |
| pkg/playbook canonicalization, normalization, typed guardrails, imports | Reuse with review | Consume scoped enterprise evidence and knowledge-release policy. |
| pkg/playbook/migrations/001_playbooks.sql | Legacy source only | Core incident/evidence/approval/feedback authority belongs to one enterprise schema; migrate through reviewed adapters. |
| pkg/playbook/resolve.go and matching contracts | Adapt | Explicit organization/cluster/application identity, current evidence eligibility, and authorized knowledge. |
| pkg/remediation executor preconditions and typed operations | Reuse mechanics | Isolated credentials, exact owner approvals, disruption policy, restore epochs, synchronous invalidation. |
| Current operation VERIFIED checks | Relabel at enterprise boundary | Operation completion is APPLIED; independent health windows decide recovery. |
| pkg/playbook/learn.go | Disable in enterprise until adapted | No learning from operation-effect strings; consume reviewed diagnosis plus independent outcomes. |
| pkg/remediation/terminal_audit.go | Replace delivery mechanism | Durable transactional outbox; no dropped terminal state events. |
| Process harness | Disable in enterprise | No reuse before credential/environment/egress isolation. |
| Legacy token-based playbook promotion and mutation endpoints | Deny in enterprise | Shared scoped owner/admin authorization must be enforced first. |

## Additional acceptance scenarios

- Restore an old backup after action execution and credential revocation; zero new writes occur with old authority.
- Present collector credentials to an executor receipt/claim endpoint and executor credentials as observation publisher; both rejected.
- Hold outbox delivery, commit False feedback, then attempt cache retrieval and action submission; both consult authoritative eligibility.
- Feed a plausible cited conclusion with unresolved alternatives; it remains uncorroborated under G1.
- Include synthetic PII in Kubernetes resource names; no unauthorized central/provider/output sink receives raw names, and exact approved targeting remains correct.
- A true unhealthy observation becomes stale after external repair; no false historical-error label is created.

## Review status

All eight findings have explicit architecture amendments and implementation acceptance requirements. The proposed design is approved by the user's instruction to implement; application readiness remains governed by G0-G3 and actual evidence. Re-review the amendments before implementation tasks are marked complete.

## Review disposition

The independent architecture re-review accepted the amendments with no remaining
material contradictions. This approves the design contracts, not a production
readiness claim. Implementation reviews and the program's release gates remain
mandatory. The PostgreSQL execution details are recorded in the companion scoped
enterprise state implementation plan.
