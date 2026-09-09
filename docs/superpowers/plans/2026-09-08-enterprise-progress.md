# Enterprise implementation progress

Worktree: `.worktrees/enterprise-sre`, branch `codex/enterprise-sre`. The original working tree remains untouched. This is an implementation and verification record, not a production certification.

Implemented since the access/feedback checkpoint:

- Fleet enrollment, one-use scoped role/audience credentials, generation rotation/revocation, restore/restart authority fencing.
- Strict report ingestion, immutable evidence provenance, encrypted local identity registry with descriptor-relative atomic persistence, separate collector runtime and CLI.
- Typed owner-approved Pod replacement, scoped exact target/hash/version/expiry binding, single submission transaction, isolated executor with UID/resourceVersion checks, controller existence checks, protected-target denial, dry-run, disabled DELETE retries and durable ambiguous-result journal.
- Independently sampled sustained recovery, versioned required health profiles, coverage/gap/generation checks, application incident episodes and explicit verified closure.
- Typed environment context, setup UI, agent enrollment/revocation UI, action approval UI, recovery UI.
- Immutable steward adjudications, independent causal corroboration, two-person golden publication with fixed baseline/held-out evaluation, synchronous historical lineage/revocation checks, scoped historical guidance in new diagnoses.
- Honest quality metrics and UI with attempt denominator, reviewed coverage, abstention/provider failures, contextual/factual distinctions and Wilson intervals.
- Durable notification deliveries, retry leases, acknowledgments, registered owner-group destinations, escalation and send-time permission recheck.
- Encrypted queued engineer authority, fair scoped diagnostic queue, cancellation and durable attempt ledger; three bounded hypothesis/challenge/reassessment rounds and typed fresh-collection requests.
- Separate enterprise chart, component Docker targets, secret-init helper, engineer CLI, verified database TLS requirement, readiness and bounded HTTP concurrency.

Verification and acceptance now live in [the release evidence](../../enterprise-release-evidence.md), with [deployment instructions](../../enterprise-deployment.md) and [measured capacity](../../enterprise-capacity.md). Repeated real PostgreSQL, full race, vet/build/chart, actual two-cluster/browser/PVC and image security checks have passed. Independent specification and quality review findings were fixed and re-reviewed. The offline paired comparison tool is implemented, independently reviewed and covered by focused race tests. Final combined race/vet/build/chart checks pass; release evidence lists the exact scope and limitations.

The program's original W0–W10 bullets are broad design contracts and illustrative expansions, not a claim that every example repair or transport is enabled. The delivered R1–R10 mapping and explicit supported limits are maintained in the release record. Enterprise traffic uses isolated HTTP/UI/CLI/agent endpoints; legacy gRPC/MCP surfaces are intentionally excluded from enterprise deployment. Only single-Pod replacement is executable; no broader write capability is inferred from the roadmap.

Known topology constraint: one control-plane replica; every restart creates a fresh authority epoch, invalidating old agent credentials, queued engineer authority and pending action authority. Historical golden guidance from old epochs stays ineligible until rebuilt from freshly reviewed evidence. Operator reenrollment and backup/restore procedures are documented.
