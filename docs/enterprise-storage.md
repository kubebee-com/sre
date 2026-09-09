# Enterprise storage contracts

The enterprise runtime uses the `enterprise_core` PostgreSQL schema for scoped
incident state. Existing `playbook_catalog` tables are legacy import sources;
their approvals are not executable enterprise authority. The file-backed runtime
remains a separately supported single-process mode. Enterprise database failures
must never select a local-file fallback.

Every repository transaction requires organization, cluster, and application
IDs. Platform-owned incidents use an explicitly registered platform application,
not an empty scope. Compound foreign keys prevent references across these
boundaries. Scope advisory locks serialize item disputes with subsequent action
submission decisions. This initially trades per-application write concurrency
for simple, reviewable ordering. Database statement/transaction timeouts bound
stalled operations. Row-level security is a possible additional deployment
control, not a replacement for scoped queries and compound references; repository
contracts must pass without relying on a superuser's RLS behavior.

Evidence and claim versions are immutable. Quarantine changes eligibility,
leaving the historical observation intact. Retrieval and authorization inspect
all ancestor versions synchronously. Asynchronous outbox delivery is useful for
notifications and cached projections, but is not the revocation barrier.

Legacy migration begins with `incident.PreviewLegacyImport`, a side-effect-free
report bound to a separately verified cluster. It records the original bytes'
SHA-256 and quarantines all imported records. Operator assertions, old approvals,
and apparent historic success never become executable permission. The report
contains counts and reason codes, not copied customer content.

Migration checksums and a version ledger protect upgrades from silent schema
changes or downgrade. Back up the database and local encrypted identity registries
under the customer's retention policy. Preserve referenced evidence when archiving
incidents: deleting an ancestor while retaining executable descendants is forbidden.
No automatic destructive retention policy is introduced by the core repository.

A restored database is not sufficient authority to resume agents or actions.
The enterprise activation flow must start locked, require a fresh external
installation authority generation, revoke old credentials and approvals, and
reconcile in-flight actions against current cluster observations. Reusing the
same external generation after a restore is unsupported. The core repository
alone does not implement that activation flow; fleet/executor integration must
pass the restore replay tests before production mutation is enabled.

Run `scripts/ci/enterprise-postgres.sh` for the real database contract suite.
It creates a uniquely named disposable container, binds an ephemeral loopback
port, generates test credentials without logging them, and cleans up only that
container. Unit tests explicitly skip database contracts when
`SRE_ENTERPRISE_TEST_DATABASE_URL` is absent; a skip is not a release-gate pass.
