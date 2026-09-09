# Migrating to unified SRE

The primary binaries are `sre-orchestrator` and `sre-agent`. The primary deployment
chart is `deploy/helm/sre`. Use the same agent for ServiceAccount and kubeconfig
operation. All incident state and approval decisions belong to the orchestrator.

## Existing control-plane installation

Back up PostgreSQL before upgrading. Existing versioned migrations remain immutable;
new migrations add shared browser authentication, diagnostic attempt leases, and
human-input requests. Keep organization/cluster/application IDs and deployment
configuration stable. Supply a new shared `SRE_AUTHORITY_KEY` (32 random bytes,
base64-encoded) and a consistent `SRE_AUTHORITY_GENERATION` to every replica.

This upgrade changes the previous per-process authority-generation behavior.
Plan a coordinated cutover: stop old workers, cancel pending old jobs, upgrade,
re-enroll agents, and obtain fresh approvals for any new action. Do not replay
uncertain actions. Preserve execution journals for reconciliation.

`SRE_CONFIG`, `SRE_DATABASE_URL`, `SRE_PUBLIC_URL`, and `SRE_LISTEN` replace their
`SRE_ENTERPRISE_*` equivalents. Old environment names remain fallback aliases;
explicit new settings take precedence, including an explicitly empty value.

Move provider secrets to the agent's local environment/Secret. The orchestrator
stores approved metadata and scopes, while agents resolve provider credentials.
Configure the agent's allowed profile IDs with `--profiles` or chart `agent.profiles`.

Deploy the unified chart with reviewed values rather than applying its defaults
over the old chart. Resource names/selectors and agent PVC layout change. Preserve
old PVCs until identity/journal migration or authorized reconciliation is complete.

## Existing standalone installation

Export and retain scan/proposal history as historical records. Standalone approvals
are not imported as live execution authority. Enroll the cluster with the
orchestrator and establish current evidence and new approvals there.

The managed `sre-agent` does not start the old standalone UI/API or accept its shared
API token as a human identity. Use OIDC identity for interactive approval. Omit
`--interactive` for unattended agents; EOF leaves central requests pending.

## Compatibility and package layout

The active packages are `pkg/orchestrator` (UI/API), `pkg/orchestrator/runtime`
(startup), `pkg/agent` (managed runtime), `pkg/agent/collection`, and
`pkg/agent/executor`. Historical standalone server/CLI regression fixtures live in
`internal/legacyserver` and `internal/legacyagent`; product binaries do not import
them. Compatibility executables, where retained, use shared runtime packages.
Database schema names and historical migration checksums retain `enterprise_core`
to preserve existing data; this is not a second product. Historical standalone
documentation is retained only as migration reference.

## Verification

Run `go test -p 1 ./...`, `make build`, and `make unified-chart-test`. Run the
PostgreSQL integration suite against a disposable database to verify shared auth,
claim fencing, cancellation, duplicate responses and evidence validation. Live
provider and production identity-provider availability require your deployment's
credentials and configuration.
