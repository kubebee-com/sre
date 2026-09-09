# Guarded playbook operations

The playbook engine uses PostgreSQL for the catalog and the configured LLM
provider for structured digest, resolution, and learning tasks. Kubernetes
changes use the existing typed remediation executor and its approval workflow.

## Configuration

Configure the database URL through the process environment or a Kubernetes
Secret. Do not place a password-bearing URL in the persisted user profile.

```sh
export SRE_PLAYBOOK_ENABLED=true
# Supply SRE_DATABASE_URL through your secret manager.
export SRE_PLAYBOOK_LEARNING_MODE=AUTO_DRAFT
export SRE_PLAYBOOK_MIN_CONFIDENCE=0.7
export SRE_PLAYBOOK_MAX_SOURCE_BYTES=65536
export SRE_PLAYBOOK_MAX_STEP_COUNT=8
export SRE_PLAYBOOK_MAX_TOTAL_TEXT_BYTES=262144
export SRE_PLAYBOOK_ALLOWED_NAMESPACES=applications
export SRE_PLAYBOOK_ALLOWED_KINDS=Pod,Deployment
export SRE_PLAYBOOK_ALLOWED_ACTIONS=Manual,RestartPod,RolloutRestart
```

Without a database URL, playbooks are disabled by default. Explicit enablement
requires a database URL. A configured URL enables the catalog by default unless
`SRE_PLAYBOOK_ENABLED=false` is set. `AUTO_DRAFT`, `OBSERVE_ONLY`, and `DISABLED`
are the learning modes; mutating drafts always require explicit review.

Settings and status expose service availability, never the database URL.
Database credentials are excluded from persisted profiles and redacted at
logging, provider, storage, and HTTP boundaries. CLI help also omits the resolved
database URL.

At startup the service opens a pool of at most four PostgreSQL connections and
applies checksummed embedded migrations in the `playbook_catalog` schema. The
database account needs permission to create this schema and its tables/indexes.
Keep this database separate from application data and include it in backups.
A failed startup connection leaves the service unavailable until restart.

When enabled, automatic scans resolve only reviewed active playbooks. No match,
a database outage, or an unsupported structured provider produces no automatic
proposal; scanning and issue visibility continue. Disable playbooks explicitly
to retain the existing diagnosis-based automatic proposal workflow.

Defaults bound each source to 64 KiB, each playbook to eight steps, and task text
to 256 KiB. Configurable ceilings are 1 MiB, 32 steps, and 4 MiB respectively;
provider request/response limits can impose lower bounds. JSON/YAML imports get
field-aware redaction before checksumming, storage, and provider calls.
Dashboard policy changes apply to the running process and may only tighten the
startup policy. Persist intended defaults through environment/profile settings
for the next restart. Credentials are never editable through this API.

## Lifecycle and approvals

Sources are bounded Markdown, YAML, or JSON documents. Imported text is
untrusted data. A structured digest is normalized into an immutable playbook
version, evaluated against policy, and submitted for review. Approval activates
a specific version. Rejection and retirement update lifecycle metadata without
rewriting that version's canonical content.

```text
RECEIVED -> DIGESTED -> NORMALIZED -> REVIEW -> ACTIVE -> RETIRED
                                      |
                                      +-> REJECTED
```

Catalog approval and incident execution approval are separate decisions.
Resolving an active playbook produces a pending remediation proposal, with the
finding's target UID and resourceVersion. The executor rechecks the target
before mutation. The first runtime version requires an exact namespace, kind,
and name binding and exactly one executable step. Multi-action plans fail
closed because each proposal executes one typed action. Manual, uncertain, and
GitOps steps remain review-only. Text or commands from a runbook or model never become an
arbitrary shell execution path.

## Dashboard and API

Open the **Playbooks** dashboard tab after authenticating with the existing API
token. Paste a runbook, select its media type, and import it. Review the source
IDs, evidence, exact target, action, replica count (for scaling), and uncertainty
before activating a version. Activation does not approve incident execution;
use the existing Approvals tab for each resulting proposal.

All routes below require the normal bearer token. Example import JSON:

```json
{"content":"# Restart a crashing application pod\nInspect events and logs first.","media_type":"text/markdown","origin":"operator runbook"}
```

Save this request as `import.json`, then use:

```sh
curl --fail-with-body -H "Authorization: Bearer $SRE_API_TOKEN" \
  -H 'Content-Type: application/json' --data-binary @import.json \
  http://localhost:8080/api/v1/playbooks/import
curl --fail-with-body -H "Authorization: Bearer $SRE_API_TOKEN" \
  'http://localhost:8080/api/v1/playbooks?limit=100'
```

The configured port may differ. Replace `PLAYBOOK_ID` with the imported ID to
activate its reviewed version:

```sh
curl --fail-with-body -H "Authorization: Bearer $SRE_API_TOKEN" \
  -H 'Content-Type: application/json' --data '{"version":1}' \
  http://localhost:8080/api/v1/playbooks/PLAYBOOK_ID/approve
```

The same versioned route supports `reject` and `retire`. `GET
/api/v1/playbooks/status` reports catalog availability, task calls and tokens,
and outcomes. `GET /api/v1/playbooks/settings` returns the safe policy;
`PUT` accepts that complete object with tightened values. Invalid policy
changes fail without changing the service. Provider/model configuration is
shown read-only and requires a restart to change. Temporary provider failures
are retryable; rejected invalid model output remains visible for review.

## Verification and learning

A successful API write alone does not qualify for learning. Pod deletion must
observe disappearance or replacement of the old UID; scaling checks replicas;
cordon checks the node state; rollout checks the target's changed generation.
Manual and GitOps actions remain unverified for learning purposes.

Execution results retain their actual status if postcondition verification is
unavailable or fails. Such results cannot create learning candidates. Verified
outcomes can generate reviewable candidates with lineage and an idempotency
key. Callback concurrency and timeouts are bounded; learning callbacks cannot
block remediation workers or shutdown. Learning gets a 30-second provider task
budget inside a 60-second observer deadline. There is no durable retry queue for
a timed-out learning callback; a missed draft does not change execution status.
Terminal outcomes are audited separately even when learning is disabled. Both
audit and learning callbacks are best effort: saturation, shutdown, or a catalog
outage can omit a catalog callback. Durable proposal records remain the source
for manual reconciliation; automatic replay is not implemented.
Token totals are reported only when a provider supplies usage; otherwise the
dashboard shows usage as unavailable.

## Verification on development hosts

Use unit, repository-contract, fake-provider, and Kubernetes fake-client tests
first. Kind testing remains deferred on resource-constrained hosts.

```sh
GOMAXPROCS=2 go test -p 2 -count=1 -timeout=240s ./...
GOMAXPROCS=2 go test -p 2 -race -count=1 -timeout=300s ./...
GOMAXPROCS=2 go vet -p 2 ./...
```

The PostgreSQL integration test runs only with an explicit
`SRE_TEST_DATABASE_URL`. Use a disposable test database. Real-provider checks
must be explicitly enabled and use host-provided credentials through the
environment; unit test success is not evidence of live-provider availability.

For the opt-in structured smoke test, provide the host credential as
`LLM_API_KEY` and its authorized HTTPS endpoint as `LLM_BASE_URL`, then run:

```sh
SRE_TEST_LIVE_STRUCTURED=1 GOMAXPROCS=2 go test -p 2 ./pkg/triage \
  -run '^TestLiveStructuredPlaybookTask$' -count=1 -v
```

This test fixes the model to `gpt-5.5`, uses Responses JSON mode, sends only a
synthetic prompt, and logs token counts or a safe error classification. It does
not import a real runbook, access PostgreSQL, or mutate Kubernetes resources.

## Verification evidence (2026-09-08)

Full repository unit and race suites, `go vet`, documentation/manifests/image
metadata checks, shell and JavaScript syntax checks, and dashboard malicious
content rendering tests pass on the integrated branch.

The opt-in live `gpt-5.5` Responses smoke test passed against the configured
host gateway: 46 input tokens, 38 output tokens, 84 total. The gateway streams
Responses events and omits output from the completion envelope; the adapter now
uses completed output-item events only after receiving final completion. Tests
reject partial streams, failed/incomplete responses, duplicate completion, early
`[DONE]`, and output after completion.

Live PostgreSQL was not exercised because `SRE_TEST_DATABASE_URL` was unset.
Repository/migration mocks and in-memory transaction contracts were exercised.
Kind remains deferred under the agreed host resource constraint.
