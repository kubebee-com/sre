# Unified SRE Kind acceptance

This suite uses two disposable Kubernetes clusters and actual Kubernetes API operations. Run it on a dedicated Linux host with sufficient free resources. The expansion was developed without executing tests or building images on the development host; it is not yet verified by a cluster run.

## Coverage

| Scenario | Boundary exercised and assertions |
| --- | --- |
| Unified agent, external mode | Launch the real `sre-agent` binary with a scoped ServiceAccount kubeconfig in each cluster; enroll, collect crash-loop evidence and complete an HTTP-queued rule investigation. |
| Unified agent, in-cluster mode | Run the same binary in a Pod with projected ServiceAccount credentials; validate cluster UID, private bootstrap initialization, TLS trust, evidence and queued diagnosis. |
| Agent persistence | Stop and restart the external process using the same private state; remove the one-use bootstrap file and verify saved credentials and encrypted target mappings still work. |
| Orchestrator restart | Queue an investigation while the agent is stopped, reconstruct the handler, policy and fleet services with the shared authority key, and verify the original durable job completes after the agent resumes. |
| Interactive mode | Separate human credentials from agent credentials, issue a diagnosis through actual stdin, observe the completed job and verify EOF drains the process. Reject credential-file aliasing. |
| Read boundaries | Namespace-scoped collection credentials cannot list another namespace's Pods or delete Pods. |
| Approval and remediation | Create a proposal through HTTP, deliver its notification, acknowledge it without granting approval, reject unauthorized/forged/wrong-hash callbacks, then use a signed Slack callback for exact approval. The actual executor deletes only the committed Pod target. |
| Replays and audit | Replayed approve/reject callbacks do not change versions. Assert durable actor attribution, action transitions and one notification per committed transition. |
| Isolation | The same failing workload in the second cluster retains its Pod UID when the first cluster's action is applied; scoped users cannot read the other cluster. |
| Privacy | Raw namespace and workload-name canaries cannot appear in orchestrator evidence or browser content. |
| Independent recovery | An applied action does not itself prove recovery. Repair the synthetic workload independently and collect the required sustained samples before accepting recovery. |
| Browser | Real Chromium drives scoped navigation, queued diagnosis, clarification and stale-answer rejection, notification acknowledgement, feedback/quarantine, administrator-only setup and desktop/mobile rendering. |
| Persistent volume | Non-root private-state fixture checks 0700/0600 permissions across writable, read-only and restarted PVC mounts. |
| Notification regression | The runner also executes the PostgreSQL E2E tests for seven provider HTTPS payloads, backoff, exhaustion, replica leases, escalation, acknowledgement suppression and permission revocation. |

The suite deliberately keeps both forms of coverage: existing collection/executor runtime checks reach the real Kubernetes mutation boundary, while new unified process tests ensure collection and diagnosis run through the shipped entrypoint. Orchestrator handlers/services run in the test harness with PostgreSQL and fixture human identities. This does **not** validate a deployed HA orchestrator Helm release, a real OIDC provider, or real external IM/LLM accounts. The in-cluster agent Pod is an acceptance fixture rather than the release Helm deployment. Rule diagnosis is deterministic and makes no paid provider calls.

## Run later on a suitable host

Prerequisites: Linux; a local Linux Docker daemon reachable through its bridge gateway; Go matching `go.mod`; a C compiler for the race detector; Kind and kubectl; Node; Playwright with its Chromium binary and system dependencies already installed. The runner does not install prerequisites. A non-local Docker daemon is unsupported because agent Pods must reach a host TLS fixture.

```sh
export SRE_PLAYWRIGHT_MODULE=/absolute/path/to/node_modules/playwright
# Optional: use an explicitly installed browser executable.
export SRE_CHROMIUM_EXECUTABLE=/absolute/path/to/chromium
export SRE_ENTERPRISE_ARTIFACTS=/absolute/path/to/artifacts
make unified-kind-test
```

Omit `SRE_CHROMIUM_EXECUTABLE` to use Playwright's installed Chromium. `make kind-test`, `make enterprise-kind-test`, and `scripts/ci/enterprise-kind.sh` forward to the same comprehensive runner.

Invocation builds the real host agent binary and uniquely tagged Linux agent/workload images, creates two pinned Kind clusters, loads the images and provisions a disposable PostgreSQL container. Tests run serially between packages with the race detector and a 30-minute test timeout; the database-wrapper subprocess has a 35-minute upper bound. Browser startup is checked before image builds or cluster creation. Both clusters, the database, generated credentials, and uniquely tagged images are cleaned up afterward, including partial-creation failures. Existing clusters and kubeconfigs are not selected.

This is intentionally resource-intensive: two control-plane nodes, PostgreSQL, browser processes, Go compilation and application Pods run during acceptance. It should not be launched on a resource-constrained workstation. CI invokes the same target on its acceptance runner; simply editing these tests does not run it locally.

## Diagnostics

On failure, the runner saves node/Pod/Deployment health fields before teardown. Browser scenarios save desktop/mobile screenshots when they reach those checkpoints; the Go test output records failed assertions and synthetic fixture diagnostics. Screenshots and test output are scoped to the synthetic test environment. The runner does not dump Kubernetes Secrets, kubeconfigs or full Pod specifications.

Resource names and image tags use a unique run identifier. Cleanup failure prints the exact owned resource name for follow-up. Normal runs delete their test resources; there is no automatic reuse of a developer's cluster.

## Lightweight development checks

Without invoking the runner, inspect shell syntax with `bash -n`, Python syntax with `ast.parse`, JavaScript syntax with `node --check`, Go syntax/formatting with `gofmt`, and changes with `git diff --check`. These checks do not demonstrate that the suite compiles or passes. The first run on a suitable host remains necessary.
