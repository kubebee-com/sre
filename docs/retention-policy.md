# Bounded inactive operational history

Scope approved for the myk3s telemetry rollout: resolved findings for 72 hours from their first confirmed resolution and known terminal proposals for seven days. Each store limits disposable inactive payloads to 10,000 records and 128 MiB; these are per-store budgets, not a whole-PVC hard quota. Active findings, pending/approved/executing proposals, unknown future states, independent audit records, and scan ordering/coverage watermarks are protected and excluded from these budgets.

## Implemented

- Replaced the old hard 500-proposal truncation, which could discard active pending approvals. Terminal expiry now works for small stores too. Unknown statuses and zero/future completion timestamps fail closed.
- Added `resolved_at` to history. Repeated resolved observations do not reset the clock; reappearance clears it. Legacy resolved rows receive a new full 72-hour grace period rather than being immediately discarded based on an old `last_seen`.
- Persistent stores prune on load/list; history also prunes during accepted records/reports. Mutations happen under the store lock using the existing atomic write/fsync/rename path. Write failure does not discard in-memory state.
- Added `PruneRetention(now)` for explicit sweeps and cancellation-aware lifecycle methods. The standalone runtime now sweeps both file stores immediately and every five minutes, including while idle. Failed writes are reported and retried on the next interval. Shutdown cancels and joins the worker before closing stores.
- Regression tests protect 650 pending proposals, preserve audit records, verify persisted expiry, count limits, resolution/reappearance/legacy behavior, cancellation and failed persistence. The full Go suite passed with 1,409 passing test/subtest events and 56 skipped events across 54 passing packages.

## Deployment boundary

The actual entrypoint `cmd/sre-agent/managed.go` supports standalone mode through `legacyagent.LegacyMain()`. The former legacy-package README incorrectly said this entrypoint was unavailable. `deploy/Dockerfile` builds the compatible HTTP/gRPC service; no orchestrator migration is needed to deploy retention.

Release builds must set VERSION, REVISION, and BUILD_DATE and be pinned by their verified ARM64 digest in myk3s. The previous image (`sha256:9f6bbb794a7fd4e0059911f7aa23030ef945a1b8eaf980bdee78b584a5427498`) remains the image rollback reference. Source publication, image publication, and runtime activation are separately verified release steps.

The release gate exposed a startup race in remediation recovery: asynchronous startup listing could mistake a newly executing action for an interrupted pre-start action. Recovery now captures its snapshot before the constructor exposes the engine; dispatch remains asynchronous and is joined during shutdown. A barrier-controlled regression and repeated persistence-failure tests cover this ordering.

Protected active/audit/coverage data can still grow beyond an inactive budget. This implementation does not silently remove those records to make a filesystem quota appear satisfied. A separate operator-visible budget/alarm policy would be needed for that state.
