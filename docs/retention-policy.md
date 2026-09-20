# Bounded inactive operational history

Scope approved for the myk3s telemetry rollout: resolved findings for 72 hours from their first confirmed resolution and known terminal proposals for seven days. Each store limits disposable inactive payloads to 10,000 records and 128 MiB; these are per-store budgets, not a whole-PVC hard quota. Active findings, pending/approved/executing proposals, unknown future states, independent audit records, and scan ordering/coverage watermarks are protected and excluded from these budgets.

## Implemented

- Replaced the old hard 500-proposal truncation, which could discard active pending approvals. Terminal expiry now works for small stores too. Unknown statuses and zero/future completion timestamps fail closed.
- Added `resolved_at` to history. Repeated resolved observations do not reset the clock; reappearance clears it. Legacy resolved rows receive a new full 72-hour grace period rather than being immediately discarded based on an old `last_seen`.
- Persistent stores prune on load/list; history also prunes during accepted records/reports. Mutations happen under the store lock using the existing atomic write/fsync/rename path. Write failure does not discard in-memory state.
- Added `PruneRetention(now)` for explicit sweeps and `RunRetention(ctx, interval)` for an application-owned, cancellation-aware periodic loop. Canceling before a sweep prevents that sweep. Constructors do not start hidden goroutines. Callers still need to attach the periodic loop to their lifecycle to guarantee cleanup while completely idle.
- Regression tests protect 650 pending proposals, preserve audit records, verify persisted expiry, count limits, resolution/reappearance/legacy behavior, cancellation and failed persistence. The full Go suite passed with 1,409 passing test/subtest events and 56 skipped events across 54 passing packages.

## Deployment boundary

The current source has evolved beyond the deployed standalone binary. Its legacy file-store consumers live in `internal/legacyagent`; adding a TTL environment variable to the new orchestrator does not enable these stores in the old deployment. A compatibility-validated standalone build and lifecycle wiring are still required before claiming live SRE retention.

The running myk3s image remains pinned to `sha256:9f6bbb794a7fd4e0059911f7aa23030ef945a1b8eaf980bdee78b584a5427498`. Image labels report revision=unknown, Go build metadata does not include a VCS revision, and the available provenance identifies base images rather than the application commit. No replacement image was built or deployed by this change. The existing healthy service and its approval/audit data were not altered.

Protected active/audit/coverage data can still grow beyond an inactive budget. This implementation does not silently remove those records to make a filesystem quota appear satisfied. A separate operator-visible budget/alarm policy would be needed for that state.
