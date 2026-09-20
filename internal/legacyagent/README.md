# Standalone compatibility runtime

`cmd/sre-agent/managed.go` invokes the exported `LegacyMain` entrypoint for
standalone mode. `deploy/Dockerfile` builds that compatible HTTP/gRPC service;
managed deployments use the explicit orchestrator configuration instead.

The standalone service starts a cancellation-aware retention sweep every five
minutes and joins it before closing its stores. Inactive findings expire after
72 hours and terminal proposals after seven days; active work and audit records
are preserved. See `docs/retention-policy.md` for the per-store size/count budgets.
