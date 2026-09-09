# Bounded enterprise storage capacity measurement

This is a reproducible local storage measurement, **not a production SLO or evidence of fleet-scale readiness**. The run on 2026-09-08 passed all result and scope assertions. It used the enterprise branch with Go 1.26.6 and PostgreSQL 17, before release; rerun after changing the queries or schema.

## Reproduce

From the repository root, with Go and Docker available:

```sh
scripts/ci/enterprise-capacity.sh
```

The script creates a uniquely named disposable PostgreSQL container using the pinned digest in the script, chooses a random password and loopback port, and removes only that container on exit. It does not use an operator database or Kubernetes context. The test is skipped in ordinary test runs unless `SRE_ENTERPRISE_CAPACITY=1`; the script sets this variable and its disposable database URL. No external model or paid service is used.

## Fixture and method

- One organization, two cluster scopes, the same application identifier in both. One scope has 500 incidents and the other 501 so a scope leak cannot hide behind equal counts.
- 1,001 incidents, 1,001 completed investigation runs, 2,002 immutable items (one evidence and one dependent claim per incident), and 1,001 lineage edges.
- Two current collector records with a configured authority epoch. One evidence item in the second scope is quarantined. Quality reads must invalidate exactly one dependent run in that scope, operations must return the expected scoped counts, and evidence eligibility must reject that item while accepting the first scope's item.
- Records are synthetic storage fixtures, inserted through transaction methods except the collector rows. This does not measure authentication, enrollment, ingestion projection, adjudication payloads, deep/historical guidance lineage, notifications, model calls, or HTTP serialization.
- Each operation executes one warm-up transaction per scope followed by 20 measured transactions per scope, sequentially. Timings include transaction begin, scope lock, query/result validation, and commit. Each percentile uses 40 pooled samples across the two scopes; p50 and p95 use the nearest-rank definition. There is no concurrent load or artificial latency threshold.
- Quality reads return 500 or 501 runs with their lineage validity. Operations reads count the scope's records. Current-evidence reads retrieve one incident's evidence and run the separate eligibility check; freshness alone is not treated as eligibility.

## Observed results

Host: Linux 7.0.0-31-generic, linux/amd64, 16 reported logical CPUs, approximately 13 GiB RAM, shared development host. The client and disposable database ran on the same host. These are warm local results; host activity and database statistics affect them.

| Operation | Samples | p50 | p95 | Maximum |
| --- | ---: | ---: | ---: | ---: |
| Scoped quality runs and lineage validity | 40 | 295.658495 ms | 302.115608 ms | 311.872209 ms |
| Scoped operational counts | 40 | 1.596119 ms | 2.254435 ms | 2.360498 ms |
| Current evidence plus eligibility | 40 | 1.460890 ms | 1.846366 ms | 2.030749 ms |

Seeding took 5.064277344 seconds. The complete Go test passed in 17.686 seconds. The quality query is materially more expensive than the other reads at this fixture size; dashboards should avoid aggressive polling. This run does not establish its scaling curve or a safe fleet size.

## Deployment limits that remain separate from this measurement

The diagnostic snapshot currently accepts at most 64 eligible observations, with a 100-row current-evidence query cap. This fixture intentionally has one evidence item per incident and does **not** validate a large application snapshot, sustained ingestion, growing historical versions, concurrent dashboard traffic, or deep dependency graphs. Queue limits, collector registry limits, provider latency and a single control plane's restart behavior also require capacity planning independently.

Before increasing deployment scale, run a representative workload with actual incident sizes, retention history, review volumes and concurrency; measure tail latency, memory, pool contention, query plans and recovery after restart. Neither the 100,000-run quality result safety cap nor the fixture's 1,001 runs is a supported production capacity guarantee.
