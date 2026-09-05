# K8sGPT Comprehensive Repository Analysis

## Executive Assessment

This audit covers the official shallow clone of `github.com/k8sgpt-ai/k8sgpt` at commit `731a6c90749e8e62b9325e41712c39c0d72510c4` (2026-09-01). Every one of the 266 Git-tracked files has an individualized record in the appendices.

K8sGPT is a Go CLI and server that discovers Kubernetes problems, optionally sends sanitized failure text to one of many AI providers, caches explanations, and exposes the same capabilities through gRPC, optional grpc-gateway HTTP, and MCP. It has broad analyzer and provider coverage, useful fake-client tests, digest-pinned GitHub Actions, a small Helm chart, a non-root distroless runtime, and an attached release SBOM workflow.

The dominant risk is the network/server boundary. The default `serve` command binds unauthenticated gRPC on all interfaces; the chart exposes that service through a ClusterIP and grants a wildcard read-only ClusterRole. MCP is disabled by default, but when enabled the chart unconditionally selects MCP HTTP, whose tools can read full Secrets and pod logs and mutate persistent configuration. No authentication, TLS, request authorization, panic recovery, or reliable shutdown is implemented. The configuration service also contains directly reachable panic paths.

The second risk cluster is data handling. Provider selection can fail open to OpenAI for an unknown configured name; stateful AI clients are global mutable singletons; anonymization is opt-in and only covers explicitly attached mappings; JSON output serializes the exported unmasked mapping fields; and custom analyzers, logs, caches, and Prometheus configuration can forward cluster data without a uniform redaction policy. Several remote transports are plaintext or have optional certificate verification disabled.

The repository is testable in a dependency-complete environment: the normal Go suite, vet, module verification, and Helm lint/render checks passed. Total statement coverage is 57.7%, with strong analyzer coverage (89.4%) but weak server/CLI/cloud-cache coverage. A full race-enabled suite was attempted but could not complete because the environment hit its disk quota while linking large test binaries; this is an environment limitation, not a source-level test assertion failure.

## Review Identity And Method

| Item | Value |
|---|---|
| Upstream | `https://github.com/k8sgpt-ai/k8sgpt.git` |
| Clone | `git clone --depth 1 --single-branch` |
| Branch | `main` |
| Commit | `731a6c90749e8e62b9325e41712c39c0d72510c4` |
| Commit subject | `chore(deps): update golang docker tag to v1.27 (#1745)` |
| Tracked files | 266 |
| Review date | 2026-09-04 |

The scope is frozen to `git ls-files` at that commit. Text files were read directly. Images were inspected by format/dimensions and repository references. `go.sum` and other generated/lock artifacts were reviewed as reproducibility and supply-chain inputs. Each appendix uses one path-exact H3 and four fields: Role, Implementation, Dependencies, and Quality/Risk. The manifest comparison reports 266 expected and 266 unique reviewed paths, with no omissions, extras, or duplicates.

## Repository Inventory

| Scope | Files | Focus |
|---|---:|---|
| Project, CLI, delivery, assets | 97 | Root metadata/docs, GitHub workflows, Helm, container, images, Cobra commands |
| AI, analysis, cache, extensions | 61 | Provider backends, prompt/sanitization flow, cache implementations, custom client/contracts |
| Kubernetes analyzers | 68 | Native and OLM resource analyzers plus tests |
| Integrations, server, Kubernetes client, utilities | 40 | AWS/KEDA/Kyverno/Prometheus, API clients, gRPC/MCP, shared helpers |
| **Total** | **266** | **203 Go, 20 Markdown, 19 YAML/YML, 12 images, and other manifests/configuration** |

## Architecture And Data Flow

~~~text
Cobra CLI / gRPC / MCP
        |
        v
analysis.NewAnalysis
        |
        +--> kubernetes.NewClient
        |       +--> typed client-go
        |       +--> controller-runtime client (Gateway API)
        |       +--> dynamic client (OLM)
        |
        +--> analyzer.GetAnalyzerMap
        |       +--> core/additional analyzers
        |       +--> activated integrations
        |
        +--> Analysis.RunAnalysis / RunCustomAnalysis
        |       +--> common.Result and common.Failure
        |
        +--> optional GetAIResults
        |       +--> Failure.Sensitive masking
        |       +--> ai.PromptMap template
        |       +--> cache key/load
        |       +--> configured provider GetCompletion
        |       +--> cache store
        |       +--> replacement of masked tokens in explanation
        |
        +--> text/JSON output or protobuf/MCP response
~~~

The main execution path is:

- `cmd/root.go` composes authentication, analysis, cache, filters, integrations, dumping, generation, custom-analyzer, and serving commands.
- `cmd/analyze/analyze.go` resolves `--resource`/filter selection, creates `analysis.Analysis`, executes built-in/custom analyzers, optionally explains findings, and prints output.
- `pkg/analysis` owns run context, Kubernetes client, result slice, selected provider, cache, filters, namespace/selector/resource constraints, and concurrency.
- `pkg/analyzer/analyzer.go` registers native analyzers; active integrations append their analyzers after Viper-backed activation checks.
- `pkg/ai` exposes 19 provider backends through `ai.IAI`, with Bedrock adapters and interactive mode.
- `pkg/server` hosts configuration, analyzer, and free-form query gRPC services, optional grpc-gateway HTTP, health/metrics, and MCP transports.

Typed analyzers generally use `Analyzer.ListOptions()`. Dynamic OLM and controller-runtime paths have their own selector behavior. `GetAIResults` masks only analyzer-supplied mappings, selects kind-specific prompts where available, computes a provider/language/failure-text cache key, invokes a provider, stores base64-encoded output, and restores masked values in the explanation. Base64 is encoding, not encryption.

## Findings

Severity reflects impact and reachability in the reviewed source. Exposure still depends on how an operator binds or publishes the service and on the permissions granted to the ServiceAccount.

### Critical

1. **Unauthenticated cluster control/data plane.** `pkg/server/server.go:98-114` listens on `:<Port>`, registers config/analyze/query services, and installs only a request-logging interceptor. `Config.Key` and `Config.Token` are unused. The default CLI port is 8080, and the chart exposes it through a ClusterIP. When MCP HTTP is enabled, `pkg/server/mcp.go` starts a plaintext HTTP listener on all interfaces; `pkg/server/mcp_handlers.go` exposes full Secret objects, pod logs, events, resource reads, filter mutation, and configuration mutation. The chart Role grants get/list/watch on every API group/resource (`charts/k8sgpt/templates/role.yaml:9-16`). Require authenticated TLS, explicit authorization per operation, network policy, and least-privilege RBAC before publishing these listeners.

2. **Unauthenticated RPC-triggered process crashes.** The always-registered config service exposes `pkg/server/config/handler.go:13-16`, whose `Shutdown` method panics. `pkg/server/config/config.go:33-46` dereferences `ca.Connection` while processing custom analyzers without validating a missing connection. `pkg/server/server.go` adds no panic-recovery interceptor. A remote caller can therefore turn malformed requests into process-wide availability failures. Return structured `InvalidArgument`/`Unimplemented` errors, validate nested messages, and add recovery plus tests at the transport boundary.

### High

3. **Build secrets are available to same-repository PR builds.** `.github/workflows/build_container.yaml` logs into GHCR and passes a bot BuildKit secret while building PR-controlled Docker context. `.github/settings.yml` grants contributor push permission. A malicious or compromised same-repository change could exfiltrate credentials during its build. Restrict credentialed publishing to trusted push/release events and approval-gated environments; keep PR builds credential-free.

4. **KEDA deactivation can delete unrelated tenants' resources.** `pkg/integration/keda/keda.go` lists KEDA resources across all namespaces, ignores list/delete failures, deletes every returned ScaledObject, ScaledJob, TriggerAuthentication, and ClusterTriggerAuthentication without ownership checks, then uninstalls the release. Scope deletion by release labels/namespace, propagate failures, and make uninstall transactional or recoverable.

5. **AI provider selection can fail open and state is shared.** `pkg/ai/iai.go:105-112` returns a new OpenAI client for any unknown provider name. `analysis.NewAnalysis` accepts a configured provider name before invoking that factory, so a typo can route failure text to OpenAI rather than reject configuration. The same file stores stateful provider pointers in a package-global registry; `Configure` mutates credentials, model, endpoint, and SDK state across analyses. Construct per-analysis clients or synchronize immutable factories, and reject unknown providers.

6. **Sensitive data controls are inconsistent and JSON exposes mapping data.** `pkg/analysis/analysis.go:533-568` masks only analyzer-supplied mappings when `--anonymize` is selected; many analyzers attach empty mappings to raw Events/logs/conditions. `pkg/util/util.go:163-168` compiles an unescaped mapping as a regular expression, so malformed values can panic or replace incorrectly. `pkg/common/types.go:105-114` leaves `Sensitive.Unmasked` exported without JSON tags, and `pkg/analysis/output.go` marshals results directly. Add a single redaction contract, use literal replacement, omit unmasked fields from all serialized outputs, and test raw logs/events/custom results.

7. **Custom analyzer transport is plaintext, deadline-free, and leaked.** `pkg/custom/client.go` dials with gRPC insecure credentials, runs with `context.Background()`, exposes no close operation, and drops sensitive metadata. `analysis.RunCustomAnalysis` creates clients per run. Use authenticated TLS, caller contexts/deadlines, explicit connection ownership/close, nil-response handling, and sensitive-field propagation.

8. **Cloud cache setup can terminate the host process.** `pkg/cache/azuresa_based.go` and `pkg/cache/gcs_based.go` call `log.Fatal` for configuration/credential/client errors from an interface that otherwise returns errors. This prevents server/CLI recovery and cleanup. Return typed errors and let the caller decide process policy.

9. **Gateway API semantics can produce false findings or panic.** `pkg/analyzer/httproute.go` checks each listener independently even though any accepted targeted listener can attach, ignores `sectionName`, compares a Gateway namespace selector against HTTPRoute labels instead of Namespace labels, and dereferences optional/defaulted listener fields. It also ignores backend `group`, `kind`, and `namespace` while assuming same-namespace Service backends. Implement Gateway API attachment semantics and test mixed listeners, defaults, cross-namespace references, and backend kinds.

10. **Security analysis misses privilege paths.** `pkg/analyzer/security.go` only lists RoleBindings and fetches namespaced Roles; it never analyzes ClusterRoleBindings or RoleBinding references whose kind is ClusterRole. It also omits init/ephemeral containers. Add ClusterRole/ClusterRoleBinding and all container classes. The explicit default-service-account check should be treated as a nonstandard/fake-object robustness issue because normal Kubernetes admission persists `default` on fetched Pods.

### Medium

11. **Release and build metadata drift.** `.goreleaser.yaml` injects `-X main.Date` although `main.go` defines lowercase `date`; direct builds therefore retain `built at: unknown`. Workflows pass `GIT_HASH`, `RELEASE_VERSION`, and `BUILD_TIME`, while `container/Dockerfile` expects `COMMIT`, `VERSION`, and `DATE`. `Makefile` references a missing `add-copyright` target. Add a build smoke test that checks `k8sgpt version`, reconcile linker/build args, and remove or implement the missing target.

12. **Chart isolation and least privilege are weak.** `charts/k8sgpt/templates/service.yaml` selects only the application name, not the release instance, so multiple releases can route to one another. The Secret name is fixed, and the Role wildcard covers all resources including Secrets. The chart should include instance selectors/names, make credentials externally managed, and publish a per-analyzer RBAC matrix.

13. **MCP lifecycle and request handling are unsafe.** `pkg/server/mcp.go` starts HTTP during construction, reports asynchronous bind failures with fatal logging, and implements `Close` as a no-op. `pkg/server/mcp_handlers.go` buffers unbounded pod logs, accepts negative bounds, serializes full Secrets, and mutates Viper without synchronization. `pkg/server/analyze/analyze.go` does not propagate the MCP request context into the analysis object. Make startup explicit, own and close listeners, bound input/output, propagate cancellation, and serialize configuration writes.

14. **Remote cache safety and cache identity are incomplete.** Interplex uses insecure gRPC without deadlines; S3 supports `InsecureSkipVerify` and treats most `HeadBucket` failures as create requests; Azure/GCS/S3 operations use background contexts. AI cache keys omit model, endpoint, sampling, and prompt-template identity (`pkg/analysis/analysis.go:580-584`). Use secure transports, contexts, precise error classification, and semantic cache keys.

15. **Analyzer scope and semantics are inconsistent.** Dynamic OLM analyzers and some controller-runtime analyzers ignore namespace, label, or name selectors. NetworkPolicy treats an empty pod selector as “allows traffic to all pods” and ignores MatchExpressions; HPA requires limits even though utilization is based on requests and can add a misleading “does not exist” failure for unsupported targets; Service analysis uses legacy Endpoints, incomplete Event identity, and no EndpointSlice path. StorageClasses/PVs also list with empty options. Align checks with Kubernetes API semantics and centralize selector propagation.

16. **Operational failures are often process-fatal or silently ignored.** Integration providers call `os.Exit`/panic for discovery/deploy errors, Prometheus/Kyverno/KEDA ignore or collapse API errors, and multiple providers index empty response arrays. Replace fatal library behavior with typed errors, validate response cardinality, and preserve authorization/timeouts as distinct errors.

17. **Dump and output artifacts can disclose credentials/data.** `cmd/dump/dump.go` writes mode 0644 and retains the first four password characters; text/JSON output can include raw failure details. Write sensitive artifacts 0600, fully redact credentials, and offer explicit safe-output modes.

### Low

18. **Documentation and tests lag implementation.** Server/client READMEs describe stale constructors/flags and omit transport security/lifecycle limitations. Several command, cache, integration, server configuration, and cloud-provider paths have no direct tests. Smoke tests accept HTTP 404 or skip/log failures, fixed ports collide, and global test seams are not parallel-safe.

19. **Release governance does not enforce the documented gates.** `.github/settings.yml` requires DCO but not tests, lint, semantic validation, or container checks. The workflows use strong action digest pinning and release SBOM generation, but the branch policy and security/review documents overstate enforced controls. Reconcile the settings file, contributor docs, and security assessment.

20. **Repository hygiene is uneven.** Eight of eleven visual assets are unreferenced, several screenshots/animations show obsolete commands or old Kubernetes versions, `images/demo5.gif` is about 1.45 MB, and `pkg/analyzer/instalplan.go` is misspelled. Archive or remove stale assets and add accessible text transcripts for retained demonstrations.

## Subsystem Summary

### Project, CLI, delivery, and assets

The root and `cmd/**` surface is a conventional Cobra application with configuration migration, authentication/provider management, analyzer filters, cache/custom-analyzer/integration commands, dump/generate helpers, and a serve command. CLI behavior is generally straightforward but relies heavily on package globals and `os.Exit`, making commands difficult to compose or test as library calls. Release automation is more mature than local build consistency: action references are digest-pinned, the container is multi-stage/distroless/non-root, and releases attach an SPDX SBOM, but linker/build-argument drift and missing Make targets are directly observable.

The Helm chart is compact and renders successfully in default and MCP modes. Its broad ClusterRole, fixed Secret naming, missing instance selector, and MCP HTTP flag behavior need to be treated as production security properties rather than chart convenience details.

### AI, analysis, cache, and extensions

The AI package supports 19 backends with provider-specific request adapters and a shared `IAIConfig` contract. Test quality is strongest around Anthropic, Azure, Bedrock Converse/Mantle, LiteLLM, file cache, Interplex, and orchestration. Several providers and all cloud object caches lack direct request/error tests. The analysis layer has useful cache and prompt abstractions, but cache identity is incomplete and sensitive-data behavior depends on every analyzer attaching correct mappings.

Cache providers include XDG files, Azure Blob, GCS, S3-compatible storage, and Interplex. Base64 cache values are not encryption. The custom analyzer client is a separate insecure gRPC extension path and currently cannot carry sensitivity metadata.

### Kubernetes analyzers

Thirty native/additional analyzers cover core workloads, networking, storage, autoscaling, policy, Gateway API, logs/events, OLM, and security. Typed analyzers use fake client tests extensively and reach 89.4% statement coverage. The main quality issue is semantic divergence: dynamic/controller-runtime paths do not consistently honor selectors or namespace, composite security/policy checks are opinionated and incomplete, and raw event/log text often bypasses anonymization. Gateway API, NetworkPolicy, HPA, Service/Endpoint, and Security behavior deserve conformance-style tests against real API semantics.

### Integrations, server, Kubernetes client, and utilities

AWS/EKS, KEDA, Kyverno, and Prometheus integrations register analyzers and may install/discover external components. KEDA has destructive uninstall behavior; Prometheus needs Secret access for configuration; Kyverno activation uses a different API-group marker from the analyzed reports; and AWS discovery uses naming conventions and non-paginated calls.

The shared Kubernetes client builds typed, controller-runtime, dynamic, and REST clients from one config and installs Gateway types once to avoid a known concurrent scheme mutation. Server handlers provide broad capabilities but lack authentication, authorization, lifecycle ownership, and consistent cancellation. Utilities centralize masking, owner/event lookup, cache keys, headers, filesystem operations, and stdout capture; several use background contexts, global process state, nondeterministic map ordering, or potentially deadlocking output capture.

## Verification Evidence

The following commands were run against the frozen clone:

| Command | Result |
|---|---|
| `git rev-parse HEAD` / shallow check | Commit matched; `true` |
| `git ls-files` | 266 tracked paths |
| `go mod verify` | `all modules verified` |
| `go test ./... -count=1 -coverprofile=/tmp/k8sgpt-cover.out` | Passed for all packages |
| `go tool cover -func=/tmp/k8sgpt-cover.out | tail -1` | 57.7% statements |
| `go vet ./...` | Passed |
| `helm lint charts/k8sgpt` | Passed; icon recommendation only |
| `helm template k8sgpt charts/k8sgpt` | Passed (136 rendered lines) |
| Scoped `go test ./cmd/...` and package review suites | Passed |
| `go test -race ./...` | Could not complete: environment disk quota exhausted while linking test binaries; several packages then failed to create temporary files |
| Local `golangci-lint`, `govulncheck`, `gosec`, `staticcheck` | Not installed; no local result claimed |

The full race attempt must not be interpreted as a source regression: errors were linker “No space left on device”/“disk quota exceeded” and temporary test-file write failures. It should be rerun in an environment with sufficient quota before release.

## Prioritized Recommendations

1. **Before exposing any server:** add TLS/authentication/authorization, narrow RBAC, remove wildcard Secret access, bind intentionally, add network policy, and test unauthenticated/unauthorized requests.
2. **Before accepting network requests:** replace `Shutdown` panic and nil nested-message dereferences with structured validation; add gRPC recovery and request-size/time limits.
3. **Before production AI use:** reject unknown providers, instantiate isolated clients, make cache keys semantic, enforce literal redaction, omit unmasked mappings from JSON, and test raw logs/events/custom results.
4. **Before enabling integrations:** make KEDA deletion ownership-aware, preserve API/auth errors, add deadlines/TLS to custom/Interplex gRPC, and make cloud-cache configuration return errors.
5. **Before the next release:** fix linker/build args and Makefile drift, add binary/container version smoke tests, reconcile branch protection with documented gates, and rerun GoReleaser in a clean environment.
6. **Then improve correctness and maintainability:** add selector/namespace conformance tests, HTTPRoute/NetworkPolicy/HPA/Security tests, EndpointSlice support, MCP lifecycle tests, command error injection, and remove/archive stale media.

## Appendices

- [Scope and method](00-scope-and-method.md)
- [Project, CLI, delivery, and assets: 97 files](01-project-cli-delivery-assets.md)
- [AI, analysis, cache, and extensions: 61 files](02-ai-analysis-cache-extensions.md)
- [Kubernetes analyzers: 68 files](03-kubernetes-analyzers.md)
- [Integrations, server, Kubernetes, and utilities: 40 files](04-integrations-server-utilities.md)
- [Tracked-file manifest](tracked-files.txt)
- [Reviewed-file manifest](reviewed-files.txt)

The appendices are the one-by-one file summaries requested for this audit; this report is the cross-file synthesis and prioritized action list.

