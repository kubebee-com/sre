# Integrations, Server, Kubernetes, and Utilities

## Subsystem Summary

This scope connects optional analyzers to Kubernetes and external services, constructs the shared Kubernetes clients used throughout analysis, exposes analysis/configuration/query operations over gRPC, grpc-gateway HTTP, MCP HTTP, and MCP stdio, and supplies common helpers for resource ancestry, events, labels, headers, masking, and filesystem operations. Integration activation is represented primarily by analyzer names persisted in Viper's `active_filters`; KEDA additionally installs/uninstalls Helm resources, while AWS creates an SDK session and Prometheus/Kyverno discover existing infrastructure. `kubernetes.NewClient` chooses in-cluster configuration unless a kubeconfig is explicitly requested or in-cluster loading fails, then builds typed, controller-runtime, and dynamic clients around the same `rest.Config`.

The always-on server surface is unauthenticated plaintext gRPC on all interfaces (port 8080 under the CLI/Helm defaults), plus a separate all-interface health/metrics listener on port 8081. The default chart exposes gRPC through a ClusterIP Service, so public reachability depends on the selected Service/ingress/network exposure. grpc-gateway is opt-in; its plaintext `localhost` dial is an internal connection back to the same listener rather than another external bind. MCP is disabled by CLI and Helm defaults: stdio mode is not a network surface, while MCP HTTP binds all interfaces only when MCP is enabled. In the chart's MCP-enabled path, the container always receives `--mcp-http` regardless of `deployment.mcp.http`, but external/public reachability still depends on Service exposure. Across enabled transports, capabilities include analysis and free-form AI queries, configuration persistence/cache setup, and, for MCP, Kubernetes resource reads (including Secrets), events, logs, filter mutation, prompts, and resources. Request handlers repeatedly construct clients and rely on process-global Viper/configuration state; several paths panic, exit, ignore errors, or fail to close resources.

## File Inventory

### `pkg/integration/aws/aws.go`
- **Role:** Implements the AWS integration lifecycle and registers the `EKS` analyzer.
- **Implementation:** `AddAnalyzer` selects the AWS SDK v1 credential chain based on `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_PROFILE`, stores a `*session.Session` on the globally registered `AWS`, and inserts `EKSAnalyzer`; activation is inferred from Viper `active_filters`, while deploy and namespace methods are no-ops.
- **Dependencies:** AWS SDK `session`/`aws.Config`, `common.IAnalyzer`, environment variables, and process-global Viper configuration.
- **Quality/Risk:** There are no direct tests. `session.Must` converts session creation failures into panics, and the mutable session field belongs to the package-global integration instance, so concurrent analyzer registration/undeploy is not synchronized. Credentials are not logged or copied into results, but normal AWS credential discovery is triggered.

### `pkg/integration/aws/eks.go`
- **Role:** Detects the current EKS cluster and reports EKS control-plane health issues.
- **Implementation:** `EKSAnalyzer.Analyze` loads the selected kubeconfig, requires the current context string to contain `eks`, calls `ListClusters`, matches cluster names by substring against that context, calls `DescribeCluster`, and emits one `common.Result` per health issue; `getKubeconfigPath` gives Viper's explicit path precedence over `$HOME/.kube/config`.
- **Dependencies:** AWS EKS SDK, the session injected by `AWS.AddAnalyzer`, client-go kubeconfig loading, Viper, and `common.Result`.
- **Quality/Risk:** Tests cover explicit and home-directory kubeconfig paths only. Discovery is not paginated, cluster identity relies on naming conventions/substrings, and AWS API failures abort all results. Health issue strings are externally reportable and are not marked sensitive.

### `pkg/integration/aws/eks_test.go`
- **Role:** Regression coverage for cross-platform EKS kubeconfig path resolution.
- **Implementation:** `TestGetKubeconfigPath` resets Viper around subtests, checks explicit configuration precedence, and asserts the fallback from `os.UserHomeDir` is absolute.
- **Dependencies:** Go testing, Viper, `filepath`, Testify assertions, and the host user-home lookup.
- **Quality/Risk:** It protects the Windows-relative-path regression but does not cover home lookup failure, invalid kubeconfigs, AWS calls, context matching, pagination, or health-result construction.

### `pkg/integration/integration.go`
- **Role:** Defines the integration contract and central registry for Prometheus, AWS, KEDA, and Kyverno.
- **Implementation:** The package-global `integrations` map contains singleton providers. `Activate` optionally deploys, appends analyzer names, deduplicates through `util.RemoveDuplicates`, writes `active_filters`, and persists Viper; `Deactivate` removes owned filters, undeploys, and persists; lookup and analyzer ownership are exposed through `List`, `Get`, and `AnalyzerByIntegration`.
- **Dependencies:** All four integration packages, `common.IAnalyzer`, Viper, and utility slice deduplication.
- **Quality/Risk:** Tests cover lookup and a skip-install Prometheus activation cycle. Registry/list ordering and deduplicated filter ordering are nondeterministic, all configuration is global and unsynchronized, and deployment can succeed before `WriteConfig` fails, leaving cluster/config state inconsistent. Deactivation mutates slices while iterating and can skip adjacent duplicate filters.

### `pkg/integration/integration_test.go`
- **Role:** Exercises integration lookup, analyzer ownership, activation status, persistence errors, and deactivation.
- **Implementation:** `TestAnalyzerByIntegration` checks invalid and Prometheus analyzer names; `TestActivate` first expects missing-config write failures, then points Viper at a JSON file and checks invalid-provider errors plus Prometheus activation/deactivation.
- **Dependencies:** Package-global integration registry and Viper state, temporary files, and Testify.
- **Quality/Risk:** Coverage omits actual deploy/undeploy implementations, concurrent access, filter ordering/duplicates, partial failure rollback, and AWS/KEDA/Kyverno activation. The temporary file returned by `os.CreateTemp` is neither closed nor used as Viper's generated pathname (`configFileName` is used instead), so the test setup leaks a descriptor and cleanup targets the wrong path.

### `pkg/integration/keda/keda.go`
- **Role:** Manages KEDA installation state through Helm, registers `ScaledObject`, and discovers KEDA deployment.
- **Implementation:** Environment-derived package variables describe the chart/release. `Deploy` adds a repo and installs/upgrades a non-waiting chart; `UnDeploy` lists and deletes ScaledObjects, ScaledJobs, TriggerAuthentications, and ClusterTriggerAuthentications across all namespaces before uninstalling; `GetNamespace` searches Helm releases; `IsActivate` combines active-filter and API-group discovery.
- **Dependencies:** go-helm-client, Helm repository types, KEDA typed clients, the shared Kubernetes client, Viper, gRPC status codes, environment variables, and console output.
- **Quality/Risk:** No tests cover this file. Repo setup panics, client/discovery failures call `os.Exit`, and most KEDA client creation/list/delete errors are ignored or only printed. Uninstall deletes every KEDA custom resource cluster-wide rather than resources owned by this release or the supplied namespace. `Version` is read but never placed in `ChartSpec`, so the advertised pin does not constrain installation.

### `pkg/integration/keda/scaledobject_analyzer.go`
- **Role:** Validates KEDA ScaledObjects against their scale targets, resource settings, and latest warning event.
- **Implementation:** It builds a KEDA typed client, lists namespace ScaledObjects, resolves Deployment/ReplicationController/ReplicaSet/StatefulSet targets through typed clients, checks CPU/memory-trigger targets for non-nil request and limit maps, reports missing/unsupported targets, appends non-Normal event messages, masks target names, and attaches owner ancestry.
- **Dependencies:** KEDA API/clientset, Kubernetes typed clients and OpenAPI documentation, `util.FetchLatestEvent`, `MaskString`, and `GetParent`.
- **Quality/Risk:** Regression tests cover missing targets, absent events, and warning events. `NewForConfig` errors are discarded, target GET errors such as forbidden/timeouts are collapsed into “does not exist,” and only nil resource maps are rejected (empty or incomplete CPU/memory requirements pass). Parent/event lookup failures are silently ignored.

### `pkg/integration/keda/scaledobject_analyzer_test.go`
- **Role:** Regression-tests ScaledObject findings when no Event exists and verifies warning-event reporting.
- **Implementation:** An `httptest.Server` serves KEDA list JSON while a fake core client supplies target Deployments and Events; three tests assert resource, missing-target, and warning-event results.
- **Dependencies:** KEDA schemas, client-go fake client, a synthetic REST endpoint, and Testify.
- **Quality/Risk:** The tests directly cover a previous early-continue loss of findings. They do not validate other target kinds, unsupported kinds, typed-client errors, namespace/list failures, partial resource maps, OpenAPI docs, masking, or parent discovery; the HTTP fixture accepts any request path or method.

### `pkg/integration/kyverno/analyzer.go`
- **Role:** Converts namespaced policy failures and cluster policy critical findings into analysis results.
- **Implementation:** Separate methods add policy-report types to the controller-runtime scheme, list reports, aggregate `Result == "fail"` or `Severity == "CRITICAL"` entries, construct `PolicyReport`/`ClusterPolicyReport` results, and attempt to attach parent objects. Boolean fields select one report mode per analyzer instance.
- **Dependencies:** Policy Reporter Kyverno CRDs, controller-runtime client, common analysis types, and `util.GetParent`.
- **Quality/Risk:** Tests cover namespaced/all-namespace PolicyReport filtering only. Scheme mutation occurs during each analysis and could race when analyzers share a scheme, cluster reports are untested, source policy messages/URLs are emitted without sensitivity metadata, and parent lookup errors are discarded.

### `pkg/integration/kyverno/analyzer_test.go`
- **Role:** Verifies namespaced and all-namespace PolicyReport selection.
- **Implementation:** `buildFakeClient` installs the CRD scheme and seeds two failing reports in different namespaces; tests run a policy-report analyzer and assert one or two results.
- **Dependencies:** Controller-runtime fake client, Policy Reporter CRDs, common analyzer configuration, and Testify.
- **Quality/Risk:** It does not assert failure text, owner attribution, non-failing policies, list/scheme errors, ClusterPolicyReport behavior, or concurrent scheme registration.

### `pkg/integration/kyverno/kyverno.go`
- **Role:** Registers Kyverno policy analyzers and reports activation/deployment state.
- **Implementation:** `AddAnalyzer` inserts mode-specific `KyvernoAnalyzer` values for `PolicyReport` and `ClusterPolicyReport`; filter membership comes from Viper, and deployment discovery scans API groups for `kyverno.io`; deploy, undeploy, and namespace operations are no-ops.
- **Dependencies:** Shared Kubernetes discovery client, Viper, common analyzer interfaces, and console output.
- **Quality/Risk:** There are no direct tests. Client/discovery failures terminate the process, activation performs live cluster I/O, and the deployment marker checks `kyverno.io` even though analyzed reports use the Policy Reporter API, so environments with reports but no Kyverno group can be reported inactive.

### `pkg/integration/prometheus/config_analyzer.go`
- **Role:** Discovers Prometheus pods/config volumes, loads ConfigMap or Secret configuration, parses plain/gzipped YAML, and reports invalid or empty scrape configuration.
- **Implementation:** Label searches plus a container-name fallback identify pods; config flags map paths to mounts and volumes; a per-call cache deduplicates volume sources; volume data is fetched and parsed through Prometheus config structs, with parent attribution on emitted results.
- **Dependencies:** Kubernetes typed APIs, Prometheus configuration types, YAML/gzip/HTTP content detection, and utility label/parent helpers.
- **Quality/Risk:** Tests only target invalid gzipped content through both analyzers. A `config-reloader` container causes `findPrometheusConfigPath` to return even when it found no flag, mount matching uses simple prefix comparison, one malformed pod aborts the full scan, the gzip reader is not closed, and Secret read permission is required even though raw secret bytes are not returned by this analyzer.

### `pkg/integration/prometheus/config_analyzer_test.go`
- **Role:** Prevents panics when a gzip-detected Prometheus payload decompresses to invalid YAML.
- **Implementation:** Helpers create gzip bytes and a fake Prometheus pod/ConfigMap; tests assert `unmarshalPromConfigBytes` returns a non-nil config with an error and drive both config and relabel analyzers end to end.
- **Dependencies:** gzip/HTTP detection, client-go fake client, Prometheus analyzers, and Testify.
- **Quality/Risk:** It covers the formerly panicking dereference and verifies the relabel analyzer remains empty. It does not cover valid YAML/gzip, Secrets, discovery variants, deduplication, config flags/mounts, missing keys, or malformed pod isolation.

### `pkg/integration/prometheus/prometheus.go`
- **Role:** Represents the discovery-only Prometheus integration and registers its validation/relabel analyzers.
- **Implementation:** `Deploy` builds a Kubernetes client and confirms at least one discoverable Prometheus config, while `UnDeploy` explicitly leaves cluster resources untouched. Analyzer ownership and activation are based on two constants and Viper `active_filters`.
- **Dependencies:** Kubernetes client construction, shared Prometheus discovery helpers, Viper, and colored terminal output.
- **Quality/Risk:** No direct tests exercise deployment. Kubernetes/discovery errors call `os.Exit` despite the method returning `error`, discovery uses an uncancellable background context, and activation records no namespace, but the implementation deliberately re-discovers resources during later analysis.

### `pkg/integration/prometheus/relabel_analyzer.go`
- **Role:** Produces bounded reports of Prometheus relabel and Kubernetes service-discovery configuration.
- **Implementation:** It reuses pod config discovery, ignores parse errors, inspects up to six non-empty scrape configs per pod, marshals relabel and Kubernetes SD structures into failure text, and attaches workload ancestry.
- **Dependencies:** Prometheus discovery types, YAML serialization, shared config discovery, common result types, and `util.GetParent`.
- **Quality/Risk:** Invalid-gzip non-panic behavior is tested, but valid reports are not. Parse and marshal errors are ignored; configuration fragments can expose internal job names, label-rewrite rules, API endpoints, and referenced credential file paths to downstream AI/output consumers. The “six” limit is per pod and does not constrain total output.

### `pkg/kubernetes/apireference.go`
- **Role:** Resolves a dotted Kubernetes field path to an OpenAPI v2 schema description.
- **Implementation:** `GetApiDocV2` searches definition names by the first API group segment, version, and kind, then `recursePath` follows object `$ref` or single-item array references until it returns a leaf/string description.
- **Dependencies:** Google gnostic OpenAPI v2 protobuf types and Kubernetes group/version metadata.
- **Quality/Risk:** Unit tests cover an empty field, one leaf, and an unresolved nested path. The resolver assumes `OpenapiSchema` is non-nil, matches definitions by suffix (potential ambiguity), treats any string node as terminal before consuming remaining path segments, and silently returns empty strings for malformed/unresolved schemas.

### `pkg/kubernetes/apireference_test.go`
- **Role:** Supplies a synthetic OpenAPI document for basic API documentation lookup tests.
- **Implementation:** `TestGetApiDocV2` builds two definitions and table-tests empty, nested-unresolved, and direct string-property lookups.
- **Dependencies:** Gnostic OpenAPI structs, runtime schema group/version, Testify, and Go testing.
- **Quality/Risk:** It does not exercise successful `$ref` recursion, arrays, nil documents/items, ambiguous suffixes, multi-segment API groups, missing kinds, or paths that continue beyond string leaves.

### `pkg/kubernetes/kubernetes.go`
- **Role:** Constructs and exposes the unified Kubernetes client bundle used by analyzers and servers.
- **Implementation:** `NewClient` prefers `rest.InClusterConfig`; when a kubeconfig is supplied or in-cluster loading fails, it uses deferred kubeconfig loading with a context override. It creates typed and controller-runtime clients, installs Gateway API types once per new scheme, probes `ServerVersion`, creates a dynamic client, and returns all artifacts.
- **Dependencies:** client-go typed/dynamic/rest/clientcmd packages, controller-runtime, Gateway API v1, and the OIDC auth plugin.
- **Quality/Risk:** Tests cover Gateway scheme installation and injected installation failure. Every call performs a live version request before returning, no caller context controls construction/probing, and high-traffic MCP handlers create a fresh bundle per request. The design correctly moved Gateway scheme mutation out of concurrent analyzer execution.

### `pkg/kubernetes/kubernetes_test.go`
- **Role:** Verifies Gateway API registration in new controller-runtime clients and error propagation from registration.
- **Implementation:** Both tests generate a kubeconfig targeting an HTTP test server that returns version JSON; one checks the Gateway GVK, and one temporarily replaces `installGatewayAPI` with a sentinel error.
- **Dependencies:** `httptest`, clientcmd config writing, Gateway API types, runtime schemes, and Testify.
- **Quality/Risk:** The mutable package-level function seam makes that second test unsafe if package tests run in parallel. Coverage omits in-cluster selection, context overrides, invalid config, typed/dynamic client failures, authentication plugins, and server-version errors.

### `pkg/kubernetes/types.go`
- **Role:** Defines the shared Kubernetes `Client` bundle and `K8sApiReference` input model.
- **Implementation:** `Client` exposes typed, controller-runtime, dynamic, REST config, and server version fields directly; `K8sApiReference` couples kind/group-version to an OpenAPI document.
- **Dependencies:** client-go, controller-runtime, Kubernetes schema/version, and gnostic OpenAPI v2.
- **Quality/Risk:** There is no encapsulation or lifecycle behavior; direct exported mutable fields make partially initialized clients easy to construct (as tests do), so callers and analyzers must tolerate nil members themselves.

### `pkg/server/README.md`
- **Role:** Briefly describes the MCP server and an intended initialization/start workflow.
- **Implementation:** It lists analysis and cluster-information capabilities and shows creating a Kubernetes client followed by `NewMCPServer(client)` and `Start`.
- **Dependencies:** Human-facing Markdown and conceptual MCP/Kubernetes APIs.
- **Quality/Risk:** The documentation is stale: MCP means Model Context Protocol, `tools.go` does not exist in this scope, and the constructor signature/example do not match the implementation. It also omits HTTP/stdio mode, binding, authentication/TLS limitations, and lifecycle behavior.

### `pkg/server/analyze/analyze.go`
- **Role:** Implements the gRPC analyzer service request pipeline.
- **Implementation:** `Analyze` mutates empty output and zero concurrency to defaults, builds an `analysis.Analysis` with docs/interactive/headers/stats disabled, replaces its context with the RPC context, runs custom and built-in analyzers, optionally obtains AI results, serializes output, and unmarshals JSON into the protobuf response; `Close` is deferred.
- **Dependencies:** Generated schema, analysis subsystem, JSON, and RPC context cancellation.
- **Quality/Risk:** There are no direct tests. `analysis.NewAnalysis` performs the effective concurrency normalization (non-positive values default and values above 100 are capped), but arbitrary output strings still reach output generation and the input protobuf is mutated. Analysis runner methods expose no returned errors, so only construction/AI/output failures are propagated.

### `pkg/server/analyze/handler.go`
- **Role:** Declares the gRPC analyzer handler type with forward-compatible unimplemented methods embedded.
- **Implementation:** `Handler` contains only `UnimplementedServerAnalyzerServiceServer`; behavior is supplied by `analyze.go`.
- **Dependencies:** Generated gRPC service bindings.
- **Quality/Risk:** No state is stored and there are no direct tests; safety and validation are entirely delegated to method implementations.

### `pkg/server/client_example/README.md`
- **Role:** Documents how to build and invoke the MCP HTTP client example.
- **Implementation:** It describes kubeconfig/namespace flags, a long-running client, and Mission Control integration.
- **Dependencies:** Markdown, Go tooling, and a configured Kubernetes environment.
- **Quality/Risk:** The instructions do not match `main.go`: there is no kubeconfig flag, the client performs one request and exits, and it also accepts port/backend/language. The output and protocol/security expectations are incomplete.

### `pkg/server/client_example/main.go`
- **Role:** Demonstrates raw JSON-RPC initialization and an `analyze` tool call against MCP HTTP.
- **Implementation:** It parses port/namespace/backend/language, builds an explain request, POSTs `initialize`, optionally propagates `Mcp-Session-Id`, invokes `tools/call`, reads the full response, prints raw JSON, parses the result envelope, and prints the first content item.
- **Dependencies:** Standard HTTP/JSON/flag/log packages and localhost MCP HTTP.
- **Quality/Risk:** There are no tests. HTTP status is never validated, initialization lacks the `Accept` header used for the subsequent call, bodies are unbounded, only the first result item is handled, and raw response printing may disclose cluster findings. It intentionally uses plaintext localhost HTTP.

### `pkg/server/config/config.go`
- **Role:** Implements gRPC/MCP-shared configuration changes for custom analyzers and remote caches.
- **Implementation:** `ApplyConfig` appends custom analyzers with new names to Viper and writes the config, then selects Azure/S3/GCS/Interplex cache providers from protobuf oneofs and installs the provider globally. `AddConfig` runs deprecated integration synchronization first; `RemoveConfig` removes the entire remote cache.
- **Dependencies:** Generated protobufs, global Viper config, custom analyzer models, cache provider factories/global cache state, and gRPC status.
- **Quality/Risk:** There are no tests in this package. `ApplyConfig` dereferences `ca.Connection.Url` and `.Port` without checking whether the protobuf connection is nil, so an unauthenticated gRPC `AddConfig` request can panic the process because the server has no recovery interceptor. Names, URLs, ports/endpoints/buckets are otherwise unchecked, updates are non-transactional, process-global Viper/cache mutation is unsynchronized, and the unused `ctx` cannot cancel the work.

### `pkg/server/config/handler.go`
- **Role:** Declares the config gRPC handler and its shutdown RPC.
- **Implementation:** `Handler` embeds generated unimplemented behavior, but explicitly implements `Shutdown` by panicking.
- **Dependencies:** Generated gRPC/protobuf service types and context.
- **Quality/Risk:** No tests cover it. The all-interface gRPC server always registers this service and has only a logging interceptor, not panic recovery, so an unauthenticated `Shutdown` RPC reaches `panic("implement me")` and terminates the process. It should return an `Unimplemented` status or invoke controlled lifecycle logic.

### `pkg/server/config/integration.go`
- **Role:** Retains deprecated server-side integration synchronization and listing behavior.
- **Implementation:** `syncIntegration` deactivates all locally active integrations only when the request's integration block is nil; the former Trivy logic is commented out. `ListIntegrations` returns an empty response, and `deactivateAllIntegrations` iterates providers, queries live activation/namespace, and deactivates only integrations with non-empty namespaces.
- **Dependencies:** Generated schema, central integration registry, gRPC statuses, context, and stdout logging.
- **Quality/Risk:** There are no tests. An omitted integrations block can trigger broad deactivation as a side effect of `AddConfig`, errors are collapsed to generic NotFound, activation checks may exit the process through provider implementations, and active no-install integrations with empty namespaces are skipped rather than clearing filters.

### `pkg/server/example/main.go`
- **Role:** Provides a runnable MCP server example with HTTP or stdio transport.
- **Implementation:** It parses port/HTTP flags, creates a production logger and an OpenAI provider from `OPENAI_API_KEY`, constructs the MCP server, invokes `Start` in a goroutine, waits for SIGINT/SIGTERM, and calls `Close`.
- **Dependencies:** Server and AI packages, zap, signals, flags, and environment configuration.
- **Quality/Risk:** There are no tests. HTTP mode was already started by `NewMCPServer`, while stdio is unnecessarily wrapped in a goroutine; `log.Fatalf` inside that goroutine exits without deferred cleanup, and the apparent graceful shutdown is ineffective because MCP `Close` is a no-op.

### `pkg/server/log.go`
- **Role:** Logs every unary gRPC request after handler completion.
- **Implementation:** `LogInterceptor` measures latency, records method, full request object, optional peer address and gRPC code, then routes through `logRequest`; the latter treats numeric codes `>=400` as errors.
- **Dependencies:** gRPC interceptors/peer/status and zap.
- **Quality/Risk:** There are no direct tests. `zap.Any("request", req)` can persist arbitrary AI query text, analyzer selectors/namespaces, custom-analyzer endpoints, cache configuration, and other user or cluster metadata. gRPC status codes are small enum values, so the HTTP-style `>=400` test never logs RPC failures at error level; error text is also logged verbatim.

### `pkg/server/mcp.go`
- **Role:** Builds the MCP server, declares tools/prompts/resources and request models, and handles analysis, cluster info, configuration, and resource reads.
- **Implementation:** `NewMCPServer` registers tools and, in HTTP mode, immediately launches a stateless `StreamableHTTPServer` on `:<port>`; stdio is started later by `Start`. Tools include analysis, cluster/config, resource/event/log/filter/integration operations. Analysis bounds concurrency to 1–100/default 10, config adapts JSON to protobuf, resources create fresh Kubernetes clients, and `Close` returns without stopping transports.
- **Dependencies:** mcp-go server/protocol, analysis, AI/config/Kubernetes packages, Viper, zap, JSON, regexp, and Kubernetes metadata.
- **Quality/Risk:** Server tests cover construction/basic HTTP loosely, but most handlers are untested. MCP is disabled by repository CLI/Helm defaults and stdio is non-network; when MCP HTTP is selected, it binds all interfaces without authentication or TLS, starts during construction, uses `logger.Fatal` on async failure, and cannot be shut down. `handleAnalyze` does not propagate the MCP context into the analysis object, `aiProvider` may be nil, prompt/resource registration occurs only in `Start` (which HTTP callers can omit), and enabled HTTP tools can mutate process-global configuration.

### `pkg/server/mcp_handlers.go`
- **Role:** Implements MCP tools for typed Kubernetes reads, events/logs, filter mutation, and integration status.
- **Implementation:** Static registries support common core/apps/batch/networking resources plus aliases; each request binds arguments, creates a new Kubernetes client, performs a typed list/get/log operation, and marshals the complete object. Limits default to 100 and cap only positive values above 1000. Filter handlers read/write Viper, and integration listing calls live `IsActivate` implementations.
- **Dependencies:** Kubernetes typed clients, analyzer/integration registries, Viper, mcp-go, JSON, and stream I/O.
- **Quality/Risk:** There are no direct tests. `secret` list/get returns full Secret objects including base64 data, and pod logs are consumed with unbounded `io.ReadAll`; these become unauthenticated network operations only when MCP HTTP is enabled (stdio remains local to the parent process, and public HTTP risk depends on Service exposure). Negative limits/tail counts are not rejected, filter names are not validated, concurrent Viper writes are not serialized, event filtering occurs after the API limit, and KEDA/Kyverno status checks can terminate the process.

### `pkg/server/mcp_prompts.go`
- **Role:** Generates three MCP troubleshooting prompt templates.
- **Implementation:** Pod and Deployment prompts interpolate optional request arguments into fixed tool-oriented workflows; the cluster prompt returns a fixed health-check workflow. Each returns one user-role text message.
- **Dependencies:** mcp-go prompt models, context signatures, and string formatting.
- **Quality/Risk:** There are no tests. Arguments are not required or validated and are interpolated verbatim, allowing prompt-injection content to be embedded in the instruction shown to an AI client; the handlers do not access Kubernetes directly.

### `pkg/server/query/handler.go`
- **Role:** Declares the free-form AI query gRPC handler type.
- **Implementation:** `Handler` only embeds `UnimplementedServerQueryServiceServer`; `query.go` supplies behavior.
- **Dependencies:** Generated gRPC query-service bindings.
- **Quality/Risk:** No local state exists; behavior and validation risks live in the query method.

### `pkg/server/query/query.go`
- **Role:** Implements the gRPC endpoint for sending arbitrary prompts to a configured AI backend.
- **Implementation:** `Query` obtains global factory/config-provider hooks, creates and defers closing a backend client, unmarshals configured providers, selects by exact name, configures the client (including stored provider credentials), calls `GetCompletion` with the RPC context, and places all failures inside the protobuf `QueryError` while returning a nil gRPC error.
- **Dependencies:** Generated schema and global AI factory/config-provider abstractions.
- **Quality/Risk:** Tests cover success and all explicit error branches. The client is created before confirming provider configuration, a factory returning nil would panic on defer, backend/query emptiness and prompt size are not validated, and transport-level monitoring always sees OK because application errors are encoded in the response.

### `pkg/server/query/query_test.go`
- **Role:** Unit-tests query success, configuration/provider/configure failures, and completion failures.
- **Implementation:** Testify mocks replace global AI factory and config-provider implementations, configure method expectations, call `Query`, assert protobuf response fields, and reset hooks with `defer`.
- **Dependencies:** Testify mock/assert, generated query protobufs, and mutable test hooks in the AI package.
- **Quality/Risk:** Branch coverage is strong for normal mock returns and confirms client closure expectations. Tests are not parallel-safe because they replace global hooks, and they omit nil factory/client behavior, cancellation, empty/large input, panic recovery, and credential/logging interactions.

### `pkg/server/server.go`
- **Role:** Hosts generated services over gRPC or an h2c gRPC/grpc-gateway multiplexer and separately serves health/Prometheus metrics.
- **Implementation:** `Serve` listens on `:<Port>`, creates handlers and a unary logging interceptor, enables reflection, registers config/analyze/query gRPC services, and optionally registers config/analyze HTTP gateways that dial the same plaintext listener. `Shutdown` closes only the listener; `ServeMetrics` exposes `/healthz` and `/metrics` on `:<MetricsPort>` with a header timeout.
- **Dependencies:** gRPC/reflection, grpc-gateway, h2c/http2, zap/controller-runtime logging, Prometheus HTTP metrics, TCP/HTTP, and generated services.
- **Quality/Risk:** One test verifies basic gRPC startup/reflection/shutdown. The primary listener is always all-interface plaintext gRPC (default `:8080`) with no authentication; `Key` and `Token` are unused, and the default chart's ClusterIP exposure is internal unless operators broaden it. grpc-gateway is opt-in and its insecure `localhost` dial is internal. Metrics/health separately bind all interfaces (default `:8081`), gateway setup failures call `log.Fatalln`, the main API has no HTTP timeouts, query has no gateway route, and shutdown does not gracefully stop gRPC/HTTP or metrics servers.

### `pkg/server/server_test.go`
- **Role:** Provides live-port smoke tests for gRPC and MCP HTTP construction/connectivity/tool calls.
- **Implementation:** `TestServe` starts a fixed-port gRPC server, checks reflection, closes the listener, and asserts `net.ErrClosed`; MCP tests use fixed ports, initialize JSON-RPC, list tools or invoke analysis, and call `Close`. `waitForPort` polls TCP readiness.
- **Dependencies:** Local TCP ports, gRPC reflection, HTTP, MCP/AI models, zap, and Testify.
- **Quality/Risk:** Tests pass but accept HTTP 404 as success, log-and-return on request failures, and may skip on startup timeout, so they do not establish usable MCP behavior. Fixed ports risk collisions, HTTP servers leak because `Close` is a no-op, one construction test starts port 8088 without cleanup, and tool-call output is not read/asserted.

### `pkg/util/util.go`
- **Role:** Supplies cross-package helpers for owner traversal, slices, masking, regex replacement, cache keys, pods/events, files/directories, labels/headers, stdout capture, and substring checks.
- **Implementation:** `GetParent` recursively dereferences selected owner kinds; `MaskString` uses crypto-random bytes mapped to a fixed alphabet and base64; Kubernetes helpers list pods and latest legacy Events; parsing helpers convert simple maps/headers/labels; `CaptureOutput` temporarily redirects global stdout through a pipe.
- **Dependencies:** Kubernetes typed APIs/labels, crypto and encoding packages, regex/HTTP/filesystem primitives, and the shared Kubernetes client.
- **Quality/Risk:** Tests cover most happy paths. `GetParent` uses uncancellable background contexts and has no cycle detection; `RemoveDuplicates`/`MapToString` return nondeterministic map order; `ReplaceIfMatch` can panic on an invalid unescaped pattern; label/header parsing silently drops malformed input. `CaptureOutput` is process-global, race-prone, leaks the read descriptor, and can deadlock when `f` writes more than the pipe buffer because reading starts only after `f` returns.

### `pkg/util/util_test.go`
- **Role:** Unit-tests utility behavior across fake Kubernetes objects and pure helpers.
- **Implementation:** Tests cover supported direct owners, dedup/diff, regex replacement, deterministic cache hashes, pod label listing, file/directory checks, map/label predicates, random masking properties, header parsing, simple label selectors, stdout capture, and substring matching.
- **Dependencies:** Client-go fake client, Kubernetes resource types, filesystem/stdout state, base64, labels, and Testify.
- **Quality/Risk:** Breadth is good but edge/concurrency coverage is limited: recursive/cyclic owners, event ordering/errors, invalid regex/selectors, deterministic ordering, large/panicking/concurrent stdout writes, file permission errors, empty masks, and malformed headers are absent. `TestEnsureDirExists` asserts an OS-specific error string, reducing portability.

## Scope Findings

- **Critical — default gRPC is unauthenticated; optional MCP HTTP adds privileged cluster reads:** `pkg/server/server.go` always binds plaintext gRPC on all interfaces and never uses `Config.Key` or `Config.Token` (default port 8080); the default chart exposes it through ClusterIP, so public risk depends on operator-selected Service/ingress/network exposure. grpc-gateway is opt-in and its `localhost` dial is internal. MCP is disabled by CLI/Helm defaults and stdio is not networked, but when MCP is enabled the chart always selects `--mcp-http` regardless of `deployment.mcp.http`; `pkg/server/mcp.go` then binds all interfaces, and `pkg/server/mcp_handlers.go` exposes full Secret list/get, pod logs, events, object reads, and filter mutation. `pkg/server/config/config.go` exposes gRPC configuration persistence in the default server.
- **Critical — unauthenticated gRPC requests can terminate the process:** `pkg/server/server.go` always registers `ServerConfigService` on the all-interface listener with only `LogInterceptor`, so no panic recovery protects handlers. `pkg/server/config/handler.go` implements `Shutdown` as an unconditional panic, and `pkg/server/config/config.go` dereferences each custom analyzer's optional protobuf `Connection` without a nil check. An unauthenticated caller can invoke `Shutdown` or submit `AddConfig` with a nil connection and crash the server.
- **High — enabled MCP HTTP lifecycle cannot be controlled:** `pkg/server/mcp.go` starts HTTP asynchronously inside `NewMCPServer`, reports bind failures through `logger.Fatal`, makes `Start` a no-op for HTTP, and implements `Close` as a no-op. This is not active under default CLI/Helm settings, but `pkg/server/example/main.go` advertises graceful shutdown that leaves an enabled listener running, while `pkg/server/server_test.go` leaks fixed-port HTTP servers for the test process.
- **High — KEDA deactivation is cluster-wide and ignores critical failures:** `pkg/integration/keda/keda.go` lists ScaledObjects, ScaledJobs, TriggerAuthentications, and ClusterTriggerAuthentications across every namespace, ignores all list errors, deletes every returned resource irrespective of release ownership/supplied namespace, prints delete failures, and then uninstalls the selected Helm release. A deactivation can silently delete unrelated tenants' KEDA configuration.
- **High — global configuration/cache state is concurrently mutable:** `pkg/server/mcp_handlers.go`, `pkg/server/mcp.go`, `pkg/server/config/config.go`, and `pkg/integration/integration.go` read, set, and write process-global Viper state from request-capable paths without locking or transactions; cache installation/removal is also global. Concurrent HTTP/gRPC requests can lose updates, race in memory, or persist a partial combination after one stage fails.
- **High — sensitive request and resource content can be disclosed:** `pkg/server/log.go` logs complete unary gRPC request objects, including arbitrary query text, analyzer selectors/namespaces, configuration endpoints, and raw error strings. When MCP HTTP is enabled, `pkg/server/mcp_handlers.go` serializes full Secret objects and reads unbounded pod logs; `pkg/integration/prometheus/relabel_analyzer.go` forwards internal relabel/service-discovery configuration as findings. These values can flow to logs, enabled MCP clients, or AI backends without field-level redaction.
- **Medium — fatal integration/setup paths reduce availability:** `pkg/server/server.go` uses `log.Fatalln` for opt-in gateway setup; `pkg/integration/keda/keda.go`, `pkg/integration/kyverno/kyverno.go`, and `pkg/integration/prometheus/prometheus.go` panic or call `os.Exit` on errors despite library-style method signatures. Enabled MCP integration status/configuration paths can reach some integration implementations, while other failures occur during local activation/deactivation.
- **Medium — request bounds and cancellation are inconsistent:** `pkg/server/mcp_handlers.go` does not reject negative list/log limits and buffers the complete log stream with `io.ReadAll`; `pkg/server/mcp.go` bounds MCP analysis concurrency but does not assign the MCP context to its analysis; and `pkg/util/util.go` owner/pod helpers use `context.Background`. Client disconnects may not stop work, and large results can consume substantial memory. gRPC analysis concurrency is normalized inside `analysis.NewAnalysis` and is not an unbounded-allocation finding.
- **Medium — integration discovery can be incomplete or misleading:** `pkg/integration/aws/eks.go` does not paginate EKS clusters and uses context-name substring matching; `pkg/integration/keda/scaledobject_analyzer.go` converts authorization/transient target GET failures into “does not exist”; `pkg/integration/prometheus/config_analyzer.go` aborts the entire scan on one malformed pod and prematurely returns an empty reloader path; `pkg/integration/kyverno/kyverno.go` uses a different API group as its deployment marker than the report resources being analyzed.
- **Low — server/example documentation and smoke tests overstate behavior:** `pkg/server/README.md` and `pkg/server/client_example/README.md` describe stale APIs/flags and omit transport security/lifecycle constraints. `pkg/server/server_test.go` treats 404 as acceptable MCP behavior, skips/logs several failures, does not assert tool results, and uses collision-prone fixed ports, leaving the highest-risk handler behavior without effective coverage.

## Verification

- Scoped inventory: 40 tracked files derived from `git ls-files` for `pkg/integration/**`, `pkg/kubernetes/**`, `pkg/server/**`, and `pkg/util/**`.
- Scoped tests: `go test ./pkg/integration/... ./pkg/kubernetes ./pkg/server/... ./pkg/util` passed; `pkg/server/analyze`, `pkg/server/client_example`, `pkg/server/config`, and `pkg/server/example` reported no test files.
