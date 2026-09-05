# Kubernetes Analyzer Review

## Architecture And Coverage Summary

At commit `731a6c90749e8e62b9325e41712c39c0d72510c4`, `pkg/analyzer` supplies 30 native analyzers through `common.IAnalyzer`, whose single method accepts a by-value `common.Analyzer` and returns `[]common.Result`. The catalog contains 14 default core analyzers and 16 opt-in additional analyzers; activated integrations can add more at runtime. Results carry a kind, object name, failures, and optional parent, while each failure can carry Kubernetes documentation and `Sensitive` replacement pairs.

Resource access is split three ways: client-go typed clients for built-in resources, controller-runtime for Gateway API resources, and dynamic clients plus unstructured conversion for OLM resources. Typed top-level lists generally use `Analyzer.ListOptions()`, which propagates a label selector and an API-server `metadata.name` field selector. Gateway API analyzers reimplement those selectors. The classic OLM dynamic analyzers do not propagate either selector, and the namespaced Gateway and HTTPRoute lists do not apply `Analyzer.Namespace`.

Failures come from status/condition inspection, missing referenced resources, warning Events, container logs, and opinionated configuration checks. Most older analyzers collect objects in a `PreAnalysis` map, attach parent ownership where implemented, and update a global Prometheus gauge; some newer OLM analyzers return slices directly, while `ClusterCatalog` and `ClusterExtension` still collect `PreAnalysis` maps. Anonymization is opt-in downstream and replaces only strings explicitly listed in each failure. Coverage of those lists is inconsistent, especially for raw Events, conditions, and logs.

The package has fake-client unit and regression coverage for all registered implementations, selector propagation on typed lists, Gateway scheme concurrency, and one manual/local replacement-loop masking assertion; it does not call `Analysis.GetAIResults`. Both `go test ./pkg/analyzer` and `go test -race ./pkg/analyzer` pass; `go test -cover ./pkg/analyzer` reports 89.4% statement coverage. Coverage remains uneven: API error paths, dynamic selector behavior, namespace scoping for controller-runtime lists, composite security semantics, and several Kubernetes API edge cases are not exercised.

## Scope Findings

- **High - HTTPRoute attachment and backend validation use the wrong Kubernetes semantics:** `pkg/analyzer/httproute.go` compares a Gateway listener's namespace selector against HTTPRoute labels (and its helper accepts any matching key, regardless of value), although that selector targets Namespace labels. It emits a rejection for each disallowing listener even when another targeted listener may accept the route, ignores `sectionName`, and can panic when optional/defaulted `AllowedRoutes` or `AllowedRoutes.Namespaces.From` are absent. It also always resolves backends as same-namespace Services, ignoring backend `group`, `kind`, and `namespace`. This can both miss invalid attachments and report valid cross-namespace or non-Service backends as broken.
- **High - the Security analyzer misses privilege exposure in RBAC and containers:** `pkg/analyzer/security.go` resolves every RoleBinding reference as a namespaced Role, so RoleBindings to wildcard-bearing ClusterRoles are silently skipped; init and ephemeral containers are also absent from privileged-container checks. ClusterRoleBindings are never examined.
- **High - anonymization does not cover much of the text sent for AI analysis:** `pkg/analyzer/log.go` can send an arbitrary matching log line while marking only the pod name; `pkg/analyzer/pod.go`, `pkg/analyzer/service.go`, `pkg/analyzer/storage.go`, `pkg/analyzer/security.go`, and the classic OLM analyzers commonly attach empty or no `Sensitive` entries to raw messages and names. `pkg/analyzer/statefulset_test.go` verifies one correctly covered path, but no suite establishes a package-wide no-leak invariant.
- **Medium - resource selectors are not uniformly honored:** `pkg/analyzer/catalogsource.go`, `pkg/analyzer/clusterserviceversion.go`, `pkg/analyzer/instalplan.go`, `pkg/analyzer/operatorgroup.go`, and `pkg/analyzer/subscription.go` always list all namespaces with empty options. `pkg/analyzer/clustercatalog.go`, `pkg/analyzer/clusterextension.go`, and the cluster-scoped StorageClasses/PVs in `pkg/analyzer/storage.go` similarly ignore label/name selectors. `pkg/analyzer/gateway.go` and `pkg/analyzer/httproute.go` apply label/name selectors but omit the requested namespace. Selected analysis can therefore scan and report out-of-scope resources.
- **Medium - NetworkPolicy findings can invert the meaning of a policy:** `pkg/analyzer/netpol.go` labels an empty `podSelector.matchLabels` as "allows traffic to all pods," but that selector only chooses the protected pods and can be part of a default-deny policy. It also ignores `matchExpressions`, both when deciding that a selector is empty and when finding selected pods, creating false positives.
- **Medium - HPA resource checks do not match autoscaling requirements:** `pkg/analyzer/hpa.go` requires at least one container with both non-nil requests and limits, even though resource utilization depends on requests and limits are not required. It can reject valid requests-only workloads, accept multi-container targets where other containers lack requests, and calls any custom scalable target unsupported before adding a second misleading "does not exist" failure.
- **Medium - Service analysis can associate unrelated Events and has legacy endpoint assumptions:** `pkg/analyzer/service.go` lists Events by `involvedObject.name` only, using `a.Namespace` rather than each endpoint's namespace, without kind or UID constraints. It analyzes legacy Endpoints rather than EndpointSlices and applies service filters to Endpoints metadata, so same-name events and modern endpoint layouts can yield misleading results.
- **Medium - analyzer discovery can terminate the hosting process:** `pkg/analyzer/analyzer.go` calls `os.Exit(1)` when activated integration lookup fails. These functions are also used by server paths, so a configuration/provider error is process-fatal rather than returned to the caller; `pkg/analyzer/analyzer_test.go` does not cover integration error behavior.
- **Low - metrics can remain stale for composite analyzers:** `pkg/analyzer/storage.go` deletes gauge series under analyzer name `Storage` but writes `Storage/StorageClass`, `Storage/PersistentVolume`, and `Storage/PersistentVolumeClaim`; `pkg/analyzer/security.go` has the same mismatch for its sub-kinds. Old series therefore survive later clean scans. Several direct-return OLM analyzers do not maintain the gauge at all.
- **Low - test and source naming obscure intent:** `pkg/analyzer/instalplan.go` misspells `installplan`; `pkg/analyzer/events_test.go` tests a local duplicate rather than the production `util.FetchLatestEvent`; several HTTPRoute tests use `HTTRoute`/`Missining`; and `pkg/analyzer/test_utils.go` puts test-only pointer helpers in a non-test production file.

## File Records

### `pkg/analyzer/analyzer.go`
- **Role:** Defines the native analyzer catalog, filter discovery, merged analyzer lookup, and the package-wide `analyzer_errors` gauge.
- **Implementation:** Registers 14 core kinds (Pod through ConfigMap) and 16 additional kinds (HPA through OperatorGroup); returns copied maps and appends analyzers from activated integrations.
- **Dependencies:** `common.IAnalyzer`, the integration provider, `fatih/color`, and Prometheus `promauto`/`GaugeVec`.
- **Quality/Risk:** Native map copying is sound, but map-order filter output is nondeterministic and integration lookup errors print then call `os.Exit(1)`, which is unsafe for library/server callers.

### `pkg/analyzer/analyzer_test.go`
- **Role:** Verifies consistency and isolation of the analyzer registries and public discovery functions.
- **Implementation:** Checks every registered key is listed, core/additional keys do not overlap, entries are non-nil, merged maps contain both catalogs, and returned maps cannot mutate package globals.
- **Dependencies:** The package registries plus standard `sort` and `testing`; integration analyzer contents are deliberately ignored.
- **Quality/Risk:** Strong coverage of native catalog invariants, but no activated-integration, provider-error, ordering, or process-exit behavior is tested.

### `pkg/analyzer/catalogsource.go`
- **Role:** Reports unhealthy OLM v0 `CatalogSource` resources.
- **Implementation:** Dynamically lists `operators.coreos.com/v1alpha1/catalogsources` cluster-wide and emits one failure when `status.connectionState.lastObservedState` is nonempty and case-insensitively not `READY`, including the connection address.
- **Dependencies:** Kubernetes dynamic client, `unstructured.NestedString`, and `common.Result`/`Failure`.
- **Quality/Risk:** Missing state is treated as healthy; namespace, label, and resource-name selectors, metrics, docs, parent lookup, and sensitive masking are absent, and a nil `a.Client` would panic before the dynamic-client check.

### `pkg/analyzer/catalogsource_test.go`
- **Role:** Exercises healthy and unhealthy CatalogSource state extraction.
- **Implementation:** Uses a dynamic fake to assert `TRANSIENT_FAILURE` returns one namespaced result and that `READY` or absent status returns none.
- **Dependencies:** `dynamic/fake`, unstructured objects, a custom GVR-to-list-kind map, and string assertions.
- **Quality/Risk:** Covers the central state branch but not lowercase readiness, list errors, nil clients, selectors, missing address, masking, or metrics.

### `pkg/analyzer/clustercatalog.go`
- **Role:** Validates cluster-scoped OLM v1 `ClusterCatalog` objects.
- **Implementation:** Converts unstructured resources to `common.ClusterCatalog`; checks source image syntax, resolved image digest shape, `Serving=True`, and `Progressing` reason `Succeeded`, then adds optional owner information and metrics.
- **Dependencies:** Dynamic client for `olm.operatorframework.io/v1/clustercatalogs`, runtime conversion, regexes, `util.MaskString`, `util.GetParent`, and Prometheus metrics.
- **Quality/Risk:** Conversion and validation errors are silently skipped, label/name selectors are ignored, output is printed unconditionally, and an empty resolved ref can produce both "missing" and digest failures. Availability mode and polling fields are not validated despite test fixture names suggesting they are.

### `pkg/analyzer/clustercatalog_test.go`
- **Role:** Covers ClusterCatalog condition/image validation and owner resolution.
- **Implementation:** Supplies one healthy and three condition-failing unstructured catalogs, expects three results, and separately verifies a Deployment owner becomes `ParentObject`.
- **Dependencies:** Dynamic fake, typed fake client, unstructured resources, `testify/require`, and `common.ClusterCatalog` conversion.
- **Quality/Risk:** The fixtures named invalid availability/poll interval pass or fail because of `Progressing` conditions, so those names overstate coverage; exact failure text/count, digest cases, conversion errors, selectors, and sensitive masking are untested.

### `pkg/analyzer/clusterextension.go`
- **Role:** Validates cluster-scoped OLM v1 `ClusterExtension` resources.
- **Implementation:** Converts unstructured objects, accepts source type `Catalog` and catalog policy `CatalogProvided` or `SelfCertified`, flags unsuccessful Installed/Progressing conditions, attaches parents, and records metrics.
- **Dependencies:** Dynamic `olm.operatorframework.io/v1/clusterextensions`, runtime conversion, common OLM types, `util.GetParent`, `util.MaskString`, and the gauge.
- **Quality/Risk:** A `Catalog` source with a nil catalog block bypasses policy validation, selectors are ignored, conversion failures are silent, and unconditional printing exposes names/package data and pollutes command output.

### `pkg/analyzer/clusterextension_test.go`
- **Role:** Tests valid policies, invalid source/policy results, and parent lookup.
- **Implementation:** Builds two valid and two invalid unstructured extensions, expects two results, then verifies a Deployment owner on an invalid extension.
- **Dependencies:** Dynamic fake, typed fake client, unstructured fixtures, and `testify/require`.
- **Quality/Risk:** Does not assert exact failures or counts and omits nil catalog, malformed conversion, selector, list-error, metric, and anonymization cases.

### `pkg/analyzer/clusterserviceversion.go`
- **Role:** Reports non-succeeded OLM `ClusterServiceVersion` resources.
- **Implementation:** Lists `operators.coreos.com/v1alpha1/clusterserviceversions` in all namespaces; for nonempty phases other than `Succeeded`, it emits the first non-True condition's reason/message or a status-conditions hint.
- **Dependencies:** Dynamic client, unstructured nested access, shared `pickWorstCondition`, and common result types.
- **Quality/Risk:** Empty phase and a failing phase whose conditions are all True can yield no result; selectors, metrics, docs, parent lookup, and masking are absent. Portuguese comments reduce local consistency.

### `pkg/analyzer/clusterserviceversion_test.go`
- **Role:** Validates successful CSV suppression and failed-condition reporting.
- **Implementation:** Uses a dynamic fake with one `Succeeded` CSV and one `Failed` CSV, asserting the latter includes `ErrorResolving`/`missing dep` context.
- **Dependencies:** Unstructured fixtures, dynamic fake list kinds, runtime scheme, and string matching.
- **Quality/Risk:** Only one condition shape is covered; empty phases, condition ordering/status variants, missing conditions, API errors, selectors, and masking remain untested.

### `pkg/analyzer/concurrent_scheme_test.go`
- **Role:** Guards against concurrent Gateway API scheme mutation regressions.
- **Implementation:** Installs Gateway types once, shares a controller-runtime fake client, and runs Gateway, GatewayClass, and HTTPRoute analyzers 50 times each across goroutines.
- **Dependencies:** Global client-go scheme, Gateway API install, controller-runtime fake client, `sync.WaitGroup`, and `common.IAnalyzer`.
- **Quality/Risk:** Effective with `-race` for the historical concurrent-map-write path; it uses empty resources, so it does not exercise concurrent result construction, metrics, or populated-object reads.

### `pkg/analyzer/configmap.go`
- **Role:** Finds unused, empty, and oversized ConfigMaps.
- **Implementation:** Lists ConfigMaps with shared selectors and all Pods in scope; recognizes direct/projected volumes plus regular/init-container `env` and `envFrom`, exempts known sidecar labels and opt-out annotations, and flags payloads over 1 MiB.
- **Dependencies:** Typed CoreV1 ConfigMap/Pod clients, `common.Result`, and the analyzer metric.
- **Quality/Risk:** Sidecar and `skip-usage-check` paths `continue`, suppressing empty/size checks as well as usage checks. Usage is inferred only from existing Pods, payload sizing omits key/object overhead, and all failure names are left unmasked.

### `pkg/analyzer/configmap_initcontainer_test.go`
- **Role:** Regression-tests ConfigMap references that exist only in init containers.
- **Implementation:** Covers both init-container `envFrom` and `env.valueFrom.configMapKeyRef`, expecting no unused findings.
- **Dependencies:** Typed fake client, CoreV1 fixtures, and `testify/assert`.
- **Quality/Risk:** Focused and useful; it does not cover optional/missing references, multiple init containers, or empty/large ConfigMaps used by init containers.

### `pkg/analyzer/configmap_projected_test.go`
- **Role:** Regression-tests projected-volume ConfigMap usage.
- **Implementation:** Covers a standalone projection, the kubelet-style `kube-root-ca.crt` projection, and a control unused ConfigMap.
- **Dependencies:** Typed fake client, volume projection API types, and `testify/assert`.
- **Quality/Risk:** Good false-positive regression coverage, but no multi-source/multi-Pod deduplication, optional projection, or missing-name behavior is asserted.

### `pkg/analyzer/configmap_test.go`
- **Role:** Provides baseline and exemption coverage for ConfigMap analysis.
- **Implementation:** Tests unused, empty, >1 MiB, and `envFrom`-used objects, plus Grafana/Prometheus sidecar labels, the custom dynamic label, and the skip annotation.
- **Dependencies:** CoreV1 fake client and `testify/assert`.
- **Quality/Risk:** Counts results rather than individual failures, so combined failures are weakly specified; only two of four built-in sidecar labels are covered, and the tests encode complete suppression by the skip annotation without checking empty/oversized content.

### `pkg/analyzer/cronjob.go`
- **Role:** Detects suspended CronJobs, invalid schedules, and negative starting deadlines.
- **Implementation:** Lists BatchV1 CronJobs with shared selectors, parses standard five-field cron syntax, attaches API docs and namespace/name masking, and records findings through `PreAnalysis`.
- **Dependencies:** client-go BatchV1, `robfig/cron/v3`, Kubernetes API reference lookup, masking utility, and metrics.
- **Quality/Risk:** Suspension short-circuits schedule/deadline validation by design; results come from a map and are unordered, and ownership is not attached.

### `pkg/analyzer/cronjob_test.go`
- **Role:** Tests CronJob failure branches, selectors, and the schedule helper.
- **Implementation:** Covers suspended, invalid schedule, negative deadline, valid, combined-invalid, label-filtered, and multiple valid/invalid cron expressions.
- **Dependencies:** BatchV1 fake client, shared pointer helpers, sorting, and `testify/require`.
- **Quality/Risk:** Broad branch coverage; it does not test resource-name selection, API/list errors, sensitive replacement, docs, metrics, or behavior of invalid fields on suspended jobs.

### `pkg/analyzer/daemonset.go`
- **Role:** Reports under-ready DaemonSets and missing image-pull Secrets.
- **Implementation:** Compares `NumberReady` with `DesiredNumberScheduled`, resolves each `imagePullSecret`, adds Kubernetes docs for readiness, masks object identifiers, attaches parent ownership, and updates metrics.
- **Dependencies:** AppsV1/CoreV1 typed clients, `context.Background`, API reference helper, `util.GetParent`, and masking.
- **Quality/Risk:** Any Secret GET error is described as non-existent, and those GETs ignore the analyzer context, weakening cancellation and conflating authorization/transient failures with NotFound.

### `pkg/analyzer/daemonset_test.go`
- **Role:** Covers healthy readiness, insufficient readiness, and missing pull Secrets.
- **Implementation:** Uses typed fake clients and asserts result count/kind/name for the two failure scenarios.
- **Dependencies:** AppsV1/CoreV1 fixtures, client-go fake, and `magiconair/properties/assert`.
- **Quality/Risk:** Does not assert failure text/count, existing Secret behavior, combined failures, parent/masking/docs/metrics, selectors, or non-NotFound GET errors.

### `pkg/analyzer/deployment.go`
- **Role:** Reports replica mismatch and failed Deployment progression.
- **Implementation:** Lists Deployments with label/name options, compares desired with ready replicas, distinguishes transient status overshoot, and emits each `Progressing=False` condition with reason/message.
- **Dependencies:** AppsV1/CoreV1 condition constants, typed client, Kubernetes API references, masking, and metrics.
- **Quality/Risk:** Uses `context.Background` rather than `a.Context`, wording conflates ready/available/running replicas, does not attach parents, and unordered map output complicates deterministic consumers.

### `pkg/analyzer/deployment_test.go`
- **Role:** Tests replica mismatch, nil replicas, namespace/label filtering, and progression conditions.
- **Implementation:** Asserts unhealthy deployments are returned, nil `spec.replicas` is panic-safe, `ProgressDeadlineExceeded` text is preserved, and `Progressing=True` is ignored.
- **Dependencies:** AppsV1/CoreV1 fake client and `magiconair/properties/assert`.
- **Quality/Risk:** Good status regression coverage, but no status-overshoot assertion, multiple conditions, name selector here, context cancellation, API errors, metrics, docs, or masking tests.

### `pkg/analyzer/events_test.go`
- **Role:** Purports to test latest-Event selection for an exact event name.
- **Implementation:** Defines a separate local `FetchLatestEvent` in package `analyzer_test`, then tests exact event-name filtering and timestamp ordering only among events matching that exact name with a fake client; the older event is excluded by the name filter.
- **Dependencies:** CoreV1 fake client and standard time/errors packages; it does not call analyzer or util production code.
- **Quality/Risk:** This is disconnected coverage: production analyzers use `util.FetchLatestEvent`, whose selector matches `involvedObject.name`, not Event metadata name. The test can pass while production behavior regresses.

### `pkg/analyzer/gateway.go`
- **Role:** Validates GatewayClass existence and core Gateway readiness conditions.
- **Implementation:** Lists Gateway API v1 Gateways with controller-runtime label/name selectors, GETs the referenced GatewayClass, and reports non-True `Accepted` or `Programmed` conditions.
- **Dependencies:** Controller-runtime client, Gateway API v1 types, Kubernetes field selectors, `apierrors.IsNotFound`, masking, and metrics.
- **Quality/Risk:** The list omits `a.Namespace`, so namespace-scoped requests scan all Gateways. Non-NotFound class lookup errors are ignored, docs/parents are absent, and the class GET supplies a namespace for a cluster-scoped object.

### `pkg/analyzer/gateway_test.go`
- **Role:** Exercises Gateway health, missing class, conditions, selector filtering, and empty status safety.
- **Implementation:** Covers Accepted Unknown/False at different indices, Programmed False, both True, missing GatewayClass, no conditions, and three label-selector cases.
- **Dependencies:** Shared client-go scheme, Gateway/API-extension registration, controller-runtime fake client, and fixture builders.
- **Quality/Risk:** Strong condition regressions, but no requested namespace or resource-name test, no non-NotFound errors, and no assertions for sensitivity, metrics, or class lookup scoping.

### `pkg/analyzer/gatewayclass.go`
- **Role:** Reports GatewayClasses whose observed status is not accepted.
- **Implementation:** Lists cluster-scoped GatewayClasses with label/name selectors and examines only `status.conditions[0]`, reporting it when status is not True.
- **Dependencies:** Controller-runtime, Gateway API v1, metadata/field selectors, masking, and metrics.
- **Quality/Risk:** It does not select the `Accepted` condition by type; a different first condition can cause a false finding or hide a later rejected Accepted condition. Empty conditions are silently considered healthy.

### `pkg/analyzer/gatewayclass_test.go`
- **Role:** Tests a non-True first condition, empty conditions, and label filtering.
- **Implementation:** Uses a controller-runtime fake client with globally registered Gateway types and checks result counts.
- **Dependencies:** Gateway/API-extension schemes, fake client, and `testify/assert`.
- **Quality/Risk:** The invalid status literal `Uknown` and the label test's status `Ready` both merely exercise "not True"; no healthy True case, multi-condition ordering, exact message, name selector, masking, or metric behavior is covered.

### `pkg/analyzer/hpa.go`
- **Role:** Diagnoses HPA conditions, target existence/type, and target container resource configuration.
- **Implementation:** Handles Deployment, ReplicationController, ReplicaSet, and StatefulSet targets; reports False non-ScalingLimited conditions, True ScalingLimited except the expected TooFewReplicas-at-minimum case, missing targets, and targets lacking any container with both requests and limits.
- **Dependencies:** AutoscalingV2, AppsV1/CoreV1 clients, a local `PodInfo` adapter interface, API docs, ownership/masking utilities, and metrics.
- **Quality/Risk:** The resource rule is semantically inaccurate for HPA, custom scale-subresource targets are rejected, unsupported targets also receive a second missing-target error, and any GET error is treated as absence.

### `pkg/analyzer/hpa_test.go`
- **Role:** Provides the largest analyzer suite, spanning targets, selectors, resources, and HPA conditions.
- **Implementation:** Covers all four accepted target kinds, unsupported/missing targets, configured and unconfigured resources, namespace/label filters, AbleToScale/ScalingActive/ScalingLimited states, and the TooFewReplicas minimum exception versus reportable limits.
- **Dependencies:** AutoscalingV2, AppsV1/CoreV1 fake client, resource quantities, string matching, and `magiconair/properties/assert`.
- **Quality/Risk:** Broad branch coverage but mostly count/substr assertions; it codifies limits as required, omits mixed multi-container cases and custom targets, and does not test API errors, masking, parent lookup, docs, metrics, or resource-name selection.

### `pkg/analyzer/httproute.go`
- **Role:** Checks HTTPRoute parents, attachment permissions, backend existence, and backend ports.
- **Implementation:** Lists routes with controller-runtime label/name selectors; resolves parent Gateways, checks listener `AllowedRoutes`, assumes each backend is a same-namespace Service, and compares the required backend port with Service ports.
- **Dependencies:** Gateway API v1, CoreV1 Service, controller-runtime, field selectors, `apierrors`, label helpers, masking, and metrics.
- **Quality/Risk:** Namespace selectors are evaluated against route labels with key-only matching, disallowing listeners can each emit a rejection even when another targeted listener accepts, `sectionName` is ignored, absent/defaulted `AllowedRoutes` or `Namespaces.From` can panic, backend group/kind/namespace and ReferenceGrant are ignored, the top-level route namespace filter is omitted, non-NotFound GET errors are treated as success, and several Sensitive entries use stale/empty objects or leave namespace unmasked.

### `pkg/analyzer/httproute_test.go`
- **Role:** Covers missing parents/backends, namespace attachment modes, selector mismatch, and port mismatch.
- **Implementation:** Builds Gateway/HTTPRoute fixtures and asserts exact messages for five failures plus backend port handling.
- **Dependencies:** Gateway/API-extension schemes, CoreV1 Service, controller-runtime fake client, and local builders.
- **Quality/Risk:** Does not cover allowed selector success, actual Namespace labels, cross-namespace backends/ReferenceGrants, non-Service backends, parent kind/group/section, namespace/name selectors, masking, or API errors. Test names repeatedly misspell HTTPRoute.

### `pkg/analyzer/ingress.go`
- **Role:** Validates Ingress class, rule backend Services, and TLS Secrets.
- **Implementation:** Uses `spec.ingressClassName` or the legacy annotation, exempts GKE `gce`/`gce-internal`, resolves service-backed HTTP paths and nonempty TLS secret names, attaches parent ownership, docs, masking, and metrics.
- **Dependencies:** NetworkingV1/CoreV1 typed clients, API reference helper, `util.GetParent`, and mask utilities.
- **Quality/Risk:** It ignores `spec.defaultBackend`, treats all GET errors as non-existence, and checks only dependency existence rather than service ports/readiness; GKE exemptions are hard-coded policy.

### `pkg/analyzer/ingress_test.go`
- **Role:** Tests missing class/service/secret combinations, resource backends, selectors, empty TLS names, and GKE class exemptions.
- **Implementation:** Table-driven exact-message assertions cover service rule failures; separate tests cover label filtering and both field/annotation forms of built-in GKE classes.
- **Dependencies:** NetworkingV1/CoreV1 fake client and `testify/assert`/`require`.
- **Quality/Risk:** Good nil/resource-backend regressions, but no default backend, existing custom IngressClass, backend port, parent/masking/docs/metrics, name selector, or non-NotFound failure coverage; two pointer helpers at the end are unused here.

### `pkg/analyzer/installplan_test.go`
- **Role:** Tests OLM InstallPlan terminal-phase handling.
- **Implementation:** Supplies one Complete and one Failed plan and asserts the failed result includes its first condition's ExecutionError.
- **Dependencies:** Dynamic fake client, unstructured objects, custom list-kind registration, and string matching.
- **Quality/Risk:** Covers only the reason+message form; empty phase, no conditions, reason-only/message-only, condition ordering, selectors, API errors, masking, and metrics are untested.

### `pkg/analyzer/instalplan.go`
- **Role:** Reports incomplete OLM InstallPlans.
- **Implementation:** Lists `operators.coreos.com/v1alpha1/installplans` cluster-wide and, for nonempty phases other than `Complete`, formats reason/message from only the first status condition.
- **Dependencies:** Dynamic client, unstructured nested access, schema GVR, and common results.
- **Quality/Risk:** The filename is misspelled. Empty phases are ignored, selectors and namespace are ignored, only the first condition is considered, and metrics/docs/parents/masking are absent.

### `pkg/analyzer/job.go`
- **Role:** Reports suspended or genuinely failed Jobs.
- **Implementation:** Flags `spec.suspend`; flags `status.failed > 0` unless Complete or SuccessCriteriaMet is True, replacing generic text with the latest BackoffLimitExceeded Event message when available.
- **Dependencies:** BatchV1/CoreV1 conditions, typed client, `util.FetchLatestEvent`, docs/masking, and metrics.
- **Quality/Risk:** It keys failure on the failed-attempt counter rather than a Failed condition, event text has no Sensitive entries, results are unordered, and ownership is not attached.

### `pkg/analyzer/job_test.go`
- **Role:** Tests suspension/failure combinations, Events, selectors, and retry-success semantics.
- **Implementation:** Covers suspended, failed, valid, combined failures, BackoffLimitExceeded message substitution, label filtering, successful completion after retries, and a reportable Failed condition with failed count.
- **Dependencies:** BatchV1/CoreV1 fake client, sorting, shared pointer helper, and `testify/require`.
- **Quality/Risk:** Good retry regression coverage; no SuccessCriteriaMet case, Failed=True with zero count, multiple Events/timestamps, name selector, API errors, masking/docs/metrics, or ownership tests.

### `pkg/analyzer/log.go`
- **Role:** Scans recent container logs for error-like text.
- **Implementation:** Lists Pods, fetches the last 100 current log lines for every regular container, also fetches previous logs after restarts, and returns the first case-insensitive line matching `error|exception|fail`; log-fetch failures are optionally reported.
- **Dependencies:** CoreV1 Pod/log REST requests, regex/string processing, parent lookup, masking utility, and metrics.
- **Quality/Risk:** Reading every container is expensive and RBAC-sensitive; substring matching is noisy, raw log lines can contain secrets while only the pod name is masked, init/ephemeral containers are ignored, and per-container findings overwrite one pod-level gauge series.

### `pkg/analyzer/log_test.go`
- **Role:** Tests log result naming, label filtering, and previous-log retrieval.
- **Implementation:** Temporarily replaces the package regex to match fake-client `"fake logs"`, asserts one result per container, and inspects client actions to confirm current and previous log requests.
- **Dependencies:** CoreV1 fake client/testing actions, mutable package `errorPattern`, sorting, and `testify/require`.
- **Quality/Risk:** Useful request-level regression coverage, but it cannot validate real log REST failures/content, default regex false positives, tail limits, secret masking, init/ephemeral containers, or parent/metric behavior.

### `pkg/analyzer/mutating_webhook.go`
- **Role:** Checks service-backed MutatingWebhook receivers.
- **Implementation:** Lists cluster-scoped configurations, skips URL clients, resolves each Service, defers selectorless Services to Service analysis, lists selected Pods, and reports missing Services, no Pods, or Pods whose phase is not Running.
- **Dependencies:** AdmissionregistrationV1/CoreV1 typed clients, API docs, label formatting, ownership/masking, and metrics.
- **Quality/Risk:** All calls use `context.Background`, so cancellation is ignored; any Service GET error becomes NotFound, Running does not guarantee readiness, selectorless services are unchecked here, and configuration namespace values are usually empty because the resource is cluster-scoped.

### `pkg/analyzer/mutating_webhook_test.go`
- **Role:** Covers receiver service/pod branches and configuration label filtering.
- **Implementation:** Expects findings for an inactive Pod, a selector with no Pods, and a missing Service; confirms selectorless Service and URL-style nil Service paths are skipped, then tests label selection.
- **Dependencies:** AdmissionregistrationV1/CoreV1 fake client and `testify/require`.
- **Quality/Risk:** Solid branch count coverage, but exact text, Running/ready distinctions, URL receivers, API errors, contexts, name selector, masking/docs/parent/metrics, and duplicate webhook names are not tested.

### `pkg/analyzer/netpol.go`
- **Role:** Flags broad or apparently unused NetworkPolicies.
- **Implementation:** Lists policies with shared options; an empty MatchLabels map is reported as selecting all pods, otherwise `util.GetPodListByLabels` checks whether any Pod has those labels.
- **Dependencies:** NetworkingV1/CoreV1 typed clients, Kubernetes docs, pod-label utility, masking, and metrics.
- **Quality/Risk:** The message confuses pod selection with traffic allowance, MatchExpressions are ignored, and selecting all pods may be intentional default-deny behavior. Parent metadata is stored but never resolved into `ParentObject`.

### `pkg/analyzer/netpol_test.go`
- **Role:** Covers empty/nonmatching selectors, matching Pods, namespaces, and label filtering.
- **Implementation:** Uses fake NetworkPolicies and Pods to assert a nonmatching selector reports, a matching Pod clears it, namespace scope applies, and analyzer labels filter policies.
- **Dependencies:** NetworkingV1/CoreV1 fake client and `magiconair/properties/assert`.
- **Quality/Risk:** Encodes the questionable empty-selector failure, and omits MatchExpressions, ingress/egress semantics, deliberate default-deny, exact text, name selector, masking/docs/metrics, parent, and API-error cases.

### `pkg/analyzer/node.go`
- **Role:** Reports unhealthy Node conditions.
- **Implementation:** Requires Ready=True; reports True/Unknown pressure or network conditions and every unknown condition type except k3s `EtcdIsVoter`, then attaches parent data and a cluster-scoped metric.
- **Dependencies:** CoreV1 typed Node client, standard condition constants, parent/masking utilities, and metrics.
- **Quality/Risk:** Unknown custom conditions are reported even when benign or False, intentionally favoring false positives; failure text includes reason/message but only node name is marked sensitive.

### `pkg/analyzer/node_test.go`
- **Role:** Exhaustively exercises standard and unknown Node condition classifications.
- **Implementation:** Asserts 11 failures across Ready False/Unknown, pressure/network True/Unknown, and a custom condition; also covers healthy/empty conditions and label filtering.
- **Dependencies:** CoreV1 fake client, sorting, and `testify/require`.
- **Quality/Risk:** Strong condition table coverage, but the EtcdIsVoter exception, exact messages, resource-name selector, API errors, masking of messages, parent, docs, and metrics are not tested.

### `pkg/analyzer/operatorgroup.go`
- **Role:** Detects namespaces containing multiple OLM OperatorGroups.
- **Implementation:** Dynamically lists `operators.coreos.com/v1/operatorgroups` across all namespaces, counts by namespace, and returns one namespace-level result when the count exceeds one.
- **Dependencies:** Dynamic client, schema GVR, metadata namespace extraction, and common results.
- **Quality/Risk:** Namespace/label/name selectors are ignored, output order is map-dependent, and no metrics, docs, owners, or sensitive masking are supplied; nil `a.Client` panics.

### `pkg/analyzer/operatorgroup_test.go`
- **Role:** Tests duplicate OperatorGroup detection by namespace.
- **Implementation:** Creates two groups in `ns-a` and one in `ns-b`, asserting one `OperatorGroup` result named `ns-a`.
- **Dependencies:** Unstructured objects, dynamic fake client, and custom list-kind registration.
- **Quality/Risk:** Clear happy/failure split, but exact failure/count, empty namespace, selectors, API errors, nil clients, masking, and metric behavior are untested.

### `pkg/analyzer/pdb.go`
- **Role:** Reports PodDisruptionBudgets whose status says disruption is not allowed.
- **Implementation:** Looks only at the first condition; when it is `DisruptionAllowed=False`, emits one failure per selector MatchLabels entry using the condition reason and the min/max availability docs.
- **Dependencies:** PolicyV1 typed client, API docs, masking, parent lookup, and metrics.
- **Quality/Risk:** A blocked PDB with nil/empty MatchLabels emits nothing, MatchExpressions are ignored, later DisruptionAllowed conditions are ignored, and specifying both min/max overwrites the selected doc path.

### `pkg/analyzer/pdb_test.go`
- **Role:** Tests empty conditions, blocked status, selectors, and analyzer label filtering.
- **Implementation:** Confirms nil/empty condition lists are safe, a blocked PDB with two MatchLabels returns one result, an empty selector returns none, and labels restrict the top-level list.
- **Dependencies:** PolicyV1 fake client, `intstr`, and `testify/require`.
- **Quality/Risk:** The suite codifies the empty-selector blind spot and does not test condition ordering, MatchExpressions, exact failure count/text, name selector, parent, masking/docs/metrics, or API errors.

### `pkg/analyzer/pod.go`
- **Role:** Diagnoses Pod scheduling, eviction, container waiting/termination, and readiness failures.
- **Implementation:** Reports Unschedulable/SchedulingGated Pending conditions, Evicted status, selected waiting reasons, CrashLoop last termination, nonzero exits, FailedMount/FailedCreatePodSandBox events during creation, and Unhealthy events for unready Running containers; init and regular status arrays are both checked.
- **Dependencies:** CoreV1 typed client/status types, `util.FetchLatestEvent`, parent lookup, and metrics.
- **Quality/Risk:** Failure/event text has empty Sensitive lists, so names and arbitrary cluster messages are not anonymized; only the latest object Event is considered, CrashLoopBackOff without last termination/message can be silent, and readiness is inferred from phase plus one latest Event.

### `pkg/analyzer/pod_test.go`
- **Role:** Provides table-driven coverage of major Pod status and Event branches.
- **Implementation:** Covers namespace filtering, Unschedulable, SchedulingGated with/without message, eviction with/without message, readiness with/without Event, init ContainerCreating, CrashLoopBackOff, recognized/unrecognized waits, and nonzero terminations.
- **Dependencies:** CoreV1 fake client, sorting, and `testify/require`.
- **Quality/Risk:** Broad branch coverage, but assertions focus on counts/names rather than exact text; no label/name selector, multiple-event ordering, image-pull matrix, successful termination, masking, parent, metrics, or API-error tests.

### `pkg/analyzer/pvc.go`
- **Role:** Reports Pending PVCs whose latest Event says provisioning failed.
- **Implementation:** Lists PVCs with shared options, fetches the latest Event for each Pending claim, emits its message only for `ProvisioningFailed`, then attaches ownership and metrics.
- **Dependencies:** CoreV1 PVC/Event clients, `util.FetchLatestEvent`, parent lookup, and the gauge.
- **Quality/Risk:** Pending claims with absent/other Events and Lost claims are silent, raw provisioner messages are not marked sensitive, and a single latest unrelated Event can hide a relevant older provisioning failure.

### `pkg/analyzer/pvc_test.go`
- **Role:** Tests PVC phase/Event behavior, namespace filtering, timestamp selection, and labels.
- **Implementation:** Covers Pending claims with latest ProvisioningFailed events, Bound/Lost suppression, no Event, other reason, empty message, namespace scope, and label selection.
- **Dependencies:** CoreV1 fake client, timestamped Events, sorting, and `testify/require`.
- **Quality/Risk:** The fake Event fixtures do not set `InvolvedObject`, so they do not realistically verify API-server field filtering; exact messages, name selector, masking, parent, metrics, and list errors are omitted.

### `pkg/analyzer/resource_selector_test.go`
- **Role:** Verifies `ResourceName` is pushed to the API server as a metadata.name field selector.
- **Implementation:** Adds a fake list reactor that honors/captures fields, then checks selected, missing, and absent-name behavior through DeploymentAnalyzer.
- **Dependencies:** client-go fake reactors/tracker objects, AppsV1 fixtures, and `common.Analyzer.ListOptions` behavior.
- **Quality/Risk:** Strong contract test for typed analyzers using shared ListOptions, but it covers only Deployments and cannot detect dynamic analyzers or controller-runtime namespace/selectors that bypass that helper.

### `pkg/analyzer/rs.go`
- **Role:** Reports zero-replica ReplicaSets with FailedCreate conditions.
- **Implementation:** Lists ReplicaSets with shared options and emits messages for every `ReplicaFailure` condition whose reason is `FailedCreate`, then attaches parent ownership and metrics.
- **Dependencies:** AppsV1 typed client, parent lookup, common pre-analysis/results, and gauge.
- **Quality/Risk:** Nonzero current replicas suppress failure conditions even if desired replicas are unmet, condition messages are unmasked, and result order is nondeterministic.

### `pkg/analyzer/rs_test.go`
- **Role:** Tests ReplicaSet phase/condition filtering, namespace scope, multiplicity, and labels.
- **Implementation:** Covers FailedCreate versus other reasons, zero versus nonzero replicas, two qualifying conditions on one object, namespace filtering, and top-level label selection.
- **Dependencies:** AppsV1 fake client, sorting, and `testify/require`.
- **Quality/Risk:** Good narrow rule coverage, but no desired/ready replica semantics, empty messages, name selector, API errors, masking, parent, metrics, or exact failure text assertions.

### `pkg/analyzer/security.go`
- **Role:** Aggregates opinionated checks for ServiceAccounts, RoleBindings, and Pod security contexts.
- **Implementation:** Reports explicit default-ServiceAccount use, RoleBindings whose referenced namespaced Role has wildcard verbs/resources, privileged regular containers, or Pods lacking a pod-level security context; returns only the first Pod security failure and does not examine ClusterRoleBindings.
- **Dependencies:** CoreV1 and RbacV1 typed clients, shared selector options, pointer helper, common results, and sub-kind metric labels.
- **Quality/Risk:** RoleBinding references to ClusterRoles are skipped, Role/Pod lookup errors are swallowed, ClusterRoleBindings and init/ephemeral containers are unchecked, a pod-level context can coexist with unsafe container settings, and gauge cleanup uses the wrong analyzer label.

### `pkg/analyzer/security_test.go`
- **Role:** Covers the three composite Security result families.
- **Implementation:** Tests an explicit default account plus contextless Pod, a privileged regular container, and a RoleBinding to a namespaced Role with wildcard verbs.
- **Dependencies:** CoreV1/RbacV1 fake client, shared `boolPtr`, and `testify/assert`.
- **Quality/Risk:** `expectedErrors` is defined but never asserted; defaulted ServiceAccount handling, ClusterRole references, wildcard resources, safe controls, init/ephemeral containers, errors, selectors, masking, and stale metrics are untested.

### `pkg/analyzer/service.go`
- **Role:** Diagnoses Services through legacy Endpoints readiness and warning Events.
- **Implementation:** Lists Endpoints with shared selectors; skips leader-election records, resolves a matching Service to report each expected selector on empty subsets, reports not-ready addresses, and appends every non-Normal Event matching involved-object name.
- **Dependencies:** CoreV1 Endpoints/Service/Event clients, leader-election annotation constant, API docs, parent/masking helpers, color output, and metrics.
- **Quality/Risk:** Filters apply to Endpoints rather than Services, EndpointSlices are ignored, Event queries omit kind/UID and use `a.Namespace`, selectorless empty Services produce no failure, and mutable `apiDoc.Kind` can leave later Service docs labeled as Endpoints.

### `pkg/analyzer/service_test.go`
- **Role:** Tests empty/not-ready endpoints, warning Events, exclusions, nil TargetRefs, and labels.
- **Implementation:** Covers selector-backed empty Endpoints, not-ready Pod/bare-IP addresses, warning augmentation, leader-election skip, orphan Endpoints skip, and one/two-label filters.
- **Dependencies:** CoreV1 fake client, sorting, and `testify/require`.
- **Quality/Risk:** Good nil regression coverage, but no EndpointSlice or selectorless Service, cross-namespace/same-name Event, kind/UID filtering, Service-versus-Endpoints label mismatch, resource name, masking/docs/parent/metrics, or API-error tests.

### `pkg/analyzer/statefulset.go`
- **Role:** Validates StatefulSet governing Service, volume claim StorageClasses, and ordinal Pod availability.
- **Implementation:** Resolves `spec.serviceName`, checks each explicit template StorageClass, and when desired differs from available walks ordinal Pods until the first missing/non-Running object, optionally surfacing the StatefulSet's latest warning Event; adds parent and metric data.
- **Dependencies:** AppsV1/CoreV1/StorageV1 typed clients, API errors/docs, Event and parent utilities, masking, and metrics.
- **Quality/Risk:** Any Service/StorageClass GET error becomes "does not exist," only the first problematic/missing ordinal is considered, Running is used instead of readiness, and latest Event text is unmasked.

### `pkg/analyzer/statefulset_test.go`
- **Role:** Covers dependency, filtering, replica, Event, Pod state, and one anonymization path.
- **Implementation:** Tests missing Service/StorageClass, namespaces/labels, available/unavailable replicas, initialized Running then Pending ordinals, and verifies pod/namespace replacements remove raw values from a non-Running failure.
- **Dependencies:** AppsV1/CoreV1 fake client, resource quantities, `util.ReplaceIfMatch`, string assertions, and `magiconair/properties/assert`.
- **Quality/Risk:** The masking regression is valuable and unique in this package; tests often also trigger an empty service-name failure, and do not cover existing storage classes, first-pod warning Events in detail, readiness, name selector, transient GET errors, parent/docs/metrics, or all sensitive paths.

### `pkg/analyzer/storage.go`
- **Role:** Aggregates policy checks for StorageClasses, PersistentVolumes, and PVCs.
- **Implementation:** Flags `kubernetes.io/no-provisioner`, each member of multiple default classes, Released/Failed or sub-1Gi PVs, and the first of Pending/Lost/sub-1Gi/no-class PVC issues.
- **Dependencies:** StorageV1/CoreV1 typed clients, Kubernetes resource quantities, common results, and composite sub-kind metrics.
- **Quality/Risk:** Static/local no-provisioner use may be intentional, the 1Gi threshold is opinionated, cluster-scoped lists ignore selectors, names/messages are unmasked, and cleanup deletes `Storage` rather than the sub-kind metric labels it writes.

### `pkg/analyzer/storage_test.go`
- **Role:** Exercises every explicit Storage analyzer rule.
- **Implementation:** Table cases cover no-provisioner, multiple defaults, Released/Failed/small PVs, and Pending/Lost/small/no-class PVCs, comparing total failure counts.
- **Dependencies:** StorageV1/CoreV1 fake client, resource quantities, and standard testing.
- **Quality/Risk:** Comprehensive branch smoke coverage but no healthy controls in the table, combined precedence, bound pre-provisioned PVC, selectors/namespaces for cluster resources, exact text/kind, API errors, masking, or stale metrics.

### `pkg/analyzer/subscription.go`
- **Role:** Reports OLM Subscriptions that are not at the latest known version.
- **Implementation:** Dynamically lists `operators.coreos.com/v1alpha1/subscriptions` cluster-wide and flags empty, `UpgradePending`, or `UpgradeAvailable` state, appending the first non-True condition reason/message.
- **Dependencies:** Dynamic client, unstructured nested data, shared `pickWorstCondition`, and common result types.
- **Quality/Risk:** Other failing states are treated as healthy, selectors/namespace are ignored, and metrics/docs/parents/masking are absent; nil `a.Client` panics.

### `pkg/analyzer/subscription_test.go`
- **Role:** Tests latest-versus-upgrade-available Subscription handling.
- **Implementation:** Uses one `AtLatestKnown` and one `UpgradeAvailable` fixture, asserting only the latter returns and includes CatalogSourcesUnhealthy context.
- **Dependencies:** Dynamic fake client, unstructured objects, list-kind map, and string checks.
- **Quality/Risk:** Does not cover empty/UpgradePending/unknown states, condition variations/order, selectors, API errors, nil clients, masking, or metrics.

### `pkg/analyzer/test_utils.go`
- **Role:** Supplies `*bool` and `*int64` constructors used only by tests.
- **Implementation:** Returns addresses of function arguments via `boolPtr` and `int64Ptr`.
- **Dependencies:** None beyond Go's type system.
- **Quality/Risk:** Correct but misplaced in a non-`_test.go` file, adding test-only unexported code to production builds; a dedicated test helper file would better communicate ownership.

### `pkg/analyzer/validating_webhook.go`
- **Role:** Checks service-backed ValidatingWebhook receivers.
- **Implementation:** Mirrors the mutating analyzer: resolves Services, skips URL and selectorless services, finds selector-matched Pods, and reports missing Services, no Pods, or non-Running receiver Pods with docs, masks, parent data, and metrics.
- **Dependencies:** AdmissionregistrationV1/CoreV1 typed clients, `context.Background`, API docs, label/parent/masking utilities, and metrics.
- **Quality/Risk:** It ignores caller cancellation, treats all Service GET failures as absence, equates Running with active/ready, and leaves selectorless Services to another analyzer that may not model external endpoints correctly.

### `pkg/analyzer/validating_webhook_test.go`
- **Role:** Covers receiver failure/skip branches and label filtering for ValidatingWebhookConfiguration.
- **Implementation:** Expects findings for an inactive Pod, no selected Pods, and missing Service; confirms selectorless and nil-Service cases are skipped and checks one- and two-label selectors.
- **Dependencies:** AdmissionregistrationV1/CoreV1 fake client and `testify/require`.
- **Quality/Risk:** It asserts counts rather than exact failures and omits URL clients, ready versus Running behavior, contexts/errors, name selector, masking/docs/parent/metrics, and duplicate webhook naming.
