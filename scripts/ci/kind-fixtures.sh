#!/usr/bin/env bash
set -Eeuo pipefail

KIND_FIXTURE_ROOT=${KIND_FIXTURE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../deploy/fixtures/kind" && pwd)}

kind_fixture_expectations_file() {
	printf '%s\n' "$KIND_FIXTURE_ROOT/expected-categories.txt"
}

kind_fixture_expectations() {
	awk -F'|' '
		NF >= 3 && $1 !~ /^[[:space:]]*#/ && $1 != "" { print $1 "|" $2 "|" $3 }
	' "$(kind_fixture_expectations_file)"
}

kind_fixture_ids() {
	kind_fixture_expectations | cut -d'|' -f1 | sort -u
}

kind_fixture_required_categories() {
	kind_fixture_expectations | awk -F'|' '$3 == "required" { print $2 }' | sort -u
}

kind_fixture_optional_expectations() {
	kind_fixture_expectations | awk -F'|' '$3 ~ /^optional:/ { print $1 "|" $2 "|" $3 }'
}

kind_fixture_files() {
	for file in namespace.yaml pods.yaml workloads.yaml networking.yaml policy.yaml storage.yaml security.yaml webhooks.yaml nodes.yaml; do
		printf '%s\n' "$KIND_FIXTURE_ROOT/$file"
	done
}

kind_fixture_render() {
	local source_file=$1 output_file=$2 token=$3
	sed "s/__KIND_FIXTURE_TOKEN__/${token}/g" "$source_file" >"$output_file"
}

kind_fixture_patch_status() {
	local kubeconfig=$1 resource=$2 name=$3 patch=$4
	shift 4
	local namespace_args=()
	if [[ $# -gt 0 && -n ${1:-} ]]; then
		namespace_args=(-n "$1")
	fi
	local status_patch
	status_patch=$(jq -cn --argjson status "$patch" '{status: $status}')
	kubectl --kubeconfig "$kubeconfig" "${namespace_args[@]}" patch "$resource" "$name" \
		--subresource=status --type=merge -p "$status_patch" >/dev/null
}

kind_fixture_apply_optional_status() {
	local kubeconfig=$1 artifact_file=$2 resource=$3 name=$4 patch=$5
	shift 5
	if ! kind_fixture_patch_status "$kubeconfig" "$resource" "$name" "$patch" "${1:-}"; then
		printf '%s/%s status patch unavailable\n' "$resource" "$name" >>"$artifact_file"
	fi
}

kind_fixture_patch_statuses() {
	local kubeconfig=$1 artifact_dir=$2
	local optional_statuses="$artifact_dir/optional-status-patches.txt"
	: >"$optional_statuses"

	kind_fixture_patch_status "$kubeconfig" pod pod-evicted \
		'{"phase":"Failed","reason":"Evicted","message":"synthetic fixture eviction due to memory pressure"}' sre-fixtures
	kind_fixture_patch_status "$kubeconfig" pod pod-high-restarts \
		'{"phase":"Failed","containerStatuses":[{"name":"high-restarts","ready":false,"restartCount":6,"state":{"terminated":{"exitCode":1,"reason":"Error","message":"synthetic high restart fixture"}}}]}' sre-fixtures
	kind_fixture_patch_status "$kubeconfig" replicaset replicaset-stuck \
		'{"replicas":1,"readyReplicas":0,"availableReplicas":0,"conditions":[{"type":"ReplicaFailure","status":"True","reason":"FailedCreate","message":"synthetic fixture ReplicaSet failure"}]}' sre-fixtures
	kind_fixture_patch_status "$kubeconfig" horizontalpodautoscaler hpa-invalid \
		'{"currentReplicas":0,"desiredReplicas":0,"conditions":[{"type":"ScalingActive","status":"False","reason":"FailedGetResourceMetric","message":"synthetic metrics fixture failure"},{"type":"ScalingLimited","status":"True","reason":"TooManyReplicas","message":"synthetic HPA cap fixture"}]}' sre-fixtures
	kind_fixture_patch_status "$kubeconfig" persistentvolume pv-failed \
		'{"phase":"Failed","reason":"FixtureFailed","message":"synthetic failed persistent volume"}'
	kind_fixture_patch_status "$kubeconfig" persistentvolume pv-released \
		'{"phase":"Released","reason":"FixtureReleased","message":"synthetic released persistent volume"}'
	kind_fixture_patch_status "$kubeconfig" node sre-fixture-node \
		'{"conditions":[{"type":"Ready","status":"False","reason":"FixtureNotReady","message":"synthetic fixture node is not ready"},{"type":"MemoryPressure","status":"True","reason":"FixtureMemoryPressure","message":"synthetic fixture memory pressure"},{"type":"NetworkUnavailable","status":"True","reason":"FixtureNetworkUnavailable","message":"synthetic fixture network unavailable"}]}'

	# Dynamic resources are optional. A failed patch is recorded so capability
	# output can distinguish an absent/forbidden API from a typed failure.
	kind_fixture_apply_optional_status "$kubeconfig" "$optional_statuses" gatewayclasses gatewayclass-unaccepted \
		'{"conditions":[{"type":"Accepted","status":"False","reason":"Unsupported","message":"fixture GatewayClass was not accepted"}]}'
	kind_fixture_apply_optional_status "$kubeconfig" "$optional_statuses" gateways gateway-invalid \
		'{"conditions":[{"type":"Accepted","status":"False","reason":"Invalid","message":"fixture Gateway was not accepted"},{"type":"Programmed","status":"False","reason":"NotProgrammed","message":"fixture Gateway was not programmed"}]}' sre-fixtures
	kind_fixture_apply_optional_status "$kubeconfig" "$optional_statuses" subscriptions olm-subscription-failed \
		'{"state":"UpgradeFailed","conditions":[{"type":"Ready","status":"False","reason":"Failed","message":"fixture subscription failed"}]}' sre-fixtures
	kind_fixture_apply_optional_status "$kubeconfig" "$optional_statuses" catalogsources olm-catalog-source-failed \
		'{"connectionState":{"lastObservedState":"TRANSIENT_FAILURE"},"conditions":[{"type":"Ready","status":"False","reason":"Failed","message":"fixture catalog source failed"}]}' sre-fixtures
	kind_fixture_apply_optional_status "$kubeconfig" "$optional_statuses" policyreports kyverno-policy-report-failed \
		'{"results":[{"result":"fail","message":"fixture policy failed"}]}' sre-fixtures

	kind_fixture_apply_optional_status "$kubeconfig" "$optional_statuses" clusterextensions olm-cluster-extension-failed \
		'{"phase":"Failed","message":"fixture extension failed"}'
	kind_fixture_apply_optional_status "$kubeconfig" "$optional_statuses" clustercatalogs olm-cluster-catalog-failed \
		'{"phase":"Failed","message":"fixture catalog failed"}'
	kind_fixture_apply_optional_status "$kubeconfig" "$optional_statuses" clusterserviceversions olm-csv-failed \
		'{"phase":"Failed","message":"fixture CSV failed"}' sre-fixtures
	kind_fixture_apply_optional_status "$kubeconfig" "$optional_statuses" installplans olm-install-plan-failed \
		'{"phase":"Failed","message":"fixture install plan failed"}' sre-fixtures
	kind_fixture_apply_optional_status "$kubeconfig" "$optional_statuses" operatorgroups olm-operator-group-failed \
		'{"conditions":[{"type":"Ready","status":"False","reason":"Failed","message":"fixture operator group failed"}]}' sre-fixtures

	# The remaining integration resources expose a paused or failed spec, which
	# is persisted on the main resource rather than the status subresource.
	kind_fixture_delete_terminating_pod "$kubeconfig"
}

kind_fixture_delete_terminating_pod() {
	kubectl --kubeconfig "$1" -n sre-fixtures delete pod pod-stuck-terminating --wait=false --grace-period=1 >/dev/null
}

kind_apply_fixture_bundle() {
	local kubeconfig=$1 token=$2 artifact_dir=$3
	if [[ -z ${kubeconfig:-} || -z ${token:-} || -z ${artifact_dir:-} ]]; then
		printf 'kind_apply_fixture_bundle requires kubeconfig, token, and artifact directory\n' >&2
		return 2
	fi
	mkdir -p "$artifact_dir"
	kubectl --kubeconfig "$kubeconfig" apply -f "$KIND_FIXTURE_ROOT/namespace.yaml" >"$artifact_dir/namespace-apply.txt"

	local file
	for file in $(kind_fixture_files); do
		if [[ "$file" == */namespace.yaml ]]; then
			continue
		fi
		kind_fixture_render "$file" /dev/stdout "$token" |
			kubectl --kubeconfig "$kubeconfig" apply -f - >>"$artifact_dir/typed-apply.txt"
	done
	kind_fixture_wait_for_crash_loop "$kubeconfig"

	kubectl --kubeconfig "$kubeconfig" apply -f "$KIND_FIXTURE_ROOT/dynamic-crds.yaml" >"$artifact_dir/dynamic-crd-apply.txt"
	kubectl --kubeconfig "$kubeconfig" wait --for=condition=Established --timeout=180s -f "$KIND_FIXTURE_ROOT/dynamic-crds.yaml" >"$artifact_dir/dynamic-crd-wait.txt"
	kubectl --kubeconfig "$kubeconfig" apply -f "$KIND_FIXTURE_ROOT/dynamic-resources.yaml" >"$artifact_dir/dynamic-resource-apply.txt"
	kind_fixture_patch_statuses "$kubeconfig" "$artifact_dir"
}

kind_fixture_wait_for_crash_loop() {
	local kubeconfig=$1
	local deadline=$((SECONDS + 120))
	local reason
	while ((SECONDS < deadline)); do
		reason=$(kubectl --kubeconfig "$kubeconfig" -n sre-fixtures get pod pod-crash-loop -o json 2>/dev/null |
			jq -r 'any(.status.containerStatuses[]?; .name == "crash-loop" and .restartCount > 0 and ((.state.terminated.exitCode // .lastState.terminated.exitCode // 0) != 0))' || true)
		if [[ "$reason" == true ]]; then
			return 0
		fi
		sleep 2
	done
	printf 'pod-crash-loop did not reach CrashLoopBackOff before the fixture scan\n' >&2
	return 1
}
