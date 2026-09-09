#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/../.." && pwd)
source "$ROOT_DIR/scripts/ci/kind-assertions.sh"
source "$ROOT_DIR/scripts/ci/kind-fixtures.sh"

if ! command -v kind >/dev/null 2>&1; then
	printf 'kind is not installed; skipping Kind acceptance\n'
	exit 0
fi

kind_assert_dependencies
for command_name in docker kubectl curl jq perl; do
	command -v "$command_name" >/dev/null 2>&1 || {
		printf '%s is required for Kind acceptance\n' "$command_name" >&2
		exit 1
	}
done

KIND_CLUSTER_NAME=${KIND_CLUSTER_NAME:-sre-agent-kind-$(date -u +%Y%m%d%H%M%S)-$RANDOM}
KIND_NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.35.0@sha256:4613778f3cfcd10e615029370f5786704559103cf27bef934597ba562b269661}
IMAGE_NAME=${KIND_IMAGE_NAME:-sre-agent:kind}
LOCAL_PORT=${KIND_LOCAL_PORT:-18080}
NAMESPACE=${SRE_KIND_NAMESPACE:-sre-fixtures}
TOKEN=${SRE_KIND_API_TOKEN:-kind-api-token-$(date -u +%Y%m%d%H%M%S)-$RANDOM}
FIXTURE_TOKEN=${SRE_KIND_FIXTURE_TOKEN:-kind-fixture-marker-$(date -u +%Y%m%d%H%M%S)-$RANDOM}
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sre-kind.XXXXXX")
OPERATOR_KUBECONFIG="$WORK_DIR/operator.kubeconfig"
PORT_FORWARD_PID=''
CLEANED_UP=0
CLUSTER_CREATED=0

first_variable() {
	local variable value
	for variable in "$@"; do
		value=${!variable:-}
		if [[ -n "$value" ]]; then
			printf '%s\n' "$value"
			return 0
		fi
	done
	return 1
}

HOST_CONFIG_FILE=''
for candidate in \
	"${CODEX_CONFIG_FILE:-}" \
	"${CODEX_HOME:-}/config.toml" \
	"${HOME:-}/.codex/config.toml" \
	"${XDG_CONFIG_HOME:-}/codex/config.toml"; do
	if [[ -n "$candidate" && -r "$candidate" ]]; then
		HOST_CONFIG_FILE=$candidate
		break
	fi
done

host_config_value() {
	local key=$1
	[[ -n "$HOST_CONFIG_FILE" ]] || return 0
	local provider
	provider=$(awk -F'=' '
		$1 ~ /^[[:space:]]*model_provider[[:space:]]*$/ {
			value = $2
			sub(/[[:space:]]*#.*/, "", value)
			sub(/^[[:space:]]*/, "", value)
			sub(/[[:space:]]*$/, "", value)
			if (value ~ /^".*"$/) { sub(/^"/, "", value); sub(/"$/, "", value) }
			if (value ~ /^'\''.*'\''$/) { sub(/^'\''/, "", value); sub(/'\''$/, "", value) }
			print value
			exit
		}
	' "$HOST_CONFIG_FILE")
	awk -F'=' -v key="$key" -v provider="$provider" '
		function trim(value) {
			sub(/^[[:space:]]*/, "", value)
			sub(/[[:space:]]*$/, "", value)
			return value
		}
		function unquote(value) {
			value = trim(value)
			if (value ~ /^".*"$/) { sub(/^"/, "", value); sub(/"$/, "", value) }
			if (value ~ /^'\''.*'\''$/) { sub(/^'\''/, "", value); sub(/'\''$/, "", value) }
			return value
		}
		$0 ~ /^\[model_providers\.[^]]+\][[:space:]]*$/ {
			section = $0
			sub(/^\[model_providers\./, "", section)
			sub(/\][[:space:]]*$/, "", section)
			active = (section == provider)
			next
		}
		/^\[/ { active = 0; next }
		active && trim($1) == key {
			value = $2
			sub(/[[:space:]]*#.*/, "", value)
			print unquote(value)
			exit
		}
	' "$HOST_CONFIG_FILE"
}

host_config_top_value() {
	local key=$1
	[[ -n "$HOST_CONFIG_FILE" ]] || return 0
	awk -F'=' -v key="$key" '
		$1 ~ "^[[:space:]]*" key "[[:space:]]*$" {
			value = $2
			sub(/[[:space:]]*#.*/, "", value)
			sub(/^[[:space:]]*/, "", value)
			sub(/[[:space:]]*$/, "", value)
			if (value ~ /^".*"$/) { sub(/^"/, "", value); sub(/"$/, "", value) }
			if (value ~ /^'\''.*'\''$/) { sub(/^'\''/, "", value); sub(/'\''$/, "", value) }
			print value
			exit
		}
	' "$HOST_CONFIG_FILE"
}

LLM_PROVIDER=$(first_variable SRE_KIND_LLM_PROVIDER || true)
LLM_PROVIDER=${LLM_PROVIDER:-codex}
case "$LLM_PROVIDER" in
codex|rule-based)
	;;
*)
	printf 'unsupported SRE_KIND_LLM_PROVIDER=%s; use codex or explicit rule-based\n' "$LLM_PROVIDER" >&2
	exit 1
	;;
esac

LLM_API_KEY=''
if [[ "$LLM_PROVIDER" == codex ]]; then
	CREDENTIAL_ENV_KEY=$(host_config_value env_key || true)
	credential_variables=(SRE_KIND_LLM_API_KEY)
	if [[ "$CREDENTIAL_ENV_KEY" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
		credential_variables+=("$CREDENTIAL_ENV_KEY")
	fi
	credential_variables+=(CODEX_LB_API_KEY SUB2API_API_KEY OPENAI_API_KEY)
	LLM_API_KEY=$(first_variable "${credential_variables[@]}" || true)
	if [[ -z "$LLM_API_KEY" ]]; then
		printf 'Codex acceptance needs SRE_KIND_LLM_API_KEY or CODEX_LB_API_KEY/SUB2API_API_KEY/OPENAI_API_KEY; use SRE_KIND_LLM_PROVIDER=rule-based for offline mode\n' >&2
		exit 1
	fi
fi

LLM_MODE=$(first_variable SRE_KIND_LLM_MODE || true)
if [[ -z "$LLM_MODE" ]]; then
	if [[ "$LLM_PROVIDER" == rule-based ]]; then
		LLM_MODE=rule
	else
		LLM_MODE=remote
	fi
fi

LLM_BASE_URL=$(first_variable SRE_KIND_LLM_BASE_URL CODEX_BASE_URL CODEX_API_BASE_URL CODEX_API_BASE CODEX_ENDPOINT OPENAI_BASE_URL OPENAI_API_BASE || true)
if [[ -z "$LLM_BASE_URL" ]]; then
	LLM_BASE_URL=$(host_config_value base_url || true)
fi
LLM_BASE_URL=${LLM_BASE_URL:-https://api.openai.com/v1}

LLM_MODEL=$(first_variable SRE_KIND_LLM_MODEL CODEX_MODEL CODEX_MODEL_NAME OPENAI_MODEL || true)
if [[ -z "$LLM_MODEL" ]]; then
	LLM_MODEL=$(host_config_top_value model || true)
fi
LLM_MODEL=${LLM_MODEL:-gpt-4o}

LLM_WIRE_API=$(first_variable SRE_KIND_LLM_WIRE_API CODEX_WIRE_API OPENAI_WIRE_API || true)
if [[ -z "$LLM_WIRE_API" ]]; then
	LLM_WIRE_API=$(host_config_value wire_api || true)
fi
LLM_WIRE_API=${LLM_WIRE_API:-responses}

collect_failure_artifacts() {
	local artifact_dir="$WORK_DIR/failure-artifacts"
	local pod
	mkdir -p "$artifact_dir"
	if [[ ! -s "$OPERATOR_KUBECONFIG" ]]; then
		return 0
	fi
	kubectl --kubeconfig "$OPERATOR_KUBECONFIG" -n "$NAMESPACE" get pods -o wide >"$artifact_dir/pods-wide.txt" 2>&1 || true
	kubectl --kubeconfig "$OPERATOR_KUBECONFIG" -n sre get pods -l app.kubernetes.io/name=sre-agent -o yaml >"$artifact_dir/agent-pods.yaml" 2>&1 || true
	for pod in $(kubectl --kubeconfig "$OPERATOR_KUBECONFIG" -n sre get pods -l app.kubernetes.io/name=sre-agent -o name 2>/dev/null); do
		kubectl --kubeconfig "$OPERATOR_KUBECONFIG" -n sre logs "$pod" --all-containers=true --prefix 2>/dev/null |
			TOKEN="$TOKEN" LLM_API_KEY="$LLM_API_KEY" FIXTURE_TOKEN="$FIXTURE_TOKEN" perl -pe '
				s/\Q$ENV{TOKEN}\E/[REDACTED]/g if length($ENV{TOKEN} // "");
				s/\Q$ENV{LLM_API_KEY}\E/[REDACTED]/g if length($ENV{LLM_API_KEY} // "");
				s/\Q$ENV{FIXTURE_TOKEN}\E/[REDACTED]/g if length($ENV{FIXTURE_TOKEN} // "");
			' >"$artifact_dir/${pod##*/}-logs.txt" || true
		kubectl --kubeconfig "$OPERATOR_KUBECONFIG" -n sre logs "$pod" --all-containers=true --prefix --previous 2>/dev/null |
			TOKEN="$TOKEN" LLM_API_KEY="$LLM_API_KEY" FIXTURE_TOKEN="$FIXTURE_TOKEN" perl -pe '
				s/\Q$ENV{TOKEN}\E/[REDACTED]/g if length($ENV{TOKEN} // "");
				s/\Q$ENV{LLM_API_KEY}\E/[REDACTED]/g if length($ENV{LLM_API_KEY} // "");
				s/\Q$ENV{FIXTURE_TOKEN}\E/[REDACTED]/g if length($ENV{FIXTURE_TOKEN} // "");
			' >"$artifact_dir/${pod##*/}-previous-logs.txt" || true
	done
	kubectl --kubeconfig "$OPERATOR_KUBECONFIG" -n "$NAMESPACE" get deployments,statefulsets,daemonsets,replicasets,jobs,cronjobs -o yaml >"$artifact_dir/workloads.yaml" 2>&1 || true
	kubectl --kubeconfig "$OPERATOR_KUBECONFIG" get nodes -o yaml >"$artifact_dir/nodes.yaml" 2>&1 || true
	kubectl --kubeconfig "$OPERATOR_KUBECONFIG" get events --all-namespaces --sort-by=.lastTimestamp >"$artifact_dir/events.txt" 2>&1 || true
	kubectl --kubeconfig "$OPERATOR_KUBECONFIG" -n sre describe deployment/sre-agent >"$artifact_dir/agent-deployment.txt" 2>&1 || true
	if [[ -n "$PORT_FORWARD_PID" ]]; then
		kill "$PORT_FORWARD_PID" >/dev/null 2>&1 || true
		wait "$PORT_FORWARD_PID" >/dev/null 2>&1 || true
		PORT_FORWARD_PID=''
	fi
}

cleanup() {
	local exit_code=$?
	if ((CLEANED_UP)); then
		return
	fi
	CLEANED_UP=1
	if ((exit_code != 0)); then
		collect_failure_artifacts
	fi
	if ((CLUSTER_CREATED)); then
		kind delete cluster --name "$KIND_CLUSTER_NAME" >"$WORK_DIR/kind-delete.log" 2>&1 || true
	fi
	if ((exit_code != 0)); then
		printf 'Kind acceptance failed; failure artifacts retained at %s\n' "$WORK_DIR" >&2
	else
		rm -rf "$WORK_DIR"
	fi
	exit "$exit_code"
}
trap cleanup EXIT

if kind get clusters | grep -Fxq "$KIND_CLUSTER_NAME"; then
	printf 'refusing to reuse existing cluster %s\n' "$KIND_CLUSTER_NAME" >&2
	exit 1
fi

printf 'Creating pinned Kind cluster %s\n' "$KIND_CLUSTER_NAME"
kind create cluster --name "$KIND_CLUSTER_NAME" --image "$KIND_NODE_IMAGE" --wait 180s >"$WORK_DIR/kind-create.log" 2>&1
CLUSTER_CREATED=1
kind get kubeconfig --name "$KIND_CLUSTER_NAME" >"$OPERATOR_KUBECONFIG"
chmod 600 "$OPERATOR_KUBECONFIG"

REVISION=$(git -C "$ROOT_DIR" rev-parse --short HEAD)
BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
printf 'Building and loading local image %s\n' "$IMAGE_NAME"
docker build --pull=false \
	--build-arg VERSION=kind \
	--build-arg REVISION="$REVISION" \
	--build-arg BUILD_DATE="$BUILD_DATE" \
	-t "$IMAGE_NAME" -f "$ROOT_DIR/deploy/Dockerfile" "$ROOT_DIR" >"$WORK_DIR/docker-build.log" 2>&1
kind load docker-image "$IMAGE_NAME" --name "$KIND_CLUSTER_NAME" >"$WORK_DIR/kind-load.log" 2>&1

printf 'Deploying base manifests and Kind overlay\n'
kubectl --kubeconfig "$OPERATOR_KUBECONFIG" apply -f "$ROOT_DIR/deploy/k8s/namespace.yaml" >"$WORK_DIR/base-namespace-apply.txt"
kubectl --kubeconfig "$OPERATOR_KUBECONFIG" -n sre create secret generic sre-agent-secrets \
	--from-literal=SRE_API_TOKEN="$TOKEN" \
	--from-literal=LLM_API_KEY="$LLM_API_KEY" \
	--dry-run=client -o yaml |
	kubectl --kubeconfig "$OPERATOR_KUBECONFIG" apply -f - >"$WORK_DIR/secret-apply.txt"
kubectl --kubeconfig "$OPERATOR_KUBECONFIG" apply -k "$ROOT_DIR/deploy/overlays/kind" >"$WORK_DIR/overlay-apply.txt"

jq -n \
	--arg provider "$LLM_PROVIDER" \
	--arg mode "$LLM_MODE" \
	--arg model "$LLM_MODEL" \
	--arg base_url "$LLM_BASE_URL" \
	--arg wire_api "$LLM_WIRE_API" \
	'{"data":{"LLM_PROVIDER":$provider,"LLM_MODE":$mode,"LLM_MODEL":$model,"LLM_BASE_URL":$base_url,"LLM_ENDPOINT_ALLOWLIST":$base_url,"LLM_WIRE_API":$wire_api,"SCAN_INTERVAL":"5s","SRE_SCAN_JITTER":"0s","SRE_LEADER_ELECTION":"false"}}' \
	>"$WORK_DIR/configmap-patch.json"
kubectl --kubeconfig "$OPERATOR_KUBECONFIG" -n sre patch configmap sre-agent-config --type=merge --patch-file "$WORK_DIR/configmap-patch.json" >"$WORK_DIR/configmap-patch.txt"
kubectl --kubeconfig "$OPERATOR_KUBECONFIG" -n sre rollout restart deployment/sre-agent >"$WORK_DIR/rollout-restart.txt"
kubectl --kubeconfig "$OPERATOR_KUBECONFIG" -n sre rollout status deployment/sre-agent --timeout=240s >"$WORK_DIR/rollout-status.txt"
kubectl --kubeconfig "$OPERATOR_KUBECONFIG" -n sre wait --for=condition=available deployment/sre-agent --timeout=90s >"$WORK_DIR/available-status.txt"

kubectl --kubeconfig "$OPERATOR_KUBECONFIG" -n sre port-forward service/sre-agent "$LOCAL_PORT:8080" >"$WORK_DIR/port-forward.log" 2>&1 &
PORT_FORWARD_PID=$!
BASE_URL="http://127.0.0.1:$LOCAL_PORT"

printf 'Checking health, readiness, and authentication boundaries\n'
health_ready=0
for _ in $(seq 1 60); do
	health_status=$(curl --silent --show-error --max-time 5 --output "$WORK_DIR/healthz.json" --write-out '%{http_code}' "$BASE_URL/healthz" || true)
	if [[ "$health_status" == 200 ]]; then
		health_ready=1
		break
	fi
	sleep 1
done
[[ "$health_ready" == 1 ]] || {
	printf 'health endpoint did not become ready\n' >&2
	exit 1
}
curl --silent --show-error --fail --max-time 15 "$BASE_URL/healthz" >"$WORK_DIR/healthz-final.json"
curl --silent --show-error --fail --max-time 15 "$BASE_URL/readyz" >"$WORK_DIR/readyz-final.json"

for endpoint in /api/status /api/v1/issues /api/v1/scan; do
	unauthenticated_status=$(curl --silent --output "$WORK_DIR/unauthenticated-$(basename "$endpoint").json" --write-out '%{http_code}' "$BASE_URL$endpoint")
	[[ "$unauthenticated_status" == 401 ]] || {
		printf 'expected unauthenticated %s to return 401, got %s\n' "$endpoint" "$unauthenticated_status" >&2
		exit 1
	}
done
authenticated_status=$(curl --silent --show-error --output "$WORK_DIR/authenticated-status.json" --write-out '%{http_code}' \
	-H "Authorization: Bearer $TOKEN" "$BASE_URL/api/status")
[[ "$authenticated_status" == 200 ]] || {
	printf 'expected authenticated /api/status to return 200, got %s\n' "$authenticated_status" >&2
	exit 1
}
dashboard_status=$(curl --silent --show-error --output "$WORK_DIR/dashboard-status.json" --write-out '%{http_code}' \
	-H "Authorization: Bearer $TOKEN" "$BASE_URL/api/metrics/status")
[[ "$dashboard_status" == 200 ]] || {
	printf 'expected authenticated /api/metrics/status to return 200, got %s\n' "$dashboard_status" >&2
	exit 1
}
kind_assert_dashboard_status "$WORK_DIR/dashboard-status.json" "$LLM_PROVIDER" "$LLM_WIRE_API" "$TOKEN" "$FIXTURE_TOKEN"
kind_assert_json_safety "$WORK_DIR/dashboard-status.json" "$LLM_API_KEY"
curl --silent --show-error --fail --max-time 30 \
	-H "Authorization: Bearer $TOKEN" "$BASE_URL/metrics" >"$WORK_DIR/dashboard-prometheus.txt"
kind_assert_prometheus_metrics "$WORK_DIR/dashboard-prometheus.txt" "$TOKEN" "$FIXTURE_TOKEN"
kind_assert_json_safety "$WORK_DIR/dashboard-prometheus.txt" "$LLM_API_KEY"

printf 'Applying typed and optional fixture bundles through operator kubeconfig\n'
kind_apply_fixture_bundle "$OPERATOR_KUBECONFIG" "$FIXTURE_TOKEN" "$WORK_DIR/fixtures"

printf 'Triggering a deterministic full fixture scan\n'
printf '%s\n' '{"schema_version":"scan/v1","include_namespaces":["sre-fixtures"],"max_concurrency":4,"timeout":"120s"}' >"$WORK_DIR/fixture-scan-request.json"
fixture_scan_status=$(curl --silent --show-error --max-time 180 --output "$WORK_DIR/fixture-scan.json" --write-out '%{http_code}' \
	-H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
	--data-binary "@$WORK_DIR/fixture-scan-request.json" "$BASE_URL/api/v1/scan")
[[ "$fixture_scan_status" == 200 ]] || {
	printf 'expected full fixture scan to return 200, got %s\n' "$fixture_scan_status" >&2
	exit 1
}
kind_assert_scan_response "$WORK_DIR/fixture-scan.json" "$NAMESPACE" "$LLM_API_KEY"

printf 'Waiting for typed diagnosis categories\n'
kind_wait_for_issue_categories "$BASE_URL/api/v1/issues" "$TOKEN" "$(kind_fixture_expectations_file)" "$WORK_DIR/issues.json" 300 "$FIXTURE_TOKEN" "$NAMESPACE"
kind_assert_json_safety "$WORK_DIR/issues.json" "$TOKEN"
kind_assert_json_safety "$WORK_DIR/issues.json" "$FIXTURE_TOKEN"
kind_assert_json_safety "$WORK_DIR/issues.json" "$LLM_API_KEY"
curl --silent --show-error --fail --max-time 30 \
	-H "Authorization: Bearer $TOKEN" "$BASE_URL/api/v1/issues" >"$WORK_DIR/issues-repeat.json"
kind_assert_stable_issue_ids "$WORK_DIR/issues.json" "$WORK_DIR/issues-repeat.json"

curl --silent --show-error --fail --max-time 30 \
	-H "Authorization: Bearer $TOKEN" "$BASE_URL/api/v1/capabilities" >"$WORK_DIR/capabilities.json"
for family in gateway-api olm integration; do
	kind_assert_capability_family "$WORK_DIR/capabilities.json" "$family"
done
kind_assert_optional_categories "$WORK_DIR/issues.json" "$NAMESPACE" "$(kind_fixture_expectations_file)" "$WORK_DIR/capabilities.json" "$FIXTURE_TOKEN"

printf 'Exercising deterministic scoped scan\n'
printf '%s\n' '{"schema_version":"scan/v1","include_namespaces":["sre-fixtures"],"kinds":["Ingress"],"names":["ingress-invalid"],"max_concurrency":2,"timeout":"90s"}' >"$WORK_DIR/scan-request.json"
scan_status=$(curl --silent --show-error --max-time 120 --output "$WORK_DIR/scan.json" --write-out '%{http_code}' \
	-H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
	--data-binary "@$WORK_DIR/scan-request.json" "$BASE_URL/api/v1/scan")
[[ "$scan_status" == 200 ]] || {
	printf 'expected scoped scan to return 200, got %s\n' "$scan_status" >&2
	exit 1
}
kind_assert_scan_response "$WORK_DIR/scan.json" "$NAMESPACE"
kind_assert_json_safety "$WORK_DIR/scan.json" "$TOKEN"
kind_assert_json_safety "$WORK_DIR/scan.json" "$FIXTURE_TOKEN"
kind_assert_json_safety "$WORK_DIR/scan.json" "$LLM_API_KEY"
jq '.issues' "$WORK_DIR/scan.json" >"$WORK_DIR/scan-issues.json"
scan_repeat_status=$(curl --silent --show-error --max-time 120 --output "$WORK_DIR/scan-repeat.json" --write-out '%{http_code}' \
	-H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
	--data-binary "@$WORK_DIR/scan-request.json" "$BASE_URL/api/v1/scan")
[[ "$scan_repeat_status" == 200 ]] || {
	printf 'expected repeated scoped scan to return 200, got %s\n' "$scan_repeat_status" >&2
	exit 1
}
kind_assert_scan_response "$WORK_DIR/scan-repeat.json" "$NAMESPACE"
jq '.issues' "$WORK_DIR/scan-repeat.json" >"$WORK_DIR/scan-repeat-issues.json"
kind_assert_stable_issue_ids "$WORK_DIR/scan-issues.json" "$WORK_DIR/scan-repeat-issues.json"

printf 'Waiting for safe diagnosis proposals\n'
kind_wait_for_proposals "$BASE_URL/api/proposals" "$TOKEN" "$WORK_DIR/issues.json" "$WORK_DIR/proposals.json" 300 "$FIXTURE_TOKEN"
kind_assert_json_safety "$WORK_DIR/proposals.json" "$TOKEN"
kind_assert_json_safety "$WORK_DIR/proposals.json" "$FIXTURE_TOKEN"
kind_assert_json_safety "$WORK_DIR/proposals.json" "$LLM_API_KEY"
curl --silent --show-error --fail --max-time 30 \
	-H "Authorization: Bearer $TOKEN" "$BASE_URL/api/metrics/status" >"$WORK_DIR/dashboard-status-final.json"
kind_assert_dashboard_status "$WORK_DIR/dashboard-status-final.json" "$LLM_PROVIDER" "$LLM_WIRE_API" "$TOKEN" "$FIXTURE_TOKEN"
kind_assert_json_safety "$WORK_DIR/dashboard-status-final.json" "$LLM_API_KEY"
curl --silent --show-error --fail --max-time 30 \
	-H "Authorization: Bearer $TOKEN" "$BASE_URL/metrics" >"$WORK_DIR/dashboard-prometheus-final.txt"
kind_assert_prometheus_metrics "$WORK_DIR/dashboard-prometheus-final.txt" "$TOKEN" "$FIXTURE_TOKEN"
kind_assert_json_safety "$WORK_DIR/dashboard-prometheus-final.txt" "$LLM_API_KEY"

printf 'Kind diagnosis acceptance passed: cluster=%s provider=%s fixture_ids=%s issue_count=%s category_count=%s proposal_count=%s\n' \
	"$KIND_CLUSTER_NAME" "$LLM_PROVIDER" "$(kind_fixture_ids | wc -l | tr -d ' ')" \
	"$(kind_issue_count "$WORK_DIR/issues.json")" \
	"$(kind_category_count "$WORK_DIR/issues.json")" \
	"$(kind_proposal_count "$WORK_DIR/proposals.json")"
