#!/usr/bin/env bash
set -Eeuo pipefail

kind_assert_issue_response() {
	local response_file=$1 namespace=$2 category=$3 secret=${4:-}
	kind_assert_json_safety "$response_file" "$secret"
	jq -e --arg namespace "$namespace" --arg category "$category" '
		type == "array" and
		all(.[];
			(.id | type == "string" and length > 0 and length <= 512) and
			(.kind | type == "string" and length > 0 and length <= 128) and
			(.name | type == "string" and length > 0 and length <= 253) and
			(.details // "" | type == "string" and length <= 65536)
		) and
		any(.[]; .category == $category and ((.namespace // "") == $namespace or $namespace == ""))
	' "$response_file" >/dev/null
}

kind_assert_json_safety() {
	local response_file=$1 secret=${2:-}
	test -s "$response_file"
	if [[ -n "$secret" ]] && grep -Fq -- "$secret" "$response_file"; then
		printf 'response contains a configured secret\n' >&2
		return 1
	fi
	if grep -Fq -- '__KIND_FIXTURE_TOKEN__' "$response_file"; then
		printf 'response contains an unrendered fixture token marker\n' >&2
		return 1
	fi
}

kind_assert_dashboard_status() {
	local response_file=$1 provider=$2 wire_api=$3 token=${4:-} fixture_token=${5:-}
	kind_assert_json_safety "$response_file" "$token"
	kind_assert_json_safety "$response_file" "$fixture_token"
	jq -e --arg provider "$provider" --arg wire_api "$wire_api" '
		type == "object" and
		(.settings | type == "object" and
			.llm_provider == $provider and
			.llm_wire_api == $wire_api and
			(.llm_model | type == "string") and
			(.scan_interval | type == "string") and
			(.scan_jitter | type == "string") and
			(.cache_enabled | type == "boolean") and
			(.webhook_configured | type == "boolean")) and
		(.error_counts | type == "object") and
		(.token_usage | type == "object" and
			(.input_tokens | type == "number") and
			(.output_tokens | type == "number") and
			(.total_tokens | type == "number") and
			(.estimated | type == "boolean"))
	' "$response_file" >/dev/null
}

kind_assert_prometheus_metrics() {
	local response_file=$1 token=${2:-} fixture_token=${3:-}
	kind_assert_json_safety "$response_file" "$token"
	kind_assert_json_safety "$response_file" "$fixture_token"
	grep -Eq '^sre_scans_total\{' "$response_file"
	grep -Eq '^sre_errors_total\{' "$response_file"
}

kind_assert_expected_categories() {
	local response_file=$1 namespace=$2 expectations_file=$3 secret=${4:-}
	kind_assert_json_safety "$response_file" "$secret"
	if ! jq -e 'type == "array"' "$response_file" >/dev/null; then
		printf 'issue response is not an array\n' >&2
		return 1
	fi
	while IFS='|' read -r fixture_id category requirement; do
		if [[ "$requirement" != required ]]; then
			continue
		fi
		local expected_name="$fixture_id"
		case "$fixture_id" in
			node-synthetic-failure) expected_name=sre-fixture-node ;;
		esac
		if ! jq -e --arg namespace "$namespace" --arg category "$category" \
			--arg expected_name "$expected_name" \
			'any(.[]; .category == $category and .name == $expected_name and ($namespace == "" or (.namespace // "") == $namespace or $expected_name == "sre-fixture-node"))' \
			"$response_file" >/dev/null; then
			printf 'missing required fixture issue: %s (%s)\n' "$fixture_id" "$category" >&2
			return 1
		fi
	done < <(awk -F'|' 'NF >= 3 && $1 !~ /^[[:space:]]*#/ && $1 != "" { print $1 "|" $2 "|" $3 }' "$expectations_file" | sort -t'|' -u -k2,2)
}

kind_assert_stable_issue_ids() {
	local first_file=$1 second_file=$2
	local first_ids second_ids
	first_ids=$(jq -r '[.[].id] | sort | join("\n")' "$first_file")
	second_ids=$(jq -r '[.[].id] | sort | join("\n")' "$second_file")
	if [[ "$first_ids" != "$second_ids" ]]; then
		printf 'issue IDs changed between equivalent scans\n' >&2
		return 1
	fi
}

kind_assert_scan_response() {
	local response_file=$1 namespace=$2 secret=${3:-}
	kind_assert_json_safety "$response_file" "$secret"
	jq -e --arg namespace "$namespace" '
		type == "object" and
		.schema_version == "scan/v1" and
		(.scope | type == "object" and .schema_version == "scan/v1" and (.include_namespaces | index($namespace) != null)) and
		(.issues | type == "array") and
		all(.issues[]; (.id | type == "string" and length > 0 and length <= 512)) and
		([.issues[].id] | length) == ([.issues[].id] | unique | length)
	' "$response_file" >/dev/null
}

kind_assert_proposal_response() {
	local response_file=$1 issue_id=$2 secret=${3:-}
	kind_assert_json_safety "$response_file" "$secret"
	jq -e --arg issue_id "$issue_id" '
		def safe_command:
			type == "string" and length > 0 and length <= 2048 and
			(startswith("kubectl ") or startswith("# ")) and
			(contains("--all") | not) and
			(contains("delete namespace") | not) and
				(contains("rm -rf") | not) and
				(contains(";") | not) and
				(contains("&&") | not) and
				(contains("|") | not) and
				(contains(">") | not) and
				(contains("<") | not) and
				(contains("`") | not) and
				(contains("$(") | not) and
				(contains("${") | not) and
				(contains("\n") | not);
		any(.[];
			.issue_id == $issue_id and
			(.diagnosis.provider_name | type == "string" and length > 0 and length <= 256) and
			(.diagnosis.root_cause | type == "string" and length > 0 and length <= 8192) and
			(.diagnosis.remediation_plan | type == "string" and length > 0 and length <= 8192) and
			(.diagnosis.confidence_score | type == "number" and . >= 0 and . <= 1) and
			(.diagnosis.action_type | IN("RestartPod", "DeleteFailedPod", "ScaleWorkload", "RolloutRestart", "CordonNode", "CleanupPods", "GitOpsPR", "Manual")) and
			(.diagnosis.proposed_command | safe_command)
		)
	' "$response_file" >/dev/null
}

kind_assert_proposals_for_issues() {
	local response_file=$1 issues_file=$2 secret=${3:-}
	while IFS= read -r issue_id; do
		if [[ -z "$issue_id" ]]; then
			continue
		fi
		kind_assert_proposal_response "$response_file" "$issue_id" "$secret"
	done < <(jq -r '.[].id' "$issues_file" | sort -u)
}

kind_assert_capability_family() {
	local response_file=$1 family=$2
	jq -e --arg family "$family" '
		type == "object" and (.schema_version == "capabilities/v1") and
		(.dynamic | type == "array") and
		any(.dynamic[]; .family == $family and
			(.state | IN("available", "absent", "forbidden", "unavailable")) and
			all(.resources[]; .state | IN("available", "absent", "forbidden", "unavailable")))
	' "$response_file" >/dev/null
}

kind_capability_family_state() {
	local response_file=$1 family=$2
	jq -r --arg family "$family" '.dynamic[] | select(.family == $family) | .state' "$response_file" | sort -u | head -n 1
}

kind_assert_optional_categories() {
	local response_file=$1 namespace=$2 expectations_file=$3 capabilities_file=$4 secret=${5:-}
	kind_assert_json_safety "$response_file" "$secret"
	if ! jq -e 'type == "array"' "$response_file" >/dev/null; then
		printf 'issue response is not an array\n' >&2
		return 1
	fi
	while IFS='|' read -r fixture_id category requirement; do
		local family=${requirement#optional:}
		if [[ "$(kind_capability_family_state "$capabilities_file" "$family")" != available ]]; then
			continue
		fi
		local expected_name="$fixture_id"
		case "$fixture_id" in
			node-synthetic-failure) expected_name=sre-fixture-node ;;
		esac
		if ! jq -e --arg namespace "$namespace" --arg category "$category" --arg expected_name "$expected_name" \
			'any(.[]; .category == $category and .name == $expected_name and ($namespace == "" or (.namespace // "") == $namespace or $expected_name == "sre-fixture-node"))' \
			"$response_file" >/dev/null; then
			printf 'missing available optional issue category: %s (family %s)\n' "$category" "$family" >&2
			return 1
		fi
	done < <(awk -F'|' 'NF >= 3 && $3 ~ /^optional:/ { print $1 "|" $2 "|" $3 }' "$expectations_file" | sort -t'|' -u -k2,2 -k3,3)
}

kind_wait_for_issue_categories() {
	local url=$1 token=$2 expectations_file=$3 output_file=$4 timeout_seconds=${5:-180} secret=${6:-} namespace=${7:-}
	local deadline=$((SECONDS + timeout_seconds))
	local status
	while ((SECONDS < deadline)); do
		status=$(curl --silent --show-error --max-time 15 --output "$output_file" --write-out '%{http_code}' \
			-H "Authorization: Bearer $token" "$url" || true)
		if [[ "$status" == 200 ]] && kind_assert_expected_categories "$output_file" "$namespace" "$expectations_file" "$secret"; then
			return 0
		fi
		sleep 2
	done
	printf 'timed out waiting for required issue categories\n' >&2
	return 1
}

kind_wait_for_proposals() {
	local url=$1 token=$2 issues_file=$3 output_file=$4 timeout_seconds=${5:-180} secret=${6:-}
	local deadline=$((SECONDS + timeout_seconds))
	local status
	while ((SECONDS < deadline)); do
		status=$(curl --silent --show-error --max-time 15 --output "$output_file" --write-out '%{http_code}' \
			-H "Authorization: Bearer $token" "$url" || true)
		if [[ "$status" == 200 ]] && kind_assert_proposals_for_issues "$output_file" "$issues_file" "$secret"; then
			return 0
		fi
		sleep 2
	done
	printf 'timed out waiting for complete proposals\n' >&2
	return 1
}

kind_assert_dependencies() {
	local command_name
	for command_name in kind docker kubectl curl jq; do
		command -v "$command_name" >/dev/null 2>&1 || {
			printf '%s is required for Kind acceptance\n' "$command_name" >&2
			return 1
		}
	done
}

kind_issue_count() {
	jq 'length' "$1"
}

kind_category_count() {
	jq '[.[].category] | unique | length' "$1"
}

kind_proposal_count() {
	jq 'length' "$1"
}
