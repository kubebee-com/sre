#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

source "$ROOT_DIR/scripts/ci/kind-fixtures.sh"
source "$ROOT_DIR/scripts/ci/kind-assertions.sh"

fixture_ids=$(kind_fixture_ids)
expected_ids=(
	"pod-pending-scheduling"
	"pod-invalid-image"
	"pod-crash-loop"
	"pod-oom-exit-137"
	"pod-failed"
	"pod-evicted"
	"pod-stuck-terminating"
	"pod-current-log-error"
	"pod-previous-log-error"
	"deployment-degraded"
	"statefulset-degraded"
	"daemonset-degraded"
	"replicaset-stuck"
	"job-failed"
	"cronjob-suspended"
	"service-no-endpoints"
	"endpointslice-mismatch"
	"ingress-invalid"
	"networkpolicy-orphaned"
	"hpa-invalid"
	"pdb-invalid"
	"pvc-pending"
	"pv-failed"
	"storageclass-invalid"
	"configmap-empty"
	"webhook-missing-service"
	"node-synthetic-failure"
	"security-privilege"
	"security-cluster-binding"
)

for expected_id in "${expected_ids[@]}"; do
	if ! grep -Fxq "$expected_id" <<<"$fixture_ids"; then
		printf 'missing fixture id: %s\n' "$expected_id" >&2
		exit 1
	fi
done

test -f "$ROOT_DIR/deploy/fixtures/kind/dynamic-crds.yaml"
test -f "$ROOT_DIR/deploy/fixtures/kind/dynamic-resources.yaml"
grep -q 'gateway-api' "$ROOT_DIR/deploy/fixtures/kind/dynamic-crds.yaml"
grep -q 'olm' "$ROOT_DIR/deploy/fixtures/kind/dynamic-crds.yaml"
grep -q 'keda' "$ROOT_DIR/deploy/fixtures/kind/dynamic-crds.yaml"
grep -q 'kyverno' "$ROOT_DIR/deploy/fixtures/kind/dynamic-crds.yaml"
grep -q 'prometheus' "$ROOT_DIR/deploy/fixtures/kind/dynamic-crds.yaml"
test -f "$ROOT_DIR/deploy/overlays/kind/rbac-secrets-patch.yaml"
grep -q 'resources: \["secrets"\]' "$ROOT_DIR/deploy/overlays/kind/rbac-secrets-patch.yaml"

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
cat >"$tmp_dir/issues.json" <<'JSON'
[{"id":"sre-fixtures/Pod/pod-invalid-image/ImagePullBackOff","namespace":"sre-fixtures","kind":"Pod","name":"pod-invalid-image","category":"ImagePullBackOff","details":"redacted fixture evidence"}]
JSON
cat >"$tmp_dir/proposals.json" <<'JSON'
[{"issue_id":"sre-fixtures/Pod/pod-invalid-image/ImagePullBackOff","diagnosis":{"provider_name":"Rule-Based SRE Engine","root_cause":"image cannot be pulled","remediation_plan":"inspect the image","confidence_score":0.9,"action_type":"Manual","proposed_command":"kubectl describe pod pod-invalid-image -n sre-fixtures"}}]
JSON

kind_assert_issue_response "$tmp_dir/issues.json" "sre-fixtures" "ImagePullBackOff" "fixture-secret"
kind_assert_proposal_response "$tmp_dir/proposals.json" "sre-fixtures/Pod/pod-invalid-image/ImagePullBackOff" "fixture-secret"

cat >"$tmp_dir/scan.json" <<'JSON'
{"schema_version":"scan/v1","scope":{"schema_version":"scan/v1","include_namespaces":["sre-fixtures"]},"issues":[{"id":"node-sre-fixture-node-1234"},{"id":"configmap-configmap-empty-5678"}]}
JSON
kind_assert_scan_response "$tmp_dir/scan.json" "sre-fixtures" "fixture-secret"

printf 'kind fixture shell contract passed\n'
