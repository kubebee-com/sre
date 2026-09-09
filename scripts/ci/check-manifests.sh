#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
KUSTOMIZE=${KUSTOMIZE:-kubectl}

if ! command -v "$KUSTOMIZE" >/dev/null 2>&1; then
	printf 'kubectl is required for manifest checks\n' >&2
	exit 1
fi

rendered=$($KUSTOMIZE kustomize "$ROOT_DIR/deploy/k8s")
kind_rendered=$($KUSTOMIZE kustomize "$ROOT_DIR/deploy/overlays/kind")
remediation_rendered=$($KUSTOMIZE kustomize "$ROOT_DIR/deploy/overlays/remediation")

require_text() {
	local haystack=$1
	local needle=$2
	if ! grep -Fq -- "$needle" <<<"$haystack"; then
		printf 'manifest check failed: missing %s\n' "$needle" >&2
		exit 1
	fi
}

reject_text() {
	local haystack=$1
	local needle=$2
	if grep -Fq -- "$needle" <<<"$haystack"; then
		printf 'manifest check failed: forbidden %s\n' "$needle" >&2
		exit 1
	fi
}

if grep -Eq 'image: .*:latest([[:space:]]|$)' <<<"$rendered"; then
	printf 'manifest check failed: floating application image\n' >&2
	exit 1
fi
reject_text "$rendered" 'resources: ["*"]'
reject_text "$rendered" 'verbs: ["*"]'
reject_text "$rendered" '  - delete'
if grep -Fq -- 'verbs: ["delete", "patch"]' "$ROOT_DIR/deploy/k8s/rbac.yaml" || grep -Fq -- 'verbs: ["patch", "update"]' "$ROOT_DIR/deploy/k8s/rbac.yaml"; then
	printf 'manifest check failed: base RBAC grants remediation verbs\n' >&2
	exit 1
fi
reject_text "$rendered" 'secretRef:'

require_text "$rendered" 'image: ghcr.io/kubebee-com/sre:'
require_text "$rendered" 'livenessProbe:'
require_text "$rendered" 'path: /healthz'
require_text "$rendered" 'readinessProbe:'
require_text "$rendered" 'path: /readyz'
require_text "$rendered" 'runAsNonRoot: true'
require_text "$rendered" 'readOnlyRootFilesystem: true'
require_text "$rendered" 'allowPrivilegeEscalation: false'
require_text "$rendered" 'SRE_REQUIRE_API_TOKEN'
require_text "$rendered" 'SRE_DATA_DIR'
require_text "$rendered" 'LLM_BASE_URL'
require_text "$rendered" 'LLM_ENDPOINT_ALLOWLIST'
require_text "$rendered" 'LLM_ORGANIZATION'
require_text "$rendered" 'LLM_CUSTOM_HEADERS'
require_text "$rendered" 'persistentVolumeClaim:'
require_text "$rendered" 'kind: PodDisruptionBudget'
require_text "$rendered" 'kind: NetworkPolicy'
require_text "$rendered" $'resources:\n  - pods\n  - pods/log\n  - events'
require_text "$rendered" $'resources:\n  - jobs\n  - cronjobs'
require_text "$rendered" $'resources:\n  - ingresses\n  - networkpolicies'
require_text "$rendered" $'resources:\n  - horizontalpodautoscalers'
require_text "$rendered" $'resources:\n  - poddisruptionbudgets'

require_text "$kind_rendered" 'image: sre-agent:kind'
require_text "$kind_rendered" 'LLM_PROVIDER: codex'
require_text "$kind_rendered" 'LLM_WIRE_API: responses'
require_text "$kind_rendered" 'emptyDir: {}'
reject_text "$kind_rendered" 'kind: Ingress'

require_text "$remediation_rendered" '  - delete'
require_text "$remediation_rendered" '  - deployments'
require_text "$(<"$ROOT_DIR/deploy/overlays/remediation/remediation-rbac-patch.yaml")" 'resources: ["pods"]'
require_text "$(<"$ROOT_DIR/deploy/overlays/remediation/remediation-rbac-patch.yaml")" 'resources: ["nodes"]'
require_text "$(<"$ROOT_DIR/deploy/overlays/remediation/remediation-rbac-patch.yaml")" 'resources: ["deployments"]'

printf 'manifest checks passed\n'
