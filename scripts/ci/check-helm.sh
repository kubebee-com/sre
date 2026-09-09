#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
CHART_DIR="$ROOT_DIR/deploy/legacy/helm/sre-agent"

if ! command -v helm >/dev/null 2>&1; then
  printf 'helm is required for Helm chart checks\n' >&2
  exit 1
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

default_rendered="$tmp_dir/default.yaml"
second_rendered="$tmp_dir/second.yaml"
optional_rendered="$tmp_dir/optional.yaml"
managed_secret_rendered="$tmp_dir/managed-secret.yaml"
digest_rendered="$tmp_dir/digest.yaml"
disabled_rendered="$tmp_dir/disabled.yaml"
rbac_rendered="$tmp_dir/rbac.yaml"

helm lint --strict "$CHART_DIR"
helm template sre-agent "$CHART_DIR" --namespace sre >"$default_rendered"
helm template sre-agent-2 "$CHART_DIR" --namespace sre >"$second_rendered"
helm template sre-agent "$CHART_DIR" --namespace sre \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=sre.example.com \
  --set ingress.tls[0].secretName=sre-agent-tls \
  --set ingress.tls[0].hosts[0]=sre.example.com \
  --set serviceMonitor.enabled=true \
  --set-string image.digest=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  >"$optional_rendered"
helm template sre-agent "$CHART_DIR" --namespace sre \
  --set secret.create=true \
  --set-string secret.apiToken=temporary-validation-token \
  >"$managed_secret_rendered"
helm template sre-agent "$CHART_DIR" --namespace sre \
  --set-string image.digest=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  >"$digest_rendered"
helm template sre-agent "$CHART_DIR" --namespace sre \
  --set pdb.enabled=false \
  --set networkPolicy.enabled=false \
  >"$disabled_rendered"
helm template sre-agent "$CHART_DIR" --namespace sre \
  --set rbac.readSecrets=true \
  --set rbac.remediation.enabled=true \
  >"$rbac_rendered"

require_text() {
  local file=$1
  local needle=$2
  if ! grep -Fq -- "$needle" "$file"; then
    printf 'Helm check failed: missing %s in %s\n' "$needle" "$file" >&2
    exit 1
  fi
}

reject_text() {
  local file=$1
  local needle=$2
  if grep -Fq -- "$needle" "$file"; then
    printf 'Helm check failed: forbidden %s in %s\n' "$needle" "$file" >&2
    exit 1
  fi
}

for kind in Deployment ServiceAccount ClusterRole ClusterRoleBinding ConfigMap PersistentVolumeClaim Service PodDisruptionBudget NetworkPolicy; do
  require_text "$default_rendered" "kind: $kind"
done
reject_text "$default_rendered" 'kind: Ingress'
reject_text "$default_rendered" 'kind: ServiceMonitor'
reject_text "$default_rendered" 'kind: Secret'
require_text "$default_rendered" 'app.kubernetes.io/instance: sre-agent'
require_text "$second_rendered" 'app.kubernetes.io/instance: sre-agent-2'
require_text "$default_rendered" 'image: "ghcr.io/kubebee-com/sre:0.1.0"'
require_text "$default_rendered" 'runAsNonRoot: true'
require_text "$default_rendered" 'readOnlyRootFilesystem: true'
require_text "$default_rendered" 'allowPrivilegeEscalation: false'
require_text "$default_rendered" 'drop:'
require_text "$default_rendered" 'automountServiceAccountToken: true'
require_text "$default_rendered" 'name: SRE_REQUIRE_API_TOKEN'
require_text "$default_rendered" 'value: "true"'
require_text "$default_rendered" 'LLM_ORGANIZATION: ""'
require_text "$default_rendered" 'LLM_PROXY_URL: ""'
require_text "$default_rendered" 'name: LLM_CUSTOM_HEADERS'
require_text "$default_rendered" 'path: /healthz'
require_text "$default_rendered" 'path: /readyz'
require_text "$default_rendered" 'resources:'
require_text "$default_rendered" 'verbs: ["get", "list", "watch"]'
reject_text "$default_rendered" 'resources: ["*"]'
reject_text "$default_rendered" 'verbs: ["*"]'
reject_text "$default_rendered" 'secretRef:'
reject_text "$default_rendered" 'delete'
reject_text "$disabled_rendered" 'kind: PodDisruptionBudget'
reject_text "$disabled_rendered" 'kind: NetworkPolicy'
require_text "$digest_rendered" 'image: "ghcr.io/kubebee-com/sre@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"'
require_text "$optional_rendered" 'kind: Ingress'
require_text "$optional_rendered" 'kind: ServiceMonitor'
require_text "$optional_rendered" 'host: "sre.example.com"'
require_text "$optional_rendered" 'secretName: sre-agent-tls'
require_text "$optional_rendered" 'port: "http"'
require_text "$managed_secret_rendered" 'kind: Secret'
require_text "$managed_secret_rendered" 'SRE_API_TOKEN: "temporary-validation-token"'
require_text "$rbac_rendered" 'resources:'
require_text "$rbac_rendered" '      - secrets'
require_text "$rbac_rendered" 'verbs: ["delete", "patch"]'

if helm template sre-agent "$CHART_DIR" --set image.tag=latest >/dev/null 2>&1; then
  printf 'Helm check failed: latest image tag was accepted\n' >&2
  exit 1
fi
if helm template sre-agent "$CHART_DIR" --set-string image.digest=sha256:not-a-digest >/dev/null 2>&1; then
  printf 'Helm check failed: malformed image digest was accepted\n' >&2
  exit 1
fi
if helm template sre-agent "$CHART_DIR" --set ingress.enabled=true >/dev/null 2>&1; then
  printf 'Helm check failed: TLS-less ingress was accepted\n' >&2
  exit 1
fi

bash "$ROOT_DIR/scripts/ci/enterprise-deployment_test.sh"

printf 'Helm chart checks passed\n'
