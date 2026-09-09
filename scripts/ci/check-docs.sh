#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT_DIR"

require_file() {
	local path=$1
	[[ -f "$path" ]] || {
		printf 'docs check failed: missing file %s\n' "$path" >&2
		exit 1
	}
}

require_text() {
	local path=$1
	local needle=$2
	grep -Fq -- "$needle" "$path" || {
		printf 'docs check failed: %s is missing from %s\n' "$needle" "$path" >&2
		exit 1
	}
}

reject_text() {
	local path=$1
	local needle=$2
	if grep -Fq -- "$needle" "$path"; then
		printf 'docs check failed: stale text %s remains in %s\n' "$needle" "$path" >&2
		exit 1
	fi
}

for path in \
	README.md \
	docs/legacy-standalone.md \
	docs/kubebee-sre-k8sgpt-feature-gap.md \
	docs/kubebee-sre-k8sgpt-evidence.md \
	docs/deployment.md \
	cmd/sre-agent/managed.go \
	pkg/config/profile.go \
	pkg/scanplan/plan.go \
	pkg/output/output.go \
	pkg/supportbundle/bundle.go \
	pkg/cache/file.go \
	pkg/cache/remote.go \
	pkg/cache/blobstore.go \
	pkg/cache/blobstore_test.go \
	internal/legacyserver/server.go \
	internal/legacyserver/mcp.go \
	pkg/grpcapi/server.go \
	api/v1/sre.proto \
	api/v1/plugin.proto \
	pkg/plugin/client.go \
	pkg/plugin/registry.go \
	pkg/integration/registry.go \
	pkg/integration/aws.go \
	pkg/integration/aws_test.go \
	pkg/triage/aws_provider.go \
	pkg/triage/aws_provider_test.go \
	pkg/triage/cloud_provider.go \
	pkg/triage/providers/catalog.go \
	pkg/scheduler/scheduler.go \
	pkg/metrics/metrics.go \
	deploy/k8s/rbac.yaml \
	deploy/overlays/remediation/kustomization.yaml \
	deploy/overlays/remediation/remediation-rbac-patch.yaml \
	deploy/legacy/helm/sre-agent/values.yaml \
	scripts/ci/kind-integration.sh; do
	require_file "$path"
done

require_text docs/legacy-standalone.md '`scan/v1`'
require_text docs/legacy-standalone.md '`output/v1`'
require_text docs/legacy-standalone.md '`support-bundle/v1`'
require_text docs/legacy-standalone.md 'github.com/modelcontextprotocol/go-sdk'
require_text docs/legacy-standalone.md 'SRE_GRPC_PORT'
require_text docs/legacy-standalone.md 'SRE_LEADER_ELECTION=true'
require_text docs/legacy-standalone.md 'make kind-test'
require_text docs/legacy-standalone.md 'ingress-nginx controller ConfigMap'
require_text docs/legacy-standalone.md 'use-forwarded-headers: "false"'
require_text docs/legacy-standalone.md 'compute-full-forwarded-for: "false"'
require_text docs/legacy-standalone.md 'gocloud.dev/blob'
require_text docs/legacy-standalone.md '`s3://`, `gs://`, and `azblob://`'
require_text docs/legacy-standalone.md 'SRE_ENABLE_AWS_EKS=true'
require_text docs/legacy-standalone.md 'AWS/EKS'
require_text docs/legacy-standalone.md 'LLM_MODE=aws'
require_text docs/legacy-standalone.md 'AWS SDK v2 runtime clients'
require_text docs/legacy-standalone.md 'explain [question]'
require_text docs/legacy-standalone.md '--no-cache'
require_text docs/legacy-standalone.md '--llm-headers'
require_text docs/legacy-standalone.md 'LLM_CUSTOM_HEADERS'
require_text docs/legacy-standalone.md 'LLM_ENDPOINT_ALLOWLIST'

require_text docs/kubebee-sre-k8sgpt-feature-gap.md '14 `Covered`, 31 `Partial`, and 0 `Missing` slices'
require_text docs/kubebee-sre-k8sgpt-feature-gap.md 'KG-CLI-01'
require_text docs/kubebee-sre-k8sgpt-feature-gap.md 'KG-OPS-04'
require_text docs/kubebee-sre-k8sgpt-feature-gap.md 'Go Cloud `BlobObjectStore`'
require_text docs/kubebee-sre-k8sgpt-feature-gap.md 'Interplex driver is not included'
require_text docs/kubebee-sre-k8sgpt-feature-gap.md 'read-only AWS/EKS integration is available through explicit activation'
require_text docs/deployment.md 'deploy/overlays/remediation'
require_text docs/legacy-standalone.md 'deploy/overlays/remediation'
require_text docs/deployment.md 'LLM_ENDPOINT_ALLOWLIST'

require_text docs/kubebee-sre-k8sgpt-evidence.md 'go test ./... -count=1'
require_text docs/kubebee-sre-k8sgpt-evidence.md 'make kind-test'
require_text docs/kubebee-sre-k8sgpt-evidence.md 'support-bundle/v1'
require_text docs/kubebee-sre-k8sgpt-evidence.md 'cloud credentials'
require_text docs/kubebee-sre-k8sgpt-evidence.md 'gocloud.dev/blob'
require_text docs/kubebee-sre-k8sgpt-evidence.md 'BlobObjectStore'
require_text docs/kubebee-sre-k8sgpt-evidence.md 'AWS/EKS'
require_text docs/kubebee-sre-k8sgpt-evidence.md 'request-level bypass'

covered=$(grep -Ec '^\| KG-[^|]+ \| Covered \|' docs/kubebee-sre-k8sgpt-feature-gap.md || true)
partial=$(grep -Ec '^\| KG-[^|]+ \| Partial \|' docs/kubebee-sre-k8sgpt-feature-gap.md || true)
missing=$(grep -Ec '^\| KG-[^|]+ \| Missing \|' docs/kubebee-sre-k8sgpt-feature-gap.md || true)
total=$((covered + partial + missing))
[[ "$covered" -eq 14 && "$partial" -eq 31 && "$missing" -eq 0 && "$total" -eq 45 ]] || {
	printf 'docs check failed: matrix counts are Covered=%s Partial=%s Missing=%s\n' "$covered" "$partial" "$missing" >&2
	exit 1
}

analyzer_count=$(grep -c 'analyzerAdapter{info:' pkg/scanner/contract.go)
[[ "$analyzer_count" -eq 25 ]] || {
	printf 'docs check failed: built-in analyzer count is %s, expected 25\n' "$analyzer_count" >&2
	exit 1
}

require_text internal/legacyserver/server.go 'mux.HandleFunc("/api/v1/support-bundle"'
require_text internal/legacyserver/server.go 'mux.Handle("/api/v1/mcp"'
require_text internal/legacyserver/server.go 'mux.Handle("/metrics"'
require_text pkg/grpcapi/server.go 'RegisterAnalyzerServiceServer'
require_text pkg/plugin/client.go 'credentials.NewTLS'
require_text pkg/scheduler/scheduler.go 'leaderelection.NewLeaderElector'
require_text pkg/metrics/metrics.go 'prometheus.NewRegistry'
require_text pkg/cache/blobstore.go 'case "s3", "gs", "azblob"'
require_text pkg/integration/aws.go 'eks.NewListClustersPaginator'
require_text pkg/triage/aws_provider.go 'bedrockruntime.NewFromConfig'
require_text pkg/triage/aws_provider.go 'sagemakerruntime.NewFromConfig'
require_text go.mod 'gocloud.dev'
require_text go.mod 'github.com/aws/aws-sdk-go-v2/service/eks'
require_text go.mod 'github.com/aws/aws-sdk-go-v2/service/bedrockruntime'
require_text go.mod 'github.com/aws/aws-sdk-go-v2/service/sagemakerruntime'

for stale in \
	'0 Covered, 24 Partial, and 21 Missing' \
	'there is no Cobra command tree' \
	'No cache or no-cache control' \
	'Concrete S3, GCS, Azure Blob, and Interplex cache clients are not included' \
	'No MCP package, route, or deployment value' \
	'No dynamic client/OLM code' \
	'No AWS/EKS cluster integration analyzer'; do
	reject_text docs/kubebee-sre-k8sgpt-feature-gap.md "$stale"
	reject_text docs/kubebee-sre-k8sgpt-evidence.md "$stale"
done

reject_text docs/kubebee-sre-k8sgpt-feature-gap.md 'there is no CLI flag for arbitrary provider request headers'

printf 'documentation consistency checks passed\n'
