#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
DOCKERFILE="$ROOT_DIR/deploy/Dockerfile"
MAKEFILE="$ROOT_DIR/Makefile"

require_text() {
	local file=$1
	local needle=$2
	if ! grep -Fq -- "$needle" "$file"; then
		printf 'image metadata check failed: %s is missing from %s\n' "$needle" "$file" >&2
		exit 1
	fi
}

require_text "$DOCKERFILE" 'golang:1.26.6-alpine@sha256:'
require_text "$DOCKERFILE" 'cgr.dev/chainguard/static@sha256:'
require_text "$DOCKERFILE" 'CGO_ENABLED=0'
require_text "$DOCKERFILE" 'org.opencontainers.image.source='
require_text "$DOCKERFILE" 'org.opencontainers.image.version='
require_text "$DOCKERFILE" 'org.opencontainers.image.revision='
require_text "$DOCKERFILE" 'org.opencontainers.image.created='
require_text "$DOCKERFILE" 'USER 65532:65532'
require_text "$ROOT_DIR/deploy/k8s/deployment.yaml" 'busybox:1.36.1@sha256:'
require_text "$MAKEFILE" 'VERSION ?='
require_text "$MAKEFILE" 'REVISION ?='
require_text "$MAKEFILE" 'BUILD_DATE ?='
require_text "$MAKEFILE" '--build-arg VERSION=$(VERSION)'

if grep -Eq '^FROM[[:space:]]+[^@[:space:]]+:(latest|main|edge)([[:space:]]|$)' "$DOCKERFILE"; then
	printf 'image metadata check failed: floating base image\n' >&2
	exit 1
fi

if [[ -n "${IMAGE_TO_CHECK:-}" ]] && command -v docker >/dev/null 2>&1; then
	labels=$(docker image inspect --format '{{json .Config.Labels}}' "$IMAGE_TO_CHECK")
	user=$(docker image inspect --format '{{.Config.User}}' "$IMAGE_TO_CHECK")
	for label in org.opencontainers.image.source org.opencontainers.image.version org.opencontainers.image.revision org.opencontainers.image.created; do
		grep -Fq "\"$label\":" <<<"$labels" || {
			printf 'image metadata check failed: built image lacks %s\n' "$label" >&2
			exit 1
		}
	done
	[[ "$user" != "" && "$user" != "0" && "$user" != "root" ]] || {
		printf 'image metadata check failed: image runs as root\n' >&2
		exit 1
	}
fi

printf 'image metadata checks passed\n'
