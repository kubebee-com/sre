#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

"$ROOT_DIR/scripts/ci/check-manifests.sh"
"$ROOT_DIR/scripts/ci/check-image-metadata.sh"
"$ROOT_DIR/scripts/ci/check-helm.sh"
bash -n "$ROOT_DIR/scripts/ci/check-manifests.sh"
bash -n "$ROOT_DIR/scripts/ci/check-image-metadata.sh"
bash -n "$ROOT_DIR/scripts/ci/kind-integration.sh"
bash -n "$ROOT_DIR/scripts/ci/check-helm.sh"

echo "deployment contract checks passed"
