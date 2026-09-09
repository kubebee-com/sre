#!/usr/bin/env bash
# Compatibility entrypoint: enterprise and unified acceptance share one runner.
set -euo pipefail
exec "$(dirname "${BASH_SOURCE[0]}")/unified-kind.sh" "$@"
