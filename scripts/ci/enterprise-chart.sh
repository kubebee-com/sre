#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_dir"
python3 scripts/ci/unified-chart_test.py
