#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_dir"
: "${SRE_ENTERPRISE_TEST_DATABASE_URL:?Set SRE_ENTERPRISE_TEST_DATABASE_URL to an isolated PostgreSQL database; E2E tests must not skip}"
go test -p 1 -race -count=1 -v ./pkg/orchestrator ./pkg/delivery -run 'E2E'
