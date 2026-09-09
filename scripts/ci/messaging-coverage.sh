#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_dir"
coverage_file=$(mktemp)
trap 'rm -f "$coverage_file"' EXIT
go test -p 1 -coverprofile="$coverage_file" ./pkg/messaging ./pkg/delivery
python3 - "$coverage_file" <<'PY'
import sys
covered = {"messaging": 0, "adapters": 0}
total = dict(covered)
for line in open(sys.argv[1]):
    if line.startswith("mode:"):
        continue
    location, statements, count = line.split()
    group = "messaging" if "/pkg/messaging/" in location else "adapters" if "/pkg/delivery/channels.go:" in location else None
    if group:
        total[group] += int(statements)
        covered[group] += int(statements) if int(count) else 0
for group in total:
    percent = 100 * covered[group] / total[group] if total[group] else 0
    print(f"{group}: {percent:.1f}% statement coverage (minimum 90%)")
    if percent < 90:
        raise SystemExit(1)
PY
