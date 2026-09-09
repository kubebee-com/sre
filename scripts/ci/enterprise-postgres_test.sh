#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

cat >"$tmp_dir/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
run|exec)
  exit 0
  ;;
port)
  printf '127.0.0.1:5432\n'
  ;;
rm)
  exit 1
  ;;
*)
  exit 0
  ;;
esac
SH
cat >"$tmp_dir/go" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod +x "$tmp_dir/docker" "$tmp_dir/go"

output="$tmp_dir/output"
if PATH="$tmp_dir:$PATH" bash "$ROOT_DIR/scripts/ci/enterprise-postgres.sh" >"$output" 2>&1; then
  printf 'postgres wrapper accepted a failed cleanup\n' >&2
  exit 1
fi
if ! grep -Fq 'PostgreSQL cleanup failed' "$output"; then
  cat "$output" >&2
  exit 1
fi
printf 'postgres cleanup contract passed\n'
