#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
chart_dir="$repo_dir/deploy/legacy/helm/sre-agent"
render_dir=$(mktemp -d)
trap 'rm -rf "$render_dir"' EXIT
helm template test "$chart_dir" --namespace sre --set serviceMonitor.enabled=true > "$render_dir/chart.yaml"
python3 - "$render_dir/chart.yaml" <<'PY'
import sys,yaml
items=list(yaml.safe_load_all(open(sys.argv[1])))
monitor=next(x for x in items if x and x['kind']=='ServiceMonitor')
auth=monitor['spec']['endpoints'][0].get('authorization',{})
assert auth.get('type')=='Bearer', 'authenticated metrics require Bearer authorization'
assert auth.get('credentials',{}).get('key')=='SRE_API_TOKEN', 'metrics require Secret key reference'
assert auth.get('credentials',{}).get('name'), 'metrics require Secret name reference'
deploy=next(x for x in items if x and x['kind']=='Deployment')
assert deploy['spec'].get('strategy',{}).get('type')=='Recreate', 'file writer rollout must not overlap'
PY
if helm template test "$chart_dir" --set replicaCount=2 >/dev/null 2>&1; then
  echo 'file-backed multiwriter configuration was accepted' >&2
  exit 1
fi
printf 'enterprise deployment boundary checks passed\n'
