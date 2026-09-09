#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_dir"
: "${SRE_TRIVY_BIN:?Set SRE_TRIVY_BIN to the reviewed Trivy executable}"
: "${SRE_ENTERPRISE_ARTIFACTS:?Set SRE_ENTERPRISE_ARTIFACTS to the report directory}"
mkdir -p "$SRE_ENTERPRISE_ARTIFACTS"
for component in orchestrator agent; do
  docker build -f deploy/Dockerfile.unified --target "$component" -t "sre-$component:review" .
  "$SRE_TRIVY_BIN" image --scanners vuln --format json --output "$SRE_ENTERPRISE_ARTIFACTS/$component-trivy.json" "sre-$component:review"
  python3 - "$SRE_ENTERPRISE_ARTIFACTS/$component-trivy.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
findings=[v for group in r.get('Results',[]) for v in group.get('Vulnerabilities',[])]
blocking=[v for v in findings if v.get('Severity') in ('HIGH','CRITICAL')]
print('Image findings:',len(findings),'high/critical:',len(blocking))
if blocking:
    for v in blocking:print(v['VulnerabilityID'],v['PkgName'],v.get('FixedVersion','unfixed'))
    raise SystemExit(1)
PY
  "$SRE_TRIVY_BIN" image --format cyclonedx --output "$SRE_ENTERPRISE_ARTIFACTS/$component-sbom.json" "sre-$component:review"
done
