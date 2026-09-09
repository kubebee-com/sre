#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_dir"
python3 - <<'PY'
import os, secrets, signal, subprocess, time

# Disposable test-only resources. Never use the operator's database or kubeconfig.
name = 'sre-enterprise-capacity-pg-' + secrets.token_hex(8)
password = secrets.token_urlsafe(32)
env = dict(os.environ, POSTGRES_PASSWORD=password)
created = False
image = 'postgres@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675'

def interrupted(signum, _frame):
    raise SystemExit(128 + signum)
signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)
try:
    subprocess.run(['docker', 'run', '--rm', '-d', '--name', name,
                    '-e', 'POSTGRES_PASSWORD', '-e', 'POSTGRES_DB=sre',
                    '-p', '127.0.0.1::5432', image],
                   env=env, stdout=subprocess.DEVNULL, check=True)
    created = True
    for _ in range(60):
        if subprocess.run(['docker', 'exec', name, 'pg_isready', '-U', 'postgres'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            break
        time.sleep(0.5)
    else:
        raise RuntimeError('database readiness deadline exceeded')
    port = subprocess.check_output(['docker', 'port', name, '5432/tcp'], text=True).strip().rsplit(':', 1)[1]
    dsn = f'postgres://postgres:{password}@127.0.0.1:{port}/sre?sslmode=disable'
    env['SRE_ENTERPRISE_TEST_DATABASE_URL'] = dsn
    env['SRE_TEST_DATABASE_URL'] = dsn
    env['SRE_ENTERPRISE_CAPACITY'] = '1'
    result = subprocess.run(['go', 'test', './pkg/storage/postgres', '-run', '^TestEnterpriseCapacity$', '-count=1', '-v', '-timeout=3m'], env=env)
    raise SystemExit(result.returncode)
finally:
    if created:
        subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
PY
