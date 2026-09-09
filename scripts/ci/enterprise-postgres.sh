#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_dir"
python3 - <<'PY'
import os, secrets, signal, subprocess, sys, time

# Disposable test-only resources. Never use the operator's database or kubeconfig.
name = 'sre-enterprise-test-pg-' + secrets.token_hex(8)
password = secrets.token_urlsafe(32)
env = dict(os.environ, POSTGRES_PASSWORD=password)
created = False
exit_code = 1
pending_error = None
image = 'postgres@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675'

def interrupted(signum, _frame):
    raise SystemExit(128 + signum)
signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)
try:
    created = True  # Track before creation so interruption cleans partial resources.
    subprocess.run(['docker', 'run', '--rm', '-d', '--name', name,
                    '-e', 'POSTGRES_PASSWORD', '-e', 'POSTGRES_DB=sre',
                    '-p', '127.0.0.1::5432', image],
                   env=env, stdout=subprocess.DEVNULL, check=True)
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
    result = subprocess.run(['go', 'test', '-p', '1', '-timeout', os.environ.get('SRE_KIND_TEST_TIMEOUT', '10m'), '-race', './pkg/storage/postgres', './pkg/playbook', './pkg/feedback', './pkg/investigation', './pkg/orchestrator', './pkg/fleet', './pkg/agent/collection', './pkg/execution', './pkg/recovery', './pkg/stewardship', './pkg/knowledge', './pkg/quality', './pkg/delivery', './pkg/systemintegration', '-count=1'], env=env)
    exit_code = result.returncode
except BaseException as error:
    pending_error = error
finally:
    if created:
        try:
            cleanup = subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as error:
            print(f'PostgreSQL cleanup failed: {error}', file=sys.stderr)
            exit_code = 1
        else:
            if cleanup.returncode != 0:
                print(f'PostgreSQL cleanup failed (exit {cleanup.returncode})', file=sys.stderr)
                exit_code = 1
if pending_error is not None:
    raise pending_error
raise SystemExit(exit_code)
PY
