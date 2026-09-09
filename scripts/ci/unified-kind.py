"""Disposable two-cluster acceptance runner; invocation builds and runs real workloads."""
import ipaddress
import json
import os
import sys
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import tempfile

NODE_IMAGE = 'kindest/node@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f'


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


def run(args, *, env=None, capture=False, timeout=600, check=True):
    # A separate group lets interruption stop Go, browser, and database wrapper
    # descendants, allowing their cleanup handlers to finish before our teardown.
    process = subprocess.Popen(args, env=env, start_new_session=True,
                               stdout=subprocess.PIPE if capture else None,
                               text=True)
    try:
        output, _ = process.communicate(timeout=timeout)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
        raise
    if check and process.returncode:
        # Do not print arguments: a caller may supply sensitive configuration.
        raise RuntimeError(f'{Path(args[0]).name} failed (exit {process.returncode})')
    return output if capture else process.returncode


def preflight():
    if sys.platform != "linux":
        raise RuntimeError("Kind acceptance currently requires a Linux host with a reachable Docker bridge gateway")
    for command in ('go', 'docker', 'kind', 'kubectl', 'node', 'cc'):
        if not shutil.which(command):
            raise RuntimeError(f'required command missing: {command}')
    module = os.environ.get('SRE_PLAYWRIGHT_MODULE', '')
    if not module or not Path(module).is_absolute():
        raise RuntimeError('SRE_PLAYWRIGHT_MODULE must name an absolute installed Playwright module path')
    # Actually launch the browser to detect missing browser binaries/system libs
    # before building an image or creating a cluster. Never install implicitly.
    run(['node', '-e', '''
const {chromium} = require(process.env.SRE_PLAYWRIGHT_MODULE);
(async () => {
  const browser = await chromium.launch({headless: true,
    executablePath: process.env.SRE_CHROMIUM_EXECUTABLE || undefined});
  await browser.close();
})().catch(error => { console.error(error.message); process.exit(1); });
'''], timeout=60)
    if run(['docker', 'info', '--format', '{{.OSType}}'], capture=True, timeout=30).strip() != 'linux':
        raise RuntimeError('Kind acceptance requires a Linux Docker daemon')
    arch = run(['docker', 'info', '--format', '{{.Architecture}}'], capture=True, timeout=30).strip()
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(arch, arch)
    if arch not in ('amd64', 'arm64'):
        raise RuntimeError('unsupported Docker architecture: ' + arch)
    run(['kind', 'version'], capture=True, timeout=30)
    run(['kubectl', 'version', '--client=true'], capture=True, timeout=30)
    # The race detector used by the acceptance suite needs a native C compiler.
    run(['cc', '--version'], capture=True, timeout=30)
    return arch


def preserve(artifacts, clusters):
    # Deliberately collect only resource health fields, never pod specs, Secret
    # data, kubeconfigs, environment variables, command lines, or raw app logs.
    artifacts.mkdir(parents=True, exist_ok=True)
    columns = {
        'nodes': 'NAME:.metadata.name,READY:.status.conditions[?(@.type=="Ready")].status',
        'pods': 'NAMESPACE:.metadata.namespace,NAME:.metadata.name,PHASE:.status.phase,REASON:.status.reason,RESTARTS:.status.containerStatuses[*].restartCount',
        'deployments': 'NAMESPACE:.metadata.namespace,NAME:.metadata.name,DESIRED:.spec.replicas,READY:.status.readyReplicas,AVAILABLE:.status.availableReplicas',
    }
    for name, config in clusters:
        for resource, fields in columns.items():
            try:
                output = run(['kubectl', '--kubeconfig', str(config),
                              '--request-timeout=10s', 'get', resource, '-A',
                              '-o', 'custom-columns=' + fields],
                             capture=True, timeout=15, check=False)
                (artifacts / f'{name}-{resource}.txt').write_text(output or '')
            except Exception:
                (artifacts / f'{name}-{resource}.txt').write_text('Resource health unavailable.\n')


def cleanup_resources(clusters, images):
    cleanup_ok = True
    for name, _ in reversed(clusters):
        try:
            result = run(['kind', 'delete', 'cluster', '--name', name], timeout=120, check=False)
            if result:
                cleanup_ok = False
                print(f'Cluster cleanup failed for {name} (exit {result})', flush=True)
        except Exception as error:
            cleanup_ok = False
            print(f'Cluster cleanup failed for {name}: {error}', flush=True)
    for tag in images:
        try:
            result = run(['docker', 'image', 'rm', tag], timeout=60, check=False)
            if result:
                cleanup_ok = False
                print(f'Image cleanup failed for {tag} (exit {result})', flush=True)
        except Exception as error:
            cleanup_ok = False
            print(f'Image cleanup failed for {tag}: {error}', flush=True)
    return cleanup_ok


def main():
    arch = preflight()
    token = secrets.token_hex(8)
    names = [f'sre-unified-{token}-a', f'sre-unified-{token}-b']
    artifacts = Path(os.environ.get('SRE_ENTERPRISE_ARTIFACTS',
                                    'artifacts/unified-kind')).resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    clusters, images = [], []
    failed = True
    result = 1
    with tempfile.TemporaryDirectory(prefix='sre-unified-kind-') as directory:
        temp = Path(directory)
        try:
            host_binary = temp / 'sre-agent-host'
            run(['go', 'build', '-p', '1', '-trimpath', '-o', str(host_binary),
                 './cmd/sre-agent'], env=dict(os.environ, CGO_ENABLED='0'))
            # Compile for the Docker daemon's platform, which may differ from
            # the host platform on machines running Docker Desktop.
            for component, package in [('fixture', './pkg/systemintegration/testdata/fixture'),
                                       ('sre-agent', './cmd/sre-agent')]:
                context = temp / component
                context.mkdir()
                run(['go', 'build', '-p', '1', '-trimpath', '-o', str(context / component), package],
                    env=dict(os.environ, CGO_ENABLED='0', GOOS='linux', GOARCH=arch))
                destination = '/usr/local/bin/' + component
                (context / 'Dockerfile').write_text(
                    f'FROM scratch\nCOPY {component} {destination}\n'
                    f'USER 65532:65532\nENTRYPOINT ["{destination}"]\n')
                tag = f'sre-unified-{component}:{token}'
                images.append(tag)  # Also remove a tag produced by a partial build.
                run(['docker', 'build', '-t', tag, str(context)])
            for index, name in enumerate(names):
                config = temp / f'{index}.kubeconfig'
                clusters.append((name, config))  # Includes partial cluster creation.
                run(['kind', 'create', 'cluster', '--name', name, '--image', NODE_IMAGE,
                     '--kubeconfig', str(config), '--wait', '180s'])
                run(['kind', 'load', 'docker-image', *images, '--name', name])
            network = json.loads(run(['docker', 'network', 'inspect', 'kind'], capture=True))
            host_ip = next((config['Gateway'] for config in network[0]['IPAM']['Config']
                            if config.get('Gateway') and
                            ipaddress.ip_address(config['Gateway']).version == 4), None)
            if not host_ip:
                raise RuntimeError('Kind network has no IPv4 gateway for the host TLS test server')
            env = dict(os.environ, SRE_KIND_REQUIRED='1',
                       SRE_KIND_AGENT_BINARY=str(host_binary), SRE_KIND_AGENT_IMAGE=images[1],
                       SRE_KIND_HOST_IP=host_ip, SRE_ENTERPRISE_FIXTURE_IMAGE=images[0],
                       SRE_ENTERPRISE_KIND_A=str(clusters[0][1]),
                       SRE_ENTERPRISE_KIND_B=str(clusters[1][1]),
                       SRE_ENTERPRISE_ARTIFACTS=str(artifacts))
            # Passed only to go test inside the database wrapper, not go build.
            env['SRE_KIND_TEST_TIMEOUT'] = '30m'
            result = run(['scripts/ci/enterprise-postgres.sh'], env=env,
                         timeout=2100, check=False)
            failed = result != 0
        finally:
            # A second interrupt must not abandon partial clusters or images.
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            if failed:
                try:
                    preserve(artifacts, clusters)
                except Exception as error:
                    print(f'Could not preserve resource health: {error}', flush=True)
            if not cleanup_resources(clusters, images) and result == 0:
                result = 1
    return result


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    raise SystemExit(main())
