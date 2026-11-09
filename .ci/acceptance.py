#!/usr/bin/env python3
"""Fixed owner gates; no resolution, selectable phase list, or source mutation."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import time

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
assert os.environ.get('CI') == 'crow', 'Crow only'
assert not os.environ.get('CHECKS'), 'Caller-selected gates cannot accept a release'
root = Path(os.environ['CI_ACCEPTANCE_ARTIFACTS']).resolve()
assert root.is_dir() and not root.is_relative_to(Path.cwd()), 'External artifacts required'
lock = Path('Cargo.lock')
capabilities = {'goog:chromeOptions': {
    'binary': os.environ['CHROME_BIN'],
    'args': ['--headless=new', '--no-sandbox', '--disable-dev-shm-usage']}}
(root / 'webdriver.json').write_text(json.dumps(capabilities, indent=2) + '\n')
os.environ['WASM_BINDGEN_TEST_WEBDRIVER_JSON'] = str(root / 'webdriver.json')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(command, output=None, env=None):
    print('+', ' '.join(map(str, command)), flush=True)
    return subprocess.run(command, check=True, stdout=output, stderr=subprocess.STDOUT,
                          env=env)


def metadata(name):
    target = root / name
    with target.open('w') as stream:
        run(['cargo', 'metadata', '--locked', '--all-features', '--format-version', '1'], stream)
    run(['python3', '.github/check-first-party.py', '--archive', '--metadata', str(target)])
    return json.loads(target.read_text())


def coverage_probe(stream):
    setup = Path(os.environ['CI_ACCEPTANCE_COVERAGE_SETUP'])
    assert sha(setup) == os.environ['CI_ACCEPTANCE_COVERAGE_SHA256']
    run(['bash', '-euo', 'pipefail', '-c',
         '. "$1"; rustc -Vv; cargo -V; cargo llvm-cov --version; '
         'case "$(rustc -V)" in *nightly*) ;; *) exit 1;; esac',
         'coverage-probe', str(setup)], stream)


def runner(metadata_value):
    versions = {p['version'] for p in metadata_value['packages'] if p['name'] == 'wasm-bindgen'}
    assert len(versions) == 1
    version = versions.pop()
    assert re.fullmatch(r'0\.2\.\d+', version)
    directory = root / 'wasm-runner'
    directory.mkdir()
    name = f'wasm-bindgen-{version}-x86_64-unknown-linux-musl.tar.gz'
    base = f"{os.environ.get('WASM_BINDGEN_DOWNLOAD_BASE', 'https://github.com/wasm-bindgen/wasm-bindgen/releases/download')}/{version}"
    for suffix in ['', '.sha256sum']:
        run(['curl', '--fail', '--location', '--retry', '3', '--output',
             str(directory / (name + suffix)), base + '/' + name + suffix])
    digest = (directory / (name + '.sha256sum')).read_text().split()[0]
    assert re.fullmatch('[0-9a-f]{64}', digest) and sha(directory / name) == digest
    with tarfile.open(directory / name, 'r:gz') as archive:
        archive.extractall(directory, filter='data')
    candidates = list(directory.glob('*/wasm-bindgen-test-runner'))
    assert len(candidates) == 1
    executable = candidates[0]
    result = subprocess.check_output([str(executable), '--version'], text=True).strip()
    assert version in result
    (root / 'wasm-runner.json').write_text(json.dumps({
        'version': result, 'release': base, 'archive_sha256': digest,
        'runner_sha256': sha(executable)}, indent=2) + '\n')
    os.environ['PATH'] = str(executable.parent) + os.pathsep + os.environ['PATH']
    os.environ['CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER'] = str(executable)


def native_with_valkey(log):
    # A disposable loopback-only instance, never a configured service or host store.
    directory = root / 'valkey'
    directory.mkdir()
    with socket.socket() as available:
        available.bind(('127.0.0.1', 0))
        port = available.getsockname()[1]
    with (root / 'valkey-server.log').open('w') as server_log:
        server = subprocess.Popen([
            'valkey-server', '--bind', '127.0.0.1', '--port', str(port),
            '--save', '', '--appendonly', 'no', '--maxmemory-policy', 'noeviction',
            '--maxmemory', '64mb', '--dir', str(directory)],
            stdout=server_log, stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError('Disposable Valkey exited before readiness')
                ready = subprocess.run(['valkey-cli', '-p', str(port), 'PING'],
                                       capture_output=True, text=True)
                if ready.returncode == 0 and ready.stdout.strip() == 'PONG':
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError('Disposable Valkey did not become ready')
            run(['bash', '.ci/check.sh', 'native'], log)
            environment = dict(os.environ, VALKEY_URL=f'redis://127.0.0.1:{port}/')
            run(['bash', '.ci/check.sh', 'valkey'], log, environment)
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=10)


original = sha(lock)
mode = sys.argv[1]
if mode == 'preflight':
    for tool in ['curl', 'python3', 'cargo', 'rustc', 'cargo-deny', 'rg',
                 'chromedriver', 'valkey-server', 'valkey-cli']:
        assert shutil.which(tool), 'Missing tool: ' + tool
    chrome = os.environ['CHROME_BIN']
    assert os.access(chrome, os.X_OK), 'Missing qualified browser'
    target_lib = subprocess.check_output(
        ['rustc', '--print', 'target-libdir', '--target', 'wasm32-unknown-unknown'],
        text=True).strip()
    assert list(Path(target_lib).glob('libstd-*.rlib')), 'Stable Wasm stdlib missing'
    with (root / 'tool-versions.txt').open('w') as stream:
        for command in [['rustc', '-Vv'], ['cargo', '-V'], ['cargo', 'deny', '--version'],
                        [chrome, '--version'], ['chromedriver', '--version'],
                        ['valkey-server', '--version'], ['valkey-cli', '--version']]:
            run(command, stream)
        coverage_probe(stream)
    run(['python3', '.github/check-first-party.py', '--self-test'])
    metadata('baseline-dependency-metadata.json')
elif mode == 'run':
    runner(metadata('resolved-dependency-metadata.json'))
    phases = []
    (root / 'phases.json').write_text('[]\n')
    for phase in ['native', 'wasm', 'browser', 'coverage', 'dependency-policy']:
        assert sha(lock) == original, 'Candidate lock changed before phase'
        with (root / (phase + '.log')).open('w') as stream:
            if phase == 'native':
                native_with_valkey(stream)
            else:
                run(['bash', '.ci/check.sh', phase], stream)
        assert sha(lock) == original, 'Candidate lock changed during phase'
        if phase == 'browser':
            assert re.search(r'test result: ok\. [1-9][0-9]* passed;',
                             (root / 'browser.log').read_text()), 'No actual browser tests'
        phases.append({'name': phase, 'status': 'passed', 'lock_before': original,
                       'lock_after': original, 'log': phase + '.log'})
        (root / 'phases.json').write_text(json.dumps(phases, indent=2) + '\n')
else:
    raise SystemExit('Unknown fixed owner selector')
assert sha(lock) == original, 'Owner gate mutated the candidate lock'
