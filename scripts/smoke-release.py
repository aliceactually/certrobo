#!/usr/bin/env python3
"""Start a packaged Linux x64 build using disposable local state."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

if len(sys.argv) != 2:
    raise SystemExit('Usage: python3 scripts/smoke-release.py CertRobo-linux-x64.zip')

with tempfile.TemporaryDirectory(prefix='certrobo-release-smoke-') as directory:
    root = Path(directory)
    app = root / 'app'
    app.mkdir()
    with zipfile.ZipFile(sys.argv[1]) as archive:
        archive.extractall(app)
    executable = app / 'CertRobo'
    executable.chmod(executable.stat().st_mode | 0o111)
    for relative in ('appsettings.json', 'wwwroot', 'static', 'Resources/Passphrases/eff_large_wordlist.txt'):
        if not (app / relative).exists():
            raise SystemExit('Package is missing ' + relative)

    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    env = os.environ.copy()
    env.update({
        'ASPNETCORE_ENVIRONMENT': 'Production',
        'ASPNETCORE_URLS': f'http://127.0.0.1:{port}',
        'CertRobo__DataDirectory': str(root / 'data'),
    })
    log = root / 'server.log'
    with log.open('w+', encoding='utf-8') as output:
        process = subprocess.Popen([str(executable)], cwd=app, env=env, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                try:
                    with urllib.request.urlopen(f'http://127.0.0.1:{port}/', timeout=2) as response:
                        if response.status == 200:
                            print('Packaged Linux x64 application responded successfully.')
                            break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.5)
            else:
                raise RuntimeError('Application did not respond within 45 seconds')
            if process.poll() is not None:
                raise RuntimeError(f'Application exited with code {process.returncode}')
        except Exception:
            output.flush()
            output.seek(0)
            print(output.read()[-8000:], file=sys.stderr)
            raise
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
