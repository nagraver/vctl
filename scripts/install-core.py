#!/usr/bin/env python3
"""Fetch the pinned official macOS Xray archive and verify the GitHub asset digest."""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import tempfile
import urllib.request
import zipfile

VERSION = '26.9.9'


def main():
    if platform.system() != 'Darwin':
        raise SystemExit('This installer targets macOS')
    machine = platform.machine()
    if machine not in ('arm64', 'x86_64'):
        raise SystemExit('Unsupported architecture')
    name = 'Xray-macos-arm64-v8a.zip' if machine == 'arm64' else 'Xray-macos-64.zip'
    url = f'https://api.github.com/repos/XTLS/Xray-core/releases/tags/v{VERSION}'
    with urllib.request.urlopen(url, timeout=30) as response:
        release = json.load(response)
    asset = next(a for a in release['assets'] if a['name'] == name)
    with urllib.request.urlopen(asset['browser_download_url'], timeout=60) as response:
        data = response.read()
    if asset.get('digest') != 'sha256:' + hashlib.sha256(data).hexdigest():
        raise SystemExit('Digest missing or mismatched; existing binary preserved')
    directory = Path(__file__).resolve().parent.parent / '.tools'
    directory.mkdir(exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=directory, prefix='.xray-')
    try:
        with os.fdopen(fd, 'wb') as output, zipfile.ZipFile(io.BytesIO(data)) as archive:
            output.write(archive.read('xray'))
        os.chmod(temporary, 0o755)
        os.replace(temporary, directory / 'xray')
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print(f'Installed verified Xray {VERSION}: {directory / "xray"}')


if __name__ == '__main__':
    main()
