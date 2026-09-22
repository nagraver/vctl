"""Versioned routing presets and immutable, profile-local Xray databases."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit

from .config import PRIVATE, make_rule
from .storage import HTTPSRedirect

DEFAULT_URL = 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/{}.dat'
BUILTINS = {
    'lan': {'version': 1, 'rules': [make_rule('cidr', value, 'direct') for value in PRIVATE]},
    'ads': {'version': 1, 'rules': [make_rule('geosite', 'category-ads-all', 'block')]},
}


def download(url, limit):
    if urlsplit(url).scheme != 'https':
        raise ValueError('Routing data URL must use HTTPS')
    try:
        opener = urllib.request.build_opener(HTTPSRedirect())
        with opener.open(urllib.request.Request(url, headers={'User-Agent': 'vctl'}), timeout=30) as response:
            body = response.read(limit + 1)
    except (OSError, TimeoutError):
        raise ValueError('Routing data download failed; previous cache preserved') from None
    if not body or len(body) > limit:
        raise ValueError('Routing data is empty or exceeds the size limit')
    return body


def interval_value(value):
    if type(value) is not int or value < 60:
        raise ValueError('Minimum update interval is 60 seconds')
    return value


def load_preset(source, interval=43200):
    interval_value(interval)
    if source.startswith('builtin:'):
        name = source.removeprefix('builtin:')
        if name not in BUILTINS:
            raise ValueError('Unknown built-in preset; available: lan, ads')
        data = BUILTINS[name]
    else:
        if urlsplit(source).scheme:
            body = download(source, 2_000_000)
        else:
            source = str(Path(source).expanduser().resolve())
            with open(source, 'rb') as stream:
                body = stream.read(2_000_001)
            if len(body) > 2_000_000:
                raise ValueError('Preset exceeds 2 MB')
        try:
            data = json.loads(body)
        except (ValueError, UnicodeError):
            raise ValueError('Preset must be a UTF-8 JSON document') from None
    if not isinstance(data, dict) or set(data) - {'version', 'rules', 'description'} or data.get('version') != 1:
        raise ValueError('Preset requires version 1 and rules; optional description')
    rules = data.get('rules')
    if not isinstance(rules, list) or not 1 <= len(rules) <= 5000:
        raise ValueError('Preset must contain 1..5000 rules')
    if any(not isinstance(r, dict) or set(r) != {'kind', 'value', 'action'} for r in rules):
        raise ValueError('Each preset rule requires kind, value, action')
    try:
        rules = [make_rule(**r) for r in rules]
    except (TypeError, UnicodeError):
        raise ValueError('Invalid preset rule') from None
    return {'source': source, 'interval': interval, 'updated': time.time(),
            'enabled': True, 'rules': rules}


def cache_asset(store, body):
    directory = store.state_home / 'geodata'
    directory.mkdir(mode=0o700, exist_ok=True)
    owner = store.state_home.stat()
    if os.geteuid() == 0:
        os.chown(directory, owner.st_uid, owner.st_gid)
    digest = hashlib.sha256(body).hexdigest()
    fd, temporary = tempfile.mkstemp(prefix='.pending-', dir=directory)
    try:
        if os.geteuid() == 0:
            os.fchown(fd, owner.st_uid, owner.st_gid)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, directory / (digest + '.dat'))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return digest


def fetch_geodata(store, kind, url, interval=86400):
    interval_value(interval)
    body = download(url, 64_000_000)
    return {'url': url, 'sha256': cache_asset(store, body),
            'updated': time.time(), 'interval': interval}


def refresh(store, state):
    """Mutate a candidate only; callers validate before committing the state."""
    now = time.time()
    for name, preset in list(state.get('presets', {}).items()):
        # Only remote presets refresh automatically; root never reads arbitrary local files.
        if preset.get('enabled', True) and preset['source'].startswith('https://') and now - preset['updated'] >= preset['interval']:
            state['presets'][name] = load_preset(preset['source'], preset['interval'])
    for kind, asset in list(state.get('geodata', {}).items()):
        if now - asset['updated'] >= asset['interval']:
            state['geodata'][kind] = fetch_geodata(store, kind, asset['url'], asset['interval'])


def asset_env(directory):
    return dict(os.environ, XRAY_LOCATION_ASSET=str(directory))


def first_category(body):
    """Read a category from a standard protobuf list; Xray performs final validation."""
    def fields(data):
        offset = 0
        def varint():
            nonlocal offset
            value = 0
            for shift in range(0, 70, 7):
                if offset >= len(data):
                    raise ValueError('Truncated geodata')
                byte = data[offset]; offset += 1
                value |= (byte & 127) << shift
                if byte < 128:
                    return value
            raise ValueError('Invalid geodata integer')
        while offset < len(data):
            tag = varint(); wire = tag & 7
            if wire == 2:
                length = varint(); end = offset + length
                if end > len(data):
                    raise ValueError('Truncated geodata field')
                yield tag >> 3, data[offset:end]
                offset = end
            elif wire == 0:
                varint()
            elif wire in (1, 5):
                offset += 8 if wire == 1 else 4
                if offset > len(data):
                    raise ValueError('Truncated geodata field')
            else:
                raise ValueError('Invalid geodata format')
    for number, entry in fields(body):
        if number == 1:
            for field, value in fields(entry):
                if field == 1:
                    try:
                        return make_rule('geosite', value.decode('ascii'), 'direct')['value']
                    except (ValueError, UnicodeError):
                        raise ValueError('Invalid geodata category') from None
    raise ValueError('Geodata contains no categories')


def validate_assets(store, binary, state):
    """Validate both databases even when no active rule references them yet."""
    from .runtime import validate
    from .storage import atomic_json
    for kind, asset in state.get('geodata', {}).items():
        digest = asset.get('sha256', '')
        if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('Invalid geodata digest')
        body = (store.state_home / 'geodata' / (digest + '.dat')).read_bytes()
        if hashlib.sha256(body).hexdigest() != digest:
            raise ValueError('Geodata checksum mismatch; run geodata update')
        category = first_category(body)
        value = f'ext:{digest}.dat:{category}'
        config = {'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}],
                  'routing': {'rules': [{'type': 'field', 'outboundTag': 'direct',
                                       'ip' if kind == 'geoip' else 'domain': [value]}]}}
        path = store.home / 'geodata-validation.json'
        try:
            atomic_json(path, config)
            validate(binary, path, store.state_home / 'geodata')
        finally:
            path.unlink(missing_ok=True)
