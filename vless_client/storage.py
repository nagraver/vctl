import base64
import binascii
import contextlib
import fcntl
import json
import os
from pathlib import Path
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .profiles import parse_subscription


def atomic_json(path, value):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        if os.geteuid() == 0:
            owner = path.parent.stat()
            os.fchown(fd, owner.st_uid, owner.st_gid)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Store:
    def __init__(self, home, state_home=None):
        self.home = Path(home).expanduser().resolve()
        self.home.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.home.stat().st_uid != os.geteuid():
            raise ValueError('Profile directory must belong to the current user; use a separate root-owned profile for TUN')
        if len(str(self.home / 'control.sock').encode()) >= 104:
            raise ValueError('Profile path is too long for a macOS control socket; use a shorter --home')
        self.home.chmod(0o700)
        self.state_home = Path(state_home).expanduser().resolve() if state_home else self.home
        if self.state_home != self.home:
            owner = self.state_home.stat().st_uid
            if os.geteuid() != 0 or owner != int(os.environ.get('SUDO_UID', '-1')):
                raise ValueError('Shared profile must belong to the sudo caller')
        self.path = self.state_home / 'state.json'

    @contextlib.contextmanager
    def lock(self, name='state.lock', nonblocking=False):
        directory = self.state_home if name == 'state.lock' else self.home
        fd = os.open(directory / name, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            if os.geteuid() == 0:
                owner = directory.stat()
                os.fchown(fd, owner.st_uid, owner.st_gid)
            fcntl.flock(fd, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
            yield
        finally:
            os.close(fd)

    def read(self):
        if self.path.exists():
            return json.loads(self.path.read_text())
        return {'version': 1, 'subscriptions': {}, 'rules': [], 'selected': 'auto',
                'default': 'proxy', 'test_url': 'https://www.gstatic.com/generate_204'}

    def write(self, state):
        atomic_json(self.path, state)


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != 'https':
            raise ValueError('Non-HTTPS subscription redirect refused')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, interval=43200):
    if urlsplit(url).scheme != 'https':
        raise ValueError('Subscription URL must use HTTPS')
    try:
        opener = urllib.request.build_opener(HTTPSRedirect())
        with opener.open(urllib.request.Request(url, headers={'User-Agent': 'vctl/0.1'}), timeout=20) as r:
            title = subscription_title(r.headers.get('Profile-Title', ''), url)
            nodes = parse_subscription(r.read(2_000_001))
    except (urllib.error.URLError, TimeoutError, OSError):
        raise ValueError('Subscription download failed; existing cache preserved') from None
    return {'url': url, 'interval': interval, 'updated': time.time(), 'nodes': nodes, 'title': title}


def subscription_title(header, url):
    value = header.strip()
    if value.lower().startswith('base64:'):
        try:
            encoded = value[7:].strip()
            value = base64.b64decode(encoded + '=' * (-len(encoded) % 4), validate=True).decode('utf-8')
        except (ValueError, binascii.Error, UnicodeError):
            value = ''
    value = ''.join(c for c in value if c.isprintable()).strip()[:120]
    return value or urlsplit(url).hostname or 'subscription'


def subscription_name(subscriptions, title):
    name = title
    suffix = 2
    while name in subscriptions:
        name = f'{title} ({suffix})'
        suffix += 1
    return name
