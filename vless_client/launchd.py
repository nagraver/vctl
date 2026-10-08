"""Manual-start system LaunchDaemon, independent of the invoking terminal."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

from . import runtime
from .config import generate
from .routing_data import validate_assets
from .storage import Store, atomic_json

DAEMONS = Path('/Library/LaunchDaemons')
APPLICATIONS = Path('/Library/Application Support/vctl')
RUN = Path('/var/run')
SOURCE = Path(__file__).resolve().parent.parent


def label_for(profile, uid):
    digest = hashlib.sha256(str(Path(profile).resolve()).encode()).hexdigest()[:12]
    return f'io.github.nagraver.vctl.{uid}.{digest}'


def interpreter():
    # Keep Homebrew's stable opt path across patch upgrades of Python.
    for prefix in ('/opt/homebrew', '/usr/local'):
        candidate = Path(prefix) / 'opt' / f'python@{sys.version_info.major}.{sys.version_info.minor}' / 'bin' / f'python{sys.version_info.major}.{sys.version_info.minor}'
        if candidate.exists() and candidate.resolve() == Path(sys.executable).resolve():
            return str(candidate)
    return str(Path(sys.executable).resolve())


def physical_interface():
    result = subprocess.run(['/sbin/route', '-n', 'get', 'default'], capture_output=True, text=True, timeout=5)
    match = re.search(r'^\s*interface:\s*([A-Za-z0-9._-]+)\s*$', result.stdout, re.MULTILINE)
    if result.returncode or not match or match[1].startswith(('utun', 'lo')):
        raise ValueError('Cannot find the physical default interface for TUN preflight')
    return match[1]


def root_directory(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Service directory must not be a symlink')
    path.mkdir(mode=0o755, parents=True, exist_ok=True)
    stat = path.stat()
    if stat.st_uid != 0 or stat.st_mode & 0o022:
        raise ValueError('Service directory must be root-owned and not writable by other users')
    return path


def write_plist(path, data):
    fd, temporary = tempfile.mkstemp(prefix='.vctl-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o644)
            os.fchown(stream.fileno(), 0, 0)
            plistlib.dump(data, stream)
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def snapshot(binary, directory):
    """Copy executable code into a root-owned immutable release, not user settings."""
    root_directory(APPLICATIONS)
    root_directory(directory)
    files = {'vctl': (SOURCE / 'vctl').read_bytes(), '.tools/xray': Path(binary).read_bytes()}
    for path in sorted((SOURCE / 'vless_client').rglob('*')):
        if path.is_file() and (path.suffix == '.py' or path.name == '_vctl'):
            files[str(path.relative_to(SOURCE))] = path.read_bytes()
    digest = hashlib.sha256()
    for name, body in sorted(files.items()):
        digest.update(name.encode() + b'\0' + hashlib.sha256(body).digest())
    release = directory / digest.hexdigest()
    if release.exists():
        root_directory(release)
        return release
    temporary = Path(tempfile.mkdtemp(prefix='.install-', dir=directory))
    try:
        for name, body in files.items():
            target = temporary / name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            target.write_bytes(body)
            target.chmod(0o755 if name in ('vctl', '.tools/xray') else 0o644)
        temporary.chmod(0o755)
        os.replace(temporary, release)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return release


def definition(label, profile, uid, release, port, marker):
    return {
        'Label': label,
        'ProgramArguments': [interpreter(), '-E', '-s', str(release / 'vctl'),
                             '--core', str(release / '.tools/xray'), '_tun-service',
                             '--profile', str(profile), '--owner', str(uid), '--port', str(port)],
        'WorkingDirectory': str(release),
        'EnvironmentVariables': {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'PYTHONUNBUFFERED': '1',
                                 'VCTL_LAUNCHD_LABEL': label},
        'RunAtLoad': False,
        # /var/run is cleared at boot: crash recovery does not imply boot autostart.
        'KeepAlive': {'PathState': {str(marker): True}},
        'ThrottleInterval': 15,
        'ExitTimeOut': 45,
        'Umask': 0o077,
        'StandardOutPath': str(profile / 'tun' / 'supervisor.log'),
        'StandardErrorPath': str(profile / 'tun' / 'supervisor.log'),
    }


class Service:
    def __init__(self, store, uid):
        self.store = store
        self.uid = uid
        self.label = label_for(store.state_home, uid)
        self.target = 'system/' + self.label
        self.plist = DAEMONS / (self.label + '.plist')
        self.marker = RUN / (self.label + '.enabled')
        self.directory = APPLICATIONS / self.label

    def ctl(self, *args, check=True):
        result = subprocess.run(['/bin/launchctl', *args], capture_output=True, text=True, timeout=60)
        if check and result.returncode:
            raise ValueError('launchd operation failed: ' + args[0] + '; run vctl tun status')
        return result

    def loaded(self):
        return self.ctl('print', self.target, check=False).returncode == 0

    def runtime_status(self):
        try:
            result = runtime.command(self.store, 'status')
            return json.loads(result) if result != 'stopped' else None
        except TimeoutError:
            return {'starting': True}

    def status(self):
        loaded = self.loaded()
        status = self.runtime_status()
        manager = status.get('manager', 'standalone') if status and not status.get('starting') else ('launchd' if loaded else 'standalone')
        return {'manager': manager, 'service': self.label, 'registered': loaded,
                'installed': self.plist.exists(), 'enabled': self.marker.exists(),
                'autostart': False, 'runtime': status}

    def install(self, binary, port=2180):
        if not 1 <= port <= 65534:
            raise ValueError('Port must be 1..65534')
        root_directory(DAEMONS)
        release = snapshot(binary, self.directory)
        data = definition(self.label, self.store.state_home, self.uid, release, port, self.marker)
        previous = plistlib.loads(self.plist.read_bytes()) if self.plist.exists() else None
        loaded = self.loaded()
        if previous == data and loaded:
            return
        if loaded:
            if self.marker.exists() or self.runtime_status():
                raise ValueError('Stop the service or use tun restart before updating its installation')
            self.ctl('bootout', self.target)
        self.marker.unlink(missing_ok=True)
        write_plist(self.plist, data)
        try:
            self.ctl('bootstrap', 'system', str(self.plist))
        except Exception:
            if previous:
                write_plist(self.plist, previous)
                if loaded:
                    self.ctl('bootstrap', 'system', str(self.plist), check=False)
            else:
                self.plist.unlink(missing_ok=True)
            raise

    def preflight(self, binary, port):
        if not 1 <= port <= 65534:
            raise ValueError('Port must be 1..65534')
        with self.store.lock():
            state = self.store.read()
            resolved = runtime.resolve_tun_state(state)
            fd, name = tempfile.mkstemp(prefix='preflight-', suffix='.json', dir=self.store.home)
            os.close(fd)
            path = Path(name)
            try:
                atomic_json(path, generate(resolved, 'tun', port))
                validate_assets(self.store, binary, state)
                runtime.validate(binary, path, self.store.state_home / 'geodata')
            finally:
                path.unlink(missing_ok=True)
        probes = runtime.ping(self.store, binary, interface=physical_interface())
        if not any(delay is not None and (state['selected'] == 'auto' or node['id'] == state['selected'])
                   for node, delay, _ in probes):
            raise ValueError('Selected servers failed preflight; running VPN was not stopped')

    def wait_ready(self, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.runtime_status()
            if status and status.get('manager') == 'launchd' and not status.get('stopping'):
                return status
            time.sleep(.2)
        raise ValueError('Service startup timed out; see tun/supervisor.log')

    def enable(self):
        fd = os.open(self.marker, os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        self.ctl('kickstart', self.target)
        return self.wait_ready()

    def stop(self):
        # Clear KeepAlive before any stop request, or launchd would restart the VPN.
        self.marker.unlink(missing_ok=True)
        if self.loaded():
            self.ctl('bootout', self.target)
        # A newly installed idle job can coexist with a legacy supervisor.
        try:
            runtime.command(self.store, 'stop')
        except TimeoutError:
            pass
        deadline = time.monotonic() + 50
        while time.monotonic() < deadline:
            try:
                with self.store.lock('runtime.lock', nonblocking=True):
                    from .watchdog import recover
                    recover(self.store)
                    return
            except BlockingIOError:
                time.sleep(.2)
        raise ValueError('Stop pending; recovery was not attempted while the supervisor is running')

    def start(self, binary, port=2180):
        if self.runtime_status() or self.marker.exists():
            raise ValueError('Already running or starting; use tun restart to migrate/update the service')
        self.preflight(binary, port)
        self.install(binary, port)
        try:
            return self.enable()
        except Exception:
            self.stop()
            raise

    def restart(self, binary, port=None):
        previous_status = self.runtime_status()
        if previous_status and previous_status.get('starting'):
            raise ValueError('Startup in progress; wait for tun status before restarting')
        old_port = (previous_status or {}).get('socks_port', 2180)
        port = old_port if port is None else port
        # Check new code, configuration and connectivity before touching a working VPN.
        self.preflight(binary, port)
        old_plist = self.plist.read_bytes() if self.plist.exists() else None
        old_managed = self.loaded() and (previous_status or {}).get('manager') == 'launchd'
        self.stop()
        try:
            self.install(binary, port)
            return self.enable()
        except Exception as error:
            self.stop()
            if previous_status:
                if old_managed and old_plist:
                    write_plist(self.plist, plistlib.loads(old_plist))
                    self.ctl('bootstrap', 'system', str(self.plist))
                    self.enable()
                else:
                    runtime.start(self.store, binary, 'tun', old_port)
                raise ValueError('New service failed; previous VPN launch mode restored') from error
            raise

    def uninstall(self):
        self.stop()
        self.plist.unlink(missing_ok=True)
        if self.directory.exists():
            root_directory(APPLICATIONS)
            root_directory(self.directory)
            shutil.rmtree(self.directory)


def serve(profile, uid, binary, port):
    if os.geteuid() != 0:
        raise ValueError('The system service requires root')
    profile = Path(profile).resolve()
    label = label_for(profile, uid)
    if os.environ.get('VCTL_LAUNCHD_LABEL') != label:
        raise ValueError('This entry point must be launched by the installed service')
    store = Store(profile / 'tun', state_home=profile, owner_uid=uid)
    if not (RUN / (label + '.enabled')).exists():
        return
    runtime.serve(store, binary, 'tun', port)
