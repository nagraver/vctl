import concurrent.futures
import copy
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import sys
import uuid
import urllib.parse

from .config import generate
from .storage import atomic_json, fetch
from .macos import DNSLease
from .routing_data import asset_env, refresh, validate_assets


def core_binary(override=None):
    local = Path(__file__).resolve().parent.parent / '.tools' / 'xray'
    candidate = override or os.environ.get('VCTL_CORE') or (str(local) if local.exists() else None) or shutil.which('xray')
    if not candidate:
        raise ValueError('Xray missing. Install: brew install xray; or set VCTL_CORE')
    candidate = str(Path(candidate).resolve())
    version = subprocess.run([candidate, 'version'], capture_output=True, text=True, timeout=10)
    if version.returncode or not version.stdout.startswith('Xray '):
        raise ValueError('Selected binary is not Xray; update VCTL_CORE or --core')
    return candidate


def validate(binary, path, assets=None):
    result = subprocess.run([binary, 'run', '-test', '-c', str(path)], capture_output=True, timeout=20,
                            env=asset_env(assets) if assets else None)
    if result.returncode:
        # Core diagnostics can contain credentials; do not forward them to a terminal.
        raise ValueError('Xray rejected the configuration; current configuration preserved')


def prepare(store, binary, state, mode, port):
    if mode == 'tun':
        state = resolve_tun_state(state)
    config = generate(state, mode, port)
    candidate = store.home / 'candidate.json'
    atomic_json(candidate, config)
    try:
        validate_assets(store, binary, state)
        validate(binary, candidate, store.state_home / 'geodata')
        os.replace(candidate, store.home / 'config.json')
    finally:
        candidate.unlink(missing_ok=True)
    return store.home / 'config.json'


def resolve_tun_state(state):
    """Pin upstream IPs before the TUN/DNS switch to avoid recursive bootstrap."""
    state = copy.deepcopy(state)
    for sub in state['subscriptions'].values():
        for node in sub['nodes']:
            outbound = node['outbound']
            try:
                ipaddress.ip_address(outbound['server'])
            except ValueError:
                addresses = socket.getaddrinfo(outbound['server'], outbound['server_port'], type=socket.SOCK_STREAM)
                addresses.sort(key=lambda item: item[0] != socket.AF_INET)
                if not addresses:
                    raise ValueError('Cannot resolve VPN server before TUN start')
                outbound['server'] = addresses[0][4][0]
    return state


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait_ready(process, port, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ValueError('Xray failed to start (configuration or port conflict)')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                return
        except OSError:
            time.sleep(.05)
    raise ValueError('Xray listener did not become ready')


def wait_tun_ready(process, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ValueError('Xray exited during TUN initialization')
        result = subprocess.run(['/sbin/route', '-n', 'get', '198.19.255.53'],
                                capture_output=True, text=True, timeout=2)
        if 'gateway: 172.28.0.1' in result.stdout and 'interface: utun' in result.stdout:
            return
        time.sleep(.1)
    raise ValueError('TUN route did not become ready; DNS was not changed')


def ping(store, binary):
    state = store.read()
    if urllib.parse.urlsplit(state['test_url']).scheme != 'https':
        raise ValueError('Probe URL must use HTTPS')
    nodes = {n['id']: n for sub in state['subscriptions'].values() for n in sub['nodes']}
    if not nodes:
        raise ValueError('Add a subscription first')
    def test(node):
        with tempfile.TemporaryDirectory(prefix='probe-', dir=store.home) as directory:
            port = free_port()
            while port == 65535:
                port = free_port()
            probe = dict(state, subscriptions={'probe': {'nodes': [node]}}, selected=node['id'], rules=[], presets={}, default='proxy')
            config = generate(probe, 'proxy', port)
            # A dedicated inbound ensures no user bypass rule can fake a successful probe.
            config['inbounds'] = config['inbounds'][:1]
            config['routing']['rules'] = [{'type': 'field', 'network': 'tcp,udp', 'outboundTag': 'node-' + node['id']}]
            path = Path(directory) / 'config.json'
            atomic_json(path, config)
            validate(binary, path)
            process = subprocess.Popen([binary, 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                wait_ready(process, port)
                result = subprocess.run(['curl', '--silent', '--output', '/dev/null', '--write-out', '%{http_code} %{time_total}',
                                         '--noproxy', '', '--proxy', f'socks5h://127.0.0.1:{port}', '--max-time', '10',
                                         '--proto', '=https', state['test_url']], capture_output=True, text=True, timeout=12)
                parts = result.stdout.split()
                if result.returncode == 0 and len(parts) == 2 and 200 <= int(parts[0]) < 400:
                    return node, round(float(parts[1]) * 1000), ''
                return node, None, 'HTTPS probe failed (connection, TLS or HTTP status)'
            except (OSError, ValueError, subprocess.SubprocessError):
                return node, None, 'HTTPS probe failed (startup, connection or timeout)'
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        return sorted(pool.map(test, nodes.values()), key=lambda item: item[1] if item[1] is not None else float('inf'))


def command(store, operation):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(3)
        try:
            sock.connect(str(store.home / 'control.sock'))
            sock.sendall(operation.encode())
            return sock.recv(8192).decode()
        except (FileNotFoundError, ConnectionRefusedError):
            return 'stopped'


def serve(store, binary, mode, port):
    if mode == 'tun' and os.geteuid() != 0:
        raise ValueError('TUN needs root. Use vctl tun start')
    with store.lock('runtime.lock', nonblocking=True):
        if mode == 'tun':
            from .watchdog import recover
            recover(store)
            selected = store.read()['selected']
            probes = ping(store, binary)
            if not any(delay is not None and (selected == 'auto' or node['id'] == selected)
                       for node, delay, _ in probes):
                raise ValueError('TUN not started: selected servers failed HTTPS checks. Run ping for details')
        socket_path = store.home / 'control.sock'
        socket_path.unlink(missing_ok=True)
        running = True
        child = None
        dns = DNSLease(store) if mode == 'tun' else None
        watcher = None
        instance = uuid.uuid4().hex
        def stop(*_):
            nonlocal running
            running = False
        old_handlers = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGINT)}
        def stop_child():
            if child and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        quiet = open(os.devnull, 'w')
        def launch():
            process = subprocess.Popen([binary, 'run', '-c', str(store.home / 'config.json')],
                                       stdout=quiet, stderr=quiet, start_new_session=True,
                                       env=asset_env(store.state_home / 'geodata'))
            if dns:
                from .watchdog import process_command
                atomic_json(store.home / 'runtime.json', {'instance': instance, 'pid': os.getpid(),
                            'core_pid': process.pid, 'supervisor_command': process_command(os.getpid())})
            return process
        try:
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(socket_path))
                os.chmod(socket_path, 0o600)
                listener.listen(4)
                listener.settimeout(1)
                state = store.read()
                prepare(store, binary, state, mode, port)
                child = launch()
                if dns:
                    watcher = subprocess.Popen([sys.executable, '-m', 'vless_client.watchdog', str(store.home), instance],
                                               stdin=subprocess.DEVNULL, stdout=quiet, stderr=quiet,
                                               cwd=Path(__file__).resolve().parent.parent, start_new_session=True)
                wait_ready(child, port)
                if dns:
                    wait_tun_ready(child)
                    dns.acquire()
                applied = json.dumps(state, sort_keys=True)
                retry_at = 0
                last_error = ''
                print(f'Running {mode}; subscription auto-refresh enabled', flush=True)
                while running:
                    if child.poll() is not None:
                        raise ValueError('Xray exited; run doctor to check configuration and ports')
                    try:
                        conn, _ = listener.accept()
                    except socket.timeout:
                        conn = None
                    if conn:
                        with conn:
                            conn.settimeout(1)
                            try:
                                op = conn.recv(64).decode()
                                if op == 'stop':
                                    running = False
                                response = json.dumps({'mode': mode, 'pid': os.getpid(), 'core_pid': child.pid,
                                                       'engine': 'xray', 'socks_port': port, 'http_port': port + 1,
                                                       'error': last_error, 'stopping': not running})
                                conn.sendall(response.encode())
                            except (OSError, UnicodeError):
                                pass
                    if not running:
                        break
                    if time.time() < retry_at:
                        continue
                    try:
                        with store.lock():
                            current = store.read()
                            refresh(store, current)
                            for name, sub in list(current['subscriptions'].items()):
                                if time.time() - sub['updated'] >= sub['interval']:
                                    current['subscriptions'][name] = fetch(sub['url'], sub['interval'])
                            fingerprint = json.dumps(current, sort_keys=True)
                            if fingerprint != applied:
                                previous = json.loads((store.home / 'config.json').read_text())
                                prepare(store, binary, current, mode, port)
                                updated = json.loads((store.home / 'config.json').read_text())
                                # Refresh timestamps alone must not disconnect active sessions.
                                if updated != previous:
                                    stop_child()
                                    child = launch()
                                    try:
                                        wait_ready(child, port)
                                        if dns:
                                            wait_tun_ready(child)
                                    except ValueError:
                                        stop_child()
                                        atomic_json(store.home / 'config.json', previous)
                                        child = launch()
                                        raise ValueError('New configuration failed; previous configuration restored')
                                store.write(current)
                                applied = fingerprint
                        last_error = ''
                    except (ValueError, OSError, subprocess.SubprocessError):
                        last_error = 'Update failed; previous configuration retained; retry in 60s'
                        retry_at = time.time() + 60
                stop_child()
        finally:
            stop_child()
            try:
                if dns:
                    dns.restore()
            finally:
                if watcher:
                    watcher.terminate()
                    watcher.wait(timeout=5)
                (store.home / 'runtime.json').unlink(missing_ok=True)
                quiet.close()
                socket_path.unlink(missing_ok=True)
                for sig, handler in old_handlers.items():
                    signal.signal(sig, handler)


def restart(store, binary, mode=None, port=None):
    response = command(store, 'status')
    previous = json.loads(response) if response != 'stopped' else {}
    mode = mode or previous.get('mode', 'proxy')
    port = port if port is not None else previous.get('socks_port', 2180 if mode == 'tun' else 2080)
    # Reject invalid settings before interrupting the working process.
    prepare(store, binary, store.read(), mode, port)
    if previous:
        command(store, 'stop')
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if command(store, 'status') == 'stopped':
                try:
                    with store.lock('runtime.lock', nonblocking=True):
                        break
                except BlockingIOError:
                    pass
            time.sleep(.1)
        else:
            raise ValueError('Stop pending; restart cancelled. Check status.')
    start(store, binary, mode, port)


def start(store, binary, mode, port):
    if command(store, 'status') != 'stopped':
        raise ValueError('Already running')
    if mode == 'tun' and os.geteuid() != 0:
        raise ValueError('TUN requires sudo; use vctl tun start')
    prepare(store, binary, store.read(), mode, port)
    import sys
    args = [sys.executable, '-m', 'vless_client', '--home', str(store.home), '--core', binary,
            '--state-home', str(store.state_home), '_serve', '--mode', mode, '--port', str(port)]
    fd = os.open(store.home / 'supervisor.log', os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    with os.fdopen(fd, 'a') as log:
        child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                 start_new_session=True, cwd=Path(__file__).resolve().parent.parent)
    for _ in range(300):
        if child.poll() is not None:
            raise ValueError('Supervisor failed to start; see private supervisor.log')
        time.sleep(.1)
        try:
            if command(store, 'status') != 'stopped':
                return
        except TimeoutError:
            continue
    raise ValueError('Startup timed out; check status')
