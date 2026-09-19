"""One user-owned settings file, with privileged TUN runtime in its subdirectory."""
import json
import os
from pathlib import Path
import subprocess
import sys

from .storage import Store
from .runtime import core_binary, command


ACTIONS = {'start', 'run', 'restart', 'stop', 'status', 'recover'}


def dispatch(args, user_store, binary):
    if not args or args[0] not in ACTIONS:
        raise ValueError('Usage: vctl tun start|run|restart|stop|status|recover. Manage settings without tun.')
    script = Path(__file__).resolve().parent.parent / 'vctl'
    request = {'home': str(user_store.state_home), 'args': args, 'core': binary}
    result = subprocess.run(['/usr/bin/sudo', sys.executable, str(script), '_tun-root'],
                            input=json.dumps(request), text=True)
    if result.returncode:
        raise ValueError('TUN command failed; see the message above')


def root_dispatch():
    if os.geteuid() != 0:
        raise ValueError('This command requires sudo')
    request = json.loads(sys.stdin.read(2_000_001))
    args = request['args']
    if not args or args[0] not in ACTIONS:
        raise ValueError('Unsupported privileged command')
    profile = Path(request['home']).expanduser().resolve()
    if profile.stat().st_uid != int(os.environ.get('SUDO_UID', '-1')):
        raise ValueError('Profile must belong to the sudo caller')
    store = Store(profile / 'tun', state_home=profile)
    binary = core_binary(request['core'])
    if args[0] == 'recover':
        if command(store, 'status') != 'stopped':
            raise ValueError('Stop TUN before recovering DNS')
        from .watchdog import recover
        with store.lock('runtime.lock', nonblocking=True):
            recover(store)
        print('TUN resources and DNS restored')
        return
    if args[0] in ('start', 'run', 'restart'):
        if '--mode' in args:
            raise ValueError('The tun command always uses TUN mode')
        args += ['--mode', 'tun']
        if '--port' not in args and args[0] != 'restart':
            args += ['--port', '2180']
    from .cli import parser, run
    run(parser().parse_args(['--home', str(store.home), '--state-home', str(profile), '--core', binary] + args))
