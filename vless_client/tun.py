"""One user-owned settings file, with privileged TUN runtime in its subdirectory."""
import json
import argparse
import os
from pathlib import Path
import subprocess
import sys

from .storage import Store
from .runtime import core_binary
from .output import color_enabled, print_status


ACTIONS = {'start', 'run', 'restart', 'stop', 'status', 'recover', 'install', 'uninstall'}


def dispatch(args, user_store, binary):
    if not args or args[0] not in ACTIONS:
        raise ValueError('Usage: vctl tun start|run|restart|stop|status|recover|install|uninstall')
    script = Path(__file__).resolve().parent.parent / 'vctl'
    request = {'home': str(user_store.state_home), 'args': args, 'core': binary,
               'color': color_enabled()}
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
    from .launchd import Service
    service = Service(store, profile.stat().st_uid)
    if args[0] != 'run':
        if args[0] == 'status':
            return service_action(service, args, binary, color=request.get('color', False))
        try:
            with store.lock('service.lock', nonblocking=True):
                return service_action(service, args, binary, color=request.get('color', False))
        except BlockingIOError:
            raise ValueError('Another TUN lifecycle operation is in progress') from None
    if service.marker.exists() or service.runtime_status():
        raise ValueError('Stop the running TUN before using foreground mode')
    if '--mode' in args:
        raise ValueError('The tun command always uses TUN mode')
    args += ['--mode', 'tun']
    if '--port' not in args:
        args += ['--port', '2180']
    from .cli import parser, run
    run(parser().parse_args(['--home', str(store.home), '--state-home', str(profile), '--core', binary] + args))


def service_action(service, args, binary, color=None):
    p = argparse.ArgumentParser(prog='vctl tun ' + args[0])
    if args[0] in ('start', 'restart', 'install'):
        p.add_argument('--port', type=int, default=None if args[0] == 'restart' else 2180)
    options = p.parse_args(args[1:])
    if args[0] == 'start':
        service.start(binary, options.port)
        print_status(service.status(), color=color)
    elif args[0] == 'restart':
        service.restart(binary, options.port)
        print_status(service.status(), color=color)
    elif args[0] == 'install':
        service.install(binary, options.port)
        print('Service installed. Start with vctl tun start; boot autostart is disabled.')
    elif args[0] == 'uninstall':
        service.uninstall()
        print('Service removed; profile settings preserved.')
    elif args[0] == 'stop':
        service.stop()
        print_status(service.status(), color=color)
    elif args[0] == 'status':
        print_status(service.status(), color=color)
    elif args[0] == 'recover':
        if service.runtime_status():
            raise ValueError('Stop TUN before recovering DNS')
        service.stop()
        print('TUN resources and DNS restored')
