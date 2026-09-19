import argparse
import getpass
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from .config import FIELDS, generate, make_rule
from .runtime import command, core_binary, ping, prepare, restart, serve, start, validate
from .storage import Store, atomic_json, fetch, subscription_name


def clean(text):
    return ''.join(c for c in text if c.isprintable())[:120]


def parser():
    p = argparse.ArgumentParser(prog='vctl', description='macOS Xray client: subscriptions, probes and split routing')
    p.add_argument('--home', default=os.environ.get('VCTL_HOME', str(Path(__file__).resolve().parent.parent / '.local')))
    p.add_argument('--core', help='Path to Xray')
    p.add_argument('--state-home', help=argparse.SUPPRESS)
    subs = p.add_subparsers(dest='command', required=True)
    completion = subs.add_parser('completion', help='Print shell completion file')
    completion.add_argument('shell', choices=['zsh'])
    sub = subs.add_parser('sub', help='Manage subscriptions').add_subparsers(dest='action', required=True)
    add = sub.add_parser('add')
    add.add_argument('name', nargs='?', help='Optional name; defaults to the subscription title')
    add.add_argument('--url', help='Omit to enter privately without shell history')
    add.add_argument('--interval', type=int, default=43200, help='Refresh interval in seconds (minimum 60)')
    sub.add_parser('list')
    update = sub.add_parser('update')
    update.add_argument('name', nargs='?')
    remove = sub.add_parser('remove')
    remove.add_argument('name')
    subs.add_parser('nodes')
    select = subs.add_parser('use')
    select.add_argument('node', help='Stable node ID or auto')
    subs.add_parser('ping', help='HTTPS delay through each server; does not change system routes')
    rules = subs.add_parser('rule').add_subparsers(dest='action', required=True)
    r = rules.add_parser('add')
    r.add_argument('kind', choices=FIELDS)
    r.add_argument('value')
    r.add_argument('target', choices=['direct', 'proxy', 'block'])
    rules.add_parser('list')
    r = rules.add_parser('remove')
    r.add_argument('index', type=int)
    policy = subs.add_parser('default')
    policy.add_argument('target', choices=['proxy', 'direct'])
    for name in ('start', 'run', '_serve', 'check'):
        r = subs.add_parser(name)
        r.add_argument('--mode', choices=['proxy', 'tun'], default='proxy')
        r.add_argument('--port', type=int, default=2080)
    for name in ('stop', 'status', 'doctor'):
        subs.add_parser(name)
    r = subs.add_parser('restart', help='Restart, preserving the running mode and ports unless overridden')
    r.add_argument('--mode', choices=['proxy', 'tun'])
    r.add_argument('--port', type=int)
    tun = subs.add_parser('tun', help='System-wide VPN; requests sudo automatically',
                         description='TUN lifecycle: start (background), run (foreground), restart, stop, status, recover. Manage settings without tun.')
    tun.add_argument('tun_args', nargs=argparse.REMAINDER, metavar='ACTION')
    subs.add_parser('_tun-root', help=argparse.SUPPRESS)
    return p


def run(args):
    if args.command == 'completion':
        from .completion import ZSH
        print(ZSH)
        return
    if args.command == '_tun-root':
        from .tun import root_dispatch
        return root_dispatch()
    store = Store(args.home, args.state_home)
    if args.command == 'tun':
        from .tun import dispatch
        return dispatch(args.tun_args, store, core_binary(args.core))
    if getattr(args, 'port', None) is not None and not 1 <= args.port <= 65534:
        raise ValueError('Port must be 1..65534 (HTTP uses port+1)')
    if args.command in ('status', 'stop'):
        response = command(store, args.command)
        if args.command == 'stop' and response != 'stopped':
            for _ in range(100):
                time.sleep(.1)
                if command(store, 'status') == 'stopped':
                    print('Stopped')
                    return
            raise ValueError('Stop pending; check status again')
        print(response)
        return
    if args.command == 'nodes':
        s = store.read()
        print('Selected:', s['selected'])
        for name, sub in s['subscriptions'].items():
            for n in sub['nodes']:
                print(n['id'], clean(name), clean(n['name']), n['outbound']['type'])
        return
    if args.command in ('sub', 'rule', 'use', 'default'):
        with store.lock():
            s = store.read()
            if args.command == 'sub':
                if args.action == 'list':
                    for name, sub in s['subscriptions'].items():
                        age = int(time.time() - sub['updated'])
                        print(clean(name), f"{len(sub['nodes'])} nodes; age={age}s; interval={sub['interval']}s")
                    return
                if args.action == 'add':
                    if args.name in s['subscriptions']:
                        raise ValueError('Subscription already exists; use sub update')
                    if args.interval < 60:
                        raise ValueError('Minimum update interval is 60 seconds')
                    url = args.url or getpass.getpass('Subscription URL (hidden): ')
                    if any(sub['url'] == url for sub in s['subscriptions'].values()):
                        raise ValueError('This subscription URL already exists; use sub update')
                    subscription = fetch(url, args.interval)
                    name = args.name or subscription_name(s['subscriptions'], subscription['title'])
                    s['subscriptions'][name] = subscription
                elif args.action == 'update':
                    names = [args.name] if args.name else list(s['subscriptions'])
                    for name in names:
                        if name not in s['subscriptions']:
                            raise ValueError('Unknown subscription')
                        old = s['subscriptions'][name]
                        s['subscriptions'][name] = fetch(old['url'], old['interval'])
                elif args.action == 'remove':
                    if args.name not in s['subscriptions']:
                        raise ValueError('Unknown subscription')
                    del s['subscriptions'][args.name]
            elif args.command == 'rule':
                if args.action == 'list':
                    for i, r in enumerate(s['rules'], 1):
                        print(i, r['kind'], clean(r['value']), r['action'])
                    return
                if args.action == 'add':
                    r = make_rule(args.kind, args.value, args.target)
                    if r not in s['rules']:
                        s['rules'].append(r)
                else:
                    if not 1 <= args.index <= len(s['rules']):
                        raise ValueError('Invalid rule index')
                    s['rules'].pop(args.index - 1)
            elif args.command == 'use':
                ids = {n['id'] for sub in s['subscriptions'].values() for n in sub['nodes']}
                if args.node != 'auto' and args.node not in ids:
                    raise ValueError('Unknown node ID; use nodes')
                s['selected'] = args.node
            else:
                s['default'] = args.target
            if s['subscriptions']:
                path = store.home / 'validation.json'
                try:
                    atomic_json(path, generate(s))
                    validate(core_binary(args.core), path)
                finally:
                    path.unlink(missing_ok=True)
            elif command(store, 'status') != 'stopped':
                raise ValueError('Stop the client before removing the last subscription')
            store.write(s)
        if args.command == 'sub' and args.action == 'add':
            print('Subscription:', clean(name))
        print('Saved. Running supervisor applies changes automatically (connections may reconnect).')
        return
    binary = core_binary(args.core)
    if args.command == 'ping':
        results = ping(store, binary)
        for node, delay, reason in results:
            print(node['id'], f'{delay} ms' if delay is not None else 'FAILED', clean(node['name']), reason)
        if not any(delay is not None for _, delay, _ in results):
            raise ValueError('All servers failed HTTPS probes')
    elif args.command in ('run', '_serve'):
        serve(store, binary, args.mode, args.port)
    elif args.command == 'restart':
        restart(store, binary, args.mode, args.port)
        print('Restarted.', command(store, 'status'))
    elif args.command == 'start':
        start(store, binary, args.mode, args.port)
        print('Started.', command(store, 'status'))
    elif args.command == 'check':
        # Validation never replaces a running core's configuration.
        with store.lock():
            path = store.home / 'validation.json'
            try:
                atomic_json(path, generate(store.read(), args.mode, args.port))
                validate(binary, path)
            finally:
                path.unlink(missing_ok=True)
        print('Configuration valid')
    elif args.command == 'doctor':
        version = subprocess.run([binary, 'version'], capture_output=True, text=True, timeout=10)
        print(version.stdout.splitlines()[0])
        print('State:', store.home)
        print('Runtime:', command(store, 'status'))
        print('SOCKS: 127.0.0.1:2080; HTTP: 127.0.0.1:2081; mode tun requires root.')


def main():
    try:
        run(parser().parse_args())
    except KeyboardInterrupt:
        sys.exit(130)
    except BlockingIOError:
        print('Error: another supervisor already uses this profile', file=sys.stderr)
        sys.exit(1)
    except (ValueError, OSError, subprocess.SubprocessError) as e:
        # OSError can contain paths/URLs. Keep diagnostics free of credentials.
        message = str(e) if isinstance(e, ValueError) else type(e).__name__
        print('Error:', message, file=sys.stderr)
        sys.exit(1)
