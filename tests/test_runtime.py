"""Opt-in integration test: real core, loopback sockets, no VPN or external requests."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from test_client import state
from vless_client.runtime import command, core_binary, free_port, wait_ready
from vless_client.storage import Store, atomic_json
from vless_client.config import generate


@unittest.skipUnless(os.environ.get('VCTL_INTEGRATION') == '1', 'opt-in loopback integration')
class RuntimeTest(unittest.TestCase):
    def test_sniffed_domain_replaces_stale_destination_ip(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200); self.end_headers(); self.wfile.write(b'correct-address')
            def log_message(self, *_):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory(prefix='vctl-', dir='/tmp') as d:
                s = state()
                s['rules'] = [{'kind': 'suffix', 'value': 'sevsu.ru', 'action': 'direct'}]
                s['selected'] = s['subscriptions']['test']['nodes'][0]['id']
                port = free_port(); config = generate(s, port=port)
                config.pop('observatory', None)
                config['dns']['hosts'] = {'full:schedule.sevsu.ru': '127.0.0.1'}
                path = Path(d) / 'config.json'; atomic_json(path, config)
                process = subprocess.Popen([core_binary(), 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    wait_ready(process, port)
                    # SOCKS receives a wrong numeric destination; HTTP Host supplies the domain.
                    result = subprocess.run(['curl', '--silent', '--noproxy', '', '--max-time', '4',
                                             '--proxy', f'socks5://127.0.0.1:{port}',
                                             '--resolve', f'schedule.sevsu.ru:{server.server_port}:127.0.0.2',
                                             f'http://schedule.sevsu.ru:{server.server_port}/'], capture_output=True, text=True, timeout=6)
                    self.assertEqual(result.stdout, 'correct-address', result.stderr)
                finally:
                    process.terminate(); process.wait(timeout=5)
        finally:
            server.shutdown(); server.server_close(); worker.join(timeout=5)

    def test_darwin_process_matching_without_system_routes(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200); self.end_headers(); self.wfile.write(b'process-direct')
            def log_message(self, *_):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
        try:
            with tempfile.TemporaryDirectory(prefix='vctl-', dir='/tmp') as d:
                for kind, value in [('process', 'curl'), ('path', '/usr/bin/curl'), ('process', 'not-the-requesting-process')]:
                    s = state()
                    s['rules'] = [{'kind': kind, 'value': value, 'action': 'direct'},
                                  {'kind': 'cidr', 'value': '127.0.0.0/8', 'action': 'block'}]
                    s['selected'] = s['subscriptions']['test']['nodes'][0]['id']
                    port = free_port(); config = generate(s, port=port)
                    config.pop('observatory', None)
                    # Exercise the actual Darwin socket lookup with a loopback SOCKS inbound.
                    # No utun, system routes, DNS or active VPN are changed.
                    config['inbounds'][0]['tag'] = 'tun-in'
                    path = Path(d) / 'config.json'; atomic_json(path, config)
                    process = subprocess.Popen([core_binary(), 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    try:
                        wait_ready(process, port)
                        result = subprocess.run(['/usr/bin/curl', '--silent', '--noproxy', '', '--max-time', '3',
                                                 '--proxy', f'socks5://127.0.0.1:{port}',
                                                 f'http://127.0.0.1:{server.server_port}/'], capture_output=True, text=True, timeout=5)
                        if value == 'not-the-requesting-process':
                            self.assertNotEqual(result.stdout, 'process-direct')
                        else:
                            self.assertEqual(result.stdout, 'process-direct', result.stderr)
                    finally:
                        process.terminate(); process.wait(timeout=5)
        finally:
            server.shutdown(); server.server_close(); worker.join(timeout=5)

    def test_domain_direct_and_block_with_real_requests(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200); self.end_headers(); self.wfile.write(b'local-target')

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory(prefix='vctl-', dir='/tmp') as d:
                s = state()
                node = s['subscriptions']['test']['nodes'][0]
                node['outbound'].update(server='127.0.0.1', server_port=1)
                s['selected'] = node['id']
                for action in ('direct', 'block'):
                    s['rules'] = [{'kind': 'domain', 'value': 'localhost', 'action': action}]
                    port = free_port()
                    path = Path(d) / 'config.json'
                    config = generate(s, port=port)
                    config['dns']['hosts'] = {'localhost': '127.0.0.1'}
                    atomic_json(path, config)
                    process = subprocess.Popen([core_binary(), 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    try:
                        wait_ready(process, port)
                        result = subprocess.run(['curl', '--silent', '--noproxy', '', '--max-time', '3',
                                                 '--proxy', f'http://127.0.0.1:{port+1}',
                                                 f'http://localhost:{server.server_port}/'], capture_output=True, text=True, timeout=5)
                        if action == 'direct':
                            self.assertEqual(result.returncode, 0)
                            self.assertEqual(result.stdout, 'local-target')
                        else:
                            self.assertNotEqual(result.stdout, 'local-target')
                    finally:
                        process.terminate(); process.wait(timeout=5)
        finally:
            server.shutdown(); server.server_close(); worker.join(timeout=5)

    def test_auto_refresh_rules_reload_and_stop(self):
        with tempfile.TemporaryDirectory(prefix='vctl-', dir='/tmp') as d:
            st = Store(d); s = state()
            s['subscriptions']['test']['nodes'][0]['outbound']['server'] = '127.0.0.1'
            s['subscriptions']['test']['nodes'][0]['outbound']['server_port'] = 1
            st.write(s)
            code = '''
import sys,time
from vless_client.storage import Store
from vless_client import runtime
store=Store(sys.argv[1])
def fake_fetch(url,interval):
    sub=store.read()['subscriptions']['test']
    sub['updated']=time.time()
    return sub
runtime.fetch=fake_fetch
runtime.serve(store,sys.argv[2],'proxy',int(sys.argv[3]))
'''
            p = subprocess.Popen([sys.executable, '-c', code, d, core_binary(), str(free_port())], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                def wait_for(predicate):
                    end = time.time() + 12
                    while time.time() < end:
                        if predicate(): return
                        if p.poll() is not None:
                            self.fail(p.communicate()[1].decode())
                        time.sleep(.1)
                    self.fail('Runtime did not reach expected state')
                wait_for(lambda: command(st,'status') != 'stopped')
                wait_for(lambda: st.read()['subscriptions']['test']['updated'] > 1)
                before_pid = json.loads(command(st, 'status'))['core_pid']
                before_mtime = (st.home / 'config.json').stat().st_mtime_ns
                with st.lock():
                    s = st.read(); s['subscriptions']['test']['updated'] = time.time(); st.write(s)
                wait_for(lambda: (st.home / 'config.json').stat().st_mtime_ns != before_mtime)
                self.assertEqual(json.loads(command(st, 'status'))['core_pid'], before_pid)
                with st.lock():
                    s=st.read();s['rules']=[{'kind':'suffix','value':'example.org','action':'direct'}];st.write(s)
                wait_for(lambda: any(r.get('domain')==['domain:example.org'] for r in json.loads((st.home/'config.json').read_text())['routing']['rules']))
                self.assertEqual(json.loads(command(st,'status'))['error'],'')
                command(st,'stop');p.wait(timeout=12)
                self.assertEqual(p.returncode,0)
                self.assertEqual(command(st,'status'),'stopped')
                p.communicate()
            finally:
                if p.poll() is None:
                    p.terminate();p.communicate(timeout=12)
