import contextlib
import json
import unittest
from unittest.mock import Mock, patch
from vless_client.cli import parser
from vless_client.runtime import restart


class RestartTests(unittest.TestCase):
    def execute(self, status, mode=None, port=None):
        store = Mock()
        store.lock.return_value = contextlib.nullcontext()
        with patch('vless_client.runtime.command', side_effect=[status, '{}', 'stopped'] if status != 'stopped' else [status]), patch('vless_client.runtime.prepare'), patch('vless_client.runtime.start') as start:
            restart(store, 'xray', mode, port)
            return start.call_args.args[2:]

    def test_preserves_mode_and_custom_port(self):
        self.assertEqual(self.execute(json.dumps({'mode':'tun', 'socks_port':3180})), ('tun',3180))

    def test_stopped_defaults_and_override(self):
        self.assertEqual(self.execute('stopped'), ('proxy',2080))
        self.assertEqual(self.execute('stopped', 'tun'), ('tun',2180))
        self.assertEqual(self.execute('stopped', 'proxy',4080), ('proxy',4080))

    def test_invalid_configuration_does_not_stop(self):
        store=Mock()
        with patch('vless_client.runtime.command', return_value=json.dumps({'mode':'proxy','socks_port':3080})) as command, patch('vless_client.runtime.prepare', side_effect=ValueError('invalid')), patch('vless_client.runtime.start') as start:
            with self.assertRaises(ValueError):restart(store,'xray')
            command.assert_called_once_with(store,'status')
            start.assert_not_called()

    def test_parser_preserves_unspecified_values(self):
        args=parser().parse_args(['restart'])
        self.assertIsNone(args.mode)
        self.assertIsNone(args.port)


import os
import tempfile
import time
from vless_client.runtime import command, core_binary, free_port, start
from vless_client.storage import Store
from test_client import state


@unittest.skipUnless(os.environ.get('VCTL_INTEGRATION') == '1', 'opt-in loopback integration')
class RestartIntegrationTests(unittest.TestCase):
    def test_real_restart_keeps_port_changes_pid(self):
        with tempfile.TemporaryDirectory(dir='/tmp', prefix='vctl-') as directory:
            store=Store(directory)
            store.write(state())
            binary=core_binary()
            port=free_port()
            try:
                start(store,binary,'proxy',port)
                before=json.loads(command(store,'status'))
                restart(store,binary)
                after=json.loads(command(store,'status'))
                self.assertEqual(after['socks_port'],port)
                self.assertEqual(after['mode'],'proxy')
                self.assertNotEqual(before['pid'],after['pid'])
                self.assertNotEqual(before['core_pid'],after['core_pid'])
            finally:
                command(store,'stop')
                for _ in range(100):
                    if command(store,'status')=='stopped':break
                    time.sleep(.1)
