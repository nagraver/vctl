import base64
import contextlib
import io
import tempfile
import unittest
from email.message import Message
from unittest.mock import patch, MagicMock

from test_client import URI, state
from vless_client.cli import parser, run
from vless_client.storage import Store, fetch, subscription_title, subscription_name


class SubscriptionNamesTests(unittest.TestCase):
    def test_title_formats_and_fallback(self):
        title = 'Мой VPN'
        encoded = base64.b64encode(title.encode()).decode().rstrip('=')
        for header in (title, 'base64:' + encoded):
            self.assertEqual(subscription_title(header, 'https://example.org/secret'), title)
        for header in ('', 'base64:!bad!', '\x1b\x00'):
            self.assertEqual(subscription_title(header, 'https://example.org/secret'), 'example.org')
        self.assertEqual(subscription_name({'VPN': {}, 'VPN (2)': {}}, 'VPN'), 'VPN (3)')

    def test_fetch_reads_case_insensitive_header(self):
        headers = Message(); headers['profile-title'] = 'base64:VGVzdA=='
        response = MagicMock()
        response.__enter__.return_value = response
        response.headers = headers
        response.read.return_value = URI.encode()
        with patch('urllib.request.OpenerDirector.open', return_value=response):
            self.assertEqual(fetch('https://example.org/sub')['title'], 'Test')

    def test_cli_auto_name_collision_manual_name_and_duplicate(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            store = Store(directory)
            def download(url, interval):
                return dict(state()['subscriptions']['test'], url=url, interval=interval, title='Test')
            def add(url, name=None):
                argv = ['--home', directory, 'sub', 'add'] + ([name] if name else []) + ['--url', url]
                run(parser().parse_args(argv))
            with patch('vless_client.cli.fetch', side_effect=download), patch('vless_client.cli.validate'), patch('vless_client.cli.core_binary', return_value='xray'), contextlib.redirect_stdout(io.StringIO()):
                add('https://example.org/one')
                add('https://example.org/two')
                add('https://example.org/three', 'Manual')
                before = store.path.read_bytes()
                with self.assertRaisesRegex(ValueError, 'already exists'):
                    add('https://example.org/one')
                self.assertEqual(store.path.read_bytes(), before)
            self.assertEqual(list(store.read()['subscriptions']), ['Test', 'Test (2)', 'Manual'])
