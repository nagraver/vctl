import copy
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_client import state
from vless_client.config import effective_rules, generate, make_rule
from vless_client.routing_data import load_preset, cache_asset, refresh, validate_assets
from vless_client.runtime import core_binary, prepare
from vless_client.storage import Store
from vless_client.cli import parser, run


class RoutingTests(unittest.TestCase):
    def test_dns_order_matches_overlapping_rules(self):
        s = state()
        s['rules'] = [make_rule('domain', 'login.sevsu.ru', 'proxy'), make_rule('suffix', 'sevsu.ru', 'direct')]
        c = generate(s, 'tun')
        self.assertEqual([r['tag'] for r in c['dns']['servers']], ['dns-proxy', 'dns-direct', 'dns-proxy'])
        self.assertTrue(c['dns']['servers'][0]['finalQuery'])
        self.assertTrue(c['dns']['disableFallbackIfMatch'])
        self.assertFalse(c['inbounds'][-1]['sniffing']['routeOnly'])
        self.assertEqual(c['routing']['rules'][0]['outboundTag'], 'direct')
        self.assertEqual(c['routing']['rules'][1]['balancerTag'], 'auto')

    def test_presets_follow_personal_rules_and_disable(self):
        s = state()
        personal = make_rule('domain', 'ads.example.org', 'direct')
        s['rules'] = [personal]
        s['presets'] = {'a': {'enabled': True, 'rules': [make_rule('suffix', 'example.org', 'block')]},
                        'b': {'enabled': False, 'rules': [make_rule('process', 'curl', 'block')]}}
        self.assertEqual(len(effective_rules(s)), 2)
        self.assertEqual(effective_rules(s)[0], personal)

    def test_application_path_and_domain_normalization(self):
        self.assertEqual(make_rule('path', '/Applications/Firefox.app', 'direct')['value'], '/Applications/Firefox.app/')
        self.assertEqual(make_rule('domain', 'SEVSU.RU.', 'direct')['value'], 'sevsu.ru')
        for kind, value in [('path', 'relative'), ('process', '/usr/bin/curl'), ('suffix', 'https://sevsu.ru'), ('geoip', '../ru')]:
            with self.assertRaises(ValueError): make_rule(kind, value, 'direct')

    def test_missing_geodata_is_actionable(self):
        s = state(); s['rules'] = [make_rule('geoip', 'ru', 'direct')]
        with self.assertRaisesRegex(ValueError, 'geodata update'): generate(s)

    def test_preset_schema_and_file_refresh(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'rules.json'
            path.write_text(json.dumps({'version': 1, 'rules': [make_rule('suffix', 'sevsu.ru', 'direct')]}))
            preset = load_preset(str(path))
            self.assertTrue(preset['enabled'])
            self.assertEqual(preset['rules'][0]['value'], 'sevsu.ru')
            for data in [{'version': 2, 'rules': []}, {'version': 1, 'rules': [{'invalid': 1}]}, [], {'version': 1, 'rules': [], 'outbounds': []}]:
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError): load_preset(str(path))

    def test_failed_remote_refresh_preserves_saved_state(self):
        with tempfile.TemporaryDirectory(prefix='vctl-', dir='/tmp') as d:
            store = Store(d); s = state()
            s['presets'] = {'remote': {'source': 'https://example.org/rules', 'enabled': True, 'updated': 0, 'interval': 60, 'rules': []}}
            store.write(s)
            with patch('vless_client.routing_data.download', side_effect=ValueError('offline')):
                with self.assertRaises(ValueError): refresh(store, copy.deepcopy(s))
            self.assertEqual(store.read(), s)

    def test_local_preset_not_reread_by_background_root(self):
        s = state(); s['presets'] = {'local': {'source': '/missing.json', 'enabled': True, 'updated': 0, 'interval': 60, 'rules': []}}
        refresh(None, s)

    def test_real_geodata_loading_and_invalid_update(self):
        if not (Path(__file__).resolve().parent.parent / '.tools/xray').exists():
            self.skipTest('Xray not installed')
        # Minimal protobuf GeoIPList/GeoSiteList fixtures, with one private category each.
        def field(number, payload):
            return bytes([number * 8 + 2, len(payload)]) + payload
        geoip = field(1, field(1, b'PRIVATE') + field(2, field(1, bytes([127, 0, 0, 0])) + b'\x10\x08'))
        geosite = field(1, field(1, b'PRIVATE') + field(2, b'\x08\x03' + field(2, b'localhost')))
        with tempfile.TemporaryDirectory(prefix='vctl-', dir='/tmp') as d:
            store = Store(d); s = state()
            s['geodata'] = {kind: {'sha256': cache_asset(store, body)} for kind, body in [('geoip', geoip), ('geosite', geosite)]}
            s['rules'] = [make_rule('geoip', 'private', 'direct'), make_rule('geosite', 'private', 'direct')]
            binary = core_binary()
            validate_assets(store, binary, s)
            prepare(store, binary, s, 'proxy', 2080)
            store.write(s)
            candidate = copy.deepcopy(s)
            candidate['geodata']['geoip']['sha256'] = cache_asset(store, b'<html>error</html>')
            with self.assertRaises(ValueError): prepare(store, binary, candidate, 'proxy', 2080)
            self.assertEqual(store.read(), s)
            self.assertNotIn(candidate['geodata']['geoip']['sha256'], (store.home / 'config.json').read_text())

    def test_cli_presets_persist_and_invalid_edits_are_atomic(self):
        if not (Path(__file__).resolve().parent.parent / '.tools/xray').exists():
            self.skipTest('Xray not installed')
        with tempfile.TemporaryDirectory(prefix='vctl-', dir='/tmp') as d:
            source = Path(d) / 'preset.json'
            source.write_text(json.dumps({'version': 1, 'rules': [make_rule('suffix', 'sevsu.ru', 'direct')]}))
            store = Store(d)
            def cli(*args):
                with contextlib.redirect_stdout(io.StringIO()):
                    run(parser().parse_args(['--home', d, *args]))
            cli('preset', 'add', 'work', str(source))
            cli('preset', 'disable', 'work')
            cli('preset', 'update', 'work')
            self.assertFalse(store.read()['presets']['work']['enabled'])
            cli('preset', 'enable', 'work')
            cli('rule', 'add', 'path', '/Applications/Firefox.app', 'direct')
            cli('dns', 'set', '--direct', 'https://9.9.9.9/dns-query', '--strategy', 'UseIPv4')
            before = store.path.read_bytes()
            for args in [('dns', 'set', '--direct', 'https://resolver.example.org/dns-query'),
                         ('rule', 'add', 'geoip', 'ru', 'direct')]:
                with self.assertRaises(ValueError): cli(*args)
                self.assertEqual(store.path.read_bytes(), before)
            source.write_text('{broken')
            with self.assertRaises(ValueError): cli('preset', 'update', 'work')
            self.assertEqual(store.path.read_bytes(), before)
            cli('preset', 'remove', 'work')
            self.assertEqual(store.read()['presets'], {})


if __name__ == '__main__':
    unittest.main()
