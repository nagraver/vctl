import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from vless_client.config import generate, make_rule, outbound
from vless_client.profiles import ProfileError, parse_subscription, parse_uri
from vless_client.storage import Store, atomic_json, fetch

URI = 'vless://11111111-1111-4111-8111-111111111111@example.com:443?type=tcp&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sni=example.com&sid=abcd&fp=chrome&flow=xtls-rprx-vision&encryption=none&spx=%2F#Example'


def state():
    return {'version': 1, 'subscriptions': {'test': {'url': 'https://example.com/sub',
            'nodes': [parse_uri(URI)], 'interval': 43200, 'updated': 1}},
            'selected': 'auto', 'rules': [], 'default': 'proxy',
            'test_url': 'https://www.gstatic.com/generate_204'}


class ProfileTests(unittest.TestCase):
    def test_plain_and_base64(self):
        self.assertEqual(parse_subscription(URI.encode()), parse_subscription(base64.b64encode(URI.encode())))

    def test_reality_vision_conversion(self):
        node = parse_uri(URI)
        out = node['outbound']
        self.assertEqual(out['flow'], 'xtls-rprx-vision')
        self.assertEqual(out['tls']['reality']['short_id'], 'abcd')
        self.assertNotIn('transport', out)
        self.assertNotIn('spx', out)

    def test_identity_survives_renaming_and_query_order(self):
        renamed = URI.replace('#Example', '#New')
        self.assertEqual(parse_uri(URI)['id'], parse_uri(renamed)['id'])

    def test_dedup(self):
        self.assertEqual(len(parse_subscription((URI + '\n' + URI).encode())), 1)

    def test_reject_unsupported_without_secrets(self):
        for changed in (URI.replace('type=tcp', 'type=xhttp'), URI.replace('encryption=none', 'encryption=mlkem768x25519plus'), URI + '&unused=yes'):
            if changed.endswith('unused=yes'):
                changed = URI.replace('#Example', '&unused=yes#Example')
            with self.assertRaises(ProfileError) as e:
                parse_subscription(changed.encode())
            self.assertNotIn('11111111', str(e.exception))

    def test_partial_subscription_not_accepted(self):
        with self.assertRaises(ProfileError):
            parse_subscription((URI + '\nvmess://unsupported').encode())

    def test_empty_and_bad_payload(self):
        for body in (b'', b'<html>error</html>', b'{}', b'a' * 2000001):
            with self.assertRaises((ProfileError, ValueError)):
                parse_subscription(body)

    def test_ws(self):
        uri = URI.replace('type=tcp', 'type=ws&host=cdn.example.com&path=%2Fws').replace('&flow=xtls-rprx-vision', '')
        self.assertEqual(parse_uri(uri)['outbound']['transport'], {'type': 'ws', 'path': '/ws', 'headers': {'Host': 'cdn.example.com'}})


class ConfigTests(unittest.TestCase):
    def test_split_and_dns(self):
        s = state()
        s['rules'] = [make_rule('suffix', 'example.org', 'direct'), make_rule('domain', 'exact.example.org', 'proxy'), make_rule('cidr', '10.0.0.0/8', 'block')]
        c = generate(s, 'tun')
        self.assertEqual(c['routing']['rules'][-1]['balancerTag'], 'auto')
        self.assertEqual(c['routing']['rules'][3]['outboundTag'], 'direct')
        self.assertEqual(c['routing']['rules'][3]['domain'], ['domain:example.org'])
        self.assertEqual(c['dns']['servers'][0]['tag'], 'dns-direct')
        self.assertEqual(c['routing']['rules'][5]['outboundTag'], 'block')
        self.assertEqual(c['inbounds'][-1]['settings']['autoSystemRoutingTable'], ['0.0.0.0/0', '::/0'])

    def test_xray_reality_fields_and_selection(self):
        s = state(); node = s['subscriptions']['test']['nodes'][0]
        s['selected'] = node['id']
        c = generate(s)
        o = c['outbounds'][0]
        self.assertEqual(o['protocol'], 'vless')
        self.assertEqual(o['settings']['vnext'][0]['users'][0]['flow'], 'xtls-rprx-vision')
        self.assertEqual(o['streamSettings']['realitySettings']['shortId'], 'abcd')
        self.assertEqual(c['routing']['rules'][-1]['outboundTag'], 'node-' + node['id'])
        self.assertNotIn('observatory', c)

    def test_process_rules_are_scoped_to_tun(self):
        s = state(); s['rules'] = [{'kind': 'process', 'value': 'curl', 'action': 'direct'}]
        rule = generate(s, 'tun')['routing']['rules'][3]
        self.assertEqual(rule['process'], ['curl'])
        self.assertEqual(rule['inboundTag'], ['tun-in'])

    def test_xray_trojan(self):
        n = parse_uri('trojan://secret@example.com:443?security=tls#Test')
        self.assertEqual(outbound(n)['settings']['servers'][0]['password'], 'secret')


    def test_missing_selection_fails_closed(self):
        s = state(); s['selected'] = 'gone'
        with self.assertRaises(ValueError): generate(s)

    def test_no_mutation(self):
        s = state(); before = copy.deepcopy(s)
        generate(s)
        self.assertEqual(s, before)

    def test_invalid_rule(self):
        for args in [('cidr', 'bad', 'direct'), ('path', 'relative', 'proxy'), ('process', '\x1b', 'direct')]:
            with self.assertRaises(ValueError): make_rule(*args)

    def test_proxy_is_loopback_only(self):
        c = generate(state())
        self.assertEqual(c['inbounds'][0]['listen'], '127.0.0.1')

    def test_real_core_validation(self):
        core = Path(__file__).resolve().parent.parent / '.tools/xray'
        if not core.exists(): self.skipTest('Xray not installed')
        with tempfile.TemporaryDirectory() as d:
            s = state()
            s['rules'] = [make_rule(k, v, 'direct') for k, v in [('suffix', 'example.org'), ('domain', 'exact.example.org'), ('cidr', '10.0.0.0/8'), ('process', 'curl'), ('path', '/Applications/Safari.app')]]
            for mode in ('proxy', 'tun'):
                p = Path(d) / 'config.json'; atomic_json(p, generate(s, mode))
                r = subprocess.run([str(core), 'run', '-test', '-c', str(p)], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)


class StorageTests(unittest.TestCase):
    def test_permissions_and_atomic_write(self):
        with tempfile.TemporaryDirectory() as d:
            st = Store(d); st.write(state())
            self.assertEqual(st.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(st.home.stat().st_mode & 0o777, 0o700)
            self.assertEqual(st.read(), state())
            self.assertFalse(list(st.home.glob('.pending-*')))

    def test_https_only(self):
        with self.assertRaises(ValueError): fetch('http://example.com/sub')

    def test_failed_download_does_not_touch_cache(self):
        with tempfile.TemporaryDirectory() as d:
            st = Store(d); st.write(state()); original = st.path.read_bytes()
            with patch('urllib.request.OpenerDirector.open', side_effect=OSError('secret')):
                with self.assertRaises(ValueError) as e: fetch('https://example.com/SECRET')
            self.assertNotIn('SECRET', str(e.exception))
            self.assertEqual(st.path.read_bytes(), original)


if __name__ == '__main__': unittest.main()
