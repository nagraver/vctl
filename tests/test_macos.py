import tempfile
import unittest
from unittest.mock import patch
from vless_client.macos import DNSLease
from vless_client.storage import Store, atomic_json


class DNSRestoreTest(unittest.TestCase):
    def test_restore_previous_or_preserve_external_change(self):
        for current, expected in [('198.19.255.53', ['192.168.0.1']), ('8.8.8.8', None)]:
            with self.subTest(current=current), tempfile.TemporaryDirectory(dir='/tmp') as d:
                lease = DNSLease(Store(d))
                atomic_json(lease.path, {'previous': {'Wi-Fi': ['192.168.0.1']}, 'applied': ['198.19.255.53']})
                with patch('vless_client.macos.system', return_value=current) as system, patch('vless_client.macos.subprocess.run'):
                    lease.restore()
                    setters = [c.args for c in system.call_args_list if '-setdnsservers' in c.args]
                    self.assertEqual(setters, [('/usr/sbin/networksetup', '-setdnsservers', 'Wi-Fi', *expected)] if expected else [])
                self.assertFalse(lease.path.exists())

    def test_failure_retains_recovery_journal(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as d:
            lease = DNSLease(Store(d))
            atomic_json(lease.path, {'previous': {'Wi-Fi': []}, 'applied': ['198.19.255.53']})
            with patch('vless_client.macos.system', side_effect=ValueError('failed')):
                with self.assertRaisesRegex(ValueError, 'recover'):
                    lease.restore()
            self.assertTrue(lease.path.exists())
