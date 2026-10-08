import contextlib
import json
import os
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import Mock, patch

from vless_client.launchd import Service, definition, label_for, physical_interface
from vless_client.storage import Store


class LaunchdTests(unittest.TestCase):
    def service(self, directory):
        store = Mock()
        store.state_home = Path(directory) / 'profile'
        store.home = store.state_home / 'tun'
        store.home.mkdir(parents=True)
        store.lock.return_value = contextlib.nullcontext()
        service = Service(store, 501)
        service.marker = Path(directory) / 'enabled'
        service.plist = Path(directory) / 'service.plist'
        return service

    def test_definition_runs_foreground_without_boot_autostart(self):
        p = Path('/Users/test/profile')
        data = definition('test', p, 501, Path('/Library/Application Support/vctl/release'), 3180, Path('/var/run/test.enabled'))
        self.assertFalse(data['RunAtLoad'])
        self.assertEqual(data['KeepAlive'], {'PathState': {'/var/run/test.enabled': True}})
        self.assertIn('_tun-service', data['ProgramArguments'])
        self.assertNotIn('start', data['ProgramArguments'])
        self.assertNotIn('sudo', data['ProgramArguments'])
        self.assertEqual(data['ExitTimeOut'], 45)
        self.assertEqual(plistlib.loads(plistlib.dumps(data)), data)
        self.assertNotIn('PYTHONPATH', data['EnvironmentVariables'])

    def test_label_is_unique_per_user_and_profile(self):
        self.assertNotEqual(label_for('/tmp/a', 501), label_for('/tmp/b', 501))
        self.assertNotEqual(label_for('/tmp/a', 501), label_for('/tmp/a', 502))
        self.assertEqual(label_for('/tmp/a', 501), label_for('/tmp/a', 501))

    def test_start_existing_legacy_does_not_interrupt(self):
        with tempfile.TemporaryDirectory() as d:
            service = self.service(d)
            with patch.object(service, 'runtime_status', return_value={'pid': 42}), patch.object(service, 'stop') as stop:
                with self.assertRaisesRegex(ValueError, 'Already running'): service.start('xray')
                stop.assert_not_called()

    def test_failed_preflight_does_not_stop_or_install(self):
        with tempfile.TemporaryDirectory() as d:
            service = self.service(d)
            with patch.object(service, 'runtime_status', return_value={'socks_port': 3180}), patch.object(service, 'preflight', side_effect=ValueError('offline')), patch.object(service, 'stop') as stop, patch.object(service, 'install') as install:
                with self.assertRaises(ValueError): service.restart('xray')
                stop.assert_not_called(); install.assert_not_called()

    def test_stop_disables_keepalive_before_bootout_and_recovery(self):
        with tempfile.TemporaryDirectory() as d:
            service = self.service(d); service.marker.touch()
            def ctl(*args):
                self.assertFalse(service.marker.exists())
                self.assertEqual(args, ('bootout', service.target))
            with patch.object(service, 'loaded', return_value=True), patch.object(service, 'ctl', side_effect=ctl), patch('vless_client.watchdog.recover') as recover:
                service.stop()
                recover.assert_called_once_with(service.store)

    def test_start_failure_disarms_service(self):
        with tempfile.TemporaryDirectory() as d:
            service = self.service(d)
            with patch.object(service, 'runtime_status', return_value=None), patch.object(service, 'preflight'), patch.object(service, 'install'), patch.object(service, 'enable', side_effect=ValueError('failed')), patch.object(service, 'stop') as stop:
                with self.assertRaises(ValueError): service.start('xray')
                stop.assert_called_once()

    def test_restart_rolls_back_legacy_and_preserves_port(self):
        with tempfile.TemporaryDirectory() as d:
            service = self.service(d)
            with patch.object(service, 'runtime_status', return_value={'socks_port': 3180}), patch.object(service, 'preflight') as preflight, patch.object(service, 'loaded', return_value=False), patch.object(service, 'stop'), patch.object(service, 'install', side_effect=ValueError('install failed')), patch('vless_client.launchd.runtime.start') as start:
                with self.assertRaisesRegex(ValueError, 'restored'): service.restart('xray')
                preflight.assert_called_once_with('xray', 3180)
                start.assert_called_once_with(service.store, 'xray', 'tun', 3180)

    def test_ready_requires_managed_healthy_runtime(self):
        with tempfile.TemporaryDirectory() as d:
            service = self.service(d)
            with patch.object(service, 'runtime_status', side_effect=[{'starting': True}, {'manager': 'standalone'}, {'manager': 'launchd', 'stopping': True}, {'manager': 'launchd', 'pid': 42}]), patch('vless_client.launchd.time.sleep'):
                self.assertEqual(service.wait_ready()['pid'], 42)

    def test_store_accepts_explicit_owner_only_when_root(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as d:
            profile = Path(d); runtime = profile / 'tun'; runtime.mkdir()
            uid = profile.stat().st_uid
            with patch('vless_client.storage.os.geteuid', return_value=uid):
                if uid != 0:
                    with self.assertRaises(ValueError): Store(runtime, profile, owner_uid=uid)

    def test_installed_idle_job_does_not_claim_legacy_runtime(self):
        with tempfile.TemporaryDirectory() as d:
            service = self.service(d)
            with patch.object(service, 'loaded', return_value=True), patch.object(service, 'runtime_status', return_value={'pid': 42}):
                status = service.status()
                self.assertTrue(status['registered'])
                self.assertEqual(status['manager'], 'standalone')

    def test_physical_interface_rejects_another_tunnel(self):
        for interface in ('en0', 'en5', 'utun9', 'lo0'):
            with patch('vless_client.launchd.subprocess.run', return_value=Mock(returncode=0, stdout='  interface: ' + interface + '\n')):
                if interface.startswith('en'):
                    self.assertEqual(physical_interface(), interface)
                else:
                    with self.assertRaises(ValueError): physical_interface()

    def test_preflight_binds_probes_outside_running_tun(self):
        with tempfile.TemporaryDirectory() as d:
            service = self.service(d); service.store.read.return_value = {'selected': 'auto'}
            with patch('vless_client.launchd.runtime.resolve_tun_state'), patch('vless_client.launchd.generate', return_value={}), patch('vless_client.launchd.validate_assets'), patch('vless_client.launchd.runtime.validate'), patch('vless_client.launchd.physical_interface', return_value='en0'), patch('vless_client.launchd.runtime.ping', return_value=[({'id': 'a'}, 20, '')]) as ping:
                service.preflight('xray', 2180)
                ping.assert_called_once_with(service.store, 'xray', interface='en0')

    def test_restart_restores_previous_managed_definition(self):
        with tempfile.TemporaryDirectory() as d:
            service = self.service(d)
            previous = {'Label': service.label, 'ProgramArguments': ['/old/python', '/old/vctl']}
            service.plist.write_bytes(plistlib.dumps(previous))
            with patch.object(service, 'runtime_status', return_value={'manager': 'launchd', 'socks_port': 3180}), patch.object(service, 'preflight'), patch.object(service, 'loaded', return_value=True), patch.object(service, 'stop'), patch.object(service, 'install'), patch.object(service, 'enable', side_effect=[ValueError('failed'), {}]), patch.object(service, 'ctl'), patch('vless_client.launchd.write_plist') as write:
                with self.assertRaisesRegex(ValueError, 'restored'): service.restart('xray')
                write.assert_called_once_with(service.plist, previous)


if __name__ == '__main__':
    unittest.main()
