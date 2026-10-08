#!/usr/bin/env python3
"""Root-only launchd integration check. Uses a disposable idle worker, never TUN."""
import os
from pathlib import Path
import plistlib
import signal
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from vless_client.launchd import definition


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run with sudo; this checks system launchd without touching VPN or DNS')
    label = 'io.github.nagraver.vctl.test.' + uuid.uuid4().hex
    target = 'system/' + label
    def ctl(*args):
        return subprocess.run(['/bin/launchctl', *args], capture_output=True, text=True, timeout=50)
    def wait_for(test, timeout=25):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if test():
                return
            time.sleep(.2)
        raise RuntimeError('launchd did not reach expected state')
    with tempfile.TemporaryDirectory(prefix='vctl-launchd-', dir='/private/tmp') as directory:
        home = Path(directory); (home / 'tun').mkdir()
        marker = home / 'enabled'; events = home / 'events'
        worker = home / 'worker.py'
        worker.write_text('import os,time\nfrom pathlib import Path\nwith open(' + repr(str(events)) + ', "a") as f:\n f.write(str(os.getpid()) + "\\n"); f.flush()\nwhile True: time.sleep(1)\n')
        data = definition(label, home, 0, home, 2180, marker)
        data['ProgramArguments'] = [sys.executable, '-E', '-s', str(worker)]
        data['ThrottleInterval'] = 1
        path = home / (label + '.plist'); path.write_bytes(plistlib.dumps(data)); path.chmod(0o644)
        try:
            result = ctl('bootstrap', 'system', str(path))
            if result.returncode:
                raise RuntimeError('bootstrap failed: ' + result.stderr)
            time.sleep(2)
            assert not events.exists(), 'Installing an idle service started it'
            marker.touch(); result = ctl('kickstart', target)
            assert result.returncode == 0, result.stderr
            wait_for(events.exists)
            first = int(events.read_text().splitlines()[0])
            os.kill(first, signal.SIGKILL)
            wait_for(lambda: len(events.read_text().splitlines()) >= 2)
            assert int(events.read_text().splitlines()[-1]) != first
            marker.unlink(); result = ctl('bootout', target)
            assert result.returncode == 0, result.stderr
            count = len(events.read_text().splitlines())
            time.sleep(2)
            assert len(events.read_text().splitlines()) == count
            assert ctl('print', target).returncode != 0
            print('PASS: idle install, manual start, crash restart, explicit stop; no TUN/DNS changes')
        finally:
            marker.unlink(missing_ok=True)
            ctl('bootout', target)


if __name__ == '__main__':
    main()
