"""Restore TUN resources if the supervisor disappears unexpectedly."""
import json
import os
import signal
import subprocess
import sys
import time

from .macos import DNSLease
from .storage import Store


def process_command(pid):
    return subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'command='],
                          capture_output=True, text=True, timeout=3).stdout


def recover(store, instance=None):
    path = store.home / 'runtime.json'
    if path.exists():
        data = json.loads(path.read_text())
        if instance and data['instance'] != instance:
            return
        pid = data['core_pid']
        expected = str(store.home / 'config.json')
        if expected in process_command(pid):
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            for _ in range(50):
                if expected not in process_command(pid):
                    break
                time.sleep(.1)
            else:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        path.unlink(missing_ok=True)
    DNSLease(store).restore()
    (store.home / 'control.sock').unlink(missing_ok=True)


def main():
    store = Store(sys.argv[1]); instance = sys.argv[2]
    path = store.home / 'runtime.json'
    while path.exists():
        data = json.loads(path.read_text())
        if data['instance'] != instance:
            return
        supervisor = process_command(data['pid'])
        if not supervisor or supervisor != data['supervisor_command']:
            try:
                with store.lock('runtime.lock', nonblocking=True):
                    recover(store, instance)
            except BlockingIOError:
                time.sleep(1)
                continue
            return
        time.sleep(1)


if __name__ == '__main__':
    main()
