"""macOS DNS lifecycle: record before changing, restore after core teardown."""

import ipaddress
import json
import subprocess

from .storage import atomic_json


def system(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise ValueError("macOS network command failed: " + args[0].rsplit("/", 1)[-1])
    return result.stdout.strip()


def dns_values(text):
    values = text.splitlines()
    if text.startswith("There aren't any DNS Servers"):
        return []
    for value in values:
        ipaddress.ip_address(value)
    return values


class DNSLease:
    def __init__(self, store):
        self.path = store.home / "dns-restore.json"

    def acquire(self):
        if self.path.exists():
            self.restore()
        names = system("/usr/sbin/networksetup", "-listallnetworkservices").splitlines()[1:]
        previous = {}
        for name in names:
            if name and not name.startswith("*"):
                # Only network services with a physical device need DNS changes.
                info = system("/usr/sbin/networksetup", "-getinfo", name)
                addresses = [
                    line.split(":", 1)[1].strip() for line in info.splitlines() if line.startswith("IP address:")
                ]
                if addresses and addresses[0] not in ("none", ""):
                    previous[name] = dns_values(system("/usr/sbin/networksetup", "-getdnsservers", name))
        if not previous:
            raise ValueError("No active network service found for TUN DNS")
        atomic_json(self.path, {"previous": previous, "applied": ["198.19.255.53"]})
        try:
            for name in previous:
                system("/usr/sbin/networksetup", "-setdnsservers", name, "198.19.255.53")
            subprocess.run(["/usr/bin/dscacheutil", "-flushcache"], capture_output=True, timeout=10)
        except Exception:
            self.restore()
            raise

    def restore(self):
        if not self.path.exists():
            return
        snapshot = json.loads(self.path.read_text())
        errors = []
        for name, previous in snapshot["previous"].items():
            try:
                current = dns_values(system("/usr/sbin/networksetup", "-getdnsservers", name))
                # Don't undo a deliberate change made by another client/user.
                if current == snapshot["applied"]:
                    system("/usr/sbin/networksetup", "-setdnsservers", name, *(previous or ["Empty"]))
            except (ValueError, OSError, subprocess.SubprocessError):
                errors.append(name)
        if errors:
            raise ValueError("DNS restoration incomplete; run vctl tun recover")
        self.path.unlink()
        subprocess.run(["/usr/bin/dscacheutil", "-flushcache"], capture_output=True, timeout=10)
