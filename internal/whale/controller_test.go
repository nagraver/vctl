package whale

import (
	"os"
	"strings"
	"testing"
)

func TestControllerActionBoundary(t *testing.T) {
	for _, action := range []string{"status", "up", "down", "restart", "install", "uninstall", "recover"} {
		if !controllerActionAllowed(action) {
			t.Fatal(action)
		}
	}
	for _, action := range []string{"", "run", "_serve", "/bin/sh", "up; whoami", "--core", "up\n"} {
		if controllerActionAllowed(action) {
			t.Fatalf("unsafe action accepted: %q", action)
		}
	}
}
func TestControllerProfileIsolation(t *testing.T) {
	a := newController("/Users/alice/.config/vctl", 501)
	b := newController("/Users/bob/.config/vctl", 502)
	c := newController("/Users/alice/other", 501)
	if a.socket() == b.socket() || a.socket() == c.socket() {
		t.Fatal("control socket collision")
	}
	if len(a.socket()) >= 104 || !strings.HasPrefix(a.socket(), "/var/run/") {
		t.Fatal("unsafe socket path", a.socket())
	}
	if !strings.HasPrefix(a.Directory, serviceRoot+"/") {
		t.Fatal(a.Directory)
	}
	vpn := NewService(a.Store, a.UID)
	if a.Directory == vpn.Directory || a.Plist == vpn.Plist {
		t.Fatal("controller would be removed during VPN service update")
	}
}
func TestControllerInstallRequiresAdministrator(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires unprivileged test runner")
	}
	if InstallController("/missing-profile", "/missing-core") == nil {
		t.Fatal("unprivileged install allowed")
	}
}
