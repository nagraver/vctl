package whale

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicCommands(t *testing.T) {
	root := newCommand(&App{Home: t.TempDir()})
	var names []string
	for _, c := range root.Commands() {
		if !c.Hidden {
			names = append(names, c.Name())
		}
	}
	if strings.Join(names, ",") != "down,status,up" {
		t.Fatalf("public commands: %v", names)
	}
	for _, name := range []string{"tun", "sub", "start", "stop", "completion", "nodes", "rule"} {
		c := newCommand(&App{Home: t.TempDir()})
		c.SetArgs([]string{name})
		c.SetOut(&bytes.Buffer{})
		c.SetErr(&bytes.Buffer{})
		if c.Execute() == nil {
			t.Errorf("accepted removed command %s", name)
		}
	}
}
func TestNativeSnapshotRedactsCredentials(t *testing.T) {
	home, err := os.MkdirTemp("/private/tmp", "whale-native-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	s, err := NewStore(home, home)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	n, err := ParseURI("trojan://private-password@example.org:443?security=tls#Example")
	if err != nil {
		t.Fatal(err)
	}
	v.Subscriptions.Set("Test", Subscription{URL: "https://example.org/private-token", Nodes: []Node{n}, Interval: 43200})
	v.Subscriptions.Set("Duplicate", Subscription{Nodes: []Node{n}, Interval: 43200})
	if err = s.Write(v); err != nil {
		t.Fatal(err)
	}
	snap, err := NativeSnapshot(&App{Home: home})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(snap)
	for _, secret := range []string{"private-password", "private-token", "outbound"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatalf("snapshot leaked %s", secret)
		}
	}
	if len(snap["nodes"].([]M)) != 1 {
		t.Fatal("duplicate server identifiers")
	}
}
func TestStatusDoesNotCreateProfile(t *testing.T) {
	home := filepath.Join(t.TempDir(), "missing")
	c := newCommand(&App{Home: home})
	c.SetArgs([]string{"status"})
	var out bytes.Buffer
	c.SetOut(&out)
	if err := c.Execute(); err != nil {
		t.Fatal(err)
	}
	if exists(home) {
		t.Fatal("status created profile")
	}
	if !strings.Contains(out.String(), "VPN: off") {
		t.Fatal(out.String())
	}
}
