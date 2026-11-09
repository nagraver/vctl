package whale

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRealXrayLifecycle(t *testing.T) {
	if os.Getenv("WHALE_INTEGRATION") != "1" {
		t.Skip("opt-in loopback integration")
	}
	dir, e := os.MkdirTemp("/private/tmp", "whale-it-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	s, e := NewStore(dir, "")
	if e != nil {
		t.Fatal(e)
	}
	binary := canonical("../../dist/whale")
	core := canonical("../../.tools/xray")
	state := fixture(t).State
	state.Subscriptions = Ordered[Subscription]{}
	n, e := ParseURI("trojan://secret@127.0.0.1:1?security=tls#OfflineFixture")
	if e != nil {
		t.Fatal(e)
	}
	n2, e := ParseURI("trojan://second@127.0.0.1:1?security=tls#SecondFixture")
	if e != nil {
		t.Fatal(e)
	}
	state.Subscriptions.Set("fixture", Subscription{URL: "https://example.invalid/sub", Interval: 43200, Updated: float64(time.Now().Unix()), Nodes: []Node{n, n2}})
	state.Selected = "auto"
	state.Presets = Ordered[Preset]{}
	state.Rules = nil
	if e = s.Write(state); e != nil {
		t.Fatal(e)
	}
	run := func(args ...string) []byte {
		t.Helper()
		cmd := exec.Command(binary, append([]string{"--home", dir, "--core", core}, args...)...)
		b, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("%v: %v %s", args, e, b)
		}
		return b
	}
	defer exec.Command(binary, "--home", dir, "down").Run()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	run("up", "--port", itoa(port))
	before, e := Control(s, "status")
	if e != nil || num(before, "pid") == 0 {
		t.Fatal(before, e)
	}
	// Verify the actual private API, including a target other than the first node.
	waitSelection := func(id string, fallback bool) {
		t.Helper()
		for i := 0; i < 70; i++ {
			r, _ := Control(s, "status")
			server := obj(r, "server")
			if str(server, "id") == id && server["fallback"] == fallback {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		r, _ := Control(s, "status")
		t.Fatalf("selection %s (fallback %v) not reported: %v", id, fallback, r)
	}
	waitSelection(n.ID, true)
	api := "--server=unix://" + filepath.Join(s.Home, "api.sock")
	if b, err := exec.Command(core, "api", "bo", api, "-b", "auto", "node-"+n2.ID).CombinedOutput(); err != nil {
		t.Fatalf("override: %v %s", err, b)
	}
	waitSelection(n2.ID, false)
	if b, err := exec.Command(core, "api", "bo", api, "-b", "auto", "-r").CombinedOutput(); err != nil {
		t.Fatalf("reset override: %v %s", err, b)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("whale-ok")) }))
	defer server.Close()
	proxyURL, _ := url.Parse("http://127.0.0.1:" + itoa(port+1))
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	response, e := client.Get(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "whale-ok" {
		t.Fatal(string(body))
	}
	// Timestamp and UI-language updates must not restart Xray.
	state.UI = &UIPreferences{Language: "ru"}
	state.Subscriptions.Values["fixture"] = func() Subscription { v := state.Subscriptions.Values["fixture"]; v.Updated++; return v }()
	if e = s.Write(state); e != nil {
		t.Fatal(e)
	}
	time.Sleep(1500 * time.Millisecond)
	same, e := Control(s, "status")
	if e != nil || num(same, "core_pid") != num(before, "core_pid") {
		t.Fatal("unnecessary reconnect", same, e)
	}

	// Invalid edits must leave the persisted profile byte-for-byte intact.
	beforeState, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	bad := exec.Command(binary, "--home", dir, "--core", core, "rule", "add", "geosite", "missing-category", "direct")
	if err := bad.Run(); err == nil {
		t.Fatal("invalid geodata rule accepted")
	}
	afterState, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if string(beforeState) != string(afterState) {
		t.Fatal("failed mutation changed profile")
	}
	// A real routing change must be picked up by the running supervisor.
	run("rule", "add", "suffix", "example.test", "block")
	changed := false
	for i := 0; i < 50; i++ {
		r, _ := Control(s, "status")
		if num(r, "core_pid") != 0 && num(r, "core_pid") != num(before, "core_pid") {
			changed = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !changed {
		t.Fatal("running supervisor did not apply routing change")
	}
	run("restart")
	after, e := Control(s, "status")
	if e != nil || num(after, "pid") == num(before, "pid") || num(after, "socks_port") != port {
		t.Fatal("restart failed", after, e)
	}
	run("stop")
	stopped, e := Control(s, "status")
	if e != nil || stopped != nil {
		t.Fatal("stop failed", stopped, e)
	}
	var status M
	if json.Unmarshal(run("status"), &status) != nil || str(status, "state") != "stopped" {
		t.Fatal(status)
	}
}

func TestWatchTerminatesOnSignal(t *testing.T) {
	if os.Getenv("WHALE_INTEGRATION") != "1" {
		t.Skip("opt-in executable integration")
	}
	dir, e := os.MkdirTemp("/private/tmp", "whale-watch-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	if e = writeJSON(filepath.Join(dir, "runtime.json"), M{"instance": "test", "pid": os.Getpid(), "core_pid": 0, "supervisor_command": processCommand(os.Getpid())}); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(canonical("../../dist/whale"), "--home", dir, "_watch", "test")
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer cmd.Process.Kill()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	time.Sleep(200 * time.Millisecond)
	if e = cmd.Process.Signal(syscall.SIGTERM); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("watchdog ignored SIGTERM")
	}
}
