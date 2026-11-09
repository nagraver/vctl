package whale

import (
	tea "github.com/charmbracelet/bubbletea"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSelectedTag(t *testing.T) {
	config := M{"routing": M{"balancers": []M{{"tag": "auto", "fallbackTag": "node-reserve"}}}}
	for _, tc := range []struct {
		body, tag string
		fallback  bool
	}{
		{`{"balancer":{"override":{"target":"node-override"},"principleTarget":{"tag":["node-ping"]}}}`, "node-override", false},
		{`{"balancer":{"principleTarget":{"tag":["node-ping"]}}}`, "node-ping", false},
		{`{"balancer":{"principle_target":{"tag":["node-snake"]}}}`, "node-snake", false},
		{`{"balancer":{}}`, "node-reserve", true},
	} {
		tag, fallback, err := selectedTag([]byte(tc.body), config)
		if err != nil || tag != tc.tag || fallback != tc.fallback {
			t.Fatal(tag, fallback, err)
		}
	}
	if _, _, err := selectedTag([]byte(`{}`), config); err == nil {
		t.Fatal("missing response treated as fallback")
	}
}
func TestTunSummaryFreshness(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tun-status.json")
	v := connectionSummary{123, time.Now().Unix(), M{"name": "Chosen"}}
	if err := writeJSON(p, v); err != nil {
		t.Fatal(err)
	}
	if str(readTunSelection(dir, "  pid = 123\n"), "name") != "Chosen" {
		t.Fatal("fresh selection not read")
	}
	if readTunSelection(dir, "pid = 124") != nil {
		t.Fatal("wrong daemon accepted")
	}
	v.Updated -= 20
	if err := writeJSON(p, v); err != nil {
		t.Fatal(err)
	}
	if readTunSelection(dir, "pid = 123") != nil {
		t.Fatal("stale summary accepted")
	}
}
func TestUISelectionAndActivity(t *testing.T) {
	m := uiModel{width: 120, height: 40, page: "Home", tunState: "on", proxyState: "off", state: fixture(t).State, tunServer: M{"name": "Chosen server", "fallback": true}}
	m.state.Selected = "auto"
	m.rebuild()
	if m.items[1].page != "Local proxy" || len(m.items[1].args) != 0 {
		t.Fatal("proxy entry is not consolidated")
	}
	count := 0
	for _, item := range m.items {
		if item.page == "Local proxy" {
			count++
		}
	}
	if count != 1 {
		t.Fatal("duplicate proxy menu")
	}
	if !strings.Contains(m.View(), "automatic — TUN: Chosen server (fallback)") {
		t.Fatal(m.View())
	}
	m.startActivity("Restarting TUN…")
	if !strings.Contains(m.View(), "Subscriptions") || !strings.Contains(m.View(), "Restarting TUN…") {
		t.Fatal("menu disappeared during operation")
	}
	_, cmd := m.Update(activityMsg{m.started.Add(-time.Second)})
	if cmd != nil {
		t.Fatal("old spinner continues into next operation")
	}
	model, _ := m.Update(authRequiredMsg{menuItem{args: []string{"tun", "restart"}}})
	m = model.(uiModel)
	m.password.SetValue("secret-value")
	if strings.Contains(m.View(), "secret-value") {
		t.Fatal("password exposed")
	}
	model, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = model.(uiModel)
	if m.auth != nil || m.password.Value() != "" {
		t.Fatal("cancel retained password")
	}
}
