package whale

import (
	"path/filepath"
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
