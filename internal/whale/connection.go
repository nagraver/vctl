package whale

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Private Unix socket: the routing API is never exposed on a TCP port.
func addRuntimeAPI(config M, store Store) {
	config["api"] = M{"tag": "whale-api", "listen": filepath.Join(store.Home, "api.sock"), "services": []string{"RoutingService"}}
}
func selectedTag(body []byte, config M) (string, bool, error) {
	var response M
	if err := json.Unmarshal(body, &response); err != nil {
		return "", false, err
	}
	balancer, ok := response["balancer"].(map[string]any)
	if !ok {
		return "", false, errors.New("missing balancer status")
	}
	if tag := str(obj(balancer, "override"), "target"); tag != "" {
		return tag, false, nil
	}
	target := obj(balancer, "principleTarget")
	if len(target) == 0 {
		target = obj(balancer, "principle_target")
	}
	if tags, ok := target["tag"].([]any); ok {
		for _, v := range tags {
			if tag, ok := v.(string); ok && tag != "" {
				return tag, false, nil
			}
		}
	}
	// leastPing returns an empty target until a healthy server is known.
	// Xray then uses the explicitly configured fallbackTag, not an assumed node.
	if balancers, ok := obj(config, "routing")["balancers"].([]M); ok {
		for _, b := range balancers {
			if str(b, "tag") == "auto" && str(b, "fallbackTag") != "" {
				return str(b, "fallbackTag"), true, nil
			}
		}
	}
	return "", false, errors.New("no target selected")
}
func actualSelection(core string, store Store, state State, config M) M {
	id := state.Selected
	fallback := false
	if id == "auto" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		body, err := exec.CommandContext(ctx, core, "api", "bi", "--server=unix://"+filepath.Join(store.Home, "api.sock"), "--timeout=1", "--json", "auto").Output()
		if err != nil {
			return nil
		}
		tag, f, err := selectedTag(body, config)
		if err != nil {
			return nil
		}
		fallback = f
		id = strings.TrimPrefix(tag, "node-")
	}
	for _, n := range state.Nodes() {
		if n.ID == id {
			return M{"id": n.ID, "name": clean(n.Name), "automatic": state.Selected == "auto", "fallback": fallback}
		}
	}
	return nil
}

type connectionSummary struct {
	PID     int   `json:"pid"`
	Updated int64 `json:"updated"`
	Server  M     `json:"server"`
}

func summaryPath(s Store) string { return filepath.Join(s.Profile, "tun-status.json") }
func readTunSelection(profile, launchctlText string) M {
	b, err := os.ReadFile(filepath.Join(profile, "tun-status.json"))
	if err != nil {
		return nil
	}
	var summary connectionSummary
	if json.Unmarshal(b, &summary) != nil || time.Now().Unix()-summary.Updated > 15 || summary.PID <= 0 {
		return nil
	}
	// A stale summary from a previous supervisor must never label a new session.
	for _, line := range strings.Split(launchctlText, "\n") {
		if strings.TrimSpace(line) == "pid = "+itoa(summary.PID) {
			return summary.Server
		}
	}
	return nil
}
