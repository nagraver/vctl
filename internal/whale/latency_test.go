package whale

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"
)

func TestLatencyStreamsBeforeSlowProbeAndCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	slowDone := make(chan struct{})
	slowStarted := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- streamLatency(ctx, []Node{{ID: "slow"}, {ID: "fast"}}, func(ctx context.Context, n Node) latencyResult {
			if n.ID == "slow" {
				close(slowStarted)
				<-ctx.Done()
				close(slowDone)
			}
			if n.ID == "fast" {
				<-slowStarted
			}
			return latencyResult{ID: n.ID, Milliseconds: 12}
		}, writer)
		writer.Close()
	}()
	first := make(chan latencyResult, 1)
	go func() { var r latencyResult; _ = json.NewDecoder(reader).Decode(&r); first <- r }()
	select {
	case r := <-first:
		if r.ID != "fast" {
			t.Fatal(r)
		}
	case <-time.After(time.Second):
		t.Fatal("waited for all probes")
	}
	cancel()
	select {
	case <-slowDone:
	case <-time.After(time.Second):
		t.Fatal("probe not cancelled")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stream not cancelled")
	}
}
func TestStandaloneProxyCommandsRemoved(t *testing.T) {
	for _, name := range []string{"up", "down", "start", "stop", "restart", "run", "status", "doctor"} {
		root := newBackendCommand(&App{Home: t.TempDir()})
		root.SetArgs([]string{name})
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		if root.Execute() == nil {
			t.Fatalf("standalone proxy command remains: %s", name)
		}
	}
}

func TestLatencySubscriptionScope(t *testing.T) {
	v := emptyState()
	v.Subscriptions.Set("one", Subscription{Nodes: []Node{{ID: "a"}, {ID: "a"}}})
	v.Subscriptions.Set("two", Subscription{Nodes: []Node{{ID: "b"}, {ID: "a"}}})
	nodes, err := latencyNodes(v, "one", "")
	if err != nil || len(nodes) != 1 || nodes[0].ID != "a" {
		t.Fatal(nodes, err)
	}
	nodes, err = latencyNodes(v, "two", "b")
	if err != nil || len(nodes) != 1 || nodes[0].ID != "b" {
		t.Fatal(nodes, err)
	}
	if _, err = latencyNodes(v, "one", "b"); err == nil {
		t.Fatal("server escaped subscription scope")
	}
	if _, err = latencyNodes(v, "missing", ""); err == nil {
		t.Fatal("unknown subscription accepted")
	}
}
