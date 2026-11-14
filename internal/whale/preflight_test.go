package whale

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func preflightFixture(t *testing.T) State {
	t.Helper()
	s := fixture(t).State
	s.Subscriptions = Ordered[Subscription]{}
	s.TestURL = "https://example.invalid/probe"
	s.Subscriptions.Set("test", Subscription{Nodes: []Node{{ID: "slow"}, {ID: "chosen"}, {ID: "other"}}})
	return s
}
func TestPreflightExplicitOnly(t *testing.T) {
	s := preflightFixture(t)
	s.Selected = "chosen"
	var calls atomic.Int32
	err := preflightServers(context.Background(), s, func(ctx context.Context, n Node) Probe {
		calls.Add(1)
		if n.ID != "chosen" {
			t.Errorf("unselected server probed: %s", n.ID)
		}
		return Probe{Node: n}
	})
	if err != nil || calls.Load() != 1 {
		t.Fatal(err, calls.Load())
	}
	s.Selected = "missing"
	if err := preflightServers(context.Background(), s, func(context.Context, Node) Probe { t.Fatal("missing selection probed"); return Probe{} }); err == nil {
		t.Fatal("missing selection accepted")
	}
}
func TestPreflightFirstSuccessCancelsOthers(t *testing.T) {
	s := preflightFixture(t)
	s.Selected = "auto"
	started := make(chan struct{})
	finished := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := preflightServers(ctx, s, func(ctx context.Context, n Node) Probe {
		if n.ID == "chosen" {
			<-started
			return Probe{Node: n}
		}
		if n.ID == "slow" {
			close(started)
			defer close(finished)
		}
		<-ctx.Done()
		return Probe{Node: n, Error: "cancelled"}
	})
	if err != nil || ctx.Err() != nil {
		t.Fatal("waited for slow servers", err, ctx.Err())
	}
	select {
	case <-finished:
	default:
		t.Fatal("probe cleanup still running")
	}
}
func TestPreflightAllFailed(t *testing.T) {
	s := preflightFixture(t)
	s.Selected = "auto"
	if err := preflightServers(context.Background(), s, func(_ context.Context, n Node) Probe { return Probe{Node: n, Error: "offline"} }); err == nil {
		t.Fatal("failed nodes accepted")
	}
}
