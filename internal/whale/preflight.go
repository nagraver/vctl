package whale

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"time"
)

// Startup only needs proof that the selected route works, not a complete ranking.
// The explicit ping command still tests every node.
func preflightServers(parent context.Context, state State, probe func(context.Context, Node) Probe) error {
	u, err := url.Parse(state.TestURL)
	if err != nil || u.Scheme != "https" {
		return errors.New("probe URL must use HTTPS")
	}
	nodes := state.Nodes()
	if state.Selected != "auto" {
		selected := []Node{}
		for _, n := range nodes {
			if n.ID == state.Selected {
				selected = append(selected, n)
				break
			}
		}
		nodes = selected
	}
	if len(nodes) == 0 {
		return errors.New("no selected server available; add a subscription or select a server")
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	jobs := make(chan Node, len(nodes))
	for _, n := range nodes {
		jobs <- n
	}
	close(jobs)
	results := make(chan Probe, 4)
	var wg sync.WaitGroup
	for i := 0; i < min(4, len(nodes)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range jobs {
				if ctx.Err() != nil {
					return
				}
				result := probe(ctx, n)
				select {
				case results <- result:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() { wg.Wait(); close(results) }()
	success := false
	for r := range results {
		if r.Error == "" {
			success = true
			cancel()
		}
	}
	if success {
		return nil
	}
	if parent.Err() != nil {
		return parent.Err()
	}
	return errors.New("selected servers failed preflight; running VPN was not stopped")
}
