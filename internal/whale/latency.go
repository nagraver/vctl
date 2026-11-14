package whale

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type latencyResult struct {
	ID           string `json:"id"`
	Milliseconds int64  `json:"milliseconds"`
	Error        string `json:"error,omitempty"`
}

// Stream results as each bounded TCP handshake completes. No Xray process is started.
func streamLatency(ctx context.Context, nodes []Node, probe func(context.Context, Node) latencyResult, out io.Writer) error {
	results := make(chan latencyResult, 8)
	jobs := make(chan Node)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range jobs {
				if ctx.Err() != nil {
					return
				}
				r := probe(ctx, n)
				select {
				case results <- r:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, n := range nodes {
			select {
			case jobs <- n:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	encoder := json.NewEncoder(out)
	for r := range results {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e := encoder.Encode(r); e != nil {
			return e
		}
	}
	return ctx.Err()
}
func tcpLatency(ctx context.Context, n Node, iface int) latencyResult {
	r := latencyResult{ID: n.ID}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	dialer := net.Dialer{}
	if iface > 0 {
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			var err error
			e := c.Control(func(fd uintptr) {
				level, opt := unix.IPPROTO_IP, unix.IP_BOUND_IF
				if network == "tcp6" {
					level, opt = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
				}
				err = unix.SetsockoptInt(int(fd), level, opt, iface)
			})
			if e != nil {
				return e
			}
			return err
		}
	}
	at := time.Now()
	connection, e := dialer.DialContext(ctx, "tcp", net.JoinHostPort(str(n.Outbound, "server"), itoa(num(n.Outbound, "server_port"))))
	if e != nil {
		r.Error = "Unreachable"
		if ctx.Err() != nil {
			r.Error = "Timeout"
		}
		return r
	}
	r.Milliseconds = time.Since(at).Milliseconds()
	if r.Milliseconds < 1 {
		r.Milliseconds = 1
	}
	connection.Close()
	return r
}

func latencyNodes(v State, subscription, server string) ([]Node, error) {
	nodes := v.Nodes()
	if subscription != "" {
		sub, ok := v.Subscriptions.Values[subscription]
		if !ok {
			return nil, errors.New("subscription not found")
		}
		nodes = sub.Nodes
	}
	result := []Node{}
	seen := map[string]bool{}
	for _, n := range nodes {
		if (server == "" || n.ID == server) && !seen[n.ID] {
			seen[n.ID] = true
			result = append(result, n)
		}
	}
	if server != "" && len(result) == 0 {
		return nil, errors.New("server not found in selected subscription")
	}
	return result, nil
}
