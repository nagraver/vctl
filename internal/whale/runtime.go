package whale

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func itoa(v int) string  { return strconv.Itoa(v) }
func executable() string { p, _ := os.Executable(); return canonical(p) }
func Core(override string) (string, error) {
	candidates := []string{override, os.Getenv("WHALE_CORE"), os.Getenv("VCTL_CORE"), filepath.Join(filepath.Dir(executable()), "xray"), filepath.Join(filepath.Dir(executable()), ".tools/xray"), filepath.Join(filepath.Dir(executable()), "../libexec/xray"), filepath.Join(filepath.Dir(executable()), "../.tools/xray"), filepath.Join(filepath.Dir(executable()), "../libexec/.tools/xray")}
	if p, e := exec.LookPath("xray"); e == nil {
		candidates = append(candidates, p)
	}
	for i, p := range candidates {
		if p == "" {
			continue
		}
		if !exists(p) && i >= 3 {
			continue
		}
		v, e := system(10*time.Second, p, "version")
		if e != nil || !strings.HasPrefix(v, "Xray ") {
			return "", errors.New("selected binary is not Xray; set --core or WHALE_CORE")
		}
		return canonical(p), nil
	}
	return "", errors.New("cannot find Xray; set --core or WHALE_CORE")
}
func ValidateConfig(s Store, core string, c M) error {
	f, e := os.CreateTemp(s.Home, "validation-*.json")
	if e != nil {
		return e
	}
	p := f.Name()
	f.Close()
	defer os.Remove(p)
	if e = writeJSON(p, c); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(operationContext, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, core, "run", "-test", "-c", p)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Join(s.Profile, "geodata"))
	if e = cmd.Run(); e != nil {
		return errors.New("configuration rejected by Xray; previous configuration preserved")
	}
	return nil
}
func resolveState(s State) (State, error) {
	s = s.Clone()
	ctx, cancel := context.WithTimeout(operationContext, 20*time.Second)
	defer cancel()
	for _, k := range s.Subscriptions.Keys {
		p := s.Subscriptions.Values[k]
		for i := range p.Nodes {
			o := p.Nodes[i].Outbound
			host := str(o, "server")
			if net.ParseIP(host) == nil {
				ips, e := net.DefaultResolver.LookupIPAddr(ctx, host)
				if e != nil || len(ips) == 0 {
					return s, errors.New("cannot resolve VPN server")
				}
				sort.SliceStable(ips, func(i, j int) bool { return ips[i].IP.To4() != nil && ips[j].IP.To4() == nil })
				o["server"] = ips[0].IP.String()
			}
		}
		s.Subscriptions.Set(k, p)
	}
	return s, nil
}
func CheckedConfig(s Store, core string, v State, mode string, port int) (M, error) {
	if e := ValidateAssets(s, core, v); e != nil {
		return nil, e
	}
	if mode == "tun" {
		var e error
		v, e = resolveState(v)
		if e != nil {
			return nil, e
		}
	}
	c, e := Generate(v, mode, port)
	if e != nil {
		return nil, e
	}
	return c, ValidateConfig(s, core, c)
}

type child struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func spawn(core, path, assets string) (*child, error) {
	c := exec.Command(core, "run", "-c", path)
	c.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+assets)
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if e := c.Start(); e != nil {
		return nil, e
	}
	p := &child{c, make(chan struct{})}
	go func() { _ = c.Wait(); close(p.done) }()
	return p, nil
}
func (p *child) stop() {
	if p == nil {
		return
	}
	select {
	case <-p.done:
		return
	default:
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(8 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}
func (p *child) ready(port int, mode string) error {
	return p.readyContext(operationContext, port, mode)
}
func (p *child) readyContext(ctx context.Context, port int, mode string) error {
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.done:
			return errors.New("core Xray exited during startup")
		default:
		}
		c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), 100*time.Millisecond)
		if e == nil {
			c.Close()
			if mode != "tun" {
				return nil
			}
			v, _ := system(2*time.Second, "/sbin/route", "-n", "get", "198.19.255.53")
			if strings.Contains(v, "gateway: 172.28.0.1") && strings.Contains(v, "interface: utun") {
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("cannot start Xray: listener or TUN route not ready")
}
func Control(s Store, op string) (M, error) {
	c, e := net.DialTimeout("unix", filepath.Join(s.Home, "control.sock"), 3*time.Second)
	if e != nil {
		if errors.Is(e, os.ErrNotExist) || errors.Is(e, syscall.ECONNREFUSED) {
			return nil, nil
		}
		return nil, e
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = c.Write([]byte(op)); e != nil {
		return nil, e
	}
	b := make([]byte, 8192)
	n, e := c.Read(b)
	if e != nil {
		return nil, e
	}
	if string(b[:n]) == "stopped" {
		return nil, nil
	}
	var status M
	e = json.Unmarshal(b[:n], &status)
	return status, e
}
func Start(s Store, core, mode string, port int) error {
	if v, e := Control(s, "status"); e != nil {
		return e
	} else if v != nil {
		return errors.New("already running")
	}
	v, e := s.Read()
	if e != nil {
		return e
	}
	if _, e = CheckedConfig(s, core, v, mode, port); e != nil {
		return e
	}
	log, e := os.OpenFile(filepath.Join(s.Home, "supervisor.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer log.Close()
	c := exec.Command(executable(), "--home", s.Home, "--state-home", s.Profile, "--core", core, "_serve", "--mode", mode, "--port", itoa(port))
	c.Stdout = log
	c.Stderr = log
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if e = c.Start(); e != nil {
		return e
	}
	done := make(chan struct{})
	go func() { _ = c.Wait(); close(done) }()
	for i := 0; i < 300; i++ {
		select {
		case <-done:
			return errors.New("supervisor failed; see supervisor.log")
		default:
		}
		if r, _ := Control(s, "status"); r != nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = c.Process.Signal(syscall.SIGTERM)
	return errors.New("startup timed out")
}

type Probe struct {
	Node         Node
	Milliseconds int
	Error        string
}

func probeContext(ctx context.Context, s Store, core string, state State, n Node, iface string) Probe {
	fail := Probe{n, 0, "HTTPS probe failed"}
	if ctx.Err() != nil {
		return fail
	}
	dir, e := os.MkdirTemp(s.Home, "probe-")
	if e != nil {
		return fail
	}
	defer os.RemoveAll(dir)
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return fail
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	if port == 65535 {
		return fail
	}
	state = state.Clone()
	state.Subscriptions = Ordered[Subscription]{}
	state.Subscriptions.Set("probe", Subscription{Nodes: []Node{n}})
	state.Presets = Ordered[Preset]{}
	state.Rules = nil
	state.Selected = n.ID
	state.Default = "proxy"
	c, e := Generate(state, "proxy", port)
	if e != nil {
		return fail
	}
	c["inbounds"] = c["inbounds"].([]M)[:1]
	c["routing"] = M{"rules": []M{{"type": "field", "network": "tcp,udp", "outboundTag": "node-" + n.ID}}}
	if iface != "" {
		obj(c["outbounds"].([]M)[0], "streamSettings")["sockopt"] = M{"interface": iface}
	}
	path := filepath.Join(dir, "config.json")
	if writeJSON(path, c) != nil {
		return fail
	}
	p, e := spawn(core, path, filepath.Join(s.Profile, "geodata"))
	if e != nil {
		return fail
	}
	defer p.stop()
	if p.readyContext(ctx, port, "proxy") != nil {
		return fail
	}
	d, e := proxy.SOCKS5("tcp", "127.0.0.1:"+itoa(port), nil, &net.Dialer{Timeout: 10 * time.Second})
	if e != nil {
		return fail
	}
	transport := &http.Transport{DialContext: d.(proxy.ContextDialer).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if r.URL.Scheme != "https" || len(via) > 10 {
			return errors.New("redirect refused")
		}
		return nil
	}}
	at := time.Now()
	req, e := http.NewRequestWithContext(ctx, "GET", state.TestURL, nil)
	if e != nil {
		return fail
	}
	r, e := client.Do(req)
	if e != nil {
		return fail
	}
	defer r.Body.Close()
	_, e = io.Copy(io.Discard, io.LimitReader(r.Body, 1000000))
	if e != nil || r.StatusCode < 200 || r.StatusCode >= 400 {
		return fail
	}
	return Probe{n, int(time.Since(at).Milliseconds()), ""}
}
func Serve(s Store, core, mode string, port int) error {
	if mode == "tun" && os.Geteuid() != 0 {
		return errors.New("use whale tun up")
	}
	unlock, e := s.Lock("runtime.lock", true)
	if e != nil {
		return e
	}
	defer unlock()
	if mode == "tun" {
		if e = Recover(s, ""); e != nil {
			return e
		}
	}
	state, e := s.Read()
	if e != nil {
		return e
	}
	config, e := CheckedConfig(s, core, state, mode, port)
	if e != nil {
		return e
	}
	addRuntimeAPI(config, s)
	if e = ValidateConfig(s, core, config); e != nil {
		return e
	}
	path := filepath.Join(s.Home, "config.json")
	if e = writeJSON(path, config); e != nil {
		return e
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	instance := hex.EncodeToString(id)
	var p *child
	var watcher *exec.Cmd
	launch := func() error {
		var e error
		_ = os.Remove(filepath.Join(s.Home, "api.sock"))
		p, e = spawn(core, path, filepath.Join(s.Profile, "geodata"))
		if e != nil {
			return e
		}
		if mode == "tun" {
			if e = writeJSON(filepath.Join(s.Home, "runtime.json"), M{"instance": instance, "pid": os.Getpid(), "core_pid": p.cmd.Process.Pid, "supervisor_command": processCommand(os.Getpid())}); e != nil {
				return e
			}
		}
		return p.ready(port, mode)
	}
	defer func() {
		p.stop()
		_ = os.Remove(filepath.Join(s.Home, "api.sock"))
		if mode == "tun" {
			_ = os.Remove(summaryPath(s))
		}
		if mode == "tun" {
			if err := dnsRestore(s); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
			if watcher != nil {
				_ = watcher.Process.Signal(syscall.SIGTERM)
				_ = watcher.Wait()
			}
			_ = os.Remove(filepath.Join(s.Home, "runtime.json"))
		}
	}()
	if e = launch(); e != nil {
		return e
	}
	if mode == "tun" {
		watcher = exec.Command(executable(), "--home", s.Home, "_watch", instance)
		watcher.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if e = watcher.Start(); e != nil {
			return e
		}
		if e = dnsAcquire(s); e != nil {
			return e
		}
	}
	socket := filepath.Join(s.Home, "control.sock")
	_ = os.Remove(socket)
	listener, e := net.Listen("unix", socket)
	if e != nil {
		return e
	}
	defer listener.Close()
	defer os.Remove(socket)
	_ = os.Chmod(socket, 0600)
	stop := make(chan struct{}, 1)
	var mu sync.Mutex
	status := M{}
	setStatus := func(err string) {
		mu.Lock()
		defer mu.Unlock()
		manager := "standalone"
		if os.Getenv("VCTL_LAUNCHD_LABEL") != "" {
			manager = "launchd"
		}
		server := status["server"]
		status = M{"server": server, "mode": mode, "pid": os.Getpid(), "core_pid": p.cmd.Process.Pid, "manager": manager, "engine": "xray", "socks_port": port, "http_port": port + 1, "error": err, "stopping": false}
	}
	setStatus("")
	// Poll selection independently of subscription refresh and connection control.
	selectionCtx, stopSelection := context.WithCancel(context.Background())
	selectionDone := make(chan struct{})
	var selectionMu sync.RWMutex
	selectionState, selectionConfig := state, config
	go func() {
		defer close(selectionDone)
		for {
			selectionMu.RLock()
			v, c := selectionState, selectionConfig
			selectionMu.RUnlock()
			server := actualSelection(core, s, v, c)
			mu.Lock()
			status["server"] = server
			mu.Unlock()
			if mode == "tun" {
				_ = writeJSON(summaryPath(s), connectionSummary{os.Getpid(), time.Now().Unix(), server})
			}
			select {
			case <-selectionCtx.Done():
				return
			case <-time.After(3 * time.Second):
			}
		}
	}()
	defer func() { stopSelection(); <-selectionDone }()
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(time.Second))
			b := make([]byte, 64)
			n, _ := c.Read(b)
			mu.Lock()
			if string(b[:n]) == "stop" {
				operationCancel() // Interrupt subscription downloads before orderly teardown.
				status["stopping"] = true
				select {
				case stop <- struct{}{}:
				default:
				}
			}
			out, _ := json.Marshal(status)
			mu.Unlock()
			_, _ = c.Write(out)
			c.Close()
		}
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	applied, _ := connectionFingerprint(state)
	retry := time.Time{}
	for {
		select {
		case <-signals:
			return nil
		case <-stop:
			return nil
		case <-p.done:
			return errors.New("core Xray exited unexpectedly")
		case <-ticker.C:
			if time.Now().Before(retry) {
				continue
			}
			err := func() error {
				release, e := s.Lock("state.lock", true)
				if e != nil {
					return nil
				}
				defer release()
				current, e := s.Read()
				if e != nil {
					return e
				}
				if e = Refresh(s, &current); e != nil {
					return e
				}
				fingerprint, _ := connectionFingerprint(current)
				if string(fingerprint) == string(applied) {
					return nil
				}
				updated, e := CheckedConfig(s, core, current, mode, port)
				if e != nil {
					return e
				}
				addRuntimeAPI(updated, s)
				before, _ := json.Marshal(config)
				after, _ := json.Marshal(updated)
				if string(before) != string(after) {
					if e = writeJSON(path, updated); e != nil {
						return e
					}
					p.stop()
					if e = launch(); e != nil {
						p.stop()
						_ = writeJSON(path, config)
						if rollback := launch(); rollback != nil {
							return fmt.Errorf("new configuration and rollback failed")
						}
						return errors.New("new configuration failed; previous configuration restored")
					}
					config = updated
				}
				if e = s.Write(current); e != nil {
					return e
				}
				selectionMu.Lock()
				selectionState = current
				selectionConfig = config
				selectionMu.Unlock()
				applied = fingerprint
				return nil
			}()
			if err != nil {
				setStatus("Update failed; previous configuration retained; retry in 60s")
				retry = time.Now().Add(time.Minute)
			} else {
				setStatus("")
			}
		}
	}
}

func connectionFingerprint(state State) ([]byte, error) { state.UI = nil; return json.Marshal(state) }
