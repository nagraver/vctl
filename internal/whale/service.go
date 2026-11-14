package whale

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"howett.net/plist"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const serviceRoot = "/Library/Application Support/vctl"

type Service struct {
	Store                                   Store
	UID                                     int
	Label, Target, Plist, Marker, Directory string
}

func NewService(s Store, uid int) Service {
	h := sha256.Sum256([]byte(canonical(s.Profile)))
	label := fmt.Sprintf("io.github.nagraver.vctl.%d.%s", uid, hex.EncodeToString(h[:])[:12])
	return Service{s, uid, label, "system/" + label, "/Library/LaunchDaemons/" + label + ".plist", "/var/run/" + label + ".enabled", filepath.Join(serviceRoot, label)}
}
func (s Service) ctl(args ...string) error {
	_, e := system(60*time.Second, "/bin/launchctl", args...)
	return e
}
func (s Service) loaded() bool { return s.ctl("print", s.Target) == nil }
func (s Service) Status() M {
	r, e := Control(s.Store, "status")
	if e != nil {
		r = M{"starting": true, "error": "runtime status unavailable"}
	}
	loaded := s.loaded()
	manager := "standalone"
	if loaded {
		manager = "launchd"
	}
	if str(r, "manager") != "" {
		manager = str(r, "manager")
	}
	return M{"manager": manager, "service": s.Label, "registered": loaded, "installed": exists(s.Plist), "enabled": exists(s.Marker), "autostart": false, "runtime": r}
}
func rootDirectory(path string) error {
	if e := os.MkdirAll(path, 0755); e != nil {
		return e
	}
	st, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if st.Mode()&os.ModeSymlink != 0 || st.Sys().(*syscall.Stat_t).Uid != 0 || st.Mode().Perm()&0022 != 0 {
		return errors.New("service directory must be root-owned and not writable by other users")
	}
	return nil
}
func (s Service) snapshot(core string) (string, error) {
	if e := rootDirectory(serviceRoot); e != nil {
		return "", e
	}
	if e := rootDirectory(s.Directory); e != nil {
		return "", e
	}
	app, e := os.ReadFile(executable())
	if e != nil {
		return "", e
	}
	xray, e := os.ReadFile(core)
	if e != nil {
		return "", e
	}
	h := sha256.New()
	h.Write(app)
	h.Write(xray)
	release := filepath.Join(s.Directory, hex.EncodeToString(h.Sum(nil)))
	if exists(release) {
		return release, rootDirectory(release)
	}
	temp, e := os.MkdirTemp(s.Directory, ".install-")
	if e != nil {
		return "", e
	}
	defer os.RemoveAll(temp)
	if e = os.Chmod(temp, 0755); e != nil {
		return "", e
	}
	if e = atomicWrite(filepath.Join(temp, "whale"), app, 0755); e != nil {
		return "", e
	}
	if e = atomicWrite(filepath.Join(temp, "xray"), xray, 0755); e != nil {
		return "", e
	}
	return release, os.Rename(temp, release)
}
func (s Service) definition(release string, port int) M {
	return M{"Label": s.Label, "ProgramArguments": []string{filepath.Join(release, "whale"), "--home", s.Store.Home, "--state-home", s.Store.Profile, "--core", filepath.Join(release, "xray"), "_service", "--owner", itoa(s.UID), "--port", itoa(port)}, "WorkingDirectory": release, "EnvironmentVariables": map[string]string{"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "VCTL_LAUNCHD_LABEL": s.Label}, "RunAtLoad": false, "KeepAlive": M{"PathState": M{s.Marker: true}}, "ThrottleInterval": 15, "ExitTimeOut": 45, "Umask": 63, "StandardOutPath": filepath.Join(s.Store.Home, "supervisor.log"), "StandardErrorPath": filepath.Join(s.Store.Home, "supervisor.log")}
}
func (s Service) Install(core string, port int) error {
	if port < 1 || port > 65534 {
		return errors.New("invalid port")
	}
	release, e := s.snapshot(core)
	if e != nil {
		return e
	}
	b, e := plist.Marshal(s.definition(release, port), plist.XMLFormat)
	if e != nil {
		return e
	}
	previous, _ := os.ReadFile(s.Plist)
	loaded := s.loaded()
	if loaded && bytes.Equal(previous, b) {
		return nil
	}
	if loaded {
		r, err := Control(s.Store, "status")
		if err != nil || r != nil || exists(s.Marker) {
			return errors.New("service is active; use Reconnect in Whale")
		}
		if e = s.ctl("bootout", s.Target); e != nil {
			return e
		}
	}
	_ = os.Remove(s.Marker)
	if e = atomicWrite(s.Plist, b, 0644); e != nil {
		return e
	}
	if e = s.ctl("bootstrap", "system", s.Plist); e != nil {
		if len(previous) > 0 {
			_ = atomicWrite(s.Plist, previous, 0644)
			if loaded {
				_ = s.ctl("bootstrap", "system", s.Plist)
			}
		} else {
			_ = os.Remove(s.Plist)
		}
		return e
	}
	return nil
}
func physicalInterface() (string, error) {
	v, e := system(5*time.Second, "/sbin/route", "-n", "get", "default")
	if e != nil {
		return "", e
	}
	m := regexp.MustCompile(`(?m)^\s*interface:\s*([A-Za-z0-9._-]+)\s*$`).FindStringSubmatch(v)
	if len(m) < 2 || strings.HasPrefix(m[1], "utun") || strings.HasPrefix(m[1], "lo") {
		return "", errors.New("physical default interface unavailable")
	}
	return m[1], nil
}
func (s Service) Preflight(core string, port int) error {
	state, e := s.Store.Read()
	if e != nil {
		return e
	}
	if _, e = CheckedConfig(s.Store, core, state, "tun", port); e != nil {
		return e
	}
	iface, e := physicalInterface()
	if e != nil {
		return e
	}
	return preflightServers(operationContext, state, func(ctx context.Context, n Node) Probe {
		return probeContext(ctx, s.Store, core, state, n, iface)
	})
}
func (s Service) Enable() error {
	fd, e := syscall.Open(s.Marker, syscall.O_CREAT|syscall.O_WRONLY|syscall.O_TRUNC|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	syscall.Close(fd)
	if e = s.ctl("kickstart", s.Target); e != nil {
		return e
	}
	for i := 0; i < 300; i++ {
		r, _ := Control(s.Store, "status")
		if str(r, "manager") == "launchd" && r["stopping"] != true {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("service startup timed out; see tun/supervisor.log")
}
func (s Service) Down() error {
	if e := os.Remove(s.Marker); e != nil && !os.IsNotExist(e) {
		return e
	}
	if s.loaded() {
		if e := s.ctl("bootout", s.Target); e != nil {
			return e
		}
	}
	_, _ = Control(s.Store, "stop")
	for i := 0; i < 250; i++ {
		unlock, e := s.Store.Lock("runtime.lock", true)
		if e == nil {
			defer unlock()
			return Recover(s.Store, "")
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("stop pending; live supervisor was not recovered")
}
func (s Service) Up(core string, port int) error {
	r, e := Control(s.Store, "status")
	if e != nil {
		return e
	}
	if r != nil || exists(s.Marker) {
		return errors.New("already running; use Reconnect in Whale")
	}
	if e = s.Preflight(core, port); e != nil {
		return e
	}
	if e = s.Install(core, port); e != nil {
		return e
	}
	if e = s.Enable(); e != nil {
		_ = s.Down()
		return e
	}
	return nil
}
func (s Service) Restart(core string, port int) error {
	old, e := Control(s.Store, "status")
	if e != nil {
		return e
	}
	oldPort := num(old, "socks_port")
	if oldPort == 0 {
		oldPort = 2180
	}
	if port == 0 {
		port = oldPort
	}
	if e = s.Preflight(core, port); e != nil {
		return e
	}
	previous, _ := os.ReadFile(s.Plist)
	managed := str(old, "manager") == "launchd" && s.loaded()
	if e = s.Down(); e != nil {
		return e
	}
	e = s.Install(core, port)
	if e == nil {
		e = s.Enable()
	}
	if e == nil {
		return nil
	}
	_ = s.Down()
	if old != nil {
		var restore error
		if managed && len(previous) > 0 {
			restore = atomicWrite(s.Plist, previous, 0644)
			if restore == nil {
				restore = s.ctl("bootstrap", "system", s.Plist)
			}
			if restore == nil {
				restore = s.Enable()
			}
		} else {
			restore = Start(s.Store, core, "tun", oldPort)
		}
		if restore != nil {
			return errors.New("new service failed and rollback failed; run whale status")
		}
		return errors.New("new service failed; previous VPN restored")
	}
	return e
}
func TunAction(profile, core, action string, port int) (M, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("TUN action requires root")
	}
	owner, e := os.Stat(profile)
	if e != nil {
		return nil, e
	}
	uid := int(owner.Sys().(*syscall.Stat_t).Uid)
	caller := os.Getenv("SUDO_UID")
	if caller != "" && caller != itoa(uid) {
		return nil, errors.New("profile must belong to sudo caller")
	}
	store, e := NewStore(filepath.Join(profile, "tun"), profile)
	if e != nil {
		return nil, e
	}
	s := NewService(store, uid)
	if action == "status" {
		return s.Status(), nil
	}
	release, e := store.Lock("service.lock", true)
	if e != nil {
		return nil, e
	}
	defer release()
	switch action {
	case "up", "start":
		e = s.Up(core, port)
	case "down", "stop":
		e = s.Down()
	case "restart":
		e = s.Restart(core, port)
	case "install":
		e = s.Install(core, port)
	case "uninstall":
		e = s.Down()
		if e == nil {
			e = os.Remove(s.Plist)
			if os.IsNotExist(e) {
				e = nil
			}
		}
		if e == nil && exists(s.Directory) {
			e = rootDirectory(s.Directory)
			if e == nil {
				e = os.RemoveAll(s.Directory)
			}
		}
	case "recover":
		r, err := Control(store, "status")
		if err != nil || r != nil {
			return nil, errors.New("stop the supervisor before recovery")
		}
		e = s.Down()
	case "run":
		r, err := Control(store, "status")
		if err != nil || r != nil || exists(s.Marker) {
			return nil, errors.New("stop the service before foreground mode")
		}
		e = Serve(store, core, "tun", port)
	default:
		e = errors.New("unknown TUN action")
	}
	if e != nil {
		return nil, e
	}
	return s.Status(), nil
}
