package whale

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func inheritOwner(path, parent string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	st, e := os.Stat(parent)
	if e != nil {
		return e
	}
	o := st.Sys().(*syscall.Stat_t)
	return os.Chown(path, int(o.Uid), int(o.Gid))
}
func readLimit(r io.Reader, limit int64) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, limit+1))
	if e == nil && int64(len(b)) > limit {
		e = errors.New("file exceeds size limit")
	}
	return b, e
}
func system(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	b, e := exec.CommandContext(ctx, name, args...).Output()
	if e != nil {
		return "", errors.New(filepath.Base(name) + " failed")
	}
	return strings.TrimSpace(string(b)), nil
}
func dnsValues(s string) ([]string, error) {
	if strings.HasPrefix(s, "There aren't any DNS Servers") {
		return []string{}, nil
	}
	out := strings.Split(s, "\n")
	for _, v := range out {
		if net.ParseIP(v) == nil {
			return nil, errors.New("invalid system DNS response")
		}
	}
	return out, nil
}

type dnsJournal struct {
	Previous map[string][]string `json:"previous"`
	Applied  []string            `json:"applied"`
}

func dnsRestore(s Store) error {
	path := filepath.Join(s.Home, "dns-restore.json")
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	var j dnsJournal
	if json.Unmarshal(b, &j) != nil {
		return errors.New("invalid DNS recovery journal")
	}
	for name, previous := range j.Previous {
		out, e := system(15*time.Second, "/usr/sbin/networksetup", "-getdnsservers", name)
		if e != nil {
			return e
		}
		current, e := dnsValues(out)
		if e != nil {
			return e
		}
		if strings.Join(current, ",") == strings.Join(j.Applied, ",") {
			if len(previous) == 0 {
				previous = []string{"Empty"}
			}
			args := append([]string{"-setdnsservers", name}, previous...)
			if _, e = system(15*time.Second, "/usr/sbin/networksetup", args...); e != nil {
				return errors.New("DNS restoration incomplete; run whale tun recover")
			}
		}
	}
	if e = os.Remove(path); e != nil {
		return e
	}
	_, _ = system(10*time.Second, "/usr/bin/dscacheutil", "-flushcache")
	return nil
}
func dnsAcquire(s Store) error {
	if e := dnsRestore(s); e != nil {
		return e
	}
	out, e := system(15*time.Second, "/usr/sbin/networksetup", "-listallnetworkservices")
	if e != nil {
		return e
	}
	names := strings.Split(out, "\n")
	j := dnsJournal{map[string][]string{}, []string{"198.19.255.53"}}
	for _, name := range names[1:] {
		if name == "" || strings.HasPrefix(name, "*") {
			continue
		}
		info, e := system(15*time.Second, "/usr/sbin/networksetup", "-getinfo", name)
		if e != nil {
			return e
		}
		active := false
		for _, line := range strings.Split(info, "\n") {
			if strings.HasPrefix(line, "IP address:") {
				v := strings.TrimSpace(strings.TrimPrefix(line, "IP address:"))
				active = v != "" && v != "none"
			}
		}
		if active {
			v, e := system(15*time.Second, "/usr/sbin/networksetup", "-getdnsservers", name)
			if e != nil {
				return e
			}
			j.Previous[name], e = dnsValues(v)
			if e != nil {
				return e
			}
		}
	}
	if len(j.Previous) == 0 {
		return errors.New("no active network service found")
	}
	if e = writeJSON(filepath.Join(s.Home, "dns-restore.json"), j); e != nil {
		return e
	}
	for name := range j.Previous {
		if _, e = system(15*time.Second, "/usr/sbin/networksetup", "-setdnsservers", name, "198.19.255.53"); e != nil {
			_ = dnsRestore(s)
			return e
		}
	}
	_, _ = system(10*time.Second, "/usr/bin/dscacheutil", "-flushcache")
	return nil
}
func processCommand(pid int) string {
	v, _ := system(3*time.Second, "/bin/ps", "-p", itoa(pid), "-o", "command=")
	return v
}
func Recover(s Store, instance string) error {
	path := filepath.Join(s.Home, "runtime.json")
	b, e := os.ReadFile(path)
	if e == nil {
		var r M
		if json.Unmarshal(b, &r) != nil {
			return errors.New("invalid runtime journal")
		}
		if instance != "" && str(r, "instance") != instance {
			return nil
		}
		pid := num(r, "core_pid")
		expected := filepath.Join(s.Home, "config.json")
		if pid > 1 && strings.Contains(processCommand(pid), expected) {
			_ = syscall.Kill(pid, syscall.SIGTERM)
			for i := 0; i < 50 && strings.Contains(processCommand(pid), expected); i++ {
				time.Sleep(100 * time.Millisecond)
			}
			if strings.Contains(processCommand(pid), expected) {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
		_ = os.Remove(path)
	} else if !os.IsNotExist(e) {
		return e
	}
	if e = dnsRestore(s); e != nil {
		return e
	}
	_ = os.Remove(filepath.Join(s.Home, "control.sock"))
	return nil
}
func Watch(s Store, instance string) error {
	for {
		if operationContext.Err() != nil {
			return nil
		}
		b, e := os.ReadFile(filepath.Join(s.Home, "runtime.json"))
		if e != nil {
			return nil
		}
		var r M
		if json.Unmarshal(b, &r) != nil {
			return errors.New("invalid runtime journal")
		}
		if str(r, "instance") != instance {
			return nil
		}
		if strings.TrimSpace(str(r, "supervisor_command")) != processCommand(num(r, "pid")) {
			unlock, e := s.Lock("runtime.lock", true)
			if e == nil {
				defer unlock()
				return Recover(s, instance)
			}
		}
		time.Sleep(time.Second)
	}
}
