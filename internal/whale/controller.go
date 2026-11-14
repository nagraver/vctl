package whale

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"howett.net/plist"
)

type Controller struct{ Service }

func newController(profile string, uid int) Controller {
	s := NewService(Store{filepath.Join(profile, "tun"), profile}, uid)
	s.Label += ".control"
	s.Target = "system/" + s.Label
	s.Plist = "/Library/LaunchDaemons/" + s.Label + ".plist"
	s.Directory = filepath.Join(serviceRoot, s.Label)
	return Controller{s}
}
func (c Controller) socket() string { return "/var/run/" + c.Label + ".sock" }
func controllerActionAllowed(action string) bool {
	switch action {
	case "status", "up", "down", "restart", "install", "recover", "uninstall":
		return true
	}
	return false
}
func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, e := conn.SyscallConn()
	if e != nil {
		return 0, e
	}
	var uid uint32
	var credErr error
	e = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		credErr = err
		if err == nil {
			uid = cred.Uid
		}
	})
	if e != nil {
		return 0, e
	}
	return uid, credErr
}

type controllerRequest struct {
	Action string `json:"action"`
}
type controllerReply struct {
	Result M      `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

func controllerCall(profile string, uid int, action string) (M, error) {
	if !controllerActionAllowed(action) {
		return nil, errors.New("unsupported control action")
	}
	c := newController(canonical(profile), uid)
	raw, e := net.DialTimeout("unix", c.socket(), 2*time.Second)
	if e != nil {
		return nil, e
	}
	defer raw.Close()
	conn := raw.(*net.UnixConn)
	peer, e := peerUID(conn)
	if e != nil || peer != 0 {
		return nil, errors.New("system helper identity check failed")
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Minute))
	if e = json.NewEncoder(conn).Encode(controllerRequest{action}); e != nil {
		return nil, e
	}
	var reply controllerReply
	if e = json.NewDecoder(io.LimitReader(conn, 1024*1024)).Decode(&reply); e != nil {
		return nil, e
	}
	if reply.Error != "" {
		return nil, errors.New(reply.Error)
	}
	return reply.Result, nil
}
func InstallController(profile, core string) error {
	if os.Geteuid() != 0 {
		return errors.New("administrator approval required to install system helper")
	}
	profile = canonical(profile)
	st, e := os.Stat(profile)
	if e != nil {
		return e
	}
	uid := int(st.Sys().(*syscall.Stat_t).Uid)
	if uid == 0 || !st.IsDir() {
		return errors.New("profile must belong to a non-root user")
	}
	if caller := os.Getenv("SUDO_UID"); caller != "" && caller != itoa(uid) {
		return errors.New("profile owner mismatch")
	}
	c := newController(profile, uid)
	release, e := c.snapshot(core)
	if e != nil {
		return e
	}
	definition := M{"Label": c.Label, "ProgramArguments": []string{filepath.Join(release, "whale"), "--home", profile, "--core", filepath.Join(release, "xray"), "_controller", "--owner", itoa(uid)}, "WorkingDirectory": release, "RunAtLoad": true, "KeepAlive": true, "ThrottleInterval": 5, "Umask": 63, "EnvironmentVariables": M{"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "WHALE_CONTROLLER_LABEL": c.Label}, "StandardOutPath": filepath.Join(c.Directory, "controller.log"), "StandardErrorPath": filepath.Join(c.Directory, "controller.log")}
	b, e := plist.Marshal(definition, plist.XMLFormat)
	if e != nil {
		return e
	}
	previous, _ := os.ReadFile(c.Plist)
	loaded := c.loaded()
	if loaded {
		if e = c.ctl("bootout", c.Target); e != nil {
			return e
		}
	}
	if e = atomicWrite(c.Plist, b, 0644); e != nil {
		return e
	}
	if e = c.ctl("bootstrap", "system", c.Plist); e != nil {
		if len(previous) > 0 {
			_ = atomicWrite(c.Plist, previous, 0644)
			if loaded {
				_ = c.ctl("bootstrap", "system", c.Plist)
			}
		} else {
			_ = os.Remove(c.Plist)
		}
		return e
	}
	for i := 0; i < 100; i++ {
		if _, e = controllerCall(profile, uid, "status"); e == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("system helper did not start; check controller.log")
}
func ServeController(profile, core string, uid int) error {
	if os.Geteuid() != 0 {
		return errors.New("root required")
	}
	profile = canonical(profile)
	c := newController(profile, uid)
	if os.Getenv("WHALE_CONTROLLER_LABEL") != c.Label {
		return errors.New("controller must be launched by launchd")
	}
	st, e := os.Stat(profile)
	if e != nil || int(st.Sys().(*syscall.Stat_t).Uid) != uid {
		return errors.New("profile owner mismatch")
	}
	// The socket's parent is root-owned. Other users cannot replace it.
	_ = os.Remove(c.socket())
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: c.socket(), Net: "unix"})
	if e != nil {
		return e
	}
	defer listener.Close()
	if e = os.Chmod(c.socket(), 0600); e != nil {
		return e
	}
	if e = os.Chown(c.socket(), uid, -1); e != nil {
		return e
	}
	for {
		conn, e := listener.AcceptUnix()
		if e != nil {
			return e
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Minute))
		peer, e := peerUID(conn)
		if e != nil || (peer != uint32(uid) && peer != 0) {
			conn.Close()
			continue
		}
		var request controllerRequest
		decoder := json.NewDecoder(io.LimitReader(conn, 4096))
		decoder.DisallowUnknownFields()
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if decoder.Decode(&request) != nil || !controllerActionAllowed(request.Action) {
			_ = json.NewEncoder(conn).Encode(controllerReply{Error: "unsupported control request"})
			conn.Close()
			continue
		}
		reply := controllerReply{Result: M{"ready": true, "version": Version}}
		if request.Action != "status" {
			// No executable, profile, port or shell command is accepted from the client.
			current, err := os.Stat(profile)
			if err != nil || int(current.Sys().(*syscall.Stat_t).Uid) != uid {
				reply.Error = "profile owner mismatch"
			} else {
				reply.Result, err = TunAction(profile, core, request.Action, 2180)
				if err != nil {
					reply.Error = err.Error()
				}
			}
		}
		uninstall := request.Action == "uninstall" && reply.Error == ""
		if uninstall {
			if err := os.Remove(c.Plist); err != nil && !os.IsNotExist(err) {
				reply.Error = err.Error()
				uninstall = false
			}
		}
		_ = json.NewEncoder(conn).Encode(reply)
		conn.Close()
		if uninstall {
			listener.Close()
			_ = os.Remove(c.socket())
			if rootDirectory(c.Directory) == nil {
				_ = os.RemoveAll(c.Directory)
			}
			return c.ctl("bootout", c.Target)
		}
	}
}
