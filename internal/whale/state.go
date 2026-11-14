package whale

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type M = map[string]any

// Ordered preserves rule preset precedence and the automatic fallback server.
type Ordered[T any] struct {
	Keys   []string
	Values map[string]T
}

func (o *Ordered[T]) Set(k string, v T) {
	if o.Values == nil {
		o.Values = map[string]T{}
	}
	if _, ok := o.Values[k]; !ok {
		o.Keys = append(o.Keys, k)
	}
	o.Values[k] = v
}
func (o *Ordered[T]) Delete(k string) {
	delete(o.Values, k)
	for i, n := range o.Keys {
		if n == k {
			o.Keys = append(o.Keys[:i], o.Keys[i+1:]...)
			break
		}
	}
}
func (o Ordered[T]) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.Keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		v, e := json.Marshal(o.Values[k])
		if e != nil {
			return nil, e
		}
		b.Write(kb)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}
func (o *Ordered[T]) UnmarshalJSON(b []byte) error {
	*o = Ordered[T]{}
	d := json.NewDecoder(bytes.NewReader(b))
	tok, e := d.Token()
	if e != nil {
		return e
	}
	if tok != json.Delim('{') {
		return errors.New("expected object")
	}
	for d.More() {
		k, e := d.Token()
		if e != nil {
			return e
		}
		var v T
		if e = d.Decode(&v); e != nil {
			return e
		}
		o.Set(k.(string), v)
	}
	_, e = d.Token()
	return e
}

type Node struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Outbound M      `json:"outbound"`
}
type Subscription struct {
	Skipped  int     `json:"skipped,omitempty"`
	URL      string  `json:"url"`
	Interval int     `json:"interval"`
	Updated  float64 `json:"updated"`
	Nodes    []Node  `json:"nodes"`
	Title    string  `json:"title"`
}
type Rule struct {
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Action string `json:"action"`
}
type Preset struct {
	Source   string  `json:"source"`
	Interval int     `json:"interval"`
	Updated  float64 `json:"updated"`
	Enabled  bool    `json:"enabled"`
	Rules    []Rule  `json:"rules"`
}
type Asset struct {
	URL      string  `json:"url"`
	SHA      string  `json:"sha256"`
	Updated  float64 `json:"updated"`
	Interval int     `json:"interval"`
}
type UIPreferences struct {
	Language string `json:"language"`
}
type State struct {
	UI            *UIPreferences        `json:"ui,omitempty"`
	Version       int                   `json:"version"`
	Subscriptions Ordered[Subscription] `json:"subscriptions"`
	Rules         []Rule                `json:"rules"`
	Selected      string                `json:"selected"`
	Default       string                `json:"default"`
	TestURL       string                `json:"test_url"`
	Presets       Ordered[Preset]       `json:"presets"`
	Geodata       map[string]Asset      `json:"geodata,omitempty"`
	DNS           map[string]string     `json:"dns,omitempty"`
}

func emptyState() State {
	return State{Version: 1, Rules: []Rule{}, Selected: "auto", Default: "proxy", TestURL: "https://www.gstatic.com/generate_204", Geodata: map[string]Asset{}, DNS: map[string]string{}}
}
func (s State) Nodes() []Node {
	var out []Node
	seen := map[string]bool{}
	for _, k := range s.Subscriptions.Keys {
		for _, n := range s.Subscriptions.Values[k].Nodes {
			if !seen[n.ID] {
				out = append(out, n)
				seen[n.ID] = true
			}
		}
	}
	return out
}
func (s State) Clone() State {
	b, _ := json.Marshal(s)
	var r State
	_ = json.Unmarshal(b, &r)
	return r
}

type Store struct{ Home, Profile string }

func canonical(p string) string {
	if p == "~" || len(p) > 1 && p[:2] == "~/" {
		h, _ := os.UserHomeDir()
		p = filepath.Join(h, p[1:])
	}
	p, _ = filepath.Abs(p)
	if r, e := filepath.EvalSymlinks(p); e == nil {
		return r
	}
	return p
}
func NewStore(home, profile string) (Store, error) {
	home = canonical(home)
	if profile == "" {
		profile = home
	} else {
		profile = canonical(profile)
	}
	s := Store{home, profile}
	if len(filepath.Join(home, "control.sock")) >= 104 {
		return s, errors.New("profile path is too long")
	}
	if e := os.MkdirAll(home, 0700); e != nil {
		return s, e
	}
	st, e := os.Stat(home)
	if e != nil {
		return s, e
	}
	if int(st.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
		return s, errors.New("runtime directory must belong to current user")
	}
	if e = os.Chmod(home, 0700); e != nil {
		return s, e
	}
	return s, nil
}
func (s Store) Read() (State, error) {
	v := emptyState()
	b, e := os.ReadFile(filepath.Join(s.Profile, "state.json"))
	if os.IsNotExist(e) {
		return v, nil
	}
	if e != nil {
		return v, e
	}
	e = json.Unmarshal(b, &v)
	if e == nil && v.Version != 1 {
		e = errors.New("unsupported profile version")
	}
	return v, e
}
func atomicWrite(path string, b []byte, mode os.FileMode) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".pending-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if e = f.Chmod(mode); e != nil {
		return e
	}
	if os.Geteuid() == 0 {
		st, e := os.Stat(filepath.Dir(path))
		if e != nil {
			return e
		}
		o := st.Sys().(*syscall.Stat_t)
		if e = f.Chown(int(o.Uid), int(o.Gid)); e != nil {
			return e
		}
	}
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
func writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return atomicWrite(path, b, 0600)
}
func (s Store) Write(v State) error { return writeJSON(filepath.Join(s.Profile, "state.json"), v) }
func (s Store) Lock(name string, nonblock bool) (func(), error) {
	dir := s.Home
	if name == "state.lock" {
		dir = s.Profile
	}
	f, e := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if os.Geteuid() == 0 {
		st, _ := os.Stat(dir)
		o := st.Sys().(*syscall.Stat_t)
		_ = f.Chown(int(o.Uid), int(o.Gid))
	}
	flags := syscall.LOCK_EX
	if nonblock {
		flags |= syscall.LOCK_NB
	}
	if e = syscall.Flock(int(f.Fd()), flags); e != nil {
		f.Close()
		return nil, fmt.Errorf("profile is busy: %w", e)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
func str(m M, k string) string { v, _ := m[k].(string); return v }
func obj(m M, k string) M {
	v, _ := m[k].(map[string]any)
	if v == nil {
		return M{}
	}
	return v
}
func num(m M, k string) int {
	switch n := m[k].(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}
func exists(p string) bool { _, e := os.Stat(p); return e == nil }
