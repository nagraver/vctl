package whale

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	tea "github.com/charmbracelet/bubbletea"
	"howett.net/plist"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type legacyFixture struct {
	URIs  []string `json:"uris"`
	Nodes []Node   `json:"nodes"`
	State State    `json:"state"`
	Proxy M        `json:"proxy"`
	Tun   M        `json:"tun"`
}

func fixture(t *testing.T) legacyFixture {
	t.Helper()
	b, e := os.ReadFile("testdata/legacy.json")
	if e != nil {
		t.Fatal(e)
	}
	var f legacyFixture
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	return f
}
func normalized(v any) any { b, _ := json.Marshal(v); var x any; _ = json.Unmarshal(b, &x); return x }
func TestLegacyCompatibility(t *testing.T) {
	f := fixture(t)
	for i, u := range f.URIs {
		n, e := ParseURI(u)
		if e != nil {
			t.Fatal(e)
		}
		if !reflect.DeepEqual(n, f.Nodes[i]) {
			t.Fatalf("node %d differs\ngot %#v\nwant %#v", i, n, f.Nodes[i])
		}
	}
	for _, test := range []struct {
		mode string
		port int
		want M
	}{{"proxy", 2080, f.Proxy}, {"tun", 2180, f.Tun}} {
		got, e := Generate(f.State, test.mode, test.port)
		if e != nil {
			t.Fatal(e)
		}
		if !reflect.DeepEqual(normalized(got), normalized(test.want)) {
			b, _ := json.MarshalIndent(got, "", "  ")
			t.Fatalf("%s config differs:\n%s", test.mode, b)
		}
	}
	b, _ := json.Marshal(f.State)
	var reloaded State
	_ = json.Unmarshal(b, &reloaded)
	if strings.Join(reloaded.Presets.Keys, ",") != "z,a" {
		t.Fatal("preset precedence changed")
	}
}
func TestSubscriptionStrictAndDedup(t *testing.T) {
	u := fixture(t).URIs[0]
	body := base64.StdEncoding.EncodeToString([]byte(u + "\n" + u))
	nodes, e := ParseSubscription([]byte(body))
	if e != nil || len(nodes) != 1 {
		t.Fatalf("dedup: %v %d", e, len(nodes))
	}
	for _, bad := range []string{u + "\nvmess://secret", strings.Replace(u, "type=tcp", "type=xhttp", 1), strings.Replace(u, "#Example", "&fm=not-json#Example", 1), "<html>fail</html>"} {
		if _, e = ParseSubscription([]byte(bad)); e == nil {
			t.Fatal("invalid subscription accepted")
		} else if strings.Contains(e.Error(), "11111111") || strings.Contains(e.Error(), "secret") {
			t.Fatal("credentials leaked")
		}
	}
}
func TestRuleValidationAndPrecedence(t *testing.T) {
	for _, r := range []Rule{{"suffix", "https://example.com", "direct"}, {"cidr", "not-ip", "direct"}, {"path", "relative.app", "proxy"}, {"process", "/usr/bin/curl", "direct"}, {"suffix", "example.org", "unknown"}} {
		if _, e := MakeRule(r.Kind, r.Value, r.Action); e == nil {
			t.Fatalf("accepted %#v", r)
		}
	}
	r, e := MakeRule("path", "/Applications/Test.app", "direct")
	if e != nil || r.Value != "/Applications/Test.app/" {
		t.Fatal(r, e)
	}
	r, e = MakeRule("suffix", "пример.рф", "direct")
	if e != nil || r.Value != "xn--e1afmkfd.xn--p1ai" {
		t.Fatal(r, e)
	}
}
func TestAtomicProfileLockAndPermissions(t *testing.T) {
	dir, err := os.MkdirTemp("/private/tmp", "whale-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	s, e := NewStore(dir, "")
	if e != nil {
		t.Fatal(e)
	}
	v := fixture(t).State
	if e = s.Write(v); e != nil {
		t.Fatal(e)
	}
	st, _ := os.Stat(filepath.Join(s.Home, "state.json"))
	if st.Mode().Perm() != 0600 {
		t.Fatal(st.Mode())
	}
	unlock, e := s.Lock("state.lock", false)
	if e != nil {
		t.Fatal(e)
	}
	if second, e := s.Lock("state.lock", true); e == nil {
		second()
		t.Fatal("lock did not exclude concurrent writer")
	}
	unlock()
	got, e := s.Read()
	if e != nil || !reflect.DeepEqual(normalized(got), normalized(v)) {
		t.Fatal("state round trip failed", e)
	}
}
func TestServiceDefinitionAndLegacyLabel(t *testing.T) {
	s := NewService(Store{"/private/tmp/profile/tun", "/private/tmp/profile"}, 501)
	if s.Label != "io.github.nagraver.vctl.501.6dd1f9f3641a" {
		t.Fatal(s.Label)
	}
	d := s.definition("/root/release", 2180)
	args := d["ProgramArguments"].([]string)
	if args[0] != "/root/release/whale" || strings.Contains(strings.Join(args, " "), "python") {
		t.Fatal(args)
	}
	if d["RunAtLoad"] != false {
		t.Fatal("unexpected autostart")
	}
	b, e := plist.Marshal(d, plist.XMLFormat)
	if e != nil {
		t.Fatal(e)
	}
	var v M
	if _, e = plist.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
}
func TestAliasesAndCompletion(t *testing.T) {
	a := &App{Home: t.TempDir()}
	root := newCommand(a)
	for _, path := range [][]string{{"up"}, {"start"}, {"down"}, {"stop"}, {"tun", "up"}, {"tun", "start"}, {"tun", "down"}, {"tun", "stop"}} {
		c, _, e := root.Find(path)
		if e != nil || c == root {
			t.Fatal(path, e)
		}
	}
	var b bytes.Buffer
	if e := root.GenZshCompletion(&b); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(b.String(), "whale") {
		t.Fatal("missing completion")
	}
}
func TestFormsAndNavigation(t *testing.T) {
	m := uiModel{app: &App{}, state: fixture(t).State, page: "Home", width: 100, height: 35}
	m.rebuild()
	if len(m.items) < 10 {
		t.Fatal("missing sections")
	}
	for _, page := range []string{"Servers", "Subscriptions", "Routing", "Presets", "DNS", "GeoIP / GeoSite", "Local proxy", "Service", "Diagnostics"} {
		m.page = page
		m.rebuild()
		if len(m.items) == 0 {
			t.Fatal("empty page", page)
		}
	}
	m.openForm("subscription")
	m.fields[0].input.SetValue("https://example.com/secret")
	item, e := m.submit()
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(strings.Join(item.args, " "), "secret") || !strings.Contains(item.stdin, "secret") {
		t.Fatal("subscription secret must travel through stdin")
	}
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if model.(uiModel).form != "" {
		t.Fatal("escape did not cancel form")
	}
}
func TestRejectMaskRanges(t *testing.T) {
	for _, length := range []string{"0", "-1", "20-10", "99999"} {
		m := M{"tcp": []any{M{"type": "fragment", "settings": M{"packets": "tlshello", "length": length, "delay": "0"}}}}
		if validateMask(m) == nil {
			t.Fatal(length)
		}
	}
}
func TestProtoCategory(t *testing.T) {
	category := "PRIVATE"
	entry := append([]byte{10, byte(len(category))}, []byte(category)...)
	data := append([]byte{10, byte(len(entry))}, entry...)
	got, e := firstCategory(data)
	if e != nil || got != "private" {
		t.Fatal(got, e)
	}
	if _, e = firstCategory([]byte{10, 255}); e == nil {
		t.Fatal("truncated proto accepted")
	}
}
func TestEmptyProfileUIAndNoninteractive(t *testing.T) {
	m := uiModel{app: &App{}, state: emptyState(), page: "Servers", width: 80, height: 24}
	m.rebuild()
	if !strings.Contains(m.View(), "Servers") {
		t.Fatal("missing view")
	}
	if exists(filepath.Join(t.TempDir(), "state.json")) {
		t.Fatal("unexpected state")
	}
}

func TestStoppedOutput(t *testing.T) {
	var b bytes.Buffer
	var status M
	if err := output(&b, status); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"state": "stopped"`) {
		t.Fatal(b.String())
	}
}
