package whale

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestIndependentToggles(t *testing.T) {
	for _, state := range []string{"off", "on", "starting", "unknown"} {
		m := uiModel{tunState: state, proxyState: state}
		tun, proxy := m.toggle("tun"), m.toggle("proxy")
		if state == "unknown" {
			if len(tun.args) != 0 || len(proxy.args) != 0 {
				t.Fatal("unknown state must not toggle")
			}
			continue
		}
		action := "up"
		if state != "off" {
			action = "down"
		}
		if !reflect.DeepEqual(tun.args, []string{"tun", action}) || !reflect.DeepEqual(proxy.args, []string{action}) {
			t.Fatal(tun.args, proxy.args)
		}
	}
}
func TestStoppedServiceToggle(t *testing.T) {
	if got := tunSwitchState("Could not find service test in domain for system", true, false, true); got != "off" {
		t.Fatal(got)
	}
	if got := tunSwitchState("permission denied", true, false, true); got != "unknown" {
		t.Fatal(got)
	}
	if got := tunSwitchState("", true, true, true); got != "starting" {
		t.Fatal(got)
	}
}
func TestLanguagePersistsWithoutChangingConnection(t *testing.T) {
	dir, e := os.MkdirTemp("/private/tmp", "whale-lang-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	s, e := NewStore(dir, "")
	if e != nil {
		t.Fatal(e)
	}
	initial := fixture(t).State
	if e = s.Write(initial); e != nil {
		t.Fatal(e)
	}
	before, _ := connectionFingerprint(initial)
	m := uiModel{app: &App{Home: dir}}
	msg := m.saveLanguage("ru")().(languageMsg)
	if msg.err != nil {
		t.Fatal(msg.err)
	}
	v, e := s.Read()
	if e != nil || v.UI == nil || v.UI.Language != "ru" {
		t.Fatal(v.UI, e)
	}
	after, _ := connectionFingerprint(v)
	if !bytes.Equal(before, after) {
		t.Fatal("UI preference changed connection state")
	}
	m.language = "ru"
	if m.tr("Servers") != "Серверы" {
		t.Fatal("Russian not selected")
	}
	m.language = ""
	if m.tr("Servers") != "Servers" {
		t.Fatal("English is not default")
	}
}
func TestCompletionOnlyWhale(t *testing.T) {
	root := newCommand(&App{Home: t.TempDir()})
	root.SetArgs([]string{"completion", "zsh"})
	var b bytes.Buffer
	root.SetOut(&b)
	if e := root.Execute(); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(b.String(), "vctl") {
		t.Fatal("old command remains in completion")
	}
}
