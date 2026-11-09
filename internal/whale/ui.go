package whale

import (
	"bytes"
	"context"
	"fmt"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"
)

var accent = lipgloss.NewStyle().Foreground(lipgloss.Color("81")).Bold(true)
var muted = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
var selectedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("232")).Background(lipgloss.Color("81")).Padding(0, 1)

type menuItem struct {
	label, detail       string
	args                []string
	page, form, confirm string
	stdin               string
	language            string
	literal             bool
}
type field struct {
	label    string
	input    textinput.Model
	required bool
}
type menuPosition struct {
	page   string
	cursor int
}
type uiModel struct {
	tunServer, proxyServer M
	started                time.Time
	frame                  int
	auth                   *menuItem
	password               textinput.Model
	language               string
	tunState, proxyState   string
	app                    *App
	state                  State
	page                   string
	stack                  []menuPosition
	cursor, width, height  int
	items                  []menuItem
	fields                 []field
	form                   string
	focus                  int
	confirmation           *menuItem
	result                 string
	view                   viewport.Model
	busy                   bool
	quietSuccess           bool
	cancel                 context.CancelFunc
	notice                 string
}
type snapshotMsg struct {
	tunServer, proxyServer M
	state                  State
	tunState, proxyState   string
	err                    error
}
type languageMsg struct {
	language string
	err      error
}
type tickMsg time.Time
type resultMsg struct {
	out string
	err error
}

func safeText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) || r == '\n' || r == '\t' {
			return r
		}
		return -1
	}, s)
}
func RunUI(a *App) error {
	s, e := a.store()
	if e != nil {
		return e
	}
	a.Home = s.Home
	m := uiModel{app: a, page: "Home", width: 88, height: 30, view: viewport.New(80, 18)}
	v, err := s.Read()
	if err != nil {
		return err
	}
	m.state = v
	m.language = "en"
	if v.UI != nil && v.UI.Language == "ru" {
		m.language = "ru"
	}
	m.tunState = "unknown"
	m.proxyState = "unknown"
	m.rebuild()
	_, e = tea.NewProgram(m, tea.WithAltScreen()).Run()
	return e
}
func (m uiModel) Init() tea.Cmd { return tea.Batch(m.snapshot(), tick()) }
func tick() tea.Cmd             { return tea.Tick(3*time.Second, func(t time.Time) tea.Msg { return tickMsg(t) }) }
func (m uiModel) snapshot() tea.Cmd {
	home := m.app.Home
	return func() tea.Msg {
		s := Store{home, home}
		if m.app.StateHome != "" {
			s.Profile = m.app.StateHome
		}
		v, e := s.Read()
		tunState, proxyState := "off", "off"
		srv := NewService(Store{filepath.Join(s.Profile, "tun"), s.Profile}, os.Getuid())
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		text, err := exec.CommandContext(ctx, "/bin/launchctl", "print", srv.Target).CombinedOutput()
		cancel()
		tunState = tunSwitchState(string(text), err != nil, exists(srv.Marker), exists(srv.Plist))

		var proxyServer M
		if r, err := Control(s, "status"); err != nil {
			proxyState = "unknown"
		} else if r != nil {
			proxyState = "on"
			proxyServer = obj(r, "server")
		}
		return snapshotMsg{tunServer: readTunSelection(s.Profile, string(text)), proxyServer: proxyServer, state: v, err: e, tunState: tunState, proxyState: proxyState}
	}
}
func (m *uiModel) rebuild() {
	m.items = nil
	item := func(label, detail, page, form string, args ...string) {
		m.items = append(m.items, menuItem{label: label, detail: detail, page: page, form: form, args: args})
	}
	switch m.page {
	case "Home":
		proxy := m.toggle("proxy")
		proxy.page = "Local proxy"
		proxy.args = nil
		m.items = append(m.items, m.toggle("tun"), proxy)
		item("Language / Язык", "Choose interface language", "Language", "")
		item("Restart VPN", "Validate before reconnecting", "", "", "tun", "restart")
		item("VPN status", "Detailed service status", "", "", "tun", "status")
		for _, p := range []string{"Servers", "Subscriptions", "Routing", "Presets", "DNS", "GeoIP / GeoSite", "Service", "Diagnostics"} {
			item(p, "", p, "")
		}
	case "Language":
		m.items = append(m.items, menuItem{label: "English", language: "en", literal: true}, menuItem{label: "Русский", language: "ru", literal: true})
	case "Servers":
		item("Automatic selection", "Use the server with the lowest latency", "", "", "use", "auto")
		item("Test all servers", "HTTPS through each server; this may take a while", "", "", "ping")
		for _, n := range m.state.Nodes() {
			mark := ""
			if n.ID == m.state.Selected {
				mark = "✓ "
			}
			item(mark+clean(n.Name), n.ID, "", "", "use", n.ID)
		}
	case "Subscriptions":
		item("Add subscription", "The subscription URL is hidden", "", "subscription")
		item("Update all", "", "", "", "sub", "update")
		for _, name := range m.state.Subscriptions.Keys {
			p := m.state.Subscriptions.Values[name]
			item(clean(name), fmt.Sprintf(m.tr("%d servers · every %d seconds"), len(p.Nodes), p.Interval), "sub:"+name, "")
		}
	case "Routing":
		item("Add rule", "Domain, IP, GeoIP or application", "", "rule")
		item("Route everything through VPN", "Direct rules bypass the VPN", "", "", "default", "proxy")
		item("Route everything directly", "Only proxy rules use the VPN", "", "", "default", "direct")
		for i, r := range m.state.Rules {
			m.items = append(m.items, menuItem{label: fmt.Sprintf("%d. %s %s → %s", i+1, r.Kind, clean(r.Value), r.Action), detail: "Enter to delete", args: []string{"rule", "remove", itoa(i + 1)}, confirm: "Delete this rule?"})
		}
	case "Presets":
		item("Add preset", "JSON, HTTPS, builtin:lan or builtin:ads", "", "preset")
		item("Update all", "", "", "", "preset", "update")
		for _, name := range m.state.Presets.Keys {
			p := m.state.Presets.Values[name]
			enabled := "disabled"
			if p.Enabled {
				enabled = "enabled"
			}
			item(clean(name), fmt.Sprintf(m.tr("%s · %d rules"), m.tr(enabled), len(p.Rules)), "preset:"+name, "")
		}
	case "DNS":
		item("Current settings", "", "", "", "dns", "show")
		item("Edit DNS", "Separate HTTPS resolvers for VPN and direct traffic", "", "dns")
	case "GeoIP / GeoSite":
		item("Database status", "", "", "", "geodata", "status")
		item("Update databases", "Saved or default sources", "", "", "geodata", "update")
		item("Configure sources and update", "", "", "geodata")
	case "Local proxy":
		m.items = append(m.items, m.toggle("proxy"))
		item("Restart", "", "", "", "restart")
		item("Status", "", "", "", "status")
		item("Start on a custom port", "", "", "proxy")
	case "Service":
		item("Install", "Register the service without enabling VPN", "", "", "tun", "install")
		m.items = append(m.items, menuItem{label: "Uninstall service", detail: "Stops VPN; keeps your profile", args: []string{"tun", "uninstall"}, confirm: "Stop VPN and uninstall the service?"})
		item("Recover DNS after a crash", "Only when the supervisor is stopped", "", "", "tun", "recover")
	case "Diagnostics":
		item("Check configuration", "Without starting VPN", "", "", "check", "--mode", "tun")
		item("Client information", "", "", "", "doctor")
		item("VPN status", "", "", "", "tun", "status")
		item("Test servers", "", "", "", "ping")
	default:
		if strings.HasPrefix(m.page, "sub:") {
			name := strings.TrimPrefix(m.page, "sub:")
			item("Update", "", "", "", "sub", "update", name)
			m.items = append(m.items, menuItem{label: "Remove subscription", args: []string{"sub", "remove", name}, confirm: "Remove this subscription and its servers?"})
		}
		if strings.HasPrefix(m.page, "preset:") {
			name := strings.TrimPrefix(m.page, "preset:")
			for _, v := range []struct{ title, cmd string }{{"Show rules", "show"}, {"Enable", "enable"}, {"Disable", "disable"}, {"Update", "update"}} {
				item(v.title, "", "", "", "preset", v.cmd, name)
			}
			m.items = append(m.items, menuItem{label: "Remove preset", args: []string{"preset", "remove", name}, confirm: "Remove this preset?"})
		}
	}
	if m.cursor >= len(m.items) {
		m.cursor = max(0, len(m.items)-1)
	}
}
func (m *uiModel) openForm(name string) {
	m.form = name
	m.fields = nil
	m.focus = 0
	add := func(label, value string, required, secret bool) {
		t := textinput.New()
		t.SetValue(value)
		t.CharLimit = 4096
		t.Width = max(20, m.width-10)
		if secret {
			t.EchoMode = textinput.EchoPassword
			t.EchoCharacter = '•'
		}
		m.fields = append(m.fields, field{label, t, required})
	}
	switch name {
	case "subscription":
		add("Subscription URL (HTTPS)", "", true, true)
		add("Name (leave empty to use the subscription title)", "", false, false)
		add("Auto-update interval, seconds", "43200", true, false)
	case "rule":
		add("Type: domain / suffix / cidr / geoip / geosite / process / path", "suffix", true, false)
		add("Value", "", true, false)
		add("Route: direct / proxy / block", "direct", true, false)
	case "preset":
		add("Name", "", true, false)
		add("Source: file / HTTPS / builtin:lan / builtin:ads", "", true, false)
		add("Update interval, seconds", "43200", true, false)
	case "dns":
		for _, k := range []string{"direct", "proxy", "strategy"} {
			v := m.state.DNS[k]
			if v == "" {
				v = "https://1.1.1.1/dns-query"
				if k == "strategy" {
					v = "UseIP"
				}
			}
			label := k
			if k == "strategy" {
				label = "Strategy: UseIP / UseIPv4 / UseIPv6"
			}
			add(label, v, true, false)
		}
	case "geodata":
		for _, k := range []string{"geoip", "geosite"} {
			v := m.state.Geodata[k].URL
			if v == "" {
				v = fmt.Sprintf(geoURL, k)
			}
			add(k+" HTTPS URL", v, true, false)
		}
		add("Update interval, seconds", "86400", true, false)
	case "proxy":
		add("SOCKS port (HTTP uses the next port)", "2080", true, false)
	}
	if len(m.fields) > 0 {
		m.fields[0].input.Focus()
	}
}
func (m *uiModel) submit() (menuItem, error) {
	values := []string{}
	for _, f := range m.fields {
		v := strings.TrimSpace(f.input.Value())
		if v == "" && f.required {
			return menuItem{}, fmt.Errorf(m.tr("Required field: %s"), m.tr(f.label))
		}
		values = append(values, v)
	}
	a := menuItem{}
	switch m.form {
	case "subscription":
		a.args = []string{"sub", "add"}
		if values[1] != "" {
			a.args = append(a.args, values[1])
		}
		a.args = append(a.args, "--interval", values[2])
		a.stdin = values[0] + "\n"
	case "rule":
		a.args = append([]string{"rule", "add"}, values...)
	case "preset":
		a.args = []string{"preset", "add", values[0], values[1], "--interval", values[2]}
	case "dns":
		a.args = []string{"dns", "set", "--direct", values[0], "--proxy", values[1], "--strategy", values[2]}
	case "geodata":
		a.args = []string{"geodata", "update", "--geoip-url", values[0], "--geosite-url", values[1], "--interval", values[2]}
	case "proxy":
		a.args = []string{"up", "--port", values[0]}
	}
	return a, nil
}
func (m *uiModel) execute(item menuItem) tea.Cmd {
	if len(item.args) == 0 {
		m.notice = m.tr("Status unavailable; refresh before toggling")
		return m.snapshot()
	}
	args := []string{"--home", m.app.Home}
	if m.app.CorePath != "" {
		args = append(args, "--core", m.app.CorePath)
	}
	args = append(args, item.args...)
	m.quietSuccess = quietLifecycle(item.args)
	m.startActivity("Working…")
	var out bytes.Buffer
	if item.args[0] == "tun" {
		m.cancel = nil
		label := "Working…"
		if len(item.args) > 1 {
			switch item.args[1] {
			case "up":
				label = "Starting TUN…"
			case "down":
				label = "Stopping TUN…"
			case "restart":
				label = "Restarting TUN…"
			case "status":
				label = "Reading TUN status…"
			}
		}
		m.notice = m.tr(label)
		app := *m.app
		return tea.Batch(activityTick(m.started), func() tea.Msg { return runTunUI(app, item) })
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	return tea.Batch(activityTick(m.started), func() tea.Msg {
		defer cancel()
		cmd := exec.CommandContext(ctx, executable(), args...)
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGINT) }
		cmd.WaitDelay = 20 * time.Second
		cmd.Stdout = &out
		cmd.Stderr = &out
		if item.stdin != "" {
			cmd.Stdin = strings.NewReader(item.stdin)
		}
		e := cmd.Run()
		return resultMsg{out.String(), e}
	})
}
func (m uiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case activityMsg:
		if m.busy && msg.started.Equal(m.started) {
			m.frame++
			return m, activityTick(m.started)
		}
		return m, nil
	case authRequiredMsg:
		m.busy = false
		m.auth = &msg.item
		m.password = textinput.New()
		m.password.EchoMode = textinput.EchoPassword
		m.password.EchoCharacter = '•'
		m.password.CharLimit = 1024
		m.password.Width = max(20, m.width-10)
		m.notice = ""
		return m, m.password.Focus()
	case authResultMsg:
		m.busy = false
		m.cancel = nil
		if msg.err != nil {
			m.notice = m.tr(msg.err.Error())
			return m, m.password.Focus()
		}
		m.auth = nil
		m.password.Reset()
		return m, m.execute(msg.item)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.view.Width = max(20, m.width-6)
		m.view.Height = max(3, m.height-12)
		for i := range m.fields {
			m.fields[i].input.Width = max(15, m.width-10)
		}
	case tickMsg:
		if !m.busy {
			return m, tea.Batch(m.snapshot(), tick())
		}
		return m, tick()
	case snapshotMsg:
		if msg.err != nil {
			m.notice = m.tr("Could not read profile: ") + msg.err.Error()
		} else {
			m.state = msg.state
			m.tunState, m.proxyState = msg.tunState, msg.proxyState
			m.tunServer, m.proxyServer = msg.tunServer, msg.proxyServer
			m.rebuild()
		}
	case languageMsg:
		m.busy = false
		if msg.err != nil {
			m.notice = msg.err.Error()
		} else {
			m.language = msg.language
			m.notice = m.tr("Saved language preference")
			m.rebuild()
		}
		return m, m.snapshot()
	case resultMsg:
		m.busy = false
		m.cancel = nil
		if msg.err == nil {
			m.form = ""
			m.fields = nil
		}
		m.confirmation = nil
		quiet := m.quietSuccess
		m.quietSuccess = false
		if quiet && msg.err == nil {
			m.result = ""
			m.notice = ""
			return m, m.snapshot()
		}
		m.result = safeText(msg.out)
		m.result = strings.ReplaceAll(m.result, "Saved. The running service applies changes automatically.", m.tr("Saved. The running service applies changes automatically."))
		if msg.err != nil {
			m.result += m.tr("\nOperation failed: ") + msg.err.Error()
		}
		if strings.TrimSpace(m.result) == "" {
			m.result = m.tr("Done.")
		}
		m.view.SetContent(m.result)
		m.view.GotoTop()
		m.notice = ""
		return m, m.snapshot()
	case tea.KeyMsg:
		key := msg.String()
		if m.busy {
			if key == "ctrl+c" && m.cancel != nil {
				m.cancel()
				m.notice = m.tr("Cancelling…")
			}
			return m, nil
		}
		if m.auth != nil {
			if key == "esc" || key == "ctrl+c" {
				m.auth = nil
				m.password.Reset()
				m.notice = ""
				return m, nil
			}
			if key == "enter" {
				item := *m.auth
				password := m.password.Value()
				m.password.Reset()
				m.password.Blur()
				m.startActivity("Authorizing…")
				ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
				m.cancel = cancel
				return m, tea.Batch(activityTick(m.started), func() tea.Msg { defer cancel(); return authResultMsg{item, authorizeSudo(ctx, password)} })
			}
			var cmd tea.Cmd
			m.password, cmd = m.password.Update(msg)
			return m, cmd
		}
		if key == "ctrl+c" {
			return m, tea.Quit
		}
		if m.result != "" {
			if key == "esc" || key == "enter" || key == "q" {
				m.result = ""
				return m, nil
			}
			var cmd tea.Cmd
			m.view, cmd = m.view.Update(msg)
			return m, cmd
		}
		if m.confirmation != nil {
			if key == "y" || key == "д" {
				item := *m.confirmation
				m.confirmation = nil
				return m, m.execute(item)
			}
			if key == "n" || key == "н" || key == "esc" {
				m.confirmation = nil
			}
			return m, nil
		}
		if m.form != "" {
			switch key {
			case "esc":
				m.form = ""
				m.fields = nil
				m.notice = ""
				return m, nil
			case "tab", "down", "shift+tab", "up":
				m.fields[m.focus].input.Blur()
				delta := 1
				if key == "up" || key == "shift+tab" {
					delta = -1
				}
				m.focus = (m.focus + delta + len(m.fields)) % len(m.fields)
				return m, m.fields[m.focus].input.Focus()
			case "enter":
				if m.focus < len(m.fields)-1 {
					m.fields[m.focus].input.Blur()
					m.focus++
					return m, m.fields[m.focus].input.Focus()
				}
				item, e := m.submit()
				if e != nil {
					m.notice = e.Error()
					return m, nil
				}
				return m, m.execute(item)
			}
			var cmd tea.Cmd
			m.fields[m.focus].input, cmd = m.fields[m.focus].input.Update(msg)
			return m, cmd
		}
		switch key {
		case "q":
			return m, tea.Quit
		case "esc", "backspace":
			if len(m.stack) > 0 {
				previous := m.stack[len(m.stack)-1]
				m.page, m.cursor = previous.page, previous.cursor
				m.stack = m.stack[:len(m.stack)-1]
				m.rebuild()
			}
		case "up", "k":
			if len(m.items) > 0 {
				m.cursor = (m.cursor + len(m.items) - 1) % len(m.items)
			}
		case "down", "j":
			if len(m.items) > 0 {
				m.cursor = (m.cursor + 1) % len(m.items)
			}
		case "home":
			m.cursor = 0
		case "end":
			m.cursor = max(0, len(m.items)-1)
		case "pgdown":
			m.cursor = min(len(m.items)-1, m.cursor+max(1, m.height-12))
		case "pgup":
			m.cursor = max(0, m.cursor-max(1, m.height-12))
		case "r":
			return m, m.snapshot()
		case " ", "enter":
			if len(m.items) == 0 {
				return m, nil
			}
			item := m.items[m.cursor]
			if item.language != "" {
				m.startActivity("Working…")
				return m, tea.Batch(activityTick(m.started), m.saveLanguage(item.language))
			} else if item.page != "" {
				m.stack = append(m.stack, menuPosition{page: m.page, cursor: m.cursor})
				m.page = item.page
				m.cursor = 0
				m.rebuild()
			} else if item.form != "" {
				m.openForm(item.form)
				return m, textinput.Blink
			} else if item.confirm != "" {
				m.confirmation = &item
			} else {
				return m, m.execute(item)
			}
		}
	}
	return m, nil
}
func (m uiModel) View() string {
	if m.width < 45 || m.height < 15 {
		return m.tr("Whale — resize the terminal to at least 45×15.\nq / Ctrl+C to exit\n")
	}
	var b strings.Builder
	title := accent.Render("🐋 WHALE")
	b.WriteString("\n  " + title + muted.Render("  "+Version) + "\n")
	b.WriteString("  TUN [" + m.tr(strings.ToUpper(m.tunState)) + "]  ·  " + m.tr("Proxy") + " [" + m.tr(strings.ToUpper(m.proxyState)) + "]\n")
	selected := m.state.Selected
	for _, n := range m.state.Nodes() {
		if n.ID == selected {
			selected = clean(n.Name)
			break
		}
	}
	if selected == "auto" {
		selected = m.tr("automatic")
		details := []string{}
		for _, connection := range []struct {
			mode, status string
			server       M
		}{{"TUN", m.tunState, m.tunServer}, {"Proxy", m.proxyState, m.proxyServer}} {
			if connection.status != "on" {
				continue
			}
			name := str(connection.server, "name")
			if name == "" {
				name = m.tr("selection unavailable")
			}
			if connection.server["fallback"] == true {
				name += " (" + m.tr("fallback") + ")"
			}
			details = append(details, connection.mode+": "+name)
		}
		if len(details) > 0 {
			selected += " — " + strings.Join(details, " · ")
		}

	}
	b.WriteString(muted.Render(m.tr("  Server: ")+selected+m.tr("  ·  Default route: ")+m.state.Default) + "\n\n")
	page := m.tr(m.page)
	if strings.HasPrefix(page, "sub:") {
		page = m.tr("Subscription / ") + clean(strings.TrimPrefix(page, "sub:"))
	}
	if strings.HasPrefix(page, "preset:") {
		page = m.tr("Preset / ") + clean(strings.TrimPrefix(page, "preset:"))
	}
	b.WriteString("  " + accent.Render(page) + "\n\n")
	switch {
	case m.auth != nil && !m.busy:
		b.WriteString("  " + m.tr("macOS password required") + "\n  " + m.password.View() + "\n\n  " + m.tr("Enter to authorize · Esc to cancel"))
	case m.result != "":
		b.WriteString(m.view.View() + "\n\n  " + muted.Render(m.tr("↑↓ / PgUp / PgDn to scroll · Enter / Esc to go back")))
	case m.confirmation != nil:
		b.WriteString("  " + m.tr(m.confirmation.confirm) + m.tr("\n\n  y to confirm · n / Esc to cancel"))
	case m.form != "":
		for i, f := range m.fields {
			if m.height < 24 && i != m.focus {
				continue
			}
			label := ansi.Truncate(m.tr(f.label), m.width-6, "…")
			if i == m.focus {
				label = accent.Render(label)
			}
			b.WriteString("  " + label + "\n  " + f.input.View() + "\n\n")
		}
		b.WriteString(muted.Render(m.tr("  Tab: next field · Enter on last field: save · Esc: cancel")))
	default:
		rowHeight := 2
		reserved := 13
		if m.busy {
			reserved += 3
		}
		if m.page == "Home" {
			rowHeight = 1
		}
		count := max(1, (m.height-reserved)/rowHeight)
		start := max(0, m.cursor-count+1)
		end := min(len(m.items), start+count)
		for i := start; i < end; i++ {
			item := m.items[i]
			label := item.label
			if !item.literal && !strings.HasPrefix(item.page, "sub:") && !strings.HasPrefix(item.page, "preset:") && !(len(item.args) > 1 && item.args[0] == "use" && item.args[1] != "auto") {
				label = m.tr(label)
			}
			label = ansi.Truncate(label, m.width-8, "…")
			if i == m.cursor {
				label = selectedStyle.Render("› " + label)
			} else {
				label = "  " + label
			}
			b.WriteString("  " + label + "\n")
			if m.page == "Home" {
				continue
			}
			detail := ansi.Truncate(m.tr(item.detail), m.width-8, "…")
			if detail == "" {
				detail = " "
			}
			b.WriteString("    " + muted.Render(detail) + "\n")
		}
		if len(m.items) > count {
			b.WriteString(muted.Render(fmt.Sprintf("  %d / %d\n", m.cursor+1, len(m.items))))
		}
		b.WriteString("\n  " + muted.Render(m.tr("↑↓ / j k: select · Enter: open · Esc: back · q: quit")))
	}
	if m.busy {
		b.WriteString("\n" + m.activityView())
	}
	if m.notice != "" && !m.busy {
		b.WriteString("\n\n  " + safeText(m.notice))
	}
	b.WriteString("\n")
	return b.String()
}

func (m uiModel) toggle(mode string) menuItem {
	state, label := m.tunState, "TUN"
	if mode == "proxy" {
		state = m.proxyState
		label = m.tr("Proxy")
	}
	if state == "" {
		state = "unknown"
	}
	item := menuItem{label: fmt.Sprintf("[%s] %s", m.tr(strings.ToUpper(state)), label), literal: true}
	if state == "unknown" {
		item.detail = "Status unavailable; refresh before toggling"
		return item
	}
	action := "up"
	item.detail = "Enter to turn on"
	if state == "on" || state == "starting" {
		action = "down"
		item.detail = "Enter to turn off"
	}
	item.args = []string{action}
	if mode == "tun" {
		item.args = []string{"tun", action}
	}
	return item
}
func (m uiModel) saveLanguage(language string) tea.Cmd {
	profile := m.app.Home
	if m.app.StateHome != "" {
		profile = m.app.StateHome
	}
	return func() tea.Msg {
		s := Store{profile, profile}
		unlock, err := s.Lock("state.lock", false)
		if err != nil {
			return languageMsg{language, err}
		}
		defer unlock()
		state, err := s.Read()
		if err == nil {
			state.UI = &UIPreferences{Language: language}
			err = s.Write(state)
		}
		return languageMsg{language, err}
	}
}

// A registered plist may remain after bootout; that means OFF, not UNKNOWN.
func tunSwitchState(text string, failed, marker, installed bool) string {
	if strings.Contains(text, "state = running") {
		return "on"
	}
	if marker {
		return "starting"
	}
	if failed && installed && !strings.Contains(strings.ToLower(text), "could not find service") {
		return "unknown"
	}
	return "off"
}
