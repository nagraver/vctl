package whale

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var Version = "dev"

type App struct{ Home, StateHome, CorePath string }

func defaultHome() string {
	for _, k := range []string{"WHALE_HOME", "VCTL_HOME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	dir := filepath.Dir(executable())
	if exists(filepath.Join(dir, "go.mod")) || exists(filepath.Join(dir, "../go.mod")) {
		if exists(filepath.Join(dir, "../go.mod")) {
			dir = filepath.Dir(dir)
		}
		return filepath.Join(dir, ".local")
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".config/vctl")
}
func (a *App) store() (Store, error) { return NewStore(a.Home, a.StateHome) }
func (a *App) core() (string, error) { return Core(a.CorePath) }
func (a *App) mutate(f func(*State) error) error {
	s, e := a.store()
	if e != nil {
		return e
	}
	unlock, e := s.Lock("state.lock", false)
	if e != nil {
		return e
	}
	defer unlock()
	v, e := s.Read()
	if e != nil {
		return e
	}
	if e = f(&v); e != nil {
		return e
	}
	core, e := a.core()
	if e != nil {
		return e
	}
	validation := v
	if len(v.Nodes()) == 0 {
		srv := NewService(Store{filepath.Join(s.Profile, "tun"), s.Profile}, os.Getuid())
		if exists(srv.Marker) {
			return errors.New("stop VPN before removing the last subscription")
		}
		for _, home := range []string{s.Home, filepath.Join(s.Profile, "tun")} {
			r, err := Control(Store{home, s.Profile}, "status")
			if r != nil || err != nil && exists(filepath.Join(home, "control.sock")) {
				return errors.New("stop VPN before removing the last subscription")
			}
		}
		validation = v.Clone()
		n, _ := ParseURI("trojan://validation@127.0.0.1:1?security=tls#Validation")
		validation.Subscriptions.Set("validation", Subscription{Nodes: []Node{n}})
		validation.Selected = n.ID
	}
	if _, e = CheckedConfig(s, core, validation, "proxy", 2080); e != nil {
		return e
	}
	return s.Write(v)
}
func output(w io.Writer, v any) error {
	if m, ok := v.(M); v == nil || ok && m == nil {
		v = M{"state": "stopped"}
	}
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	s := string(b)
	if f, ok := w.(*os.File); ok && term.IsTerminal(int(f.Fd())) && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" {
		re := regexp.MustCompile(`("(?:[^"\\]|\\.)*"|\bnull\b)(\s*:)?`)
		s = re.ReplaceAllStringFunc(s, func(v string) string {
			parts := re.FindStringSubmatch(v)
			color := "32"
			if parts[2] != "" {
				color = "1;35"
			} else if parts[1] == "null" {
				color = "90"
			}
			return "\x1b[" + color + "m" + parts[1] + "\x1b[0m" + parts[2]
		})
	}
	_, e = fmt.Fprintln(w, s)
	return e
}

var operationContext = context.Background()
var operationCancel = func() {}

func Execute() error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	operationContext = ctx
	operationCancel = cancel
	a := &App{Home: defaultHome()}
	return newCommand(a).Execute()
}
func newCommand(a *App) *cobra.Command {
	root := &cobra.Command{Use: "whale", Short: "Terminal VPN client powered by Xray", Version: Version, SilenceUsage: true, SilenceErrors: true, RunE: func(c *cobra.Command, args []string) error {
		if len(args) > 0 {
			return errors.New("unknown command")
		}
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return errors.New("interactive mode requires a terminal; use whale --help")
		}
		return RunUI(a)
	}}
	root.PersistentFlags().StringVar(&a.Home, "home", a.Home, "Profile directory")
	root.PersistentFlags().StringVar(&a.StateHome, "state-home", a.StateHome, "Shared state directory")
	_ = root.PersistentFlags().MarkHidden("state-home")
	root.PersistentFlags().StringVar(&a.CorePath, "core", a.CorePath, "Path to Xray")
	read := func(c *cobra.Command) (Store, State, error) {
		s, e := a.store()
		if e != nil {
			return s, State{}, e
		}
		v, e := s.Read()
		return s, v, e
	}
	saved := func(c *cobra.Command, e error) error {
		if e == nil {
			fmt.Fprintln(c.OutOrStdout(), "Saved. The running service applies changes automatically.")
		}
		return e
	}
	add := func(parent *cobra.Command, use, short string, n int, fn func(*cobra.Command, []string) error) *cobra.Command {
		c := &cobra.Command{Use: use, Short: short, RunE: fn}
		if n >= 0 {
			c.Args = cobra.ExactArgs(n)
		}
		parent.AddCommand(c)
		return c
	}
	add(root, "nodes", "List servers", 0, func(c *cobra.Command, args []string) error {
		_, v, e := read(c)
		if e != nil {
			return e
		}
		fmt.Fprintln(c.OutOrStdout(), "Selected:", v.Selected)
		for _, k := range v.Subscriptions.Keys {
			for _, n := range v.Subscriptions.Values[k].Nodes {
				fmt.Fprintln(c.OutOrStdout(), n.ID, clean(k), clean(n.Name), str(n.Outbound, "type"))
			}
		}
		return nil
	})
	add(root, "use ID|auto", "Select a server", 1, func(c *cobra.Command, args []string) error {
		return saved(c, a.mutate(func(v *State) error {
			if args[0] != "auto" {
				found := false
				for _, n := range v.Nodes() {
					found = found || n.ID == args[0]
				}
				if !found {
					return errors.New("unknown node ID")
				}
			}
			v.Selected = args[0]
			return nil
		}))
	})
	add(root, "default proxy|direct", "Default route", 1, func(c *cobra.Command, args []string) error {
		return saved(c, a.mutate(func(v *State) error {
			if args[0] != "proxy" && args[0] != "direct" {
				return errors.New("choose proxy or direct")
			}
			v.Default = args[0]
			return nil
		}))
	})
	sub := add(root, "sub", "Subscriptions", -1, nil)
	add(sub, "list", "List subscriptions", 0, func(c *cobra.Command, args []string) error {
		_, v, e := read(c)
		if e != nil {
			return e
		}
		for _, k := range v.Subscriptions.Keys {
			p := v.Subscriptions.Values[k]
			fmt.Fprintf(c.OutOrStdout(), "%s: %d nodes; age=%ds; interval=%ds\n", clean(k), len(p.Nodes), time.Now().Unix()-int64(p.Updated), p.Interval)
		}
		return nil
	})
	sc := add(sub, "add [name]", "Add subscription", -1, func(c *cobra.Command, args []string) error {
		if len(args) > 1 {
			return errors.New("expected optional name")
		}
		address, _ := c.Flags().GetString("url")
		interval, _ := c.Flags().GetInt("interval")
		if address == "" {
			fmt.Fprint(c.OutOrStdout(), "Subscription URL: ")
			if term.IsTerminal(int(os.Stdin.Fd())) {
				b, e := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Fprintln(c.OutOrStdout())
				if e != nil {
					return e
				}
				address = string(b)
			} else {
				line, e := bufio.NewReader(c.InOrStdin()).ReadString('\n')
				if e != nil && e != io.EOF {
					return e
				}
				address = strings.TrimSpace(line)
			}
		}
		return saved(c, a.mutate(func(v *State) error {
			for _, s := range v.Subscriptions.Values {
				if s.URL == address {
					return errors.New("subscription already exists")
				}
			}
			p, e := Fetch(address, interval)
			if e != nil {
				return e
			}
			name := p.Title
			if len(args) > 0 {
				name = args[0]
				if _, ok := v.Subscriptions.Values[name]; ok {
					return errors.New("subscription name already exists")
				}
			} else {
				for i := 2; ; i++ {
					if _, ok := v.Subscriptions.Values[name]; !ok {
						break
					}
					name = p.Title + " (" + itoa(i) + ")"
				}
			}
			v.Subscriptions.Set(name, p)
			return nil
		}))
	})
	sc.Flags().String("url", "", "URL; omit for private input")
	sc.Flags().Int("interval", 43200, "Update interval in seconds")
	for _, action := range []string{"update", "remove"} {
		action := action
		add(sub, action+" [name]", action+" subscription", -1, func(c *cobra.Command, args []string) error {
			if len(args) > 1 || action == "remove" && len(args) != 1 {
				return errors.New("expected subscription name")
			}
			return saved(c, a.mutate(func(v *State) error {
				keys := append([]string{}, v.Subscriptions.Keys...)
				if len(args) > 0 {
					keys = args
				}
				for _, k := range keys {
					p, ok := v.Subscriptions.Values[k]
					if !ok {
						return errors.New("unknown subscription")
					}
					if action == "remove" {
						v.Subscriptions.Delete(k)
					} else {
						n, e := Fetch(p.URL, p.Interval)
						if e != nil {
							return e
						}
						v.Subscriptions.Set(k, n)
					}
				}
				return nil
			}))
		})
	}
	rule := add(root, "rule", "Routing rules", -1, nil)
	add(rule, "list", "List rules", 0, func(c *cobra.Command, args []string) error {
		_, v, e := read(c)
		if e != nil {
			return e
		}
		for i, r := range v.Rules {
			fmt.Fprintln(c.OutOrStdout(), i+1, r.Kind, clean(r.Value), r.Action)
		}
		return nil
	})
	rc := add(rule, "add KIND VALUE ACTION", "Add rule", 3, func(c *cobra.Command, args []string) error {
		return saved(c, a.mutate(func(v *State) error {
			r, e := MakeRule(args[0], args[1], args[2])
			if e != nil {
				return e
			}
			for _, old := range v.Rules {
				if old == r {
					return nil
				}
			}
			v.Rules = append(v.Rules, r)
			return nil
		}))
	})
	rc.ValidArgsFunction = func(c *cobra.Command, args []string, to string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 0 {
			return []string{"domain", "suffix", "cidr", "geoip", "geosite", "process", "path"}, cobra.ShellCompDirectiveNoFileComp
		}
		if len(args) == 2 {
			return []string{"direct", "proxy", "block"}, cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveDefault
	}
	add(rule, "remove INDEX", "Remove rule", 1, func(c *cobra.Command, args []string) error {
		return saved(c, a.mutate(func(v *State) error {
			i, e := strconv.Atoi(args[0])
			if e != nil || i < 1 || i > len(v.Rules) {
				return errors.New("invalid rule index")
			}
			v.Rules = append(v.Rules[:i-1], v.Rules[i:]...)
			return nil
		}))
	})
	preset := add(root, "preset", "Routing presets", -1, nil)
	add(preset, "list", "List presets", 0, func(c *cobra.Command, args []string) error {
		_, v, e := read(c)
		if e != nil {
			return e
		}
		for _, k := range v.Presets.Keys {
			p := v.Presets.Values[k]
			fmt.Fprintf(c.OutOrStdout(), "%s: enabled=%t; %d rules\n", clean(k), p.Enabled, len(p.Rules))
		}
		return nil
	})
	pc := add(preset, "add NAME SOURCE", "Add preset", 2, func(c *cobra.Command, args []string) error {
		interval, _ := c.Flags().GetInt("interval")
		return saved(c, a.mutate(func(v *State) error {
			if _, ok := v.Presets.Values[args[0]]; ok {
				return errors.New("preset already exists")
			}
			p, e := LoadPreset(args[1], interval)
			if e == nil {
				v.Presets.Set(args[0], p)
			}
			return e
		}))
	})
	pc.Flags().Int("interval", 43200, "Update interval")
	for _, action := range []string{"show", "update", "remove", "enable", "disable"} {
		action := action
		pc := add(preset, action+" [name]", action+" preset", -1, func(c *cobra.Command, args []string) error {
			if len(args) > 1 || action != "update" && len(args) != 1 {
				return errors.New("expected preset name")
			}
			if action == "show" {
				_, v, e := read(c)
				if e != nil {
					return e
				}
				p, ok := v.Presets.Values[args[0]]
				if !ok {
					return errors.New("unknown preset")
				}
				return output(c.OutOrStdout(), p)
			}
			return saved(c, a.mutate(func(v *State) error {
				keys := append([]string{}, v.Presets.Keys...)
				if len(args) > 0 {
					keys = args
				}
				for _, k := range keys {
					p, ok := v.Presets.Values[k]
					if !ok {
						return errors.New("unknown preset")
					}
					switch action {
					case "remove":
						v.Presets.Delete(k)
						continue
					case "enable":
						p.Enabled = true
					case "disable":
						p.Enabled = false
					case "update":
						n, e := LoadPreset(p.Source, p.Interval)
						if e != nil {
							return e
						}
						n.Enabled = p.Enabled
						p = n
					}
					v.Presets.Set(k, p)
				}
				return nil
			}))
		})
		pc.ValidArgsFunction = func(c *cobra.Command, args []string, to string) ([]string, cobra.ShellCompDirective) {
			s := Store{canonical(a.Home), canonical(a.Home)}
			v, e := s.Read()
			if e != nil {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return v.Presets.Keys, cobra.ShellCompDirectiveNoFileComp
		}
	}
	geo := add(root, "geodata", "GeoIP / GeoSite", -1, nil)
	add(geo, "status", "Database status", 0, func(c *cobra.Command, args []string) error {
		_, v, e := read(c)
		if e != nil {
			return e
		}
		return output(c.OutOrStdout(), v.Geodata)
	})
	gc := add(geo, "update", "Update databases", 0, func(c *cobra.Command, args []string) error {
		return saved(c, a.mutate(func(v *State) error {
			s, e := a.store()
			if e != nil {
				return e
			}
			if v.Geodata == nil {
				v.Geodata = map[string]Asset{}
			}
			for _, kind := range []string{"geoip", "geosite"} {
				old := v.Geodata[kind]
				address, _ := c.Flags().GetString(kind + "-url")
				if address == "" {
					address = old.URL
				}
				if address == "" {
					address = fmt.Sprintf(geoURL, kind)
				}
				interval, _ := c.Flags().GetInt("interval")
				if interval == 0 {
					interval = old.Interval
				}
				if interval == 0 {
					interval = 86400
				}
				asset, e := FetchAsset(s, kind, address, interval)
				if e != nil {
					return e
				}
				v.Geodata[kind] = asset
			}
			return nil
		}))
	})
	gc.Flags().String("geoip-url", "", "GeoIP URL")
	gc.Flags().String("geosite-url", "", "GeoSite URL")
	gc.Flags().Int("interval", 0, "Update interval")
	dns := add(root, "dns", "DNS settings", -1, nil)
	add(dns, "show", "Show DNS", 0, func(c *cobra.Command, args []string) error {
		_, v, e := read(c)
		if e != nil {
			return e
		}
		opts := map[string]string{"direct": "https://1.1.1.1/dns-query", "proxy": "https://1.1.1.1/dns-query", "strategy": "UseIP"}
		for k, s := range v.DNS {
			opts[k] = s
		}
		return output(c.OutOrStdout(), opts)
	})
	dc := add(dns, "set", "Edit DNS", 0, func(c *cobra.Command, args []string) error {
		return saved(c, a.mutate(func(v *State) error {
			if v.DNS == nil {
				v.DNS = map[string]string{}
			}
			for _, key := range []string{"direct", "proxy", "strategy"} {
				value, _ := c.Flags().GetString(key)
				if value == "" {
					continue
				}
				if key == "strategy" {
					if value != "UseIP" && value != "UseIPv4" && value != "UseIPv6" {
						return errors.New("invalid DNS strategy")
					}
				} else {
					u, e := url.Parse(value)
					if e != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || net.ParseIP(u.Hostname()) == nil {
						return errors.New("DNS requires HTTPS with a literal IP host")
					}
				}
				v.DNS[key] = value
			}
			return nil
		}))
	})
	for _, k := range []string{"direct", "proxy", "strategy"} {
		dc.Flags().String(k, "", k)
	}
	_ = dc.RegisterFlagCompletionFunc("strategy", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"UseIP", "UseIPv4", "UseIPv6"}, cobra.ShellCompDirectiveNoFileComp
	})
	add(root, "ping", "Test server latency", 0, func(c *cobra.Command, args []string) error {
		s, _, e := read(c)
		if e != nil {
			return e
		}
		core, e := a.core()
		if e != nil {
			return e
		}
		iface, _ := physicalInterface()
		p, e := Ping(s, core, iface)
		if e != nil {
			return e
		}
		ok := false
		for _, r := range p {
			delay := r.Error
			if delay == "" {
				ok = true
				delay = itoa(r.Milliseconds) + " ms"
			}
			fmt.Fprintln(c.OutOrStdout(), r.Node.ID, delay, clean(r.Node.Name))
		}
		if !ok {
			return errors.New("all servers failed probes")
		}
		return nil
	})
	for _, action := range []string{"up", "down", "restart", "status", "run", "check", "doctor", "_serve"} {
		action := action
		c := add(root, action, "Proxy: "+action, 0, func(c *cobra.Command, args []string) error {
			s, v, e := read(c)
			if e != nil {
				return e
			}
			if action == "status" || action == "down" {
				if action == "down" {
					if e = Stop(s); e != nil {
						return e
					}
				}
				r, e := Control(s, "status")
				if e != nil {
					return e
				}
				return output(c.OutOrStdout(), r)
			}
			core, e := a.core()
			if e != nil {
				return e
			}
			mode, _ := c.Flags().GetString("mode")
			port, _ := c.Flags().GetInt("port")
			switch action {
			case "up":
				e = Start(s, core, mode, port)
			case "restart":
				e = Restart(s, core, mode, port)
			case "run", "_serve":
				return Serve(s, core, mode, port)
			case "check":
				_, e = CheckedConfig(s, core, v, mode, port)
				if e == nil {
					fmt.Fprintln(c.OutOrStdout(), "Configuration valid")
				}
				return e
			case "doctor":
				r, err := Control(s, "status")
				if err != nil {
					return err
				}
				return output(c.OutOrStdout(), M{"version": Version, "core": core, "profile": s.Profile, "runtime": r})
			}
			if e != nil {
				return e
			}
			r, e := Control(s, "status")
			if e != nil {
				return e
			}
			return output(c.OutOrStdout(), r)
		})
		if action == "up" {
			c.Aliases = []string{"start"}
		}
		if action == "down" {
			c.Aliases = []string{"stop"}
		}
		if action == "_serve" {
			c.Hidden = true
		}
		if action == "up" || action == "run" || action == "restart" || action == "check" || action == "_serve" {
			mode, port := "proxy", 2080
			if action == "restart" {
				mode, port = "", 0
			}
			c.Flags().String("mode", mode, "proxy or tun")
			c.Flags().Int("port", port, "SOCKS port; HTTP uses port+1")
		}
	}
	for _, parentName := range []string{"tun", "_tun"} {
		parentName := parentName
		tun := add(root, parentName, "System VPN", -1, nil)
		tun.Hidden = parentName == "_tun"
		for _, action := range []string{"up", "down", "restart", "status", "install", "uninstall", "recover", "run"} {
			action := action
			c := add(tun, action, action+" TUN", 0, func(c *cobra.Command, args []string) error {
				port, _ := c.Flags().GetInt("port")
				core := ""
				if action == "up" || action == "restart" || action == "install" || action == "run" {
					var e error
					core, e = a.core()
					if e != nil {
						return e
					}
				}
				if parentName == "_tun" {
					r, e := TunAction(canonical(a.Home), core, action, port)
					if e != nil {
						return e
					}
					return output(c.OutOrStdout(), r)
				}
				cmd := privilegedCommand(canonical(a.Home), core, action, port)
				cmd.Stdin = c.InOrStdin()
				cmd.Stdout = c.OutOrStdout()
				cmd.Stderr = c.ErrOrStderr()
				if e := cmd.Run(); e != nil {
					return errors.New("TUN command failed")
				}
				return nil
			})
			if action == "up" {
				c.Aliases = []string{"start"}
			}
			if action == "down" {
				c.Aliases = []string{"stop"}
			}
			port := 2180
			if action == "restart" {
				port = 0
			}
			c.Flags().Int("port", port, "SOCKS port")
		}
	}
	service := add(root, "_service", "LaunchDaemon entry point", 0, func(c *cobra.Command, args []string) error {
		owner, _ := c.Flags().GetInt("owner")
		port, _ := c.Flags().GetInt("port")
		if os.Geteuid() != 0 {
			return errors.New("root required")
		}
		s, e := a.store()
		if e != nil {
			return e
		}
		st, e := os.Stat(s.Profile)
		if e != nil || int(st.Sys().(*syscall.Stat_t).Uid) != owner {
			return errors.New("profile owner mismatch")
		}
		srv := NewService(s, owner)
		if os.Getenv("VCTL_LAUNCHD_LABEL") != srv.Label {
			return errors.New("must be launched by installed service")
		}
		if !exists(srv.Marker) {
			return nil
		}
		core, e := a.core()
		if e != nil {
			return e
		}
		return Serve(s, core, "tun", port)
	})
	service.Hidden = true
	service.Flags().Int("owner", -1, "owner")
	service.Flags().Int("port", 2180, "port")
	watch := add(root, "_watch INSTANCE", "Recovery watchdog", 1, func(c *cobra.Command, args []string) error {
		s, e := a.store()
		if e != nil {
			return e
		}
		return Watch(s, args[0])
	})
	watch.Hidden = true
	completion := add(root, "completion zsh|bash|fish|powershell", "Shell completion", 1, func(c *cobra.Command, args []string) error {
		switch args[0] {
		case "zsh":
			return root.GenZshCompletion(c.OutOrStdout())
		case "bash":
			return root.GenBashCompletionV2(c.OutOrStdout(), true)
		case "fish":
			return root.GenFishCompletion(c.OutOrStdout(), true)
		case "powershell":
			return root.GenPowerShellCompletionWithDesc(c.OutOrStdout())
		}
		return errors.New("unknown shell")
	})
	completion.ValidArgs = []string{"zsh", "bash", "fish", "powershell"}
	for _, c := range root.Commands() {
		switch c.Name() {
		case "default":
			c.ValidArgs = []string{"proxy", "direct"}
		case "use":
			c.ValidArgsFunction = func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
				v, e := (Store{a.Home, a.Home}).Read()
				out := []string{"auto"}
				if e == nil {
					for _, n := range v.Nodes() {
						out = append(out, n.ID+"\t"+clean(n.Name))
					}
				}
				return out, cobra.ShellCompDirectiveNoFileComp
			}
		case "sub":
			for _, subcmd := range c.Commands() {
				if subcmd.Name() == "update" || subcmd.Name() == "remove" {
					subcmd.ValidArgsFunction = func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
						v, _ := (Store{a.Home, a.Home}).Read()
						return v.Subscriptions.Keys, cobra.ShellCompDirectiveNoFileComp
					}
				}
			}
		}
		if c.Flags().Lookup("mode") != nil {
			_ = c.RegisterFlagCompletionFunc("mode", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
				return []string{"proxy", "tun"}, cobra.ShellCompDirectiveNoFileComp
			})
		}
	}
	root.CompletionOptions.DisableDefaultCmd = true
	return root
}
