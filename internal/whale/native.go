package whale

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func helperPath() (string, error) {
	dir := filepath.Dir(executable())
	for _, p := range []string{filepath.Join(dir, "whale-helper"), filepath.Join(dir, "../libexec/whale-helper"), filepath.Join(dir, "../MacOS/whale-helper")} {
		if exists(p) {
			return canonical(p), nil
		}
	}
	return "", errors.New("Whale helper is missing; reinstall the application")
}
func Execute() error { return newCommand(&App{Home: defaultHome()}).Execute() }
func newCommand(a *App) *cobra.Command {
	root := &cobra.Command{Use: "whale", Short: "Whale VPN — manage settings in the macOS application", Version: Version, SilenceUsage: true, SilenceErrors: true, Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error { return c.Help() }}
	root.PersistentFlags().StringVar(&a.Home, "home", a.Home, "Profile directory")
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetHelpCommand(&cobra.Command{Use: "help", Hidden: true})
	root.SetUsageTemplate(`Usage:
  {{.UseLine}}
{{if .HasAvailableSubCommands}}
Available Commands:
{{range .Commands}}{{if .IsAvailableCommand}}  {{rpad .Name .NamePadding}} {{.Short}}
{{end}}{{end}}{{end}}
Flags:
{{.LocalFlags.FlagUsages}}{{if .HasAvailableInheritedFlags}}{{.InheritedFlags.FlagUsages}}{{end}}`)
	for _, action := range []string{"up", "down", "status"} {
		action := action
		c := &cobra.Command{Use: action, Short: map[string]string{"up": "Connect the system VPN", "down": "Disconnect the system VPN", "status": "Show connection status"}[action], Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
			if action != "status" {
				helper, e := helperPath()
				if e != nil {
					return e
				}
				cmd := exec.Command(helper, "--home", canonical(a.Home), "tun", action)
				cmd.Stdin = c.InOrStdin()
				cmd.Stderr = c.ErrOrStderr()
				if e = cmd.Run(); e != nil {
					return fmt.Errorf("could not %s VPN; see the message above", action)
				}
			}
			snapshot, e := NativeSnapshot(a)
			if e != nil {
				return e
			}
			tun := obj(snapshot, "tun")
			_, e = fmt.Fprintf(c.OutOrStdout(), "VPN: %s\nServer: %s\n", str(tun, "state"), str(snapshot, "serverName"))
			return e
		}}
		root.AddCommand(c)
	}
	return root
}

// Read-only, unprivileged snapshot. Never return subscription URLs, private keys,
// or raw outbound configurations to the GUI.
func NativeSnapshot(a *App) (M, error) {
	s := Store{canonical(a.Home), canonical(a.Home)}
	if a.StateHome != "" {
		s.Profile = canonical(a.StateHome)
	}
	v, e := s.Read()
	if e != nil {
		return nil, e
	}
	srv := NewService(Store{filepath.Join(s.Profile, "tun"), s.Profile}, os.Getuid())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	text, err := exec.CommandContext(ctx, "/bin/launchctl", "print", srv.Target).CombinedOutput()
	tun := M{"state": tunSwitchState(string(text), err != nil, exists(srv.Marker), exists(srv.Plist)), "installed": exists(srv.Plist)}
	actual := readTunSelection(s.Profile, string(text))
	tun["server"] = actual
	nodes := []M{}
	seen := map[string]bool{}
	subscriptions := []M{}
	presets := []M{}
	rules := []M{}
	serverName := "Automatic"
	for _, k := range v.Subscriptions.Keys {
		sub := v.Subscriptions.Values[k]
		subNodes := []M{}
		subSeen := map[string]bool{}
		for _, n := range sub.Nodes {
			if !subSeen[n.ID] {
				subSeen[n.ID] = true
				subNodes = append(subNodes, M{"id": n.ID, "name": clean(n.Name), "subscription": k, "protocol": str(n.Outbound, "type")})
			}
		}
		subscriptions = append(subscriptions, M{"name": k, "count": len(subNodes), "skipped": sub.Skipped, "nodes": subNodes, "interval": sub.Interval, "updated": sub.Updated})
		for _, n := range sub.Nodes {
			if !seen[n.ID] {
				seen[n.ID] = true
				nodes = append(nodes, M{"id": n.ID, "name": clean(n.Name), "subscription": k, "protocol": str(n.Outbound, "type")})
			}
			if n.ID == v.Selected {
				serverName = clean(n.Name)
			}
		}
	}
	if v.Selected == "auto" && str(actual, "name") != "" {
		serverName = "Automatic — " + str(actual, "name")
	}
	for _, r := range v.Rules {
		rules = append(rules, M{"kind": r.Kind, "value": r.Value, "action": r.Action})
	}
	for _, k := range v.Presets.Keys {
		p := v.Presets.Values[k]
		presets = append(presets, M{"name": k, "source": p.Source, "enabled": p.Enabled, "count": len(p.Rules), "interval": p.Interval})
	}
	dns := map[string]string{"direct": "https://1.1.1.1/dns-query", "proxy": "https://1.1.1.1/dns-query", "strategy": "UseIP"}
	for k, value := range v.DNS {
		dns[k] = value
	}
	return M{"version": Version, "home": s.Profile, "selected": v.Selected, "serverName": serverName, "defaultRoute": v.Default, "nodes": nodes, "subscriptions": subscriptions, "rules": rules, "presets": presets, "dns": dns, "geodata": v.Geodata, "tun": tun}, nil
}
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
