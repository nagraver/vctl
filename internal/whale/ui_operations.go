package whale

import (
	"bytes"
	"context"
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"os/exec"
	"strings"
	"time"
)

type authRequiredMsg struct{ item menuItem }
type authResultMsg struct {
	item menuItem
	err  error
}
type activityMsg struct{ started time.Time }

func activityTick(started time.Time) tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(time.Time) tea.Msg { return activityMsg{started} })
}
func (m *uiModel) startActivity(label string) {
	m.busy = true
	m.notice = m.tr(label)
	m.started = time.Now()
	m.frame = 0
}

// Authorization uses sudo's normal policy and timestamp. Passwords travel only
// on stdin to sudo, never in argv, environment, logs, or profile settings.
func authorizeSudo(ctx context.Context, password string) error {
	cmd := exec.CommandContext(ctx, "/usr/bin/sudo", "-S", "-p", "", "-v")
	cmd.Stdin = strings.NewReader(password + "\n")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("authorization failed; try again or press Esc")
	}
	return nil
}
func runTunUI(app App, item menuItem) tea.Msg {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err := exec.CommandContext(ctx, "/usr/bin/sudo", "-n", "-v").Run()
	cancel()
	if err != nil {
		return authRequiredMsg{item}
	}
	core := ""
	if len(item.args) < 2 {
		return resultMsg{err: fmt.Errorf("missing TUN action")}
	}
	switch item.args[1] {
	case "up", "start", "restart", "install", "run":
		core, err = app.core()
		if err != nil {
			return resultMsg{err: err}
		}
	}
	args := []string{"-n", executable(), "--home", canonical(app.Home), "--core", core, "_tun"}
	args = append(args, item.args[1:]...)
	cmd := exec.Command("/usr/bin/sudo", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	return resultMsg{out: out.String(), err: err}
}
func (m uiModel) activityView() string {
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	elapsed := time.Duration(0)
	if !m.started.IsZero() {
		elapsed = time.Since(m.started).Truncate(time.Second)
	}
	text := fmt.Sprintf("  %s %s  %s", frames[m.frame%len(frames)], m.notice, elapsed)
	if m.cancel != nil {
		text += m.tr("\n  Ctrl+C to cancel")
	}
	return text + "\n"
}

// Lifecycle success is represented by the menu switches; explicit status stays detailed.
func quietLifecycle(args []string) bool {
	if len(args) > 0 && args[0] == "tun" {
		args = args[1:]
	}
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "up", "down", "start", "stop", "restart":
		return true
	}
	return false
}
