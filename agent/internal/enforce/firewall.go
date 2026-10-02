package enforce

import (
	"context"
	"fmt"
	"strings"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// The commands that turn the host firewall on. There is deliberately no
// command here that turns one off.
const (
	windowsShell          = "powershell.exe"
	windowsFirewallScript = "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"

	darwinSocketFilterFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"
)

// Firewall turns the host firewall on when firewallEnabled requires it and the
// posture saw it off. It never turns a firewall off.
type Firewall struct {
	Runner platform.CommandRunner
	GOOS   string
}

// Name is "firewall".
func (f *Firewall) Name() string { return "firewall" }

// Apply runs the platform's firewall-on command, once, when the setting is the
// boolean true and the firewall is off. Every other case runs nothing. A goos
// with no known command also runs nothing.
func (f *Firewall) Apply(ctx context.Context, effective map[string]any, posture contract.Posture) error {
	required, ok := boolSetting(effective, SettingFirewallEnabled)
	if !ok || !required || posture.Firewall.Enabled {
		return nil
	}

	name, args, ok := firewallOnCommand(f.GOOS)
	if !ok {
		return nil
	}

	result, err := f.Runner.Run(ctx, name, args...)
	if err != nil {
		return fmt.Errorf("turn firewall on: %s: %w", name, err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("turn firewall on: %s exited with code %d: %s",
			name, result.ExitCode, strings.TrimSpace(result.Stderr))
	}
	return nil
}

// firewallOnCommand is the command that turns the firewall on for goos.
func firewallOnCommand(goos string) (string, []string, bool) {
	switch goos {
	case "windows":
		return windowsShell, []string{"-NoProfile", "-NonInteractive", "-Command", windowsFirewallScript}, true
	case "darwin":
		return darwinSocketFilterFW, []string{"--setglobalstate", "on"}, true
	default:
		return "", nil, false
	}
}
