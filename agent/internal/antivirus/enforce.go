package antivirus

import (
	"context"
	"fmt"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// SettingAntivirusEnabled is the policy setting key this enforcer acts on, the
// key the backend validates in backend/src/admin/policies.ts.
const SettingAntivirusEnabled = "antivirusEnabled"

// enforcerName is how the enforcer is named in the log.
const enforcerName = "antivirus"

// WindowsEnableScript starts the Defender service and switches real-time
// protection back on. It is the only change this package makes to a machine.
const WindowsEnableScript = `Start-Service -Name WinDefend -ErrorAction Stop; ` +
	`Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop`

// Enforcer turns Microsoft Defender on when a policy requires antivirus and
// none is active. It implements agent/internal/enforce's Enforcer.
type Enforcer struct {
	runner platform.CommandRunner
	clock  platform.Clock
	goos   string
}

// NewEnforcer returns the antivirus enforcer for goos.
func NewEnforcer(runner platform.CommandRunner, clock platform.Clock, goos string) *Enforcer {
	return &Enforcer{runner: runner, clock: clock, goos: goos}
}

// Name identifies the enforcer in the log.
func (e *Enforcer) Name() string { return enforcerName }

// Apply runs WindowsEnableScript once when goos is windows, the effective
// antivirusEnabled is the boolean true and posture reports no active
// antivirus. In every other case it does nothing and returns nil: a third-party
// product that is active already makes posture.Antivirus.Enabled true, and
// XProtect on macOS cannot be switched. The command failing to start, exiting
// non-zero or outlasting EnforceTimeout is an error.
func (e *Enforcer) Apply(ctx context.Context, effective map[string]any, posture contract.Posture) error {
	if e.goos != "windows" {
		return nil
	}
	if required, ok := effective[SettingAntivirusEnabled].(bool); !ok || !required {
		return nil
	}
	if posture.Antivirus.Enabled {
		return nil
	}

	out, err, timedOut := runBounded(ctx, e.runner, e.clock, EnforceTimeout, windowsShell, windowsArgs(WindowsEnableScript)...)
	switch {
	case timedOut:
		return fmt.Errorf("antivirus enable command: timeout after %s", EnforceTimeout)
	case err != nil:
		return fmt.Errorf("antivirus enable command: %w", err)
	case out.ExitCode != 0:
		return fmt.Errorf("antivirus enable command: exit code %d", out.ExitCode)
	}
	return nil
}
