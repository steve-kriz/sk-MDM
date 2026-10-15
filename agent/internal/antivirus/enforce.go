package antivirus

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// SettingAntivirusEnabled is the policy setting key this enforcer acts on, the
// key the backend validates in backend/src/admin/policies.ts.
const SettingAntivirusEnabled = "antivirusEnabled"

// enforcerName is how the enforcer is named in the log.
const enforcerName = "antivirus"

// WindowsEnableScript starts the Defender service, switches real-time
// protection back on and reads back whether it took: it prints a
// realTimeProtectionEnabled= line and an isTamperProtected= line. It is the
// only change the enforcer makes to a machine.
const WindowsEnableScript = `Start-Service -Name WinDefend -ErrorAction Stop; ` +
	`Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop; ` +
	`$s = Get-MpComputerStatus -ErrorAction Stop; ` +
	`"realTimeProtectionEnabled=$([bool]$s.RealTimeProtectionEnabled)"; ` +
	`"isTamperProtected=$([bool]$s.IsTamperProtected)"`

// The read-back keys WindowsEnableScript prints.
const (
	readBackRealTime = "realTimeProtectionEnabled"
	readBackTamper   = "isTamperProtected"
)

// Errors Apply wraps when the enable command exited 0 but real-time protection
// is not confirmed on. There is one attempt per Apply; the next cycle retries.
var (
	// ErrTamperProtected means real-time protection is still off and Defender
	// Tamper Protection is on, which blocks the change.
	ErrTamperProtected = errors.New("real-time protection still off: blocked by Tamper Protection")
	// ErrRealTimeStillOff means real-time protection is still off without
	// Tamper Protection, for example because Group Policy forces it off.
	ErrRealTimeStillOff = errors.New("real-time protection still off after enabling")
	// ErrEnableUnparseable means the read-back output carried no
	// realTimeProtectionEnabled=True or =False line.
	ErrEnableUnparseable = errors.New("unparseable read-back output")
)

// Enforcer turns Microsoft Defender on when a policy requires antivirus and
// none is active. It implements agent/internal/enforce's Enforcer.
type Enforcer struct {
	runner platform.CommandRunner
	clock  platform.Clock
	goos   string

	// Actions, when set, is told once each time Apply turned real-time
	// protection on and the read-back confirmed it. Nil records nothing.
	Actions func(actionType string, details map[string]string)
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
// non-zero or outlasting EnforceTimeout is an error, and so is a read-back that
// does not confirm real-time protection on (ErrTamperProtected,
// ErrRealTimeStillOff or ErrEnableUnparseable). It never retries in-call.
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

	realTime, ok := readBackBool(out.Stdout, readBackRealTime)
	switch {
	case !ok:
		return fmt.Errorf("antivirus enable command: %w", ErrEnableUnparseable)
	case realTime:
		if e.Actions != nil {
			e.Actions(contract.ActionAntivirusEnabled, map[string]string{})
		}
		return nil
	}
	if tamper, ok := readBackBool(out.Stdout, readBackTamper); ok && tamper {
		return fmt.Errorf("antivirus enable command: %w", ErrTamperProtected)
	}
	return fmt.Errorf("antivirus enable command: %w", ErrRealTimeStillOff)
}

// readBackBool finds the last "key=True" or "key=False" line in stdout. The
// second return is false when no such line is present.
func readBackBool(stdout, key string) (bool, bool) {
	value, found := false, false
	prefix := key + "="
	for _, line := range splitLines(stdout) {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		switch strings.TrimSpace(strings.TrimPrefix(line, prefix)) {
		case "True":
			value, found = true, true
		case "False":
			value, found = false, true
		}
	}
	return value, found
}
