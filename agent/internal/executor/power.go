package executor

import (
	"context"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
)

// RestartNotice is what a user sees in the Windows shutdown dialog, and the
// reason the restart is delayed on both platforms: a device is never taken
// down from under someone without a minute's warning.
const RestartNotice = "OfficeHQ MDM restart"

// runPower runs a restart or a lock: a command with no required payload field,
// whose argv is fixed per platform.
//
// The result is the exit of the command that was issued, not of the restart
// itself — the agent reports before the machine goes down, because afterwards
// it cannot report at all.
func runPower(ctx context.Context, cmd Command, deps *Deps, argv func(goos string) (string, []string)) contract.CommandResultRequest {
	seconds, ok := decodeTimeout(cmd.Payload)
	if !ok {
		return deps.fail(ErrInvalidPayload, "")
	}

	name, args := argv(deps.goos())

	deps.log(logging.LevelInfo, "running command",
		logging.F("commandId", cmd.CommandID),
		logging.F("type", cmd.Type),
	)

	return deps.report(deps.run(ctx, EffectiveTimeout(seconds), name, args...))
}

// restartArgv is how a device is restarted on each platform. Both give the
// person at the keyboard about a minute: Windows carries the notice in the
// dialog it shows, macOS takes the delay in minutes.
func restartArgv(goos string) (string, []string) {
	if goos == "windows" {
		return "shutdown.exe", []string{"/r", "/t", "60", "/c", RestartNotice}
	}
	return "/sbin/shutdown", []string{"-r", "+1"}
}

// lockArgv is how a device is locked on each platform.
//
// Locking is best-effort from a service host: the agent runs as LocalSystem on
// Windows and as root under launchd on macOS, and a command issued from
// session 0 may not reach the interactive desktop session. Both of these need
// verifying on a real device.
func lockArgv(goos string) (string, []string) {
	if goos == "windows" {
		return "rundll32.exe", []string{"user32.dll,LockWorkStation"}
	}
	return "pmset", []string{"displaysleepnow"}
}
