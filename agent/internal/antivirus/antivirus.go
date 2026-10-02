// Package antivirus keeps antivirus switched on where a policy asks for it and
// collects the threats the device's own antivirus detected.
//
// Two things live here:
//
//   - The enforcer (NewEnforcer). When the effective setting antivirusEnabled
//     is true and the posture this cycle collected says no antivirus is
//     active, it turns Microsoft Defender on, on Windows only. XProtect on
//     macOS cannot be switched, so there it never runs anything. It never
//     turns antivirus off. It satisfies agent/internal/enforce's Enforcer
//     interface without importing that package.
//   - The findings collector (CollectFindings). Every cycle it reads
//     Microsoft Defender's detections on Windows and the XProtect Remediator
//     events in the unified log on macOS, bounded so the check-in body stays
//     small.
//
// Like the rest of agent/internal, this package touches the operating system
// only through agent/internal/platform: every command goes through
// CommandRunner and every deadline through the injected Clock, so the whole
// suite runs against the fakes in agent/internal/platform/fake.
package antivirus

import (
	"context"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// Deadlines on the injected clock.
const (
	// EnforceTimeout is how long the Windows enable command may take.
	EnforceTimeout = 60 * time.Second
	// FindingsTimeout is how long a findings probe may take.
	FindingsTimeout = 30 * time.Second
)

// Bounds on what one check-in carries, so the body stays well under the
// backend's 262144-byte limit.
const (
	// MaxAntivirusFindings is the most findings one collection returns.
	MaxAntivirusFindings = 20
	// MaxFindingResources is the most resources kept per finding.
	MaxFindingResources = 3
	// MaxResourceRunes is the longest resource kept, in runes.
	MaxResourceRunes = 260
	// MaxThreatNameRunes is the longest threat name kept, in runes.
	MaxThreatNameRunes = 256
)

// windowsShell is the interpreter every Windows script runs under.
const windowsShell = "powershell.exe"

// windowsArgs is the argument list that runs script under windowsShell, the
// same shape agent/internal/posture uses.
func windowsArgs(script string) []string {
	return []string{"-NoProfile", "-NonInteractive", "-Command", script}
}

// commandResult is what one bounded command produced.
type commandResult struct {
	out platform.CommandResult
	err error
}

// runBounded runs one command and waits for it at most timeout on clock. The
// third return is true when the deadline passed first; the command's context
// is then cancelled so a real process is not left running.
func runBounded(ctx context.Context, runner platform.CommandRunner, clock platform.Clock, timeout time.Duration, name string, args ...string) (platform.CommandResult, error, bool) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan commandResult, 1)
	deadline := clock.After(timeout)

	go func() {
		out, err := runner.Run(ctx, name, args...)
		results <- commandResult{out: out, err: err}
	}()

	select {
	case res := <-results:
		return res.out, res.err, false
	case <-deadline:
		// Prefer a result that landed in the same instant the deadline did
		// over reporting a command that did answer as a timeout.
		select {
		case res := <-results:
			return res.out, res.err, false
		default:
			return platform.CommandResult{}, nil, true
		}
	}
}

// truncateRunes cuts s to at most n runes.
func truncateRunes(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}
