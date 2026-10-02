// Package posture collects the security posture the agent reports on every
// check-in: disk encryption, firewall, antivirus, OS update state and the
// local administrators.
//
// Like the inventory collector, every fact comes from a probe command run
// through platform.CommandRunner, every deadline is measured on the injected
// platform.Clock, and the target OS is the goos parameter rather than a build
// constraint. The fixtures under testdata/<goos>/<probe>.txt are what the
// probe of that name printed on a real machine.
//
// Posture degrades rather than fails. A probe that cannot be started, exits
// non-zero or does not answer within ProbeTimeout adds a warning and leaves
// its block at the zero value; output that cannot be understood — empty, in
// another language, or megabytes of noise — leaves the block's enabled flag
// false and adds "<probe>:unparseable". The warnings reach the backend on the
// wire as contract.Posture.Warnings.
package posture

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// Probe names. A probe name is the warning text a failing probe produces, the
// stem of its ":unparseable" and ":timeout" warnings, and the base name of its
// fixture file under testdata/<goos>/. Each one matches the json field of the
// posture block it fills.
const (
	ProbeDiskEncryption = "diskEncryption"
	ProbeFirewall       = "firewall"
	ProbeAntivirus      = "antivirus"
	ProbeOSUpdate       = "osUpdate"
	ProbeLocalAdmins    = "localAdmins"
)

// Disk encryption methods, as the contract spells them.
const (
	MethodBitLocker = "bitlocker"
	MethodFileVault = "filevault"
)

// ProbeTimeout is how long a single probe may take. It is measured on the
// injected clock, never on the wall clock, so a test advances a fake clock by
// ProbeTimeout instead of sleeping.
const ProbeTimeout = 30 * time.Second

// Probe is one external command the collector runs.
type Probe struct {
	// Name identifies the probe in warnings and names its fixture file.
	Name string

	// Cmd and Args are passed straight to platform.CommandRunner.Run.
	Cmd  string
	Args []string
}

// String renders the probe as the command line "cmd arg arg". It is the key
// fake.CommandRunner stores canned results under, so a test arranges a probe
// with runner.Results[p.String()] = ....
func (p Probe) String() string {
	if len(p.Args) == 0 {
		return p.Cmd
	}
	return p.Cmd + " " + strings.Join(p.Args, " ")
}

// Probes lists the probes Collect runs for goos, in the order their warnings
// appear. An unsupported goos yields no probes.
func Probes(goos string) []Probe {
	switch goos {
	case "windows":
		return windowsProbes()
	case "darwin":
		return darwinProbes()
	default:
		return nil
	}
}

// Collect runs every probe for goos and assembles the posture.
//
// The error return is reserved for a goos this package has no probes for: a
// failing, hanging or unreadable probe is reported in the returned
// Posture.Warnings, not as an error.
func Collect(runner platform.CommandRunner, clock platform.Clock, goos string) (contract.Posture, error) {
	p := contract.Posture{LocalAdmins: []string{}}

	probes := Probes(goos)
	if len(probes) == 0 {
		return p, fmt.Errorf("posture: unsupported goos %q", goos)
	}

	stdout, warnings := runProbes(runner, clock, probes)
	switch goos {
	case "windows":
		warnings = append(warnings, fillWindows(&p, stdout)...)
	case "darwin":
		warnings = append(warnings, fillDarwin(&p, stdout)...)
	}

	p.Warnings = warnings
	return p, nil
}

// probeResult is what one probe goroutine produced.
type probeResult struct {
	out platform.CommandResult
	err error
}

// runProbes runs the probes one at a time and returns the stdout of the ones
// that succeeded, keyed by probe name, together with the warnings the others
// produced, in probe order.
//
// Each probe runs on its own goroutine and the collector selects between that
// goroutine's result and clock.After(ProbeTimeout). CommandRunner offers no
// cancellation, so a probe that never answers is abandoned rather than killed:
// its goroutine holds a buffered channel nobody reads and goes away when the
// command finally returns. Abandoning it costs the collection one timeout, not
// the collection itself — the probes after it still run.
//
// The deadline is registered before the probe's goroutine starts, so a test
// that advances the fake clock the moment a probe blocks always finds the
// timer already waiting for it.
func runProbes(runner platform.CommandRunner, clock platform.Clock, probes []Probe) (map[string]string, []string) {
	stdout := make(map[string]string, len(probes))
	var warnings []string

	record := func(p Probe, res probeResult) {
		if res.err != nil || res.out.ExitCode != 0 {
			warnings = append(warnings, p.Name)
			return
		}
		stdout[p.Name] = res.out.Stdout
	}

	for _, p := range probes {
		results := make(chan probeResult, 1)
		timeout := clock.After(ProbeTimeout)

		go func(p Probe) {
			out, err := runner.Run(context.Background(), p.Cmd, p.Args...)
			results <- probeResult{out: out, err: err}
		}(p)

		select {
		case res := <-results:
			record(p, res)
		case <-timeout:
			// Prefer a result that landed in the same instant the deadline
			// did over reporting a probe that did answer as a timeout.
			select {
			case res := <-results:
				record(p, res)
			default:
				warnings = append(warnings, p.Name+":timeout")
			}
		}
	}
	return stdout, warnings
}

// unparseable is the warning a probe whose output could not be understood
// produces.
func unparseable(probe string) string { return probe + ":unparseable" }

// splitLines splits probe output into its non-blank lines, dropping the
// carriage return a Windows probe leaves behind. It is built on strings rather
// than bufio so output of any size, including a single line larger than a
// megabyte, is handled without error or panic.
func splitLines(s string) []string {
	raw := strings.Split(s, "\n")
	lines := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

// parseKeyValues reads the "key=value" lines a probe script prints. The
// scripts normalise their own output to this shape so the parser never depends
// on the display language of the machine the probe ran on.
func parseKeyValues(s string) map[string]string {
	values := map[string]string{}
	for _, line := range splitLines(s) {
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			continue
		}
		values[key] = strings.TrimSpace(value)
	}
	return values
}

// parseBool reads the many spellings of a yes or a no a system tool prints.
// The second result is false when the text is neither, which is what makes an
// answer in another language unparseable rather than silently false.
func parseBool(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "on", "1", "enabled", "enable":
		return true, true
	case "false", "no", "off", "0", "disabled", "disable":
		return false, true
	default:
		return false, false
	}
}

// parseInt reads a plain decimal count, treating anything else as zero.
func parseInt(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

// normalizeTime renders a probe timestamp as ISO-8601 UTC. An unrecognised
// value becomes the empty string rather than reaching the backend as junk.
func normalizeTime(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02 15:04:05 -0700",
		"2006-01-02 15:04:05",
		"20060102",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return ""
}

// fillAntivirus parses the shared "name=/enabled=/definitionsAgeDays=" shape
// both platforms' antivirus probes print. It reports whether the output said
// anything about whether the product is on.
func fillAntivirus(av *contract.Antivirus, out string) bool {
	kv := parseKeyValues(out)
	enabled, ok := parseBool(kv["enabled"])
	if !ok {
		return false
	}
	av.Name = kv["name"]
	av.Enabled = enabled
	av.DefinitionsAgeDays = parseInt(kv["definitionsAgeDays"])
	return true
}

// fillOSUpdate parses the shared
// "lastCheckedAt=/pendingCount=/rebootRequired=" shape both platforms' OS
// update probes print. It reports whether any of the three was present.
func fillOSUpdate(u *contract.OSUpdate, out string) bool {
	kv := parseKeyValues(out)
	_, hasChecked := kv["lastCheckedAt"]
	_, hasPending := kv["pendingCount"]
	reboot, hasReboot := parseBool(kv["rebootRequired"])
	if !hasChecked && !hasPending && !hasReboot {
		return false
	}
	u.LastCheckedAt = normalizeTime(kv["lastCheckedAt"])
	u.PendingCount = parseInt(kv["pendingCount"])
	u.RebootRequired = reboot
	return true
}
