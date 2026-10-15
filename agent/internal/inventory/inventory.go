// Package inventory collects the hardware, OS and installed-software snapshot
// the agent sends on every check-in.
//
// Every fact comes from running a probe command through
// platform.CommandRunner: the collector opens no file and calls no OS API
// directly, so the whole package is driven from recorded probe output. The
// fixtures under testdata/<goos>/<probe>.txt are exactly what the probe of
// that name printed on a real machine, and Probes reports the command line a
// test keys the fake runner by.
//
// Nothing here fails the collection. A probe that cannot be started, exits
// non-zero or does not answer within ProbeTimeout leaves its fields at their
// zero values and adds a warning; the warnings travel to the backend on the
// wire as contract.Inventory.Warnings.
//
// The target OS is the goos parameter rather than a build constraint, so the
// Windows and macOS parsers both compile and both run on either host.
package inventory

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// Probe names. A probe name is the warning text a failing probe produces, and
// the base name of its fixture file under testdata/<goos>/.
const (
	ProbeHardware = "hardware"
	ProbeOS       = "os"
	ProbeDisk     = "disk"
	ProbeSoftware = "software"

	// ProbeDetails is the Windows-only device-details probe. Besides the
	// usual "details" and "details:timeout" warnings, a section of its script
	// that fails is reported as "details:<section>" and output that is not a
	// single JSON object as "details:unparseable".
	ProbeDetails = "details"
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

// Collect runs every probe for goos and assembles the inventory.
//
// The error return is reserved for a goos this package has no probes for: a
// failing, hanging or unreadable probe is reported in the returned
// Inventory.Warnings, not as an error.
func Collect(runner platform.CommandRunner, clock platform.Clock, goos string) (contract.Inventory, error) {
	inv := contract.Inventory{Software: []contract.SoftwareEntry{}}

	probes := Probes(goos)
	if len(probes) == 0 {
		return inv, fmt.Errorf("inventory: unsupported goos %q", goos)
	}

	stdout, warnings := runProbes(runner, clock, probes)
	switch goos {
	case "windows":
		warnings = append(warnings, fillWindows(&inv, stdout)...)
	case "darwin":
		fillDarwin(&inv, stdout)
	}

	inv.Software = cleanSoftware(inv.Software)
	inv.Warnings = warnings
	return inv, nil
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

// UnknownVersion is the version sent for software the OS lists without one.
// The contract requires a non-empty version on every entry, and the backend
// refuses the whole check-in -- posture included -- over a single blank one.
const UnknownVersion = "unknown"

// cleanSoftware drops entries with a blank name, gives a blank version
// UnknownVersion, and keeps the first of any entries sharing a name and
// version, preserving probe order.
func cleanSoftware(entries []contract.SoftwareEntry) []contract.SoftwareEntry {
	cleaned := make([]contract.SoftwareEntry, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		e.Name = strings.TrimSpace(e.Name)
		if e.Name == "" {
			continue
		}
		e.Version = strings.TrimSpace(e.Version)
		if e.Version == "" {
			e.Version = UnknownVersion
		}
		key := e.Name + "\x00" + e.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		cleaned = append(cleaned, e)
	}
	return cleaned
}

// splitLines splits probe output into its non-blank lines, dropping the
// carriage return a Windows probe leaves behind. Leading whitespace is kept:
// an empty first column of a tab-separated record must stay empty. It is built
// on strings rather than bufio so output of any size, including a single line
// larger than a megabyte, is handled without error or panic.
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
// on the locale of the machine the probe ran on.
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

// parseLabelled reads the "Label: value" lines tools such as sw_vers print.
func parseLabelled(s string) map[string]string {
	values := map[string]string{}
	for _, line := range splitLines(s) {
		label, value, ok := strings.Cut(line, ":")
		label = strings.TrimSpace(label)
		if !ok || label == "" {
			continue
		}
		values[label] = strings.TrimSpace(value)
	}
	return values
}

// parseBytes reads a byte count, either plain digits or a value with a unit
// such as "16 GB" as system_profiler prints it.
func parseBytes(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}

	fields := strings.Fields(s)
	if len(fields) < 2 {
		return 0
	}
	n, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	var multiplier float64
	switch strings.ToUpper(fields[1]) {
	case "KB":
		multiplier = 1 << 10
	case "MB":
		multiplier = 1 << 20
	case "GB":
		multiplier = 1 << 30
	case "TB":
		multiplier = 1 << 40
	default:
		return 0
	}
	return int64(n * multiplier)
}

// normalizeArch maps the many spellings of an architecture onto the two the
// backend stores, leaving anything unrecognised lower-cased and untouched.
func normalizeArch(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "amd64", "x86_64", "x64", "64-bit":
		return "amd64"
	case "arm64", "aarch64":
		return "arm64"
	case "x86", "386", "32-bit":
		return "386"
	default:
		return strings.ToLower(strings.TrimSpace(s))
	}
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
