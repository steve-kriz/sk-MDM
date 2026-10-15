// Package analytics collects the endpoint analytics the agent reports on
// every check-in: when the machine last booted and how long the boot took, a
// performance sample, and the application crashes and hangs since the last
// accepted report.
//
// Like the inventory and posture collectors, every fact comes from a probe
// command run through platform.CommandRunner, every deadline and every "now"
// is measured on the injected platform.Clock, and the target OS is the goos
// parameter rather than a build constraint. The fixtures under
// testdata/<goos>/<probe>.txt are what the probe of that name prints.
//
// Analytics degrades rather than fails. A probe that cannot be started, exits
// non-zero or does not answer within ProbeTimeout adds a warning and leaves
// its sub-block null; output that cannot be understood adds
// "<probe>:unparseable". The agent applies the same bounds the backend does,
// so it never sends a value the backend would discard.
package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// Probe names. A probe name is the warning text a failing probe produces, the
// stem of its ":unparseable" and ":timeout" warnings, and the base name of its
// fixture file under testdata/<goos>/.
const (
	ProbeBoot        = "boot"
	ProbePerformance = "performance"
	ProbeCrashes     = "crashes"
)

// ProbeTimeout is how long a single probe may take before it is abandoned.
const ProbeTimeout = 30 * time.Second

// Collection bounds, mirroring what the backend accepts.
const (
	// MaxAppCrashes is the most crashes one check-in carries; the rest are
	// sent by later cycles.
	MaxAppCrashes = 50
	// CrashLookback is how far back a crash may be and still be sent.
	CrashLookback = 30 * 24 * time.Hour
	// CrashFutureSkew is how far ahead of the clock a crash may be stamped
	// and still be sent.
	CrashFutureSkew = 24 * time.Hour
	// MaxBootDurationSeconds is the longest boot duration reported.
	MaxBootDurationSeconds = 3600
)

// Crash kinds, as the contract spells them.
const (
	KindCrash = "crash"
	KindHang  = "hang"
)

// warnBootDurationUnavailable is the warning a Windows boot whose duration
// could not be established produces.
const warnBootDurationUnavailable = "bootDuration:unavailable"

// Probe is one command the collector runs.
type Probe struct {
	// Name identifies the probe in warnings and fixtures.
	Name string
	// Cmd is the program to run.
	Cmd string
	// Args are its arguments.
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

// crashEntry is one parsed crash with the full-precision time it is selected
// and ordered by.
type crashEntry struct {
	at    time.Time
	crash contract.AppCrash
}

// Collect runs every probe for goos and assembles the analytics block.
//
// since is the watermark: only crashes strictly after it (and within
// CrashLookback of now) are returned. The second result is the new watermark
// candidate: the full-precision time of the newest crash returned, or since
// when none is.
//
// The error return is reserved for a goos this package has no probes for: a
// failing, hanging or unreadable probe is reported in Analytics.Warnings.
func Collect(runner platform.CommandRunner, clock platform.Clock, goos string, since time.Time) (contract.Analytics, time.Time, error) {
	a := contract.Analytics{Crashes: []contract.AppCrash{}}

	probes := Probes(goos)
	if len(probes) == 0 {
		return a, since, fmt.Errorf("analytics: unsupported goos %q", goos)
	}

	stdout, warnings := runProbes(runner, clock, probes)
	now := clock.Now()

	if out, ok := stdout[ProbeBoot]; ok {
		switch goos {
		case "windows":
			warnings = append(warnings, fillWindowsBoot(&a.Boot, out, now)...)
		case "darwin":
			warnings = append(warnings, fillDarwinBoot(&a.Boot, out, now)...)
		}
	}

	if out, ok := stdout[ProbePerformance]; ok {
		if !fillPerformance(&a.Performance, out) {
			warnings = append(warnings, unparseable(ProbePerformance))
		}
	}

	candidate := since
	if out, ok := stdout[ProbeCrashes]; ok {
		var entries []crashEntry
		var clean bool
		switch goos {
		case "windows":
			entries, clean = parseWindowsCrashes(out)
		case "darwin":
			entries, clean = parseDarwinCrashes(out)
		}
		if !clean {
			warnings = append(warnings, unparseable(ProbeCrashes))
		}
		a.Crashes, candidate = selectCrashes(entries, since, now)
	}

	if len(warnings) > 0 {
		a.Warnings = warnings
	}
	return a, candidate, nil
}

// CollectPerformance runs only the probe named ProbePerformance for goos and
// returns its sample with the warnings it produced, for the heartbeat. Its
// values are exactly those Collect puts in Analytics.Performance. A goos with
// no performance probe yields an all-nil sample and the warning
// ProbePerformance, as a failing probe does.
func CollectPerformance(runner platform.CommandRunner, clock platform.Clock, goos string) (contract.AnalyticsPerformance, []string) {
	var p contract.AnalyticsPerformance

	var probes []Probe
	for _, probe := range Probes(goos) {
		if probe.Name == ProbePerformance {
			probes = append(probes, probe)
		}
	}
	if len(probes) == 0 {
		return p, []string{ProbePerformance}
	}

	stdout, warnings := runProbes(runner, clock, probes)
	if out, ok := stdout[ProbePerformance]; ok {
		if !fillPerformance(&p, out) {
			warnings = append(warnings, unparseable(ProbePerformance))
		}
	}
	return p, warnings
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
// goroutine's result and clock.After(ProbeTimeout). A probe that never
// answers is abandoned rather than killed, and the probes after it still run.
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
// than bufio so a line of any size is handled.
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

// parseKeyValues reads the "key=value" lines a probe script prints.
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

// wholeSecond renders t as whole-second RFC3339 UTC, the shape every
// timestamp in the block takes.
func wholeSecond(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// fillBootTime sets lastBootAt and uptimeSeconds from a parsed boot time. It
// reports false, setting nothing, when the boot time is later than now.
func fillBootTime(b *contract.AnalyticsBoot, bootAt, now time.Time) bool {
	if bootAt.After(now) {
		return false
	}
	last := wholeSecond(bootAt)
	uptime := int64(now.Sub(bootAt) / time.Second)
	b.LastBootAt = &last
	b.UptimeSeconds = &uptime
	return true
}

// fillPerformance parses the shared performance output into p, applying the
// bounds. It reports whether at least one value was valid.
func fillPerformance(p *contract.AnalyticsPerformance, out string) bool {
	kv := parseKeyValues(out)
	valid := false

	if v, ok := kv["cpuPercent"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil && !math.IsNaN(f) && f >= 0 && f <= 100 {
			p.CPUPercent = &f
			valid = true
		}
	}

	if total, used, ok := boundedPair(kv, "memoryTotalBytes", "memoryUsedBytes"); ok {
		p.MemoryTotalBytes = total
		p.MemoryUsedBytes = used
		valid = true
	}

	if total, free, ok := boundedPair(kv, "diskTotalBytes", "diskFreeBytes"); ok {
		p.SystemDiskTotalBytes = total
		p.SystemDiskFreeBytes = free
		valid = true
	}

	return valid
}

// boundedPair reads a total and a part of it. The total must be an integer
// greater than zero, or neither is returned; the part must be an integer in
// [0, total], or only the total is returned. ok reports whether the total was
// valid.
func boundedPair(kv map[string]string, totalKey, partKey string) (*int64, *int64, bool) {
	total, err := strconv.ParseInt(kv[totalKey], 10, 64)
	if err != nil || total <= 0 {
		return nil, nil, false
	}
	part, err := strconv.ParseInt(kv[partKey], 10, 64)
	if err != nil || part < 0 || part > total {
		return &total, nil, true
	}
	return &total, &part, true
}

// newCrash builds a crash entry from the fields both platforms' parsers read.
// It reports false when the line must be dropped as unparseable: an empty
// application name or an unparseable time.
func newCrash(name, version string, at time.Time, kind string) (crashEntry, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return crashEntry{}, false
	}
	c := contract.AppCrash{
		AppName:    name,
		OccurredAt: wholeSecond(at),
		Kind:       kind,
	}
	if v := strings.TrimSpace(version); v != "" {
		c.AppVersion = &v
	}
	return crashEntry{at: at.UTC(), crash: c}, true
}

// selectCrashes keeps the entries strictly after max(since, now -
// CrashLookback) and not after now + CrashFutureSkew, oldest first, and caps
// them at MaxAppCrashes. It returns the crashes to send, never nil, and the
// watermark candidate: the time of the last one sent, or since.
func selectCrashes(entries []crashEntry, since, now time.Time) ([]contract.AppCrash, time.Time) {
	lower := since
	if lookback := now.Add(-CrashLookback); lookback.After(lower) {
		lower = lookback
	}
	upper := now.Add(CrashFutureSkew)

	kept := make([]crashEntry, 0, len(entries))
	for _, e := range entries {
		if e.at.After(lower) && !e.at.After(upper) {
			kept = append(kept, e)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].at.Before(kept[j].at) })
	if len(kept) > MaxAppCrashes {
		kept = kept[:MaxAppCrashes]
	}

	crashes := make([]contract.AppCrash, 0, len(kept))
	for _, e := range kept {
		crashes = append(crashes, e.crash)
	}
	candidate := since
	if len(kept) > 0 {
		candidate = kept[len(kept)-1].at
	}
	return crashes, candidate
}

// errNotObject is what decodeObject reports for text that is not exactly one
// JSON object.
var errNotObject = errors.New("not a JSON object")

// decodeObject decodes text that must be exactly one JSON object, keeping
// numbers as json.Number so an integer can be told from a fraction.
func decodeObject(text string) (map[string]any, error) {
	trimmed := strings.TrimSpace(text)
	if !strings.HasPrefix(trimmed, "{") {
		return nil, errNotObject
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(trimmed)))
	decoder.UseNumber()
	var fields map[string]any
	if err := decoder.Decode(&fields); err != nil {
		return nil, err
	}
	if decoder.More() || fields == nil {
		return nil, errNotObject
	}
	return fields, nil
}
