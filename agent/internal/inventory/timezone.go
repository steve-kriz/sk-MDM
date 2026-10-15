package inventory

import (
	"strings"
	"sync"
	"unicode/utf16"

	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// The device's time zone is the machine-wide OS zone: the agent runs as
// SYSTEM/root, and the zone it can read is the one the signed-in user sees.
// It travels on every check-in as an IANA name so the console can show the
// device's dates in the device's own zone.
const (
	// ProbeTimeZone names the time zone probe.
	ProbeTimeZone = "timezone"

	// windowsTimeZoneScript prints the Windows zone ID, e.g.
	// "AUS Eastern Standard Time", which windowsZones maps to IANA.
	windowsTimeZoneScript = `(Get-TimeZone).Id`

	// darwinReadlink resolves the /etc/localtime link, whose target ends in
	// ".../zoneinfo/<IANA name>".
	darwinReadlink  = "/usr/bin/readlink"
	darwinLocaltime = "/etc/localtime"
	zoneinfoSegment = "zoneinfo/"
)

// The reasons ResolveTimeZone gives for producing no zone. They travel on the
// check-in as a "timezone:<reason>[:<detail>]" inventory warning and are
// logged by the scheduler, so a blank time zone on the console can be told
// apart from an agent build that predates them.
const (
	TimeZoneNoCollector   = "no_collector"
	TimeZoneUnsupportedOS = "unsupported_os"
	TimeZoneProbeFailed   = "probe_failed"
	TimeZoneTimeout       = "timeout"
	TimeZoneEmptyOutput   = "empty_output"
	TimeZoneUnmapped      = "unmapped"
	TimeZoneNoZoneinfo    = "no_zoneinfo"
)

// timeZoneDetailMax caps the characters of probe text carried in Detail.
const timeZoneDetailMax = 64

// TimeZoneResult is the outcome of one time zone collection. Zone is the IANA
// name, or "" when Reason says why none was produced; Detail carries the
// offending probe text (or goos) for the reasons that have one.
type TimeZoneResult struct {
	Zone, Reason, Detail string
}

// CollectTimeZone returns the device's IANA time zone name, or "" when it
// cannot be worked out: the probe failed, exited non-zero, timed out on clock,
// printed something unusable, or goos is not supported. A failure is never an
// error — the check-in simply carries no time zone.
func CollectTimeZone(runner platform.CommandRunner, clock platform.Clock, goos string) string {
	return ResolveTimeZone(runner, clock, goos).Zone
}

// ResolveTimeZone collects the device's IANA time zone name and, when it
// cannot, reports why in Reason (and Detail).
func ResolveTimeZone(runner platform.CommandRunner, clock platform.Clock, goos string) TimeZoneResult {
	if runner == nil || clock == nil {
		return TimeZoneResult{Reason: TimeZoneNoCollector}
	}
	switch goos {
	case "windows":
		out, reason := runTimeZoneProbe(runner, clock, Probe{
			Name: ProbeTimeZone, Cmd: windowsShell, Args: windowsArgs(windowsTimeZoneScript),
		})
		if reason != "" {
			return TimeZoneResult{Reason: reason}
		}
		return windowsZoneToIANA(out)
	case "darwin":
		out, reason := runTimeZoneProbe(runner, clock, Probe{
			Name: ProbeTimeZone, Cmd: darwinReadlink, Args: []string{darwinLocaltime},
		})
		if reason != "" {
			return TimeZoneResult{Reason: reason}
		}
		return darwinZoneFromLink(out)
	default:
		return TimeZoneResult{Reason: TimeZoneUnsupportedOS, Detail: goos}
	}
}

// runTimeZoneProbe runs the single time zone probe through runProbes so it
// shares the inventory probes' ProbeTimeout and failure handling. It returns
// the probe's stdout, or the reason it produced none: timeout when runProbes
// warned "timezone:timeout", probe_failed for any other warning.
func runTimeZoneProbe(runner platform.CommandRunner, clock platform.Clock, p Probe) (string, string) {
	stdout, warnings := runProbes(runner, clock, []Probe{p})
	if out, ok := stdout[p.Name]; ok {
		return out, ""
	}
	for _, w := range warnings {
		if w == p.Name+":timeout" {
			return "", TimeZoneTimeout
		}
	}
	return "", TimeZoneProbeFailed
}

// windowsZoneToIANA maps the first non-blank line of the cleaned probe output,
// a Windows zone ID, to its IANA name. The ID is looked up exactly first, then
// case-insensitively.
func windowsZoneToIANA(out string) TimeZoneResult {
	lines := splitLines(cleanWindowsOutput(out))
	if len(lines) == 0 {
		return TimeZoneResult{Reason: TimeZoneEmptyOutput}
	}
	id := strings.TrimSpace(lines[0])
	if zone, ok := windowsZones[id]; ok {
		return TimeZoneResult{Zone: zone}
	}
	if zone, ok := windowsZonesFolded()[strings.ToLower(id)]; ok {
		return TimeZoneResult{Zone: zone}
	}
	return TimeZoneResult{Reason: TimeZoneUnmapped, Detail: cutDetail(id)}
}

// cleanWindowsOutput decodes probe stdout that arrived as UTF-16LE (detected
// by a NUL byte), dropping its FF FE byte order mark, and otherwise drops a
// leading UTF-8 byte order mark.
func cleanWindowsOutput(out string) string {
	if strings.IndexByte(out, 0) >= 0 {
		b := []byte(out)
		if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
			b = b[2:]
		}
		units := make([]uint16, 0, len(b)/2)
		for i := 0; i+1 < len(b); i += 2 {
			units = append(units, uint16(b[i])|uint16(b[i+1])<<8)
		}
		return string(utf16.Decode(units))
	}
	return strings.TrimPrefix(out, "\xEF\xBB\xBF")
}

var (
	windowsZonesLowerOnce sync.Once
	windowsZonesLower     map[string]string
)

// windowsZonesFolded returns windowsZones keyed by lower-cased Windows ID,
// built once.
func windowsZonesFolded() map[string]string {
	windowsZonesLowerOnce.Do(func() {
		windowsZonesLower = make(map[string]string, len(windowsZones))
		for id, zone := range windowsZones {
			windowsZonesLower[strings.ToLower(id)] = zone
		}
	})
	return windowsZonesLower
}

// darwinZoneFromLink returns the trimmed text after the last "zoneinfo/" of a
// readlink output, or no_zoneinfo when there is no such segment.
func darwinZoneFromLink(out string) TimeZoneResult {
	link := strings.TrimSpace(out)
	if link == "" {
		return TimeZoneResult{Reason: TimeZoneEmptyOutput}
	}
	i := strings.LastIndex(link, zoneinfoSegment)
	if i < 0 {
		return TimeZoneResult{Reason: TimeZoneNoZoneinfo, Detail: cutDetail(link)}
	}
	zone := strings.TrimSpace(link[i+len(zoneinfoSegment):])
	if zone == "" {
		return TimeZoneResult{Reason: TimeZoneNoZoneinfo, Detail: cutDetail(link)}
	}
	return TimeZoneResult{Zone: zone}
}

// cutDetail keeps the first timeZoneDetailMax characters of s.
func cutDetail(s string) string {
	r := []rune(s)
	if len(r) > timeZoneDetailMax {
		return string(r[:timeZoneDetailMax])
	}
	return s
}
