package analytics

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
)

// The macOS probes are sysctl itself for the boot time, whose output is
// already machine-readable, and short shell scripts for the performance
// sample and the crash reports. This file is named without a _darwin suffix
// so it is compiled, and tested against its fixtures, on every OS.
const (
	darwinShell  = "/bin/sh"
	darwinSysctl = "/usr/sbin/sysctl"

	// darwinPerformanceScript samples the processor load (100 minus the idle
	// share of top's second sample), the physical memory in use (active,
	// wired and compressed pages) and the root volume.
	darwinPerformanceScript = `cpu=$(top -l 2 -n 0 -s 1 2>/dev/null | awk '/CPU usage/ {idle=$7} END {sub("%","",idle); if (idle != "") printf "%.2f", 100-idle}'); ` +
		`echo "cpuPercent=$cpu"; ` +
		`echo "memoryTotalBytes=$(sysctl -n hw.memsize 2>/dev/null)"; ` +
		`ps=$(sysctl -n hw.pagesize 2>/dev/null); ` +
		`echo "memoryUsedBytes=$(vm_stat 2>/dev/null | awk -v ps="$ps" '/^Pages active/ {a=$3} /^Pages wired down/ {w=$4} /^Pages occupied by compressor/ {c=$5} END {printf "%.0f", (a+w+c)*ps}')"; ` +
		`df -k / 2>/dev/null | awk 'NR==2 {printf "diskTotalBytes=%.0f\ndiskFreeBytes=%.0f\n", $2*1024, $4*1024}'`

	// darwinNetworkScript prints "adapter=<name> <media>" for each active en*
	// interface, then two netstat -ibdn tables one second apart, each after a
	// "--- sample" line. Loopback, tunnels, bridges and AWDL are not en*.
	darwinNetworkScript = `for i in $(ifconfig -l 2>/dev/null); do case "$i" in en*) ` +
		`if ifconfig "$i" 2>/dev/null | grep -q 'status: active'; then ` +
		`echo "adapter=$i $(ifconfig "$i" 2>/dev/null | awk -F': ' '/media:/ {print $2; exit}')"; fi;; esac; done; ` +
		`echo '--- sample'; netstat -ibdn 2>/dev/null; sleep 1; ` +
		`echo '--- sample'; netstat -ibdn 2>/dev/null; exit 0`

	// darwinCrashesScript prints the JSON header line of every crash report
	// written in the last 30 days, system-wide and per user. A missing
	// directory is skipped, and the script always exits 0.
	darwinCrashesScript = `for d in /Library/Logs/DiagnosticReports /Users/*/Library/Logs/DiagnosticReports; do ` +
		`[ -d "$d" ] || continue; ` +
		`find "$d" -maxdepth 1 -type f -name '*.ips' -mtime -30 2>/dev/null | while IFS= read -r f; do head -n 1 "$f" 2>/dev/null; echo; done; ` +
		`done; exit 0`
)

// darwinIPSTimestampLayout is the layout of the timestamp key of an .ips
// report header.
const darwinIPSTimestampLayout = "2006-01-02 15:04:05.00 -0700"

// bootSecPattern finds the seconds field of kern.boottime, and not the usec
// field that follows it.
var bootSecPattern = regexp.MustCompile(`\bsec\s*=\s*(\d+)`)

// darwinProbes is the probe list for goos "darwin".
func darwinProbes() []Probe {
	return []Probe{
		{Name: ProbeBoot, Cmd: darwinSysctl, Args: []string{"-n", "kern.boottime"}},
		{Name: ProbePerformance, Cmd: darwinShell, Args: []string{"-c", darwinPerformanceScript}},
		{Name: ProbeCrashes, Cmd: darwinShell, Args: []string{"-c", darwinCrashesScript}},
	}
}

// fillDarwinBoot parses kern.boottime into b. macOS records no boot
// duration, so it stays null without a warning.
func fillDarwinBoot(b *contract.AnalyticsBoot, out string, now time.Time) []string {
	m := bootSecPattern.FindStringSubmatch(out)
	if m == nil {
		return []string{unparseable(ProbeBoot)}
	}
	sec, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || !fillBootTime(b, time.Unix(sec, 0), now) {
		return []string{unparseable(ProbeBoot)}
	}
	return nil
}

// parseDarwinCrashes reads the .ips header lines. clean is false when any
// line was dropped as unparseable; a report whose bug_type is not a crash
// (309 or 109) is dropped silently.
func parseDarwinCrashes(out string) ([]crashEntry, bool) {
	clean := true
	var entries []crashEntry
	for _, line := range splitLines(out) {
		fields, err := decodeObject(line)
		if err != nil {
			clean = false
			continue
		}

		switch bugType(fields["bug_type"]) {
		case "309", "109":
		default:
			continue
		}

		stamp, _ := fields["timestamp"].(string)
		at, ok := parseIPSTimestamp(stamp)
		if !ok {
			clean = false
			continue
		}
		name, _ := fields["app_name"].(string)
		version, _ := fields["app_version"].(string)
		entry, ok := newCrash(name, version, at, KindCrash)
		if !ok {
			clean = false
			continue
		}
		entries = append(entries, entry)
	}
	return entries, clean
}

// bugType reads bug_type, which reports write as a string but which is
// accepted as a number too.
func bugType(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case json.Number:
		return t.String()
	default:
		return ""
	}
}

// parseIPSTimestamp reads an .ips header timestamp. The documented layout
// carries two fractional digits; any other number of them is accepted too.
func parseIPSTimestamp(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{darwinIPSTimestampLayout, "2006-01-02 15:04:05 -0700"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
