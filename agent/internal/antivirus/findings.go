package antivirus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// The warnings a findings collection can add to posture.warnings, in the
// posture probes' naming style.
const (
	// WarningFindings means the findings probe could not start or exited
	// non-zero.
	WarningFindings = "antivirusFindings"
	// WarningFindingsTimeout means the probe did not answer within
	// FindingsTimeout.
	WarningFindingsTimeout = "antivirusFindings:timeout"
	// WarningFindingsUnparseable means one or more lines were dropped.
	WarningFindingsUnparseable = "antivirusFindings:unparseable"
)

// The severities a finding may carry.
const (
	SeverityUnknown  = "unknown"
	SeverityLow      = "low"
	SeverityModerate = "moderate"
	SeverityHigh     = "high"
	SeveritySevere   = "severe"
)

// WindowsFindingsScript prints Defender's detections, newest first, one JSON
// object per line. Both cmdlets carry -ErrorAction SilentlyContinue, so a
// Defender service a third-party product has stopped yields empty output and
// exit 0 rather than an error. The severity is mapped in Go.
const WindowsFindingsScript = `Get-MpThreatDetection -ErrorAction SilentlyContinue | ` +
	`Sort-Object InitialDetectionTime -Descending | Select-Object -First 20 | ForEach-Object { ` +
	`$t = Get-MpThreat -ThreatID $_.ThreatID -ErrorAction SilentlyContinue; ` +
	`[pscustomobject]@{detectionId=[string]$_.DetectionID; threatName=[string]$t.ThreatName; ` +
	`severityId=[int]$t.SeverityID; ` +
	`detectedAt=$_.InitialDetectionTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); ` +
	`resources=@($_.Resources); actionSuccess=[bool]$_.ActionSuccess} | ConvertTo-Json -Compress -Depth 3 }`

// errNotObject is what a line that is not exactly one JSON object yields.
var errNotObject = errors.New("not a JSON object")

// CollectFindings returns the threats the device's antivirus detected and the
// warnings to add to posture.warnings. goos selects the source: Defender on
// windows, the XProtect Remediator log on darwin; any other goos collects
// nothing and runs nothing. A probe that fails costs only a warning, and
// empty output is no findings and no warning.
func CollectFindings(runner platform.CommandRunner, clock platform.Clock, goos string) ([]contract.AntivirusFinding, []string) {
	var (
		name  string
		args  []string
		parse func(string) ([]contract.AntivirusFinding, bool)
	)
	switch goos {
	case "windows":
		name, args, parse = windowsShell, windowsArgs(WindowsFindingsScript), parseWindowsFindings
	case "darwin":
		name, args, parse = DarwinLogCommand, darwinFindingsArgs(), parseDarwinFindings
	default:
		return nil, nil
	}

	out, err, timedOut := runBounded(context.Background(), runner, clock, FindingsTimeout, name, args...)
	switch {
	case timedOut:
		return nil, []string{WarningFindingsTimeout}
	case err != nil || out.ExitCode != 0:
		return nil, []string{WarningFindings}
	}
	if strings.TrimSpace(out.Stdout) == "" {
		return nil, nil
	}

	findings, clean := parse(out.Stdout)
	var warnings []string
	if !clean {
		warnings = []string{WarningFindingsUnparseable}
	}
	if len(findings) == 0 {
		findings = nil
	}
	return findings, warnings
}

// parseWindowsFindings reads one JSON object per non-blank line, keeping line
// order and the first MaxAntivirusFindings valid lines. A line that is not an
// object, has no detectionId or has a detectedAt that is not RFC3339 is
// dropped; the second return is false when any line was.
func parseWindowsFindings(stdout string) ([]contract.AntivirusFinding, bool) {
	clean := true
	var findings []contract.AntivirusFinding
	for _, line := range splitLines(stdout) {
		fields, err := decodeObject(line)
		if err != nil {
			clean = false
			continue
		}
		id, _ := fields["detectionId"].(string)
		detectedAt, _ := fields["detectedAt"].(string)
		at, err := time.Parse(time.RFC3339, detectedAt)
		if id == "" || err != nil {
			clean = false
			continue
		}
		threat, _ := fields["threatName"].(string)
		remediated, _ := fields["actionSuccess"].(bool)

		findings = append(findings, contract.AntivirusFinding{
			FindingID:  id,
			ThreatName: truncateRunes(threat, MaxThreatNameRunes),
			Severity:   severityOf(fields["severityId"]),
			DetectedAt: at.UTC().Format(time.RFC3339),
			Resources:  stringList(fields["resources"]),
			Remediated: remediated,
		})
	}
	if len(findings) > MaxAntivirusFindings {
		findings = findings[:MaxAntivirusFindings]
	}
	return findings, clean
}

// severityOf maps Defender's SeverityID: 1 low, 2 moderate, 4 high, 5 severe,
// anything else unknown.
func severityOf(value any) string {
	n, ok := integerOf(value)
	if !ok {
		return SeverityUnknown
	}
	switch n {
	case 1:
		return SeverityLow
	case 2:
		return SeverityModerate
	case 4:
		return SeverityHigh
	case 5:
		return SeveritySevere
	default:
		return SeverityUnknown
	}
}

// integerOf reads a decoded JSON number as an integer. A string, a fraction or
// anything else is not one.
func integerOf(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	n, err := number.Int64()
	if err != nil {
		return 0, false
	}
	return n, true
}

// stringList turns a resources value into the bounded string array the
// contract carries: null or absent becomes [], a single string a one-element
// array, and non-string elements are dropped. At most MaxFindingResources are
// kept, each cut to MaxResourceRunes.
func stringList(value any) []string {
	var items []any
	switch v := value.(type) {
	case string:
		items = []any{v}
	case []any:
		items = v
	}
	list := []string{}
	for _, item := range items {
		if len(list) == MaxFindingResources {
			break
		}
		if s, ok := item.(string); ok {
			list = append(list, truncateRunes(s, MaxResourceRunes))
		}
	}
	return list
}

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

// splitLines splits output into its non-blank lines, dropping the carriage
// return a Windows probe leaves behind. Built on strings rather than bufio so
// a line of any size is handled.
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
