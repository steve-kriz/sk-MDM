package antivirus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
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
// exit 0 rather than an error. The severity, threat status, cleaning action
// and category are mapped in Go. categoryId and active come from the
// Get-MpThreat record and are $null (JSON null) when that record is gone, so a
// missing record is never reported as category 0 or as not active.
const WindowsFindingsScript = `Get-MpThreatDetection -ErrorAction SilentlyContinue | ` +
	`Sort-Object InitialDetectionTime -Descending | Select-Object -First 20 | ForEach-Object { ` +
	`$t = Get-MpThreat -ThreatID $_.ThreatID -ErrorAction SilentlyContinue; ` +
	`[pscustomobject]@{detectionId=[string]$_.DetectionID; threatName=[string]$t.ThreatName; ` +
	`severityId=[int]$t.SeverityID; ` +
	`detectedAt=$_.InitialDetectionTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); ` +
	`resources=@($_.Resources); actionSuccess=[bool]$_.ActionSuccess; ` +
	`categoryId=$(if ($null -ne $t) { [int]$t.CategoryID } else { $null }); ` +
	`statusId=[int]$_.ThreatStatusID; actionId=[int]$_.CleaningActionID; ` +
	`active=$(if ($null -ne $t) { [bool]$t.IsActive } else { $null }); ` +
	`lastStatusChangeAt=$(if ($null -ne $_.LastThreatStatusChangeTime) { $_.LastThreatStatusChangeTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }); ` +
	`remediatedAt=$(if ($null -ne $_.RemediationTime) { $_.RemediationTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }); ` +
	`processName=[string]$_.ProcessName; user=[string]$_.DomainUser} | ConvertTo-Json -Compress -Depth 3 }`

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

		finding := contract.AntivirusFinding{
			FindingID:  id,
			ThreatName: truncateRunes(threat, MaxThreatNameRunes),
			Severity:   severityOf(fields["severityId"]),
			DetectedAt: at.UTC().Format(time.RFC3339),
			Resources:  stringList(fields["resources"]),
			Remediated: remediated,
		}
		applyThreatStatus(&finding, fields)
		findings = append(findings, finding)
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

// Bounds on the optional finding fields, in runes.
const (
	// MaxProcessNameRunes is the longest process name kept.
	MaxProcessNameRunes = 260
	// MaxFindingUserRunes is the longest user kept.
	MaxFindingUserRunes = 256
)

// findingStatuses maps Defender's ThreatStatusID to the contract's status.
var findingStatuses = map[int64]string{
	0:   "unknown",
	1:   "detected",
	2:   "cleaned",
	3:   "quarantined",
	4:   "removed",
	5:   "allowed",
	6:   "blocked",
	102: "quarantine_failed",
	103: "remove_failed",
	104: "allow_failed",
	105: "abandoned",
	107: "block_failed",
}

// findingActions maps Defender's CleaningActionID to the contract's action.
var findingActions = map[int64]string{
	0:  "unknown",
	1:  "clean",
	2:  "quarantine",
	3:  "remove",
	6:  "allow",
	8:  "user_defined",
	9:  "no_action",
	10: "block",
}

// findingCategories maps Defender's threat CategoryID to a readable category.
var findingCategories = map[int64]string{
	1:  "Adware",
	2:  "Spyware",
	3:  "Password stealer",
	4:  "Trojan downloader",
	5:  "Worm",
	6:  "Backdoor",
	7:  "Remote access trojan",
	8:  "Trojan",
	9:  "Email flooder",
	10: "Keylogger",
	11: "Dialer",
	12: "Monitoring software",
	13: "Browser modifier",
	14: "Cookie",
	15: "Browser plugin",
	16: "AOL exploit",
	17: "Nuker",
	18: "Security disabler",
	19: "Joke program",
	20: "Hostile ActiveX control",
	21: "Software bundler",
	22: "Stealth notifier",
	23: "Settings modifier",
	24: "Toolbar",
	25: "Remote control software",
	26: "Trojan FTP",
	27: "Potentially unwanted software",
	28: "ICQ exploit",
	29: "Trojan telnet",
	30: "Exploit",
	31: "File-sharing program",
	32: "Malware creation tool",
	33: "Remote control software",
	34: "Tool",
	36: "Trojan denial of service",
	37: "Trojan dropper",
	38: "Trojan mass mailer",
	39: "Trojan monitoring software",
	40: "Trojan proxy server",
	42: "Virus",
	43: "Known",
	44: "Unknown",
	45: "SPP",
	46: "Behavior",
	47: "Vulnerability",
	48: "Policy",
	49: "Enterprise unwanted software",
	50: "Ransomware",
	51: "ASR rule",
}

// applyThreatStatus copies the optional threat-status keys of one Windows
// findings line onto finding. A key that is absent or null leaves its field
// unset, so a line in the old output shape yields only the six original
// fields. A present statusId or actionId that is unmapped or not an integer is
// "unknown"; a categoryId that is not a non-zero integer is omitted, and an
// unmapped one is "Category <n>". active is set only from a JSON boolean.
func applyThreatStatus(finding *contract.AntivirusFinding, fields map[string]any) {
	if value, ok := fields["statusId"]; ok && value != nil {
		finding.Status = mappedOrUnknown(findingStatuses, value)
	}
	if value, ok := fields["actionId"]; ok && value != nil {
		finding.Action = mappedOrUnknown(findingActions, value)
	}
	if n, ok := integerOf(fields["categoryId"]); ok && n != 0 {
		if label, known := findingCategories[n]; known {
			finding.Category = label
		} else {
			finding.Category = "Category " + strconv.FormatInt(n, 10)
		}
	}
	if active, ok := fields["active"].(bool); ok {
		finding.Active = &active
	}
	finding.LastStatusChangeAt = rfc3339UTC(fields["lastStatusChangeAt"])
	finding.RemediatedAt = rfc3339UTC(fields["remediatedAt"])
	if name, ok := fields["processName"].(string); ok {
		finding.ProcessName = truncateRunes(name, MaxProcessNameRunes)
	}
	if user, ok := fields["user"].(string); ok {
		finding.User = truncateRunes(user, MaxFindingUserRunes)
	}
}

// mappedOrUnknown looks an integer id up in labels; anything unmapped or not
// an integer is "unknown".
func mappedOrUnknown(labels map[int64]string, value any) string {
	n, ok := integerOf(value)
	if !ok {
		return "unknown"
	}
	if label, known := labels[n]; known {
		return label
	}
	return "unknown"
}

// rfc3339UTC normalises an RFC3339 string to UTC with whole seconds; anything
// else is "" (omitted).
func rfc3339UTC(value any) string {
	text, ok := value.(string)
	if !ok {
		return ""
	}
	at, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return ""
	}
	return at.UTC().Format(time.RFC3339)
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
