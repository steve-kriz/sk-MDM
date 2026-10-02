package antivirus

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
)

// The macOS findings source: XProtect Remediator's structured events in the
// unified log. The agent runs as root under launchd, which `log show` needs.
// The file name deliberately avoids a _darwin suffix, which Go would read as a
// build constraint: goos is a parameter and both parsers run on every host.
const (
	// DarwinLogCommand is the unified log tool.
	DarwinLogCommand = "/usr/bin/log"
	// DarwinFindingsWindow is how far back each collection reads. Cycles are
	// far shorter, so consecutive windows overlap and the same event is
	// reported again under the same id, which the backend upserts.
	DarwinFindingsWindow = "24h"
	// DarwinFindingsPredicate selects XProtect Remediator's structured events.
	DarwinFindingsPredicate = `subsystem == "com.apple.XProtectFramework.PluginAPI" AND category == "XPEvent.structured"`
	// DarwinTimestampLayout is how `log show --style ndjson` spells a time.
	DarwinTimestampLayout = "2006-01-02 15:04:05.000000-0700"
	// darwinFindingIDPrefix marks an id derived from an XProtect event.
	darwinFindingIDPrefix = "xprotect-"
	// darwinFindingIDHexLength is how many hex characters of the digest the id keeps.
	darwinFindingIDHexLength = 32
)

// darwinFindingsArgs is the argument list of the findings command.
func darwinFindingsArgs() []string {
	return []string{"show", "--style", "ndjson", "--last", DarwinFindingsWindow, "--predicate", DarwinFindingsPredicate}
}

// parseDarwinFindings reads one ndjson log entry per line. Each entry's
// eventMessage is an XProtect Remediator event; one whose status_code is 0 is a
// clean scan and is skipped, any other is a finding. Findings are returned
// newest first (the reverse of log order), deduplicated by id and capped at
// MaxAntivirusFindings. The second return is false when any line was dropped.
func parseDarwinFindings(stdout string) ([]contract.AntivirusFinding, bool) {
	clean := true
	var inLogOrder []contract.AntivirusFinding
	for _, line := range splitLines(stdout) {
		finding, isFinding, ok := parseDarwinLine(line)
		if !ok {
			clean = false
			continue
		}
		if isFinding {
			inLogOrder = append(inLogOrder, finding)
		}
	}

	seen := make(map[string]bool, len(inLogOrder))
	var findings []contract.AntivirusFinding
	for i := len(inLogOrder) - 1; i >= 0 && len(findings) < MaxAntivirusFindings; i-- {
		finding := inLogOrder[i]
		if seen[finding.FindingID] {
			continue
		}
		seen[finding.FindingID] = true
		findings = append(findings, finding)
	}
	return findings, clean
}

// parseDarwinLine reads one log entry. The second return is false for a clean
// scan; the third is false when the line does not have the fixture's shape.
func parseDarwinLine(line string) (contract.AntivirusFinding, bool, bool) {
	entry, err := decodeObject(line)
	if err != nil {
		return contract.AntivirusFinding{}, false, false
	}
	timestamp, ok := entry["timestamp"].(string)
	if !ok {
		return contract.AntivirusFinding{}, false, false
	}
	message, ok := entry["eventMessage"].(string)
	if !ok {
		return contract.AntivirusFinding{}, false, false
	}
	event, err := decodeObject(message)
	if err != nil {
		return contract.AntivirusFinding{}, false, false
	}
	plugin, _ := event["plugin"].(string)
	if plugin == "" {
		return contract.AntivirusFinding{}, false, false
	}
	statusCode, ok := integerOf(event["status_code"])
	if !ok {
		return contract.AntivirusFinding{}, false, false
	}
	at, err := time.Parse(DarwinTimestampLayout, timestamp)
	if err != nil {
		return contract.AntivirusFinding{}, false, false
	}
	if statusCode == 0 {
		return contract.AntivirusFinding{}, false, true
	}

	status, _ := event["status_message"].(string)
	status = strings.ToLower(status)

	return contract.AntivirusFinding{
		FindingID:  darwinFindingID(timestamp, plugin, statusCode),
		ThreatName: truncateRunes(plugin, MaxThreatNameRunes),
		Severity:   SeverityUnknown,
		DetectedAt: at.UTC().Format(time.RFC3339),
		Resources:  stringList(event["caused_by"]),
		Remediated: strings.Contains(status, "remediated") && !strings.Contains(status, "not remediated"),
	}, true, true
}

// darwinFindingID is "xprotect-" plus the first 32 hex characters of SHA-256
// over "<timestamp>|<plugin>|<status_code>", so the same event read again in an
// overlapping window keeps its id.
func darwinFindingID(timestamp, plugin string, statusCode int64) string {
	sum := sha256.Sum256([]byte(timestamp + "|" + plugin + "|" + strconv.FormatInt(statusCode, 10)))
	return darwinFindingIDPrefix + hex.EncodeToString(sum[:])[:darwinFindingIDHexLength]
}
