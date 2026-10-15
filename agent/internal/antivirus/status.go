package antivirus

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// The warnings a status collection can add to posture.warnings, in the
// posture probes' naming style. Whenever one is returned no block is.
const (
	// WarningStatus means the status probe could not start or exited non-zero.
	WarningStatus = "antivirusStatus"
	// WarningStatusTimeout means the probe did not answer within StatusTimeout.
	WarningStatusTimeout = "antivirusStatus:timeout"
	// WarningStatusUnparseable means the probe's output could not be read.
	WarningStatusUnparseable = "antivirusStatus:unparseable"
)

// The product names a status block carries.
const (
	// ProductDefender is the Windows product name.
	ProductDefender = "Microsoft Defender"
	// ProductXProtect is the macOS product name.
	ProductXProtect = "XProtect"
)

// Bounds on what one status block carries.
const (
	// MaxStatusOutputBytes is the most stdout decoded; more is unparseable.
	MaxStatusOutputBytes = 65536
	// MaxStatusStringRunes is the longest runningMode or version kept.
	MaxStatusStringRunes = 64
	// MaxProductNameRunes is the longest Security Center product name kept.
	MaxProductNameRunes = 128
	// MaxSecurityCenterProducts is the most Security Center products kept.
	MaxSecurityCenterProducts = 10
	// MaxStatusAgeDays is the largest age in days kept; Defender's
	// 65535 / 4294967295 "never" sentinels are above it.
	MaxStatusAgeDays = 36500
	// MaxComputerState is the largest computer state kept.
	MaxComputerState = 65535
)

// defenderStatusProperties is the Get-MpComputerStatus property list the
// Windows status script selects, emitted verbatim inside "status".
const defenderStatusProperties = `AMRunningMode, AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, ` +
	`BehaviorMonitorEnabled, IoavProtectionEnabled, OnAccessProtectionEnabled, RealTimeProtectionEnabled, ` +
	`NISEnabled, IsTamperProtected, AMEngineVersion, AMProductVersion, AMServiceVersion, NISEngineVersion, ` +
	`AntivirusSignatureVersion, AntispywareSignatureVersion, NISSignatureVersion, ` +
	`AntivirusSignatureLastUpdated, AntivirusSignatureAge, AntispywareSignatureLastUpdated, AntispywareSignatureAge, ` +
	`NISSignatureLastUpdated, NISSignatureAge, DefenderSignaturesOutOfDate, ` +
	`QuickScanStartTime, QuickScanEndTime, QuickScanAge, QuickScanOverdue, ` +
	`FullScanStartTime, FullScanEndTime, FullScanAge, FullScanOverdue, FullScanRequired, ` +
	`ComputerState, RebootRequired`

// WindowsStatusScript prints one JSON object: whether Defender answered, its
// computer status and the first 10 antivirus products Windows Security Center
// lists. It only reads. Both sources carry -ErrorAction SilentlyContinue, so a
// stopped Defender service yields defenderAvailable false and a host without
// SecurityCenter2 (Windows Server) yields no products, not an error.
const WindowsStatusScript = `$s = Get-MpComputerStatus -ErrorAction SilentlyContinue; ` +
	`$p = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | ` +
	`Select-Object -First 10 | ForEach-Object { [pscustomobject]@{name=[string]$_.displayName; productState=[long]$_.productState} }); ` +
	`$d = if ($null -ne $s) { $s | Select-Object ` + defenderStatusProperties + ` } else { $null }; ` +
	`[pscustomobject]@{defenderAvailable=($null -ne $s); status=$d; products=@($p)} | ConvertTo-Json -Compress -Depth 4`

// The macOS XProtect sources.
const (
	darwinShell                  = "/bin/sh"
	darwinXProtectInfo           = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info"
	darwinXProtectRemediatorInfo = "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info"
)

// DarwinStatusScript prints three key=value lines: the XProtect definitions
// version, the definitions' Info.plist modification time in epoch seconds and
// the XProtect Remediator version. An unavailable value prints empty.
const DarwinStatusScript = `echo "definitionsVersion=$(defaults read ` + darwinXProtectInfo + ` CFBundleShortVersionString 2>/dev/null)"; ` +
	`echo "definitionsModified=$(stat -f %m ` + darwinXProtectInfo + `.plist 2>/dev/null)"; ` +
	`echo "remediatorVersion=$(defaults read ` + darwinXProtectRemediatorInfo + ` CFBundleShortVersionString 2>/dev/null)"`

// CollectStatus returns the device antivirus's full status and the warnings
// to add to posture.warnings. goos selects the source: Microsoft Defender and
// Windows Security Center on windows, XProtect on darwin; any other goos
// collects nothing and runs nothing. A probe that fails costs only a warning
// and returns no block.
func CollectStatus(runner platform.CommandRunner, clock platform.Clock, goos string) (*contract.AntivirusStatus, []string) {
	var (
		name  string
		args  []string
		parse func(string) (*contract.AntivirusStatus, bool)
	)
	switch goos {
	case "windows":
		name, args, parse = windowsShell, windowsArgs(WindowsStatusScript), parseWindowsStatus
	case "darwin":
		name, args = darwinShell, []string{"-c", DarwinStatusScript}
		parse = func(stdout string) (*contract.AntivirusStatus, bool) {
			return parseDarwinStatus(stdout, clock.Now())
		}
	default:
		return nil, nil
	}

	out, err, timedOut := runBounded(context.Background(), runner, clock, StatusTimeout, name, args...)
	switch {
	case timedOut:
		return nil, []string{WarningStatusTimeout}
	case err != nil || out.ExitCode != 0:
		return nil, []string{WarningStatus}
	}
	if len(out.Stdout) > MaxStatusOutputBytes {
		return nil, []string{WarningStatusUnparseable}
	}
	status, ok := parse(out.Stdout)
	if !ok {
		return nil, []string{WarningStatusUnparseable}
	}
	return status, nil
}

// parseWindowsStatus reads the Windows status script's single JSON object. The
// second return is false when stdout is not exactly one object. A field with
// the wrong type becomes null without making the output unparseable.
func parseWindowsStatus(stdout string) (*contract.AntivirusStatus, bool) {
	fields, err := decodeObject(stdout)
	if err != nil {
		return nil, false
	}
	available, _ := fields["defenderAvailable"].(bool)
	status := &contract.AntivirusStatus{
		Product:                ProductDefender,
		DefenderAvailable:      available,
		SecurityCenterProducts: securityCenterProducts(fields["products"]),
	}
	if !available {
		return status, true
	}
	s, _ := fields["status"].(map[string]any)
	if s == nil {
		return status, true
	}

	status.RunningMode = statusString(s["AMRunningMode"])
	status.Protection = contract.AntivirusProtection{
		AMServiceEnabled:          boolPtr(s["AMServiceEnabled"]),
		AntispywareEnabled:        boolPtr(s["AntispywareEnabled"]),
		AntivirusEnabled:          boolPtr(s["AntivirusEnabled"]),
		BehaviorMonitorEnabled:    boolPtr(s["BehaviorMonitorEnabled"]),
		IoavProtectionEnabled:     boolPtr(s["IoavProtectionEnabled"]),
		OnAccessProtectionEnabled: boolPtr(s["OnAccessProtectionEnabled"]),
		RealTimeProtectionEnabled: boolPtr(s["RealTimeProtectionEnabled"]),
		NISEnabled:                boolPtr(s["NISEnabled"]),
		TamperProtected:           boolPtr(s["IsTamperProtected"]),
	}
	status.Versions = contract.AntivirusVersions{
		Engine:               statusString(s["AMEngineVersion"]),
		Product:              statusString(s["AMProductVersion"]),
		Service:              statusString(s["AMServiceVersion"]),
		NISEngine:            statusString(s["NISEngineVersion"]),
		AntivirusSignature:   statusString(s["AntivirusSignatureVersion"]),
		AntispywareSignature: statusString(s["AntispywareSignatureVersion"]),
		NISSignature:         statusString(s["NISSignatureVersion"]),
	}
	status.Signatures = contract.AntivirusSignatures{
		AntivirusLastUpdatedAt:   parseStatusDate(s["AntivirusSignatureLastUpdated"]),
		AntivirusAgeDays:         boundedInt(s["AntivirusSignatureAge"], MaxStatusAgeDays),
		AntispywareLastUpdatedAt: parseStatusDate(s["AntispywareSignatureLastUpdated"]),
		AntispywareAgeDays:       boundedInt(s["AntispywareSignatureAge"], MaxStatusAgeDays),
		NISLastUpdatedAt:         parseStatusDate(s["NISSignatureLastUpdated"]),
		NISAgeDays:               boundedInt(s["NISSignatureAge"], MaxStatusAgeDays),
		OutOfDate:                boolPtr(s["DefenderSignaturesOutOfDate"]),
	}
	status.Scans = contract.AntivirusScans{
		QuickStartedAt: parseStatusDate(s["QuickScanStartTime"]),
		QuickEndedAt:   parseStatusDate(s["QuickScanEndTime"]),
		QuickAgeDays:   boundedInt(s["QuickScanAge"], MaxStatusAgeDays),
		QuickOverdue:   boolPtr(s["QuickScanOverdue"]),
		FullStartedAt:  parseStatusDate(s["FullScanStartTime"]),
		FullEndedAt:    parseStatusDate(s["FullScanEndTime"]),
		FullAgeDays:    boundedInt(s["FullScanAge"], MaxStatusAgeDays),
		FullOverdue:    boolPtr(s["FullScanOverdue"]),
		FullRequired:   boolPtr(s["FullScanRequired"]),
	}
	status.ComputerState = boundedInt(s["ComputerState"], MaxComputerState)
	status.RebootRequired = boolPtr(s["RebootRequired"])
	return status, true
}

// parseDarwinStatus reads the macOS status script's key=value lines. The
// second return is false when none of the three keys has a non-empty value.
func parseDarwinStatus(stdout string, now time.Time) (*contract.AntivirusStatus, bool) {
	values := map[string]string{}
	for _, line := range splitLines(stdout) {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	definitions := values["definitionsVersion"]
	modified := values["definitionsModified"]
	remediator := values["remediatorVersion"]
	if definitions == "" && modified == "" && remediator == "" {
		return nil, false
	}

	status := &contract.AntivirusStatus{
		Product:                ProductXProtect,
		DefenderAvailable:      false,
		SecurityCenterProducts: []contract.SecurityCenterProduct{},
	}
	status.Versions.XProtectDefinitions = statusString(definitions)
	status.Versions.XProtectRemediator = statusString(remediator)
	if epoch, err := strconv.ParseInt(modified, 10, 64); err == nil && epoch > 0 {
		at := time.Unix(epoch, 0).UTC()
		status.Signatures.AntivirusLastUpdatedAt = formatStatusTime(at)
		if elapsed := now.Unix() - epoch; elapsed >= 0 {
			days := int(elapsed / 86400)
			if days <= MaxStatusAgeDays {
				status.Signatures.AntivirusAgeDays = &days
			}
		}
	}
	return status, true
}

// psDatePattern matches PowerShell 5.1's "/Date(<ms>)/" and
// "/Date(<ms><+|-><hhmm>)/" DateTime serialisation after JSON decoding.
var psDatePattern = regexp.MustCompile(`^/Date\((-?\d+)(?:[+-]\d{4})?\)/$`)

// parseStatusDate normalises a Defender date to RFC3339 UTC with whole
// seconds. It accepts an RFC3339 string, PowerShell 5.1's "/Date(<ms>)/" form
// (the offset is ignored; <ms> is UTC epoch milliseconds) and an object whose
// "value" is either. Anything else, <ms> of 0 or less and a year of 1601 or
// earlier (Defender's "never") is null.
func parseStatusDate(value any) *string {
	if object, ok := value.(map[string]any); ok {
		value = object["value"]
	}
	text, ok := value.(string)
	if !ok || text == "" {
		return nil
	}
	var at time.Time
	if match := psDatePattern.FindStringSubmatch(text); match != nil {
		ms, err := strconv.ParseInt(match[1], 10, 64)
		if err != nil || ms <= 0 {
			return nil
		}
		at = time.UnixMilli(ms)
	} else {
		parsed, err := time.Parse(time.RFC3339Nano, text)
		if err != nil {
			return nil
		}
		at = parsed
	}
	at = at.UTC()
	if at.Year() <= 1601 {
		return nil
	}
	return formatStatusTime(at)
}

// formatStatusTime spells at as yyyy-MM-ddTHH:mm:ssZ, fractions truncated.
func formatStatusTime(at time.Time) *string {
	text := at.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
	return &text
}

// boundedInt keeps a JSON integer from 0 to max; anything else is null.
func boundedInt(value any, max int64) *int {
	n, ok := integerOf(value)
	if !ok || n < 0 || n > max {
		return nil
	}
	v := int(n)
	return &v
}

// boolPtr keeps a JSON boolean; anything else is null.
func boolPtr(value any) *bool {
	b, ok := value.(bool)
	if !ok {
		return nil
	}
	return &b
}

// statusString keeps a non-empty string cut to MaxStatusStringRunes; anything
// else is null.
func statusString(value any) *string {
	text, ok := value.(string)
	if !ok || text == "" {
		return nil
	}
	text = truncateRunes(text, MaxStatusStringRunes)
	return &text
}

// The Security Center productState nibbles, the same masks
// agent/internal/posture reads.
const (
	productStateScannerMask     = 0xF000
	productStateDefinitionsMask = 0x00F0
)

// securityCenterProducts maps the products value: absent or null is [], a
// single object a one-element list. Entries without a non-empty string name
// are dropped and at most MaxSecurityCenterProducts are kept.
func securityCenterProducts(value any) []contract.SecurityCenterProduct {
	var items []any
	switch v := value.(type) {
	case map[string]any:
		items = []any{v}
	case []any:
		items = v
	}
	products := []contract.SecurityCenterProduct{}
	for _, item := range items {
		if len(products) == MaxSecurityCenterProducts {
			break
		}
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := entry["name"].(string)
		if name == "" {
			continue
		}
		product := contract.SecurityCenterProduct{
			Name:  truncateRunes(name, MaxProductNameRunes),
			State: "unknown",
		}
		if state, ok := integerOf(entry["productState"]); ok {
			switch state & productStateScannerMask {
			case 0x1000:
				product.State = "on"
			case 0x0000:
				product.State = "off"
			case 0x2000:
				product.State = "snoozed"
			case 0x3000:
				product.State = "expired"
			}
			switch state & productStateDefinitionsMask {
			case 0x00:
				upToDate := true
				product.DefinitionsUpToDate = &upToDate
			case 0x10:
				upToDate := false
				product.DefinitionsUpToDate = &upToDate
			}
		}
		products = append(products, product)
	}
	return products
}
