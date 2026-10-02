package posture

import (
	"strings"

	"github.com/officehq/sk-mdm/agent/internal/contract"
)

// The macOS probes are the system tools themselves where their output is
// already machine-readable, and a short shell script that prints "key=value"
// lines where several tools have to be combined.
const (
	darwinShell          = "/bin/sh"
	darwinFdesetup       = "/usr/bin/fdesetup"
	darwinSocketFilterFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"
	darwinDSCL           = "/usr/bin/dscl"

	// darwinAntivirusScript reports on XProtect, the malware protection built
	// into macOS: its bundle version stands in for "installed and on" and the
	// age of its definition bundle for the definition age.
	darwinAntivirusScript = `xprotect=/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info; ` +
		`version=$(defaults read "$xprotect" CFBundleShortVersionString 2>/dev/null); ` +
		`modified=$(stat -f %m "$xprotect.plist" 2>/dev/null); ` +
		`echo "name=XProtect"; ` +
		`if [ -n "$version" ]; then echo "enabled=true"; else echo "enabled=false"; fi; ` +
		`if [ -n "$modified" ]; then echo "definitionsAgeDays=$(( ( $(date +%s) - modified ) / 86400 ))"; else echo "definitionsAgeDays=0"; fi`

	// darwinOSUpdateScript counts the updates softwareupdate offers and reads
	// the last successful check out of the SoftwareUpdate preferences.
	darwinOSUpdateScript = `list=$(softwareupdate -l 2>&1); ` +
		`echo "lastCheckedAt=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate LastSuccessfulDate 2>/dev/null)"; ` +
		`echo "pendingCount=$(printf '%s\n' "$list" | grep -c '^[*] Label:')"; ` +
		`if printf '%s\n' "$list" | grep -q 'Action: restart'; then echo "rebootRequired=true"; else echo "rebootRequired=false"; fi`
)

// darwinProbes is the probe list for goos "darwin".
func darwinProbes() []Probe {
	return []Probe{
		{Name: ProbeDiskEncryption, Cmd: darwinFdesetup, Args: []string{"status"}},
		{Name: ProbeFirewall, Cmd: darwinSocketFilterFW, Args: []string{"--getglobalstate"}},
		{Name: ProbeAntivirus, Cmd: darwinShell, Args: []string{"-c", darwinAntivirusScript}},
		{Name: ProbeOSUpdate, Cmd: darwinShell, Args: []string{"-c", darwinOSUpdateScript}},
		{Name: ProbeLocalAdmins, Cmd: darwinDSCL, Args: []string{".", "-read", "/Groups/admin", "GroupMembership"}},
	}
}

// fillDarwin parses the macOS probe output into p and returns one
// "<probe>:unparseable" warning for every probe that answered with something
// it could not understand. A probe missing from stdout failed or timed out and
// was already warned about.
func fillDarwin(p *contract.Posture, stdout map[string]string) []string {
	var warnings []string

	if out, ok := stdout[ProbeDiskEncryption]; ok {
		if enabled, parsed := parseFileVault(out); parsed {
			p.DiskEncryption.Enabled = enabled
			p.DiskEncryption.Method = MethodFileVault
		} else {
			warnings = append(warnings, unparseable(ProbeDiskEncryption))
		}
	}

	if out, ok := stdout[ProbeFirewall]; ok {
		if enabled, parsed := parseDarwinFirewall(out); parsed {
			p.Firewall.Enabled = enabled
		} else {
			warnings = append(warnings, unparseable(ProbeFirewall))
		}
	}

	if out, ok := stdout[ProbeAntivirus]; ok {
		if !fillAntivirus(&p.Antivirus, out) {
			warnings = append(warnings, unparseable(ProbeAntivirus))
		}
	}

	if out, ok := stdout[ProbeOSUpdate]; ok {
		if !fillOSUpdate(&p.OSUpdate, out) {
			warnings = append(warnings, unparseable(ProbeOSUpdate))
		}
	}

	if out, ok := stdout[ProbeLocalAdmins]; ok {
		if admins, parsed := parseGroupMembership(out); parsed {
			p.LocalAdmins = admins
		} else {
			warnings = append(warnings, unparseable(ProbeLocalAdmins))
		}
	}

	return warnings
}

// parseFileVault reads "FileVault is On." or "FileVault is Off." Anything
// else, including the same sentence in another language, is unparseable
// rather than quietly reported as off.
func parseFileVault(out string) (bool, bool) {
	lower := strings.ToLower(out)
	switch {
	case strings.Contains(lower, "filevault is on"):
		return true, true
	case strings.Contains(lower, "filevault is off"):
		return false, true
	default:
		return false, false
	}
}

// parseDarwinFirewall reads "Firewall is enabled. (State = 1)". The numeric
// state is preferred because it survives a localised sentence; the words are
// the fallback for the builds that print no state.
func parseDarwinFirewall(out string) (bool, bool) {
	lower := strings.ToLower(out)

	if i := strings.Index(lower, "state = "); i >= 0 {
		rest := lower[i+len("state = "):]
		digits := rest
		for j, r := range rest {
			if r < '0' || r > '9' {
				digits = rest[:j]
				break
			}
		}
		if digits != "" {
			return parseInt(digits) != 0, true
		}
	}

	switch {
	case strings.Contains(lower, "disabled"):
		return false, true
	case strings.Contains(lower, "enabled"):
		return true, true
	default:
		return false, false
	}
}

// parseGroupMembership reads dscl's "GroupMembership: root alice bob" line.
func parseGroupMembership(out string) ([]string, bool) {
	for _, line := range splitLines(out) {
		label, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(label), "GroupMembership") {
			continue
		}
		members := strings.Fields(value)
		if len(members) == 0 {
			return nil, false
		}
		return members, true
	}
	return nil, false
}
