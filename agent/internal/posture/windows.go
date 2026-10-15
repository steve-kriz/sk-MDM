package posture

import (
	"strconv"
	"strings"

	"github.com/officehq/sk-mdm/agent/internal/contract"
)

// The Windows probes are PowerShell one-liners that normalise their own output
// to "key=value" lines, or to one account per line for the administrators.
// Doing the shaping in the script keeps the Go parser free of any dependency
// on the display language of the underlying tool.
const (
	windowsShell = "powershell.exe"

	windowsDiskEncryptionScript = `$v = Get-BitLockerVolume -MountPoint $env:SystemDrive; ` +
		`"protectionStatus=$($v.ProtectionStatus)"; "volumeStatus=$($v.VolumeStatus)"`

	windowsFirewallScript = `Get-NetFirewallProfile | ForEach-Object { "$($_.Name)=$($_.Enabled)" }`

	// The antivirus probe tolerates a Defender service a third-party product
	// has stopped (Get-MpComputerStatus then errors, and the casts turn the
	// missing values into False and 0) and a host without Security Center
	// (Windows Server), which simply prints no product lines.
	windowsAntivirusScript = `$s = Get-MpComputerStatus -ErrorAction SilentlyContinue; "name=Microsoft Defender"; ` +
		`"enabled=$([bool]$s.AntivirusEnabled -and [bool]$s.RealTimeProtectionEnabled)"; "definitionsAgeDays=$([int]$s.AntivirusSignatureAge)"; ` +
		`Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | ` +
		`ForEach-Object { "product=$($_.productState)|$($_.displayName)" }`

	windowsOSUpdateScript = `$au = New-Object -ComObject Microsoft.Update.AutoUpdate; ` +
		`$searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); ` +
		`"lastCheckedAt=$($au.Results.LastSearchSuccessDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"; ` +
		`"pendingCount=$($searcher.Search('IsInstalled=0 and IsHidden=0').Updates.Count)"; ` +
		`"rebootRequired=$((New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired)"`

	windowsLocalAdminsScript = `Get-LocalGroupMember -Group Administrators | ForEach-Object { $_.Name }`
)

// windowsProbes is the probe list for goos "windows".
func windowsProbes() []Probe {
	return []Probe{
		{Name: ProbeDiskEncryption, Cmd: windowsShell, Args: windowsArgs(windowsDiskEncryptionScript)},
		{Name: ProbeFirewall, Cmd: windowsShell, Args: windowsArgs(windowsFirewallScript)},
		{Name: ProbeAntivirus, Cmd: windowsShell, Args: windowsArgs(windowsAntivirusScript)},
		{Name: ProbeOSUpdate, Cmd: windowsShell, Args: windowsArgs(windowsOSUpdateScript)},
		{Name: ProbeLocalAdmins, Cmd: windowsShell, Args: windowsArgs(windowsLocalAdminsScript)},
	}
}

func windowsArgs(script string) []string {
	return []string{"-NoProfile", "-NonInteractive", "-Command", script}
}

// fillWindows parses the Windows probe output into p and returns one
// "<probe>:unparseable" warning for every probe that answered with something
// it could not understand. A probe missing from stdout failed or timed out and
// was already warned about.
func fillWindows(p *contract.Posture, stdout map[string]string) []string {
	var warnings []string

	if out, ok := stdout[ProbeDiskEncryption]; ok {
		if enabled, parsed := parseBitLocker(out); parsed {
			p.DiskEncryption.Enabled = enabled
			p.DiskEncryption.Method = MethodBitLocker
		} else {
			warnings = append(warnings, unparseable(ProbeDiskEncryption))
		}
	}

	if out, ok := stdout[ProbeFirewall]; ok {
		if enabled, parsed := parseWindowsFirewall(out); parsed {
			p.Firewall.Enabled = enabled
		} else {
			warnings = append(warnings, unparseable(ProbeFirewall))
		}
	}

	if out, ok := stdout[ProbeAntivirus]; ok {
		if !fillAntivirus(&p.Antivirus, out) {
			warnings = append(warnings, unparseable(ProbeAntivirus))
		} else {
			applySecurityCenterProducts(&p.Antivirus, out)
		}
	}

	if out, ok := stdout[ProbeOSUpdate]; ok {
		if !fillOSUpdate(&p.OSUpdate, out) {
			warnings = append(warnings, unparseable(ProbeOSUpdate))
		}
	}

	if out, ok := stdout[ProbeLocalAdmins]; ok {
		if admins, parsed := parseAccountList(out); parsed {
			p.LocalAdmins = admins
		} else {
			warnings = append(warnings, unparseable(ProbeLocalAdmins))
		}
	}

	return warnings
}

// parseBitLocker reads the protection status of the system volume. Encryption
// is on only when BitLocker reports protection as on, which is what the
// backend means by diskEncryption.enabled.
func parseBitLocker(out string) (bool, bool) {
	status, ok := parseKeyValues(out)["protectionStatus"]
	if !ok {
		return false, false
	}
	return parseBool(status)
}

// parseWindowsFirewall reads one "profile=state" line per firewall profile.
// The firewall counts as enabled only when every profile the host reported is
// enabled, so a machine with the public profile switched off is not clean.
func parseWindowsFirewall(out string) (bool, bool) {
	profiles := parseKeyValues(out)
	if len(profiles) == 0 {
		return false, false
	}

	enabled := true
	parsed := 0
	for _, state := range profiles {
		on, ok := parseBool(state)
		if !ok {
			continue
		}
		parsed++
		enabled = enabled && on
	}
	if parsed == 0 {
		return false, false
	}
	return enabled, true
}

// parseAccountList reads one account name per line, as the local
// administrators probes print them.
func parseAccountList(out string) ([]string, bool) {
	lines := splitLines(out)
	accounts := make([]string, 0, len(lines))
	for _, line := range lines {
		if name := strings.TrimSpace(line); name != "" {
			accounts = append(accounts, name)
		}
	}
	if len(accounts) == 0 {
		return nil, false
	}
	return accounts, true
}

// Security Center productState bits. The scanner-state nibble is on (0x1000),
// off (0x0000), snoozed (0x2000) or expired (0x3000); only on counts as active.
const (
	productScannerStateMask = 0xF000
	productScannerStateOn   = 0x1000
)

// applySecurityCenterProducts reads the "product=<productState>|<displayName>"
// lines the antivirus probe prints for every product Windows Security Center
// lists. When Defender itself reports off but another product is active,
// antivirus counts as enabled and is named after the first active product.
// A line with a non-integer state, no "|" or an empty display name is ignored.
func applySecurityCenterProducts(av *contract.Antivirus, out string) {
	if av.Enabled {
		return
	}
	for _, line := range splitLines(out) {
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "product" {
			continue
		}
		stateText, name, ok := strings.Cut(value, "|")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		state, err := strconv.ParseInt(strings.TrimSpace(stateText), 10, 64)
		if err != nil {
			continue
		}
		if state&productScannerStateMask == productScannerStateOn {
			av.Enabled = true
			av.Name = name
			return
		}
	}
}
