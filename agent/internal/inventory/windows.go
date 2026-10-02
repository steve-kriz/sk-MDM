package inventory

import (
	"strings"

	"github.com/officehq/sk-mdm/agent/internal/contract"
)

// The Windows probes are PowerShell one-liners that normalise their own output
// to "key=value" lines, or to tab-separated records for the software list.
// Doing the shaping in the script keeps the Go parser free of any dependency
// on the display language or the column widths of the underlying tool.
const (
	windowsShell = "powershell.exe"

	windowsHardwareScript = `$cs = Get-CimInstance Win32_ComputerSystem; ` +
		`$bios = Get-CimInstance Win32_BIOS; ` +
		`$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1; ` +
		`"manufacturer=$($cs.Manufacturer)"; "model=$($cs.Model)"; ` +
		`"serialNumber=$($bios.SerialNumber)"; "cpu=$($cpu.Name)"; ` +
		`"ramBytes=$($cs.TotalPhysicalMemory)"`

	windowsOSScript = `$os = Get-CimInstance Win32_OperatingSystem; ` +
		`"name=$($os.Caption)"; "version=$($os.Version)"; ` +
		`"build=$($os.BuildNumber)"; "architecture=$env:PROCESSOR_ARCHITECTURE"`

	windowsDiskScript = `$d = Get-CimInstance Win32_LogicalDisk | ` +
		`Where-Object { $_.DeviceID -eq $env:SystemDrive }; "diskBytes=$($d.Size)"`

	windowsSoftwareScript = `Get-ItemProperty ` +
		`'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',` +
		`'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | ` +
		`ForEach-Object { "$($_.DisplayName)` + "`t" + `$($_.DisplayVersion)` + "`t" +
		`$($_.Publisher)` + "`t" + `$($_.InstallDate)" }`
)

// windowsProbes is the probe list for goos "windows".
func windowsProbes() []Probe {
	return []Probe{
		{Name: ProbeHardware, Cmd: windowsShell, Args: windowsArgs(windowsHardwareScript)},
		{Name: ProbeOS, Cmd: windowsShell, Args: windowsArgs(windowsOSScript)},
		{Name: ProbeDisk, Cmd: windowsShell, Args: windowsArgs(windowsDiskScript)},
		{Name: ProbeSoftware, Cmd: windowsShell, Args: windowsArgs(windowsSoftwareScript)},
	}
}

func windowsArgs(script string) []string {
	return []string{"-NoProfile", "-NonInteractive", "-Command", script}
}

// fillWindows parses the Windows probe output into inv. A probe missing from
// stdout failed or timed out; its fields stay at their zero values.
func fillWindows(inv *contract.Inventory, stdout map[string]string) {
	if out, ok := stdout[ProbeHardware]; ok {
		kv := parseKeyValues(out)
		inv.Hardware.Manufacturer = kv["manufacturer"]
		inv.Hardware.Model = kv["model"]
		inv.Hardware.SerialNumber = kv["serialNumber"]
		inv.Hardware.CPU = kv["cpu"]
		inv.Hardware.RAMBytes = parseBytes(kv["ramBytes"])
	}

	if out, ok := stdout[ProbeOS]; ok {
		kv := parseKeyValues(out)
		inv.OS.Name = kv["name"]
		inv.OS.Version = kv["version"]
		inv.OS.Build = kv["build"]
		inv.OS.Architecture = normalizeArch(kv["architecture"])
	}

	if out, ok := stdout[ProbeDisk]; ok {
		inv.Hardware.DiskBytes = parseBytes(parseKeyValues(out)["diskBytes"])
	}

	if out, ok := stdout[ProbeSoftware]; ok {
		inv.Software = parseWindowsSoftware(out)
	}
}

// parseWindowsSoftware reads the tab-separated
// "name\tversion\tpublisher\tinstallDate" records the software script prints.
// Registry install dates arrive as yyyyMMdd and leave as ISO-8601 UTC.
func parseWindowsSoftware(out string) []contract.SoftwareEntry {
	lines := splitLines(out)
	entries := make([]contract.SoftwareEntry, 0, len(lines))
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		entry := contract.SoftwareEntry{Name: strings.TrimSpace(fields[0])}
		if len(fields) > 1 {
			entry.Version = strings.TrimSpace(fields[1])
		}
		if len(fields) > 2 {
			entry.Publisher = strings.TrimSpace(fields[2])
		}
		if len(fields) > 3 {
			entry.InstalledAt = normalizeTime(strings.TrimSpace(fields[3]))
		}
		entries = append(entries, entry)
	}
	return entries
}
