package inventory

import (
	"bytes"
	"encoding/json"
	"math"
	"strconv"
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

	// windowsDetailsScript prints one JSON object holding every device detail
	// SYSTEM can read without prompting. Each section runs in its own
	// try/catch: a section that throws leaves its keys out and adds its name
	// to the "warnings" array, so one failing source never loses the others.
	// Dates are rendered by the script as yyyy-MM-ddTHH:mm:ssZ (UTC) with the
	// invariant culture, and MediaType is cast to [string] because Windows
	// PowerShell reports it as either a name or a number.
	windowsDetailsScript = `$ErrorActionPreference = 'Stop'; $r = @{}; $w = @(); ` +
		`$inv = [Globalization.CultureInfo]::InvariantCulture; ` +
		`function U($d) { if ($d) { ([datetime]$d).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", $inv) } }; ` +
		// os
		`try { $os = Get-CimInstance Win32_OperatingSystem; ` +
		`$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; ` +
		`$dv = $cv.DisplayVersion; if (-not $dv) { $dv = $cv.ReleaseId }; ` +
		`$r.os = @{ displayVersion = [string]$dv; ubr = $cv.UBR; edition = [string]$cv.EditionID; ` +
		`installDate = (U $os.InstallDate); lastBootAt = (U $os.LastBootUpTime); ` +
		`locale = [string](Get-WinSystemLocale).Name } } catch { $w += 'os' }; ` +
		// computer
		`try { $cs = Get-CimInstance Win32_ComputerSystem; ` +
		`$r.computer = @{ systemFamily = [string]$cs.SystemFamily; systemSku = [string]$cs.SystemSKUNumber; ` +
		`partOfDomain = [bool]$cs.PartOfDomain; domain = [string]$cs.Domain } } catch { $w += 'computer' }; ` +
		// cpu
		`try { $p = @(Get-CimInstance Win32_Processor); ` +
		`$r.cpu = @{ cores = [int](($p | Measure-Object NumberOfCores -Sum).Sum); ` +
		`logicalProcessors = [int](($p | Measure-Object NumberOfLogicalProcessors -Sum).Sum) } } catch { $w += 'cpu' }; ` +
		// bios
		`$fw = 0; try { $b = Get-CimInstance Win32_BIOS; ` +
		`$fw = [int](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control').PEFirmwareType; ` +
		// PEFirmwareType is absent on many installed systems; the firmware_type
		// environment variable Windows sets at boot says the same thing.
		`if ($fw -eq 0) { if ($env:firmware_type -eq 'UEFI') { $fw = 2 } elseif ($env:firmware_type -eq 'Legacy') { $fw = 1 } }; ` +
		`$r.bios = @{ biosVersion = [string]$b.SMBIOSBIOSVersion; releaseDate = (U $b.ReleaseDate); ` +
		`peFirmwareType = $fw } } catch { $w += 'bios' }; ` +
		// secureBoot
		`if ($fw -eq 2) { try { $r.secureBoot = @{ enabled = [bool](Confirm-SecureBootUEFI) } } catch { $w += 'secureBoot' } }; ` +
		// tpm
		`try { $t = Get-Tpm; $tpm = @{ present = [bool]$t.TpmPresent; ready = [bool]$t.TpmReady }; ` +
		`$tw = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm; ` +
		`if ($tw -and $tw.SpecVersion) { $tpm.version = ([string]$tw.SpecVersion).Split(',')[0].Trim() }; ` +
		`$r.tpm = $tpm } catch { $w += 'tpm' }; ` +
		// disks
		`try { $r.disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { ` +
		`@{ deviceId = [string]$_.DeviceID; fileSystem = [string]$_.FileSystem; size = $_.Size; freeSpace = $_.FreeSpace } }) } ` +
		`catch { $w += 'disks' }; ` +
		// physicalDisks
		`try { $r.physicalDisks = @(Get-PhysicalDisk | ForEach-Object { ` +
		`@{ friendlyName = [string]$_.FriendlyName; mediaType = [string]$_.MediaType; size = $_.Size } }) } ` +
		`catch { $w += 'physicalDisks' }; ` +
		// network
		`try { $r.network = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { ` +
		`@{ description = [string]$_.Description; macAddress = [string]$_.MACAddress; ipAddresses = $_.IPAddress; ` +
		`dhcpEnabled = [bool]$_.DHCPEnabled; dnsServers = $_.DNSServerSearchOrder; gateways = $_.DefaultIPGateway } }) } ` +
		`catch { $w += 'network' }; ` +
		// dsregcmd
		`try { $out = & dsregcmd.exe /status; if ($LASTEXITCODE -ne 0) { throw 'dsregcmd failed' }; ` +
		`$keep = 'AzureAdJoined','DomainJoined','TenantName','TenantId','DeviceId'; $ds = @{}; ` +
		`foreach ($l in $out) { if ($l -match '^\s*(\w+)\s*:\s*(.*)$' -and ($keep -contains $Matches[1]) -and -not $ds.ContainsKey($Matches[1])) ` +
		`{ $ds[$Matches[1]] = $Matches[2].Trim() } }; $r.dsregcmd = $ds } catch { $w += 'dsregcmd' }; ` +
		`$r.warnings = $w; ConvertTo-Json -InputObject $r -Compress -Depth 5`
)

// Caps on the device-detail lists. They match the backend's caps, so the
// agent never sends more than the backend stores.
const (
	maxDetailDisks         = 32
	maxDetailPhysicalDisks = 16
	maxDetailAdapters      = 16
	maxDetailAddresses     = 16
)

// windowsProbes is the probe list for goos "windows".
func windowsProbes() []Probe {
	return []Probe{
		{Name: ProbeHardware, Cmd: windowsShell, Args: windowsArgs(windowsHardwareScript)},
		{Name: ProbeOS, Cmd: windowsShell, Args: windowsArgs(windowsOSScript)},
		{Name: ProbeDisk, Cmd: windowsShell, Args: windowsArgs(windowsDiskScript)},
		{Name: ProbeSoftware, Cmd: windowsShell, Args: windowsArgs(windowsSoftwareScript)},
		{Name: ProbeDetails, Cmd: windowsShell, Args: windowsArgs(windowsDetailsScript)},
	}
}

func windowsArgs(script string) []string {
	return []string{"-NoProfile", "-NonInteractive", "-Command", script}
}

// fillWindows parses the Windows probe output into inv and returns the
// warnings the details probe's output produced. A probe missing from stdout
// failed or timed out; its fields stay at their zero values.
func fillWindows(inv *contract.Inventory, stdout map[string]string) []string {
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

	if out, ok := stdout[ProbeDetails]; ok {
		return fillWindowsDetails(inv, out)
	}
	return nil
}

// detailsObject is one JSON object of the details output, with every value
// left raw so a value of the wrong type drops only that value.
type detailsObject map[string]json.RawMessage

// utf8BOM is the byte-order mark a PowerShell host may put before its output.
var utf8BOM = string([]byte{0xEF, 0xBB, 0xBF})

// fillWindowsDetails parses the single JSON object the details script prints
// into the optional device-detail fields of inv. It returns
// "details:unparseable" when the output is not a JSON object, and one
// "details:<section>" warning per section the script reported as failed.
// Every value is checked on its own: a malformed value is left out rather
// than failing the section.
func fillWindowsDetails(inv *contract.Inventory, out string) []string {
	root := parseDetailsObject(json.RawMessage(strings.TrimSpace(strings.TrimPrefix(out, utf8BOM))))
	if root == nil {
		return []string{ProbeDetails + ":unparseable"}
	}

	var warnings []string
	for _, section := range root.strings("warnings", -1) {
		warnings = append(warnings, ProbeDetails+":"+section)
	}

	if os := root.object("os"); os != nil {
		inv.OS.Edition = os.str("edition")
		inv.OS.DisplayVersion = os.str("displayVersion")
		if ubr, ok := os.integer("ubr"); ok {
			v := int(ubr)
			inv.OS.UBR = &v
		}
		inv.OS.InstallDate = normalizeTime(os.str("installDate"))
		inv.OS.LastBootAt = normalizeTime(os.str("lastBootAt"))
		inv.OS.Locale = os.str("locale")
	}

	computer := root.object("computer")
	var partOfDomain *bool
	if computer != nil {
		inv.Hardware.SystemFamily = computer.str("systemFamily")
		inv.Hardware.SystemSKU = computer.str("systemSku")
		partOfDomain = computer.boolean("partOfDomain")
	}

	if cpu := root.object("cpu"); cpu != nil {
		if n, ok := cpu.integer("cores"); ok {
			inv.Hardware.CPUCores = int(n)
		}
		if n, ok := cpu.integer("logicalProcessors"); ok {
			inv.Hardware.CPULogicalProcessors = int(n)
		}
	}

	var fw contract.InventoryFirmware
	if bios := root.object("bios"); bios != nil {
		fw.BIOSVersion = bios.str("biosVersion")
		fw.BIOSReleaseDate = normalizeTime(bios.str("releaseDate"))
		if t, ok := bios.integer("peFirmwareType"); ok {
			switch t {
			case 1:
				fw.Type = "bios"
			case 2:
				fw.Type = "uefi"
			}
		}
	}
	if sb := root.object("secureBoot"); sb != nil && fw.Type != "bios" {
		fw.SecureBootEnabled = sb.boolean("enabled")
	}
	if tpm := root.object("tpm"); tpm != nil {
		fw.TPMPresent = tpm.boolean("present")
		fw.TPMReady = tpm.boolean("ready")
		fw.TPMVersion = tpm.str("version")
	}
	if fw != (contract.InventoryFirmware{}) {
		inv.Firmware = &fw
	}

	for _, d := range root.objects("disks") {
		if len(inv.Disks) == maxDetailDisks {
			break
		}
		disk := contract.InventoryDisk{DeviceID: d.str("deviceId"), FileSystem: d.str("fileSystem")}
		if n, ok := d.integer("size"); ok {
			disk.SizeBytes = n
		}
		if n, ok := d.integer("freeSpace"); ok {
			disk.FreeBytes = n
		}
		if disk != (contract.InventoryDisk{}) {
			inv.Disks = append(inv.Disks, disk)
		}
	}

	for _, d := range root.objects("physicalDisks") {
		if len(inv.PhysicalDisks) == maxDetailPhysicalDisks {
			break
		}
		disk := contract.InventoryPhysicalDisk{Model: d.str("friendlyName")}
		if n, ok := d.integer("size"); ok {
			disk.SizeBytes = n
		}
		if disk.Model == "" && disk.SizeBytes == 0 {
			continue
		}
		disk.MediaType = normalizeMediaType(d.str("mediaType"))
		inv.PhysicalDisks = append(inv.PhysicalDisks, disk)
	}

	for _, a := range root.objects("network") {
		if len(inv.Network) == maxDetailAdapters {
			break
		}
		adapter := contract.InventoryNetworkAdapter{
			Description: a.str("description"),
			MACAddress:  a.str("macAddress"),
			DHCPEnabled: a.boolean("dhcpEnabled"),
			DNSServers:  a.strings("dnsServers", maxDetailAddresses),
			Gateways:    a.strings("gateways", maxDetailAddresses),
		}
		for _, ip := range a.strings("ipAddresses", -1) {
			if strings.Contains(ip, ":") {
				if len(adapter.IPv6) < maxDetailAddresses {
					adapter.IPv6 = append(adapter.IPv6, ip)
				}
			} else if len(adapter.IPv4) < maxDetailAddresses {
				adapter.IPv4 = append(adapter.IPv4, ip)
			}
		}
		if adapter.Description == "" && adapter.MACAddress == "" && adapter.DHCPEnabled == nil &&
			len(adapter.IPv4) == 0 && len(adapter.IPv6) == 0 && len(adapter.DNSServers) == 0 && len(adapter.Gateways) == 0 {
			continue
		}
		inv.Network = append(inv.Network, adapter)
	}

	var join contract.InventoryJoin
	ds := root.object("dsregcmd")
	if ds != nil {
		join.AzureADJoined = yesNo(ds.str("AzureAdJoined"))
		join.TenantName = ds.str("TenantName")
		join.TenantID = ds.str("TenantId")
		join.EntraDeviceID = ds.str("DeviceId")
	}
	if ds != nil && ds.str("DomainJoined") != "" {
		join.DomainJoined = yesNo(ds.str("DomainJoined"))
	} else if partOfDomain != nil {
		v := *partOfDomain
		join.DomainJoined = &v
	}
	if partOfDomain != nil && *partOfDomain {
		join.Domain = computer.str("domain")
	}
	if join != (contract.InventoryJoin{}) {
		inv.Join = &join
	}

	return warnings
}

// parseDetailsObject decodes raw as a JSON object, or returns nil when it is
// anything else.
func parseDetailsObject(raw json.RawMessage) detailsObject {
	var obj detailsObject
	if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &obj) != nil {
		return nil
	}
	return obj
}

// object returns the JSON object under key, or nil.
func (o detailsObject) object(key string) detailsObject {
	return parseDetailsObject(bytes.TrimSpace(o[key]))
}

// objects returns the JSON objects under key. An array keeps its object
// entries; a lone object, which PowerShell emits for a one-entry list, counts
// as a one-entry list. Anything else yields no entries.
func (o detailsObject) objects(key string) []detailsObject {
	raw := bytes.TrimSpace(o[key])
	if single := parseDetailsObject(raw); single != nil {
		return []detailsObject{single}
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return nil
	}
	objs := make([]detailsObject, 0, len(items))
	for _, item := range items {
		if obj := parseDetailsObject(bytes.TrimSpace(item)); obj != nil {
			objs = append(objs, obj)
		}
	}
	return objs
}

// str returns the trimmed string under key, or "" when the value is not a
// JSON string.
func (o detailsObject) str(key string) string {
	var s string
	if json.Unmarshal(o[key], &s) != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

// strings returns the non-blank strings under key, keeping at most max of
// them (max < 0 keeps all). A single string, which PowerShell emits for a
// one-entry list, is a one-entry list; any other non-array value is empty.
func (o detailsObject) strings(key string, max int) []string {
	raw := o[key]
	var items []json.RawMessage
	if s := o.str(key); s != "" {
		items = []json.RawMessage{raw}
	} else if json.Unmarshal(raw, &items) != nil {
		return nil
	}
	var out []string
	for _, item := range items {
		if max >= 0 && len(out) == max {
			break
		}
		var s string
		if json.Unmarshal(item, &s) != nil {
			continue
		}
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// integer returns the whole number >= 0 under key. Negative, fractional and
// non-numeric values are rejected.
func (o detailsObject) integer(key string) (int64, bool) {
	raw := strings.TrimSpace(string(o[key]))
	if raw == "" {
		return 0, false
	}
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return n, n >= 0
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || f < 0 || f != math.Trunc(f) || f > math.MaxInt64 {
		return 0, false
	}
	return int64(f), true
}

// boolean returns the literal JSON boolean under key, or nil.
func (o detailsObject) boolean(key string) *bool {
	var b bool
	switch strings.TrimSpace(string(o[key])) {
	case "true":
		b = true
	case "false":
		b = false
	default:
		return nil
	}
	return &b
}

// yesNo maps a dsregcmd YES/NO value, in any case, to a boolean. Any other
// value is nil.
func yesNo(s string) *bool {
	var b bool
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "YES":
		b = true
	case "NO":
		b = false
	default:
		return nil
	}
	return &b
}

// normalizeMediaType maps Get-PhysicalDisk's MediaType, as a name or as its
// numeric value, onto the contract enum. Anything unrecognised is
// "unspecified".
func normalizeMediaType(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "SSD", "4":
		return "ssd"
	case "HDD", "3":
		return "hdd"
	case "SCM", "5":
		return "scm"
	default:
		return "unspecified"
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
