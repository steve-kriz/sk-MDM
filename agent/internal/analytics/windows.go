package analytics

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
)

// The Windows probes are PowerShell scripts that normalise their own output
// to "key=value" lines, or to one compact JSON object per line for the
// crashes. Each one reads its event log with -ErrorAction SilentlyContinue,
// so a missing or disabled log prints nothing rather than failing the probe.
const (
	windowsShell = "powershell.exe"

	// windowsBootScript prints the last boot time and, when the newest
	// Diagnostics-Performance event 100 is readable, the boot duration it
	// records and when it was logged.
	windowsBootScript = `$os = Get-CimInstance Win32_OperatingSystem; ` +
		`"lastBootAt=$($os.LastBootUpTime.ToUniversalTime().ToString('o'))"; ` +
		`$e = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Diagnostics-Performance/Operational'; Id=100} -MaxEvents 1 -ErrorAction SilentlyContinue; ` +
		`if ($e) { $x = [xml]$e.ToXml(); ` +
		`$bt = ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'BootTime' }).'#text'; ` +
		`if ($bt) { "bootDurationMs=$bt"; "bootEventAt=$($e.TimeCreated.ToUniversalTime().ToString('o'))" } }; ` +
		`exit 0`

	// windowsPerformanceScript samples the processor load, the physical
	// memory (reported in KB, converted here) and the system volume.
	windowsPerformanceScript = `$os = Get-CimInstance Win32_OperatingSystem; ` +
		`$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average; ` +
		`$d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"; ` +
		`"cpuPercent=$cpu"; ` +
		`"memoryTotalBytes=$([int64]$os.TotalVisibleMemorySize * 1024)"; ` +
		`"memoryUsedBytes=$(([int64]$os.TotalVisibleMemorySize - [int64]$os.FreePhysicalMemory) * 1024)"; ` +
		`"diskTotalBytes=$([int64]$d.Size)"; ` +
		`"diskFreeBytes=$([int64]$d.FreeSpace)"`

	// windowsNetworkScript prints one JSON object per physical adapter that is
	// up: its link speed and its raw TCP/IP performance counters read twice, a
	// second apart, with the counter timestamps and frequency the rates are
	// computed from. Raw counters are read through CIM rather than Get-Counter
	// so the names do not depend on the display language. A counter instance
	// is named after the adapter's description with ( ) # / \ replaced; an
	// adapter with no matching instance is printed with its link speed only.
	windowsNetworkScript = `$ErrorActionPreference = 'SilentlyContinue'; ` +
		`$up = @(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' }); ` +
		`$s1 = @(Get-CimInstance Win32_PerfRawData_Tcpip_NetworkInterface); ` +
		`Start-Sleep -Seconds 1; ` +
		`$s2 = @(Get-CimInstance Win32_PerfRawData_Tcpip_NetworkInterface); ` +
		`foreach ($n in $up) { ` +
		`$k = $n.InterfaceDescription -replace '\(','[' -replace '\)',']' -replace '[#/\\]','_'; ` +
		`$a = $s1 | Where-Object { $_.Name -eq $k } | Select-Object -First 1; ` +
		`$b = $s2 | Where-Object { $_.Name -eq $k } | Select-Object -First 1; ` +
		`$o = [ordered]@{ name = [string]$n.Name; linkSpeed = [uint64]$n.Speed }; ` +
		`if ($a -and $b) { ` +
		`$o.freq = [uint64]$a.Frequency_PerfTime; $o.t1 = [uint64]$a.Timestamp_PerfTime; $o.t2 = [uint64]$b.Timestamp_PerfTime; ` +
		`$o.rxBytes1 = [uint64]$a.BytesReceivedPersec; $o.rxBytes2 = [uint64]$b.BytesReceivedPersec; ` +
		`$o.txBytes1 = [uint64]$a.BytesSentPersec; $o.txBytes2 = [uint64]$b.BytesSentPersec; ` +
		`$o.rxPackets1 = [uint64]$a.PacketsReceivedPersec; $o.rxPackets2 = [uint64]$b.PacketsReceivedPersec; ` +
		`$o.txPackets1 = [uint64]$a.PacketsSentPersec; $o.txPackets2 = [uint64]$b.PacketsSentPersec; ` +
		`$o.rxErrors = [uint64]$b.PacketsReceivedErrors; $o.txErrors = [uint64]$b.PacketsOutboundErrors; ` +
		`$o.rxDiscards = [uint64]$b.PacketsReceivedDiscarded; $o.txDiscards = [uint64]$b.PacketsOutboundDiscarded }; ` +
		`[pscustomobject]$o | ConvertTo-Json -Compress }; ` +
		`exit 0`

	// windowsCrashesScript prints the Application Error (1000) and
	// Application Hang (1002) events of the last 30 days, one JSON object
	// per line.
	windowsCrashesScript = `Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000,1002; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 500 -ErrorAction SilentlyContinue | ` +
		`ForEach-Object { [pscustomobject]@{ eventId = $_.Id; ` +
		`occurredAt = $_.TimeCreated.ToUniversalTime().ToString('o'); ` +
		`appName = [string]$_.Properties[0].Value; ` +
		`appVersion = [string]$_.Properties[1].Value } | ConvertTo-Json -Compress }; ` +
		`exit 0`
)

// Windows event ids the crashes probe reads.
const (
	eventApplicationError = 1000
	eventApplicationHang  = 1002
)

// windowsProbes is the probe list for goos "windows".
func windowsProbes() []Probe {
	return []Probe{
		{Name: ProbeBoot, Cmd: windowsShell, Args: windowsArgs(windowsBootScript)},
		{Name: ProbePerformance, Cmd: windowsShell, Args: windowsArgs(windowsPerformanceScript)},
		{Name: ProbeCrashes, Cmd: windowsShell, Args: windowsArgs(windowsCrashesScript)},
	}
}

func windowsArgs(script string) []string {
	return []string{"-NoProfile", "-NonInteractive", "-Command", script}
}

// fillWindowsBoot parses the Windows boot output into b and returns its
// warnings. An unparseable or future boot time nulls the whole sub-block with
// "boot:unparseable" only; otherwise a boot duration that cannot be
// established adds "bootDuration:unavailable".
func fillWindowsBoot(b *contract.AnalyticsBoot, out string, now time.Time) []string {
	kv := parseKeyValues(out)

	bootAt, err := time.Parse(time.RFC3339, kv["lastBootAt"])
	if err != nil || !fillBootTime(b, bootAt, now) {
		return []string{unparseable(ProbeBoot)}
	}

	ms, err := strconv.ParseInt(kv["bootDurationMs"], 10, 64)
	if err != nil {
		return []string{warnBootDurationUnavailable}
	}
	eventAt, err := time.Parse(time.RFC3339, kv["bootEventAt"])
	if err != nil || eventAt.Before(bootAt) {
		return []string{warnBootDurationUnavailable}
	}
	seconds := float64(ms) / 1000
	if seconds <= 0 || seconds > MaxBootDurationSeconds {
		return []string{warnBootDurationUnavailable}
	}
	b.BootDurationSeconds = &seconds
	return nil
}

// parseWindowsCrashes reads the crashes probe's JSON lines. clean is false
// when any line was dropped as unparseable; a line for an event id other
// than 1000 or 1002 is dropped silently.
func parseWindowsCrashes(out string) ([]crashEntry, bool) {
	clean := true
	var entries []crashEntry
	for _, line := range splitLines(out) {
		fields, err := decodeObject(line)
		if err != nil {
			clean = false
			continue
		}

		var kind string
		switch eventID(fields["eventId"]) {
		case eventApplicationError:
			kind = KindCrash
		case eventApplicationHang:
			kind = KindHang
		default:
			continue
		}

		occurred, _ := fields["occurredAt"].(string)
		at, err := time.Parse(time.RFC3339, occurred)
		if err != nil {
			clean = false
			continue
		}
		name, _ := fields["appName"].(string)
		version, _ := fields["appVersion"].(string)
		entry, ok := newCrash(name, version, at, kind)
		if !ok {
			clean = false
			continue
		}
		entries = append(entries, entry)
	}
	return entries, clean
}

// eventID reads an event id decoded as a json.Number, or -1 when it is not
// an integer.
func eventID(v any) int64 {
	n, ok := v.(json.Number)
	if !ok {
		return -1
	}
	id, err := n.Int64()
	if err != nil {
		return -1
	}
	return id
}
