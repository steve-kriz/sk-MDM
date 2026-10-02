package inventory

import (
	"encoding/json"
	"strings"

	"github.com/officehq/sk-mdm/agent/internal/contract"
)

// The macOS probes lean on the machine-readable output the system tools
// already offer: system_profiler emits JSON, sw_vers and df emit fixed labels
// and columns. Nothing here parses a localised sentence.
const (
	darwinProfiler = "/usr/sbin/system_profiler"
	darwinShell    = "/bin/sh"
	darwinDF       = "/bin/df"

	// darwinOSScript prints sw_vers' own labelled lines and appends the
	// architecture under a label of the same shape.
	darwinOSScript = `sw_vers; printf 'Architecture:\t%s\n' "$(uname -m)"`

	// darwinManufacturer is a constant: system_profiler reports the model and
	// the serial of a Mac but never names the vendor.
	darwinManufacturer = "Apple"
)

// darwinProbes is the probe list for goos "darwin".
func darwinProbes() []Probe {
	return []Probe{
		{Name: ProbeHardware, Cmd: darwinProfiler, Args: []string{"-json", "SPHardwareDataType"}},
		{Name: ProbeOS, Cmd: darwinShell, Args: []string{"-c", darwinOSScript}},
		{Name: ProbeDisk, Cmd: darwinDF, Args: []string{"-k", "/"}},
		{Name: ProbeSoftware, Cmd: darwinProfiler, Args: []string{"-json", "SPApplicationsDataType"}},
	}
}

// fillDarwin parses the macOS probe output into inv. A probe missing from
// stdout failed or timed out; its fields stay at their zero values.
func fillDarwin(inv *contract.Inventory, stdout map[string]string) {
	if out, ok := stdout[ProbeHardware]; ok {
		fillDarwinHardware(inv, out)
	}

	if out, ok := stdout[ProbeOS]; ok {
		labels := parseLabelled(out)
		inv.OS.Name = labels["ProductName"]
		inv.OS.Version = labels["ProductVersion"]
		inv.OS.Build = labels["BuildVersion"]
		inv.OS.Architecture = normalizeArch(labels["Architecture"])
	}

	if out, ok := stdout[ProbeDisk]; ok {
		inv.Hardware.DiskBytes = parseDarwinDisk(out)
	}

	if out, ok := stdout[ProbeSoftware]; ok {
		inv.Software = parseDarwinSoftware(out)
	}
}

// fillDarwinHardware reads system_profiler -json SPHardwareDataType.
func fillDarwinHardware(inv *contract.Inventory, out string) {
	var doc struct {
		Items []struct {
			MachineModel   string `json:"machine_model"`
			MachineName    string `json:"machine_name"`
			SerialNumber   string `json:"serial_number"`
			ChipType       string `json:"chip_type"`
			CPUType        string `json:"cpu_type"`
			PhysicalMemory string `json:"physical_memory"`
		} `json:"SPHardwareDataType"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.Items) == 0 {
		return
	}

	item := doc.Items[0]
	inv.Hardware.Manufacturer = darwinManufacturer
	inv.Hardware.Model = firstNonEmpty(item.MachineModel, item.MachineName)
	inv.Hardware.SerialNumber = item.SerialNumber
	inv.Hardware.CPU = firstNonEmpty(item.ChipType, item.CPUType)
	inv.Hardware.RAMBytes = parseBytes(item.PhysicalMemory)
}

// parseDarwinSoftware reads system_profiler -json SPApplicationsDataType. The
// publisher is the signing authority when the application is signed, and the
// source it was obtained from otherwise.
func parseDarwinSoftware(out string) []contract.SoftwareEntry {
	var doc struct {
		Items []struct {
			Name         string   `json:"_name"`
			Version      string   `json:"version"`
			ObtainedFrom string   `json:"obtained_from"`
			LastModified string   `json:"lastModified"`
			SignedBy     []string `json:"signed_by"`
		} `json:"SPApplicationsDataType"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil
	}

	entries := make([]contract.SoftwareEntry, 0, len(doc.Items))
	for _, item := range doc.Items {
		publisher := item.ObtainedFrom
		if len(item.SignedBy) > 0 && strings.TrimSpace(item.SignedBy[0]) != "" {
			publisher = item.SignedBy[0]
		}
		entries = append(entries, contract.SoftwareEntry{
			Name:        item.Name,
			Version:     item.Version,
			Publisher:   publisher,
			InstalledAt: normalizeTime(item.LastModified),
		})
	}
	return entries
}

// parseDarwinDisk reads the 1024-byte block count of the root volume out of
// "df -k /" and returns it in bytes.
func parseDarwinDisk(out string) int64 {
	lines := splitLines(out)
	if len(lines) < 2 {
		return 0
	}
	fields := strings.Fields(lines[1])
	if len(fields) < 2 {
		return 0
	}
	return parseBytes(fields[1]) * 1024
}

// firstNonEmpty returns the first value that is not blank.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
