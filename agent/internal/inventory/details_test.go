package inventory_test

// Cucumber-style (Given/When/Then) and unit tests for TASK-059: the Windows
// "details" probe and the new device-detail fields it fills. No real
// PowerShell is run anywhere here: every probe is answered by
// fake.CommandRunner from a recorded fixture or from a JSON object built in
// the test, and every clock is fake.Clock. Nothing opens a network or
// database connection.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/inventory"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// detailsProbe returns the "windows" details probe.
func detailsProbe(t *testing.T) inventory.Probe {
	t.Helper()
	for _, p := range inventory.Probes("windows") {
		if p.Name == inventory.ProbeDetails {
			return p
		}
	}
	t.Fatal("no details probe found")
	return inventory.Probe{}
}

// seedOtherWindowsFixtures loads the recorded fixture for every Windows probe
// except "details", so a test can set the details probe's output on its own.
func seedOtherWindowsFixtures(t *testing.T, runner *fake.CommandRunner) {
	t.Helper()
	for _, p := range inventory.Probes("windows") {
		if p.Name == inventory.ProbeDetails {
			continue
		}
		content, err := loadFixture("windows", p.Name)
		if err != nil {
			t.Fatalf("failed to load fixture for %s: %v", p.Name, err)
		}
		runner.Results[p.String()] = platform.CommandResult{Stdout: content, ExitCode: 0}
	}
}

// setDetailsOutput arranges the details probe's raw stdout/exit code.
func setDetailsOutput(t *testing.T, runner *fake.CommandRunner, stdout string, exitCode int) {
	t.Helper()
	p := detailsProbe(t)
	runner.Results[p.String()] = platform.CommandResult{Stdout: stdout, ExitCode: exitCode}
}

// setDetailsJSON marshals sections to JSON and arranges it as the details
// probe's stdout, exit code 0.
func setDetailsJSON(t *testing.T, runner *fake.CommandRunner, sections map[string]interface{}) {
	t.Helper()
	data, err := json.Marshal(sections)
	if err != nil {
		t.Fatalf("failed to marshal details sections: %v", err)
	}
	setDetailsOutput(t, runner, string(data), 0)
}

func hasWarning(warnings []string, want string) bool {
	for _, w := range warnings {
		if w == want {
			return true
		}
	}
	return false
}

// ----------------------------------------------------------------------
// AC1
// ----------------------------------------------------------------------

func TestScenario_AC1_WindowsGainsDetailsProbe(t *testing.T) {
	// When Probes is called with goos "windows"
	probes := inventory.Probes("windows")

	// Then it returns probes named hardware, os, disk, software, details in
	// that order
	wantNames := []string{
		inventory.ProbeHardware, inventory.ProbeOS, inventory.ProbeDisk,
		inventory.ProbeSoftware, inventory.ProbeDetails,
	}
	if len(probes) != len(wantNames) {
		t.Fatalf("expected %d probes, got %d: %+v", len(wantNames), len(probes), probes)
	}
	for i, want := range wantNames {
		if probes[i].Name != want {
			t.Errorf("probe[%d].Name = %q, want %q", i, probes[i].Name, want)
		}
	}

	// And the details probe runs "powershell.exe" with "-NoProfile
	// -NonInteractive -Command"
	details := probes[len(probes)-1]
	if details.Cmd != "powershell.exe" {
		t.Errorf("details.Cmd = %q, want powershell.exe", details.Cmd)
	}
	if len(details.Args) < 4 || details.Args[0] != "-NoProfile" || details.Args[1] != "-NonInteractive" || details.Args[2] != "-Command" {
		t.Errorf("details.Args = %v, want to start with [-NoProfile -NonInteractive -Command <script>]", details.Args)
	}
	if details.Args[3] == "" {
		t.Error("details script is empty")
	}

	// And Probes for goos "darwin" returns exactly its existing 4 probes
	darwinProbes := inventory.Probes("darwin")
	if len(darwinProbes) != 4 {
		t.Fatalf("expected 4 darwin probes, got %d: %+v", len(darwinProbes), darwinProbes)
	}
	for _, p := range darwinProbes {
		if p.Name == inventory.ProbeDetails {
			t.Error("darwin probes should not include details")
		}
	}
}

// ----------------------------------------------------------------------
// AC2
// ----------------------------------------------------------------------

func TestScenario_AC2_RecordedWindowsDetailsFixtureFillsNewFields(t *testing.T) {
	// Given the recorded Windows fixtures including testdata/windows/details.txt
	runner := fake.NewCommandRunner()
	for _, p := range inventory.Probes("windows") {
		content, err := loadFixture("windows", p.Name)
		if err != nil {
			t.Fatalf("failed to load fixture for %s: %v", p.Name, err)
		}
		runner.Results[p.String()] = platform.CommandResult{Stdout: content, ExitCode: 0}
	}
	clock := fake.NewClock(time.Now())

	// When Collect runs with goos "windows"
	inv, err := inventory.Collect(runner, clock, "windows")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then os.edition is "Enterprise", os.displayVersion is "23H2" and
	// os.ubr is 4317
	if inv.OS.Edition != "Enterprise" {
		t.Errorf("OS.Edition = %q, want Enterprise", inv.OS.Edition)
	}
	if inv.OS.DisplayVersion != "23H2" {
		t.Errorf("OS.DisplayVersion = %q, want 23H2", inv.OS.DisplayVersion)
	}
	if inv.OS.UBR == nil || *inv.OS.UBR != 4317 {
		t.Errorf("OS.UBR = %v, want 4317", inv.OS.UBR)
	}

	// And os.installDate and os.lastBootAt are RFC3339 UTC strings ending in "Z"
	for name, value := range map[string]string{"InstallDate": inv.OS.InstallDate, "LastBootAt": inv.OS.LastBootAt} {
		if value == "" || value[len(value)-1] != 'Z' {
			t.Errorf("OS.%s = %q, want a string ending in Z", name, value)
		}
		if _, err := time.Parse(time.RFC3339, value); err != nil {
			t.Errorf("OS.%s = %q is not RFC3339: %v", name, value, err)
		}
	}
	if inv.OS.Locale == "" {
		t.Error("OS.Locale is empty")
	}

	if inv.Hardware.SystemFamily == "" {
		t.Error("Hardware.SystemFamily is empty")
	}
	if inv.Hardware.SystemSKU == "" {
		t.Error("Hardware.SystemSKU is empty")
	}
	if inv.Hardware.CPUCores <= 0 {
		t.Errorf("Hardware.CPUCores = %d, want > 0", inv.Hardware.CPUCores)
	}
	if inv.Hardware.CPULogicalProcessors <= 0 {
		t.Errorf("Hardware.CPULogicalProcessors = %d, want > 0", inv.Hardware.CPULogicalProcessors)
	}

	// And firmware.type is "uefi", secureBootEnabled is true, tpmPresent is
	// true and tpmVersion is "2.0"
	if inv.Firmware == nil {
		t.Fatal("Firmware is nil")
	}
	if inv.Firmware.Type != "uefi" {
		t.Errorf("Firmware.Type = %q, want uefi", inv.Firmware.Type)
	}
	if inv.Firmware.SecureBootEnabled == nil || !*inv.Firmware.SecureBootEnabled {
		t.Errorf("Firmware.SecureBootEnabled = %v, want true", inv.Firmware.SecureBootEnabled)
	}
	if inv.Firmware.TPMPresent == nil || !*inv.Firmware.TPMPresent {
		t.Errorf("Firmware.TPMPresent = %v, want true", inv.Firmware.TPMPresent)
	}
	if inv.Firmware.TPMVersion != "2.0" {
		t.Errorf("Firmware.TPMVersion = %q, want 2.0", inv.Firmware.TPMVersion)
	}

	// And disks contains "C:" with sizeBytes greater than 0
	foundDisk := false
	for _, d := range inv.Disks {
		if d.DeviceID == "C:" && d.SizeBytes > 0 {
			foundDisk = true
		}
	}
	if !foundDisk {
		t.Errorf("expected a disk C: with sizeBytes > 0, got %+v", inv.Disks)
	}

	// And physicalDisks contains an "ssd" entry
	foundSSD := false
	for _, d := range inv.PhysicalDisks {
		if d.MediaType == "ssd" {
			foundSSD = true
		}
	}
	if !foundSSD {
		t.Errorf("expected a physical disk with mediaType ssd, got %+v", inv.PhysicalDisks)
	}

	// And network contains an adapter with a MAC address and an IPv4 address
	foundAdapter := false
	for _, a := range inv.Network {
		if a.MACAddress != "" && len(a.IPv4) > 0 {
			foundAdapter = true
		}
	}
	if !foundAdapter {
		t.Errorf("expected a network adapter with a MAC and IPv4, got %+v", inv.Network)
	}

	// And join.azureAdJoined is true with a non-empty tenantName
	if inv.Join == nil {
		t.Fatal("Join is nil")
	}
	if inv.Join.AzureADJoined == nil || !*inv.Join.AzureADJoined {
		t.Errorf("Join.AzureADJoined = %v, want true", inv.Join.AzureADJoined)
	}
	if inv.Join.TenantName == "" {
		t.Error("Join.TenantName is empty")
	}

	// And the inventory has no warnings
	if len(inv.Warnings) != 0 {
		t.Errorf("expected no warnings, got %v", inv.Warnings)
	}
}

// ----------------------------------------------------------------------
// AC3
// ----------------------------------------------------------------------

func TestScenario_AC3_ExistingFactsUnaffectedByDetailsProbe(t *testing.T) {
	// Given the recorded fixtures for hardware, os, disk and software
	runSucceeding := func() contract.Inventory {
		runner := fake.NewCommandRunner()
		for _, p := range inventory.Probes("windows") {
			content, err := loadFixture("windows", p.Name)
			if err != nil {
				t.Fatalf("failed to load fixture for %s: %v", p.Name, err)
			}
			runner.Results[p.String()] = platform.CommandResult{Stdout: content, ExitCode: 0}
		}
		clock := fake.NewClock(time.Now())
		inv, err := inventory.Collect(runner, clock, "windows")
		if err != nil {
			t.Fatalf("Collect failed: %v", err)
		}
		return inv
	}
	runFailing := func() contract.Inventory {
		runner := fake.NewCommandRunner()
		seedOtherWindowsFixtures(t, runner)
		setDetailsOutput(t, runner, "", 1)
		clock := fake.NewClock(time.Now())
		inv, err := inventory.Collect(runner, clock, "windows")
		if err != nil {
			t.Fatalf("Collect failed: %v", err)
		}
		return inv
	}

	// When Collect runs once with details succeeding and once with details
	// exiting 1
	withDetails := runSucceeding()
	withoutDetails := runFailing()

	// Then the hardware, os base fields, diskBytes and software are identical
	// in both runs
	if withDetails.Hardware.Manufacturer != withoutDetails.Hardware.Manufacturer ||
		withDetails.Hardware.Model != withoutDetails.Hardware.Model ||
		withDetails.Hardware.SerialNumber != withoutDetails.Hardware.SerialNumber ||
		withDetails.Hardware.CPU != withoutDetails.Hardware.CPU ||
		withDetails.Hardware.RAMBytes != withoutDetails.Hardware.RAMBytes ||
		withDetails.Hardware.DiskBytes != withoutDetails.Hardware.DiskBytes {
		t.Errorf("hardware differs: %+v vs %+v", withDetails.Hardware, withoutDetails.Hardware)
	}
	if withDetails.OS.Name != withoutDetails.OS.Name ||
		withDetails.OS.Version != withoutDetails.OS.Version ||
		withDetails.OS.Build != withoutDetails.OS.Build ||
		withDetails.OS.Architecture != withoutDetails.OS.Architecture {
		t.Errorf("os base fields differ: %+v vs %+v", withDetails.OS, withoutDetails.OS)
	}
	if len(withDetails.Software) != len(withoutDetails.Software) {
		t.Fatalf("software length differs: %d vs %d", len(withDetails.Software), len(withoutDetails.Software))
	}
	for i := range withDetails.Software {
		if withDetails.Software[i] != withoutDetails.Software[i] {
			t.Errorf("software[%d] differs: %+v vs %+v", i, withDetails.Software[i], withoutDetails.Software[i])
		}
	}
}

// ----------------------------------------------------------------------
// AC4
// ----------------------------------------------------------------------

func TestScenario_AC4_FailingDetailsProbeLeavesNewFieldsEmpty(t *testing.T) {
	// Given the details probe exits with code 1
	runner := fake.NewCommandRunner()
	seedOtherWindowsFixtures(t, runner)
	setDetailsOutput(t, runner, "", 1)
	clock := fake.NewClock(time.Now())

	// When Collect runs with goos "windows"
	inv, err := inventory.Collect(runner, clock, "windows")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then the warnings contain exactly one "details"
	count := 0
	for _, w := range inv.Warnings {
		if w == inventory.ProbeDetails {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly one %q warning, got %v", inventory.ProbeDetails, inv.Warnings)
	}

	// And firmware, join, disks, physicalDisks, network, os.displayVersion
	// and os.ubr are empty
	if inv.Firmware != nil {
		t.Errorf("Firmware = %+v, want nil", inv.Firmware)
	}
	if inv.Join != nil {
		t.Errorf("Join = %+v, want nil", inv.Join)
	}
	if len(inv.Disks) != 0 {
		t.Errorf("Disks = %+v, want empty", inv.Disks)
	}
	if len(inv.PhysicalDisks) != 0 {
		t.Errorf("PhysicalDisks = %+v, want empty", inv.PhysicalDisks)
	}
	if len(inv.Network) != 0 {
		t.Errorf("Network = %+v, want empty", inv.Network)
	}
	if inv.OS.DisplayVersion != "" {
		t.Errorf("OS.DisplayVersion = %q, want empty", inv.OS.DisplayVersion)
	}
	if inv.OS.UBR != nil {
		t.Errorf("OS.UBR = %v, want nil", inv.OS.UBR)
	}
}

// ----------------------------------------------------------------------
// AC5
// ----------------------------------------------------------------------

func TestScenario_AC5_HangingDetailsProbeTimesOut(t *testing.T) {
	// Given the details probe never answers
	runner := &hangingCommandRunner{
		inner:   fake.NewCommandRunner(),
		hangOn:  inventory.ProbeDetails,
		started: make(chan struct{}),
	}
	for _, p := range inventory.Probes("windows") {
		if p.Name == inventory.ProbeDetails {
			continue
		}
		content, err := loadFixture("windows", p.Name)
		if err != nil {
			t.Fatalf("failed to load fixture for %s: %v", p.Name, err)
		}
		runner.inner.Results[p.String()] = platform.CommandResult{Stdout: content, ExitCode: 0}
	}
	clock := fake.NewClock(time.Now())

	// When the fake clock advances by ProbeTimeout
	go func() {
		<-runner.started
		clock.Advance(inventory.ProbeTimeout)
	}()
	inv, err := inventory.Collect(runner, clock, "windows")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then the warnings contain "details:timeout"
	if !hasWarning(inv.Warnings, inventory.ProbeDetails+":timeout") {
		t.Errorf("expected %q warning, got %v", inventory.ProbeDetails+":timeout", inv.Warnings)
	}
}

// ----------------------------------------------------------------------
// AC6
// ----------------------------------------------------------------------

func TestScenario_AC6_UnparseableDetailsOutput(t *testing.T) {
	// Given the details probe prints "not json"
	runner := fake.NewCommandRunner()
	seedOtherWindowsFixtures(t, runner)
	setDetailsOutput(t, runner, "not json", 0)
	clock := fake.NewClock(time.Now())

	// When Collect runs with goos "windows"
	inv, err := inventory.Collect(runner, clock, "windows")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then the warnings contain "details:unparseable"
	if !hasWarning(inv.Warnings, inventory.ProbeDetails+":unparseable") {
		t.Errorf("expected %q warning, got %v", inventory.ProbeDetails+":unparseable", inv.Warnings)
	}

	// And no new device-detail field is filled
	if inv.Firmware != nil || inv.Join != nil || len(inv.Disks) != 0 || len(inv.PhysicalDisks) != 0 ||
		len(inv.Network) != 0 || inv.OS.DisplayVersion != "" || inv.OS.UBR != nil {
		t.Errorf("expected no new fields filled, got firmware=%+v join=%+v disks=%v physicalDisks=%v network=%v displayVersion=%q ubr=%v",
			inv.Firmware, inv.Join, inv.Disks, inv.PhysicalDisks, inv.Network, inv.OS.DisplayVersion, inv.OS.UBR)
	}
}

// ----------------------------------------------------------------------
// AC7
// ----------------------------------------------------------------------

func TestScenario_AC7_OneFailingSectionDoesNotLoseOthers(t *testing.T) {
	// Given the details output has warnings ["tpm"] and a filled os, bios and
	// network section
	runner := fake.NewCommandRunner()
	seedOtherWindowsFixtures(t, runner)
	setDetailsJSON(t, runner, map[string]interface{}{
		"warnings": []string{"tpm"},
		"os":       map[string]interface{}{"displayVersion": "23H2", "edition": "Enterprise", "ubr": 4317},
		"bios":     map[string]interface{}{"biosVersion": "N32ET91W", "peFirmwareType": 2},
		"network": []map[string]interface{}{
			{"description": "Ethernet", "macAddress": "AA:BB:CC:DD:EE:FF", "ipAddresses": "10.0.0.5"},
		},
	})
	clock := fake.NewClock(time.Now())

	// When Collect runs with goos "windows"
	inv, err := inventory.Collect(runner, clock, "windows")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then the warnings contain "details:tpm"
	if !hasWarning(inv.Warnings, inventory.ProbeDetails+":tpm") {
		t.Errorf("expected %q warning, got %v", inventory.ProbeDetails+":tpm", inv.Warnings)
	}

	// And os.displayVersion, firmware.biosVersion and network are filled
	if inv.OS.DisplayVersion != "23H2" {
		t.Errorf("OS.DisplayVersion = %q, want 23H2", inv.OS.DisplayVersion)
	}
	if inv.Firmware == nil || inv.Firmware.BIOSVersion != "N32ET91W" {
		t.Errorf("Firmware.BIOSVersion = %+v, want N32ET91W", inv.Firmware)
	}
	if len(inv.Network) != 1 || inv.Network[0].MACAddress != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("Network = %+v, want one filled adapter", inv.Network)
	}
}

// ----------------------------------------------------------------------
// AC8
// ----------------------------------------------------------------------

func TestScenario_AC8_LegacyBIOSHasNoSecureBootValue(t *testing.T) {
	// Given the details output reports PEFirmwareType 1
	runner := fake.NewCommandRunner()
	seedOtherWindowsFixtures(t, runner)
	setDetailsJSON(t, runner, map[string]interface{}{
		"bios": map[string]interface{}{"biosVersion": "LEGACY1", "peFirmwareType": 1},
	})
	clock := fake.NewClock(time.Now())

	// When Collect runs with goos "windows"
	inv, err := inventory.Collect(runner, clock, "windows")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then firmware.type is "bios"
	if inv.Firmware == nil || inv.Firmware.Type != "bios" {
		t.Fatalf("Firmware = %+v, want type bios", inv.Firmware)
	}
	// And firmware.secureBootEnabled is nil
	if inv.Firmware.SecureBootEnabled != nil {
		t.Errorf("Firmware.SecureBootEnabled = %v, want nil", inv.Firmware.SecureBootEnabled)
	}
	// And no "details:secureBoot" warning is present
	if hasWarning(inv.Warnings, inventory.ProbeDetails+":secureBoot") {
		t.Errorf("unexpected details:secureBoot warning: %v", inv.Warnings)
	}
}

// ----------------------------------------------------------------------
// AC9
// ----------------------------------------------------------------------

func TestScenario_AC9_DsregcmdValuesMapToBooleans(t *testing.T) {
	// Scenario Outline: dsregcmd values map to booleans
	cases := []struct {
		value  string
		result *bool
	}{
		{"YES", boolPtr(true)},
		{"no", boolPtr(false)},
		{"MAYBE", nil},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			// Given the dsregcmd section reports AzureAdJoined "<value>"
			runner := fake.NewCommandRunner()
			seedOtherWindowsFixtures(t, runner)
			setDetailsJSON(t, runner, map[string]interface{}{
				"dsregcmd": map[string]interface{}{"AzureAdJoined": tc.value},
			})
			clock := fake.NewClock(time.Now())

			// When Collect runs with goos "windows"
			inv, err := inventory.Collect(runner, clock, "windows")
			if err != nil {
				t.Fatalf("Collect failed: %v", err)
			}

			// Then join.azureAdJoined is <result>
			if tc.result == nil {
				if inv.Join != nil && inv.Join.AzureADJoined != nil {
					t.Errorf("Join.AzureADJoined = %v, want nil", *inv.Join.AzureADJoined)
				}
				return
			}
			if inv.Join == nil || inv.Join.AzureADJoined == nil || *inv.Join.AzureADJoined != *tc.result {
				t.Errorf("Join.AzureADJoined = %v, want %v", inv.Join, *tc.result)
			}
		})
	}
}

func TestScenario_AC9_DsregcmdUnavailableFallsBackToPartOfDomain(t *testing.T) {
	// Given the details output has no dsregcmd section and warnings ["dsregcmd"]
	// And the computer section reports PartOfDomain true and Domain "contoso.local"
	runner := fake.NewCommandRunner()
	seedOtherWindowsFixtures(t, runner)
	setDetailsJSON(t, runner, map[string]interface{}{
		"warnings": []string{"dsregcmd"},
		"computer": map[string]interface{}{"partOfDomain": true, "domain": "contoso.local"},
	})
	clock := fake.NewClock(time.Now())

	// When Collect runs with goos "windows"
	inv, err := inventory.Collect(runner, clock, "windows")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then the warnings contain "details:dsregcmd"
	if !hasWarning(inv.Warnings, inventory.ProbeDetails+":dsregcmd") {
		t.Errorf("expected %q warning, got %v", inventory.ProbeDetails+":dsregcmd", inv.Warnings)
	}
	// And join.domainJoined is true and join.domain is "contoso.local"
	if inv.Join == nil || inv.Join.DomainJoined == nil || !*inv.Join.DomainJoined {
		t.Errorf("Join.DomainJoined = %v, want true", inv.Join)
	}
	if inv.Join == nil || inv.Join.Domain != "contoso.local" {
		t.Errorf("Join.Domain = %v, want contoso.local", inv.Join)
	}
}

func TestScenario_AC9_WorkgroupNameIsNotReportedAsADomain(t *testing.T) {
	// Given the computer section reports PartOfDomain false and Domain "WORKGROUP"
	runner := fake.NewCommandRunner()
	seedOtherWindowsFixtures(t, runner)
	setDetailsJSON(t, runner, map[string]interface{}{
		"computer": map[string]interface{}{"partOfDomain": false, "domain": "WORKGROUP"},
	})
	clock := fake.NewClock(time.Now())

	// When Collect runs with goos "windows"
	inv, err := inventory.Collect(runner, clock, "windows")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then join.domain is empty
	if inv.Join != nil && inv.Join.Domain != "" {
		t.Errorf("Join.Domain = %q, want empty", inv.Join.Domain)
	}
}

// ----------------------------------------------------------------------
// AC10
// ----------------------------------------------------------------------

func TestScenario_AC10_MixedAddressesSplitAndSingleStringsBecomeLists(t *testing.T) {
	// Given an adapter with ipAddresses ["10.0.0.5","fe80::1"] and dnsServers "8.8.8.8"
	runner := fake.NewCommandRunner()
	seedOtherWindowsFixtures(t, runner)
	setDetailsJSON(t, runner, map[string]interface{}{
		"network": []map[string]interface{}{
			{
				"description": "Ethernet",
				"macAddress":  "11:22:33:44:55:66",
				"ipAddresses": []string{"10.0.0.5", "fe80::1"},
				"dnsServers":  "8.8.8.8",
			},
		},
	})
	clock := fake.NewClock(time.Now())

	// When Collect runs with goos "windows"
	inv, err := inventory.Collect(runner, clock, "windows")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then the adapter ipv4 is ["10.0.0.5"], ipv6 is ["fe80::1"] and dnsServers is ["8.8.8.8"]
	if len(inv.Network) != 1 {
		t.Fatalf("expected one network adapter, got %+v", inv.Network)
	}
	adapter := inv.Network[0]
	if len(adapter.IPv4) != 1 || adapter.IPv4[0] != "10.0.0.5" {
		t.Errorf("IPv4 = %v, want [10.0.0.5]", adapter.IPv4)
	}
	if len(adapter.IPv6) != 1 || adapter.IPv6[0] != "fe80::1" {
		t.Errorf("IPv6 = %v, want [fe80::1]", adapter.IPv6)
	}
	if len(adapter.DNSServers) != 1 || adapter.DNSServers[0] != "8.8.8.8" {
		t.Errorf("DNSServers = %v, want [8.8.8.8]", adapter.DNSServers)
	}
}

// ----------------------------------------------------------------------
// AC11
// ----------------------------------------------------------------------

func TestScenario_AC11_PhysicalDiskMediaTypeNormalisation(t *testing.T) {
	cases := []struct {
		raw    string
		mapped string
	}{
		{"SSD", "ssd"},
		{"4", "ssd"},
		{"HDD", "hdd"},
		{"3", "hdd"},
		{"SCM", "scm"},
		{"5", "scm"},
		{"0", "unspecified"},
		{"Unspecified", "unspecified"},
		{"Weird", "unspecified"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			// Given a physical disk with MediaType "<raw>"
			runner := fake.NewCommandRunner()
			seedOtherWindowsFixtures(t, runner)
			setDetailsJSON(t, runner, map[string]interface{}{
				"physicalDisks": []map[string]interface{}{
					{"friendlyName": "Disk1", "mediaType": tc.raw, "size": 123456},
				},
			})
			clock := fake.NewClock(time.Now())

			// When Collect runs with goos "windows"
			inv, err := inventory.Collect(runner, clock, "windows")
			if err != nil {
				t.Fatalf("Collect failed: %v", err)
			}

			// Then its mediaType is "<mapped>"
			if len(inv.PhysicalDisks) != 1 || inv.PhysicalDisks[0].MediaType != tc.mapped {
				t.Errorf("PhysicalDisks = %+v, want mediaType %q", inv.PhysicalDisks, tc.mapped)
			}
		})
	}
}

// ----------------------------------------------------------------------
// AC12
// ----------------------------------------------------------------------

func TestScenario_AC12_MalformedAndOversizedValuesAreDroppedOrCapped(t *testing.T) {
	// Given the details output has installDate "garbage", ubr -1, 40 disks and
	// 20 adapters
	disks := make([]map[string]interface{}, 40)
	for i := range disks {
		disks[i] = map[string]interface{}{"deviceId": fmt.Sprintf("D%d:", i), "size": 1024}
	}
	adapters := make([]map[string]interface{}, 20)
	for i := range adapters {
		adapters[i] = map[string]interface{}{"macAddress": fmt.Sprintf("AA:BB:CC:DD:EE:%02d", i)}
	}
	runner := fake.NewCommandRunner()
	seedOtherWindowsFixtures(t, runner)
	setDetailsJSON(t, runner, map[string]interface{}{
		"os":      map[string]interface{}{"installDate": "garbage", "ubr": -1},
		"disks":   disks,
		"network": adapters,
	})
	clock := fake.NewClock(time.Now())

	// When Collect runs with goos "windows"
	inv, err := inventory.Collect(runner, clock, "windows")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then os.installDate is empty and os.ubr is nil
	if inv.OS.InstallDate != "" {
		t.Errorf("OS.InstallDate = %q, want empty", inv.OS.InstallDate)
	}
	if inv.OS.UBR != nil {
		t.Errorf("OS.UBR = %v, want nil", inv.OS.UBR)
	}

	// And disks has 32 entries and network has 16 entries
	if len(inv.Disks) != 32 {
		t.Errorf("len(Disks) = %d, want 32", len(inv.Disks))
	}
	if len(inv.Network) != 16 {
		t.Errorf("len(Network) = %d, want 16", len(inv.Network))
	}
}

// ----------------------------------------------------------------------
// AC13
// ----------------------------------------------------------------------

func TestScenario_AC13_OldShapeInventoryMarshalsWithoutNewKeys(t *testing.T) {
	// Given an Inventory with only the existing hardware, os and software fields
	inv := contract.Inventory{
		Hardware: contract.InventoryHardware{
			Manufacturer: "Dell", Model: "OptiPlex", SerialNumber: "ABC123",
			CPU: "Intel", RAMBytes: 1, DiskBytes: 2,
		},
		OS:       contract.InventoryOS{Name: "Windows", Version: "10", Build: "19045", Architecture: "amd64"},
		Software: []contract.SoftwareEntry{},
	}

	// When it is marshalled to JSON
	data, err := json.Marshal(inv)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	s := string(data)

	// Then none of the new device-detail keys appear
	newKeys := []string{
		"firmware", "disks", "physicalDisks", "network", "join",
		"edition", "displayVersion", "ubr", "installDate", "lastBootAt", "locale",
		"systemFamily", "systemSku", "cpuCores", "cpuLogicalProcessors",
	}
	for _, key := range newKeys {
		if strings.Contains(s, `"`+key+`"`) {
			t.Errorf("marshalled JSON should not contain key %q: %s", key, s)
		}
	}
}

func boolPtr(b bool) *bool { return &b }
