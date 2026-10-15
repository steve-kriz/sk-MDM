package posture_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/posture"
)

// loadFixture reads a fixture file from testdata.
func loadFixture(goos string, probeName string) (string, error) {
	// Testdata is relative to the posture package directory
	path := filepath.Join("testdata", goos, probeName+".txt")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// TestScenario_BitLockerPostureIsRead tests Windows BitLocker.
func TestScenario_BitLockerPostureIsRead(t *testing.T) {
	// Given the recorded Windows BitLocker and Defender output
	runner := fake.NewCommandRunner()
	probes := posture.Probes("windows")

	// Load fixtures for each probe
	for _, p := range probes {
		content, err := loadFixture("windows", p.Name)
		if err != nil {
			t.Fatalf("failed to load fixture for %s: %v", p.Name, err)
		}
		runner.Results[p.String()] = platform.CommandResult{
			Stdout:   content,
			ExitCode: 0,
		}
	}

	clock := fake.NewClock(time.Now())

	// When posture Collect runs with goos windows
	pos, err := posture.Collect(runner, clock, "windows")

	// Then diskEncryption.enabled is true, method is bitlocker and antivirus.name is "Microsoft Defender"
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if !pos.DiskEncryption.Enabled {
		t.Error("diskEncryption.enabled should be true")
	}
	if pos.DiskEncryption.Method != posture.MethodBitLocker {
		t.Errorf("method should be %q, got %q", posture.MethodBitLocker, pos.DiskEncryption.Method)
	}
	if pos.Antivirus.Name != "Microsoft Defender" {
		t.Errorf("antivirus.name should be 'Microsoft Defender', got %q", pos.Antivirus.Name)
	}
}

// TestScenario_FileVaultPostureIsRead tests macOS FileVault.
func TestScenario_FileVaultPostureIsRead(t *testing.T) {
	// Given the recorded macOS fdesetup and socketfilterfw output
	runner := fake.NewCommandRunner()
	probes := posture.Probes("darwin")

	// Load fixtures for each probe
	for _, p := range probes {
		content, err := loadFixture("darwin", p.Name)
		if err != nil {
			t.Fatalf("failed to load fixture for %s: %v", p.Name, err)
		}
		runner.Results[p.String()] = platform.CommandResult{
			Stdout:   content,
			ExitCode: 0,
		}
	}

	clock := fake.NewClock(time.Now())

	// When posture Collect runs with goos darwin
	pos, err := posture.Collect(runner, clock, "darwin")

	// Then diskEncryption.method is filevault and firewall.enabled matches the fixture
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if pos.DiskEncryption.Method != posture.MethodFileVault {
		t.Errorf("method should be %q, got %q", posture.MethodFileVault, pos.DiskEncryption.Method)
	}
}

// TestScenario_UnparseableOutputBecomesAWarning tests unparseable posture output.
func TestScenario_UnparseableOutputBecomesAWarning(t *testing.T) {
	// Given the firewall probe returns "???"
	runner := fake.NewCommandRunner()
	probes := posture.Probes("windows")

	for _, p := range probes {
		if p.Name == posture.ProbeFirewall {
			// Return unparseable output
			runner.Results[p.String()] = platform.CommandResult{
				Stdout:   "???",
				ExitCode: 0,
			}
		} else {
			content, err := loadFixture("windows", p.Name)
			if err == nil {
				runner.Results[p.String()] = platform.CommandResult{
					Stdout:   content,
					ExitCode: 0,
				}
			}
		}
	}

	clock := fake.NewClock(time.Now())

	// When posture Collect runs
	pos, err := posture.Collect(runner, clock, "windows")

	// Then firewall.enabled is false and Warnings contains "firewall:unparseable"
	if err != nil {
		t.Fatalf("Collect should not error: %v", err)
	}
	if pos.Firewall.Enabled {
		t.Error("firewall.enabled should be false for unparseable output")
	}
	found := false
	for _, w := range pos.Warnings {
		if w == "firewall:unparseable" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Warnings should contain 'firewall:unparseable', got %v", pos.Warnings)
	}
}

// TestScenario_EmptyAndOversizedOutputDoNotPanic tests large outputs don't panic.
func TestScenario_EmptyAndOversizedOutputDoNotPanic(t *testing.T) {
	// Given probes returning empty output and 1 MB of output
	runner := fake.NewCommandRunner()
	probes := posture.Probes("windows")

	for _, p := range probes {
		if p.Name == posture.ProbeFirewall {
			// Empty output
			runner.Results[p.String()] = platform.CommandResult{
				Stdout:   "",
				ExitCode: 0,
			}
		} else if p.Name == posture.ProbeAntivirus {
			// 1 MB of junk
			runner.Results[p.String()] = platform.CommandResult{
				Stdout:   strings.Repeat("x", 1024*1024),
				ExitCode: 0,
			}
		} else {
			content, err := loadFixture("windows", p.Name)
			if err == nil {
				runner.Results[p.String()] = platform.CommandResult{
					Stdout:   content,
					ExitCode: 0,
				}
			}
		}
	}

	clock := fake.NewClock(time.Now())

	// When Collect runs
	// Then it returns without panicking
	pos, err := posture.Collect(runner, clock, "windows")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	// Just verify we got a result
	_ = pos
}

// TestScenario_HangingProbeTimesOut tests the timeout scenario for posture.
func TestScenario_HangingProbeTimesOut(t *testing.T) {
	// Given a probe that never returns and a fake clock
	runner := &hangingCommandRunner{
		inner:   fake.NewCommandRunner(),
		hangOn:  posture.ProbeFirewall,
		started: make(chan struct{}),
	}

	probes := posture.Probes("windows")
	for _, p := range probes {
		if p.Name != posture.ProbeFirewall {
			content, err := loadFixture("windows", p.Name)
			if err == nil {
				runner.inner.Results[p.String()] = platform.CommandResult{
					Stdout:   content,
					ExitCode: 0,
				}
			}
		}
	}

	clock := fake.NewClock(time.Now())

	// When Collect runs and the test advances the fake clock by 30 seconds
	go func() {
		<-runner.started
		clock.Advance(posture.ProbeTimeout)
	}()

	pos, err := posture.Collect(runner, clock, "windows")

	// Then Warnings contains "firewall:timeout", the remaining probes still ran
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	found := false
	for _, w := range pos.Warnings {
		if w == posture.ProbeFirewall+":timeout" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Warnings should contain %q:timeout, got %v", posture.ProbeFirewall, pos.Warnings)
	}
}

// hangingCommandRunner wraps a fake runner but makes one probe hang forever.
type hangingCommandRunner struct {
	inner   *fake.CommandRunner
	hangOn  string
	started chan struct{}
}

func (h *hangingCommandRunner) Run(ctx context.Context, name string, args ...string) (platform.CommandResult, error) {
	cmd := fake.Command{Name: name, Args: append([]string(nil), args...)}
	cmdStr := cmd.String()

	// Check if this is the probe that should hang
	for _, p := range posture.Probes("windows") {
		if p.Name == h.hangOn && p.String() == cmdStr {
			close(h.started)
			// Block forever
			select {}
		}
	}

	return h.inner.Run(ctx, name, args...)
}

// TestScenario_WarningsAreCarriedOnTheWire tests JSON marshalling for posture.
func TestScenario_WarningsAreCarriedOnTheWire(t *testing.T) {
	// Given a collection result holding warnings
	pos := contract.Posture{
		DiskEncryption: contract.DiskEncryption{},
		Firewall:       contract.Firewall{},
		Antivirus:      contract.Antivirus{},
		OSUpdate:       contract.OSUpdate{},
		LocalAdmins:    []string{},
		Warnings:       []string{"firewall", "antivirus:unparseable"},
	}

	// When the result is marshalled to JSON
	data, err := marshalJSON(pos)
	if err != nil {
		t.Fatalf("marshalling failed: %v", err)
	}

	// Then the warnings array contains the warnings
	if !strings.Contains(string(data), `"warnings":["firewall","antivirus:unparseable"]`) &&
		!strings.Contains(string(data), `"warnings": ["firewall", "antivirus:unparseable"]`) {
		t.Errorf("warnings not found in JSON: %s", string(data))
	}
}

// TestScenario_EmptyWarningsListIsOmittedFromWire tests omitempty for posture.
func TestScenario_EmptyWarningsListIsOmittedFromWire(t *testing.T) {
	// Given a collection result with no warnings
	pos := contract.Posture{
		DiskEncryption: contract.DiskEncryption{},
		Firewall:       contract.Firewall{},
		Antivirus:      contract.Antivirus{},
		OSUpdate:       contract.OSUpdate{},
		LocalAdmins:    []string{},
		Warnings:       nil,
	}

	// When the result is marshalled to JSON
	data, err := marshalJSON(pos)
	if err != nil {
		t.Fatalf("marshalling failed: %v", err)
	}

	// Then the JSON contains no "warnings" key
	if strings.Contains(string(data), `"warnings"`) {
		t.Errorf("warnings key should not appear in JSON: %s", string(data))
	}
}

// TestScenario_LocalAdminsInitToEmptySlice tests LocalAdmins initialization.
func TestScenario_LocalAdminsInitToEmptySlice(t *testing.T) {
	runner := fake.NewCommandRunner()
	probes := posture.Probes("windows")

	// Set up probes with local admins
	for _, p := range probes {
		if p.Name == posture.ProbeLocalAdmins {
			runner.Results[p.String()] = platform.CommandResult{
				Stdout:   "DOMAIN\\user1\nDOMAIN\\user2",
				ExitCode: 0,
			}
		} else {
			content, err := loadFixture("windows", p.Name)
			if err == nil {
				runner.Results[p.String()] = platform.CommandResult{
					Stdout:   content,
					ExitCode: 0,
				}
			}
		}
	}

	clock := fake.NewClock(time.Now())
	pos, err := posture.Collect(runner, clock, "windows")

	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if len(pos.LocalAdmins) == 0 {
		t.Error("LocalAdmins should be populated")
	}
}

// TestScenario_UnsupportedGoosReturnsError tests unsupported OS for posture.
func TestScenario_UnsupportedGoosReturnsError(t *testing.T) {
	runner := fake.NewCommandRunner()
	clock := fake.NewClock(time.Now())

	// When Collect runs with unsupported goos
	_, err := posture.Collect(runner, clock, "unsupported")

	// Then it returns an error
	if err == nil {
		t.Error("expected error for unsupported goos")
	}
}

// Helper to marshal posture to JSON
func marshalJSON(pos contract.Posture) ([]byte, error) {
	return json.Marshal(pos)
}

// TestUnit_ProbeString tests the posture Probe.String method
func TestUnit_ProbeString(t *testing.T) {
	p := posture.Probe{Name: "test", Cmd: "cmd"}
	expected := "cmd"
	if p.String() != expected {
		t.Errorf("expected %q, got %q", expected, p.String())
	}

	p = posture.Probe{Name: "test", Cmd: "cmd", Args: []string{"arg1", "arg2"}}
	expected = "cmd arg1 arg2"
	if p.String() != expected {
		t.Errorf("expected %q, got %q", expected, p.String())
	}
}

// TestUnit_Probes tests the posture Probes function
func TestUnit_Probes(t *testing.T) {
	tests := []struct {
		goos     string
		hasProbe bool
	}{
		{"windows", true},
		{"darwin", true},
		{"linux", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.goos, func(t *testing.T) {
			probes := posture.Probes(tt.goos)
			if tt.hasProbe && len(probes) == 0 {
				t.Error("expected probes for", tt.goos)
			}
			if !tt.hasProbe && len(probes) != 0 {
				t.Error("expected no probes for", tt.goos)
			}
		})
	}
}

// TestUnit_ParseBool tests boolean parsing
func TestUnit_ParseBool(t *testing.T) {
	tests := []struct {
		input       string
		expected    bool
		shouldParse bool
	}{
		{"true", true, true},
		{"yes", true, true},
		{"on", true, true},
		{"1", true, true},
		{"enabled", true, true},
		{"enable", true, true},
		{"false", false, true},
		{"no", false, true},
		{"off", false, true},
		{"0", false, true},
		{"disabled", false, true},
		{"disable", false, true},
		{"maybe", false, false},
		{"", false, false},
		{"  true  ", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			runner := fake.NewCommandRunner()
			probes := posture.Probes("windows")

			for _, p := range probes {
				if p.Name == posture.ProbeFirewall {
					runner.Results[p.String()] = platform.CommandResult{
						Stdout:   "profile=" + tt.input,
						ExitCode: 0,
					}
				} else {
					runner.Results[p.String()] = platform.CommandResult{
						Stdout:   "",
						ExitCode: 0,
					}
				}
			}

			clock := fake.NewClock(time.Now())
			pos, _ := posture.Collect(runner, clock, "windows")

			if tt.shouldParse {
				if pos.Firewall.Enabled != tt.expected {
					t.Errorf("expected %v, got %v", tt.expected, pos.Firewall.Enabled)
				}
				// Should not add unparseable warning for valid input
				for _, w := range pos.Warnings {
					if strings.Contains(w, "firewall:unparseable") {
						t.Errorf("should not have unparseable warning for valid input")
					}
				}
			} else {
				// Should have unparseable warning for invalid input
				found := false
				for _, w := range pos.Warnings {
					if strings.Contains(w, "firewall:unparseable") {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("should have unparseable warning for invalid input")
				}
			}
		})
	}
}

// TestUnit_FailingProbeAddsWarning tests that failing probes add warnings.
func TestUnit_FailingProbeAddsWarning(t *testing.T) {
	runner := fake.NewCommandRunner()
	probes := posture.Probes("windows")

	for _, p := range probes {
		if p.Name == posture.ProbeFirewall {
			// Probe exits with error code
			runner.Results[p.String()] = platform.CommandResult{
				Stdout:   "",
				ExitCode: 1,
			}
		} else {
			content, err := loadFixture("windows", p.Name)
			if err == nil {
				runner.Results[p.String()] = platform.CommandResult{
					Stdout:   content,
					ExitCode: 0,
				}
			}
		}
	}

	clock := fake.NewClock(time.Now())
	pos, err := posture.Collect(runner, clock, "windows")

	if err != nil {
		t.Fatalf("Collect should not error: %v", err)
	}

	// Should have firewall warning
	found := false
	for _, w := range pos.Warnings {
		if w == posture.ProbeFirewall {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Warnings should contain %q, got %v", posture.ProbeFirewall, pos.Warnings)
	}
}

// buildWindowsRunner arranges a fake runner replaying fixtureName for the
// antivirus probe and the unchanged fixture for every other Windows probe.
func buildWindowsRunner(t *testing.T, fixturePath string) *fake.CommandRunner {
	t.Helper()
	runner := fake.NewCommandRunner()
	for _, p := range posture.Probes("windows") {
		if p.Name == posture.ProbeAntivirus {
			data, err := os.ReadFile(fixturePath)
			if err != nil {
				t.Fatalf("failed to load %s: %v", fixturePath, err)
			}
			runner.Results[p.String()] = platform.CommandResult{Stdout: string(data), ExitCode: 0}
			continue
		}
		content, err := loadFixture("windows", p.Name)
		if err == nil {
			runner.Results[p.String()] = platform.CommandResult{Stdout: content, ExitCode: 0}
		}
	}
	return runner
}

// TestScenario_WindowsAntivirusProbeQueriesDefenderAndSecurityCenter covers the
// probe script's text and the unchanged existing fixture.
func TestScenario_WindowsAntivirusProbeQueriesDefenderAndSecurityCenter(t *testing.T) {
	var antivirusProbe posture.Probe
	for _, p := range posture.Probes("windows") {
		if p.Name == posture.ProbeAntivirus {
			antivirusProbe = p
		}
	}
	if len(antivirusProbe.Args) == 0 {
		t.Fatal("antivirus probe has no args")
	}
	script := antivirusProbe.Args[len(antivirusProbe.Args)-1]

	if !strings.Contains(script, "Get-MpComputerStatus -ErrorAction SilentlyContinue") {
		t.Error("script should contain Get-MpComputerStatus -ErrorAction SilentlyContinue")
	}
	if !strings.Contains(script, "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue") {
		t.Error("script should contain the Security Center query")
	}
	if !strings.Contains(script, "product=$($_.productState)|$($_.displayName)") {
		t.Error("script should print one product line per product")
	}

	// The unchanged fixture still yields the same antivirus block.
	runner := buildWindowsRunner(t, filepath.Join("testdata", "windows", "antivirus.txt"))
	clock := fake.NewClock(time.Now())
	pos, err := posture.Collect(runner, clock, "windows")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if pos.Antivirus.Name != "Microsoft Defender" || !pos.Antivirus.Enabled || pos.Antivirus.DefinitionsAgeDays != 1 {
		t.Errorf("antivirus = %+v, want {Microsoft Defender true 1}", pos.Antivirus)
	}
}

// TestScenario_ActiveThirdPartyAntivirusSatisfiesEnabled covers the new
// antivirus-thirdparty.txt fixture.
func TestScenario_ActiveThirdPartyAntivirusSatisfiesEnabled(t *testing.T) {
	runner := buildWindowsRunner(t, filepath.Join("testdata", "windows", "antivirus-thirdparty.txt"))
	clock := fake.NewClock(time.Now())

	pos, err := posture.Collect(runner, clock, "windows")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if pos.Antivirus.Name != "Contoso Endpoint Security" {
		t.Errorf("antivirus.name = %q, want Contoso Endpoint Security", pos.Antivirus.Name)
	}
	if !pos.Antivirus.Enabled {
		t.Error("antivirus.enabled should be true")
	}
	if pos.Antivirus.DefinitionsAgeDays != 0 {
		t.Errorf("antivirus.definitionsAgeDays = %d, want 0", pos.Antivirus.DefinitionsAgeDays)
	}
	for _, w := range pos.Warnings {
		if w == "antivirus:unparseable" {
			t.Error("warnings should not contain antivirus:unparseable")
		}
	}
}

// TestScenario_AC1_RealTimeProtectionOffCountsAsDisabled covers the new
// antivirus-realtime-off.txt fixture (TASK-055): AntivirusEnabled=True with
// RealTimeProtectionEnabled=False must still print enabled=False, since the
// probe script ANDs the two booleans together.
func TestScenario_AC1_RealTimeProtectionOffCountsAsDisabled(t *testing.T) {
	// Given the Windows antivirus probe printed the fixture
	// "antivirus-realtime-off.txt"
	runner := buildWindowsRunner(t, filepath.Join("testdata", "windows", "antivirus-realtime-off.txt"))
	clock := fake.NewClock(time.Now())

	// When posture is collected for goos "windows"
	pos, err := posture.Collect(runner, clock, "windows")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then posture.antivirus.enabled is false
	if pos.Antivirus.Enabled {
		t.Error("antivirus.enabled should be false when real-time protection is off")
	}
	// And posture.antivirus.name is "Microsoft Defender"
	if pos.Antivirus.Name != "Microsoft Defender" {
		t.Errorf("antivirus.name = %q, want Microsoft Defender", pos.Antivirus.Name)
	}
	if pos.Antivirus.DefinitionsAgeDays != 1 {
		t.Errorf("antivirus.definitionsAgeDays = %d, want 1", pos.Antivirus.DefinitionsAgeDays)
	}
}

// TestScenario_AC1_ProbeScriptCombinesAntivirusEnabledAndRealTime covers the
// exact enabled= line text AC1 requires.
func TestScenario_AC1_ProbeScriptCombinesAntivirusEnabledAndRealTime(t *testing.T) {
	var antivirusProbe posture.Probe
	for _, p := range posture.Probes("windows") {
		if p.Name == posture.ProbeAntivirus {
			antivirusProbe = p
		}
	}
	script := antivirusProbe.Args[len(antivirusProbe.Args)-1]
	want := "enabled=$([bool]$s.AntivirusEnabled -and [bool]$s.RealTimeProtectionEnabled)"
	if !strings.Contains(script, want) {
		t.Errorf("script should contain %q, got %q", want, script)
	}
}

// TestScenario_InactiveOrMalformedProductLinesDoNotCountAsActive covers every
// product line that must not flip antivirus.enabled to true.
func TestScenario_InactiveOrMalformedProductLinesDoNotCountAsActive(t *testing.T) {
	cases := []string{
		"product=393472|Off AV",
		"product=270336|Snoozed AV",
		"product=abc|Bad AV",
		"product=266240|",
		"product=266240",
	}

	for _, line := range cases {
		t.Run(line, func(t *testing.T) {
			runner := fake.NewCommandRunner()
			for _, p := range posture.Probes("windows") {
				if p.Name == posture.ProbeAntivirus {
					stdout := "name=Microsoft Defender\nenabled=False\ndefinitionsAgeDays=0\n" + line
					runner.Results[p.String()] = platform.CommandResult{Stdout: stdout, ExitCode: 0}
					continue
				}
				content, err := loadFixture("windows", p.Name)
				if err == nil {
					runner.Results[p.String()] = platform.CommandResult{Stdout: content, ExitCode: 0}
				}
			}
			clock := fake.NewClock(time.Now())

			pos, err := posture.Collect(runner, clock, "windows")
			if err != nil {
				t.Fatalf("Collect failed: %v", err)
			}
			if pos.Antivirus.Enabled {
				t.Errorf("antivirus.enabled should be false for line %q", line)
			}
			if pos.Antivirus.Name != "Microsoft Defender" {
				t.Errorf("antivirus.name = %q, want Microsoft Defender for line %q", pos.Antivirus.Name, line)
			}
		})
	}
}

// TestScenario_JunkAntivirusOutputIsStillUnparseable covers the 1 MB junk case
// still producing the existing warning, unaffected by the product-line parse.
func TestScenario_JunkAntivirusOutputIsStillUnparseable(t *testing.T) {
	runner := fake.NewCommandRunner()
	for _, p := range posture.Probes("windows") {
		if p.Name == posture.ProbeAntivirus {
			runner.Results[p.String()] = platform.CommandResult{
				Stdout:   strings.Repeat("x", 1024*1024),
				ExitCode: 0,
			}
			continue
		}
		content, err := loadFixture("windows", p.Name)
		if err == nil {
			runner.Results[p.String()] = platform.CommandResult{Stdout: content, ExitCode: 0}
		}
	}
	clock := fake.NewClock(time.Now())

	pos, err := posture.Collect(runner, clock, "windows")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	found := false
	for _, w := range pos.Warnings {
		if w == "antivirus:unparseable" {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings should contain antivirus:unparseable, got %v", pos.Warnings)
	}
}

// TestUnit_MultipleWarnings tests that multiple warnings accumulate.
func TestUnit_MultipleWarnings(t *testing.T) {
	runner := fake.NewCommandRunner()
	probes := posture.Probes("windows")

	for _, p := range probes {
		if p.Name == posture.ProbeFirewall || p.Name == posture.ProbeAntivirus {
			// Both fail
			runner.Results[p.String()] = platform.CommandResult{
				Stdout:   "???",
				ExitCode: 0,
			}
		} else {
			content, err := loadFixture("windows", p.Name)
			if err == nil {
				runner.Results[p.String()] = platform.CommandResult{
					Stdout:   content,
					ExitCode: 0,
				}
			}
		}
	}

	clock := fake.NewClock(time.Now())
	pos, _ := posture.Collect(runner, clock, "windows")

	warningsCount := len(pos.Warnings)
	if warningsCount < 2 {
		t.Errorf("expected at least 2 warnings, got %d: %v", warningsCount, pos.Warnings)
	}
}
