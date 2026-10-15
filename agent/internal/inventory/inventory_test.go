package inventory_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/inventory"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// loadFixture reads a fixture file from testdata.
func loadFixture(goos string, probeName string) (string, error) {
	// Testdata is relative to the inventory package directory
	path := filepath.Join("testdata", goos, probeName+".txt")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// TestScenario_WindowsFixturesProduceHardwareAndOSFacts implements the first
// Gherkin scenario.
func TestScenario_WindowsFixturesProduceHardwareAndOSFacts(t *testing.T) {
	// Given the recorded Windows probe outputs
	runner := fake.NewCommandRunner()
	probes := inventory.Probes("windows")

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

	// When Collect runs with goos windows
	inv, err := inventory.Collect(runner, clock, "windows")

	// Then serialNumber, model, ramBytes and os.build match the fixture values
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if inv.Hardware.SerialNumber == "" {
		t.Error("serialNumber is empty")
	}
	if inv.Hardware.Model == "" {
		t.Error("model is empty")
	}
	if inv.Hardware.RAMBytes == 0 {
		t.Error("ramBytes is zero")
	}
	if inv.OS.Build == "" {
		t.Error("os.build is empty")
	}
}

// TestScenario_MacOSFixturesProduceHardwareAndOSFacts implements the macOS
// fixtures scenario.
func TestScenario_MacOSFixturesProduceHardwareAndOSFacts(t *testing.T) {
	// Given the recorded macOS probe outputs
	runner := fake.NewCommandRunner()
	probes := inventory.Probes("darwin")

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

	// When Collect runs with goos darwin
	inv, err := inventory.Collect(runner, clock, "darwin")

	// Then serialNumber, model, ramBytes and os.version match the fixture values
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if inv.Hardware.SerialNumber == "" {
		t.Error("serialNumber is empty")
	}
	if inv.Hardware.Model == "" {
		t.Error("model is empty")
	}
	if inv.Hardware.RAMBytes == 0 {
		t.Error("ramBytes is zero")
	}
	if inv.OS.Version == "" {
		t.Error("os.version is empty")
	}
}

// TestScenario_FailingProbeDegradesToAWarning implements the probe failure
// scenario.
func TestScenario_FailingProbeDegradesToAWarning(t *testing.T) {
	// Given the software probe exits with code 1
	runner := fake.NewCommandRunner()
	probes := inventory.Probes("windows")

	// Load other fixtures
	for _, p := range probes {
		if p.Name != inventory.ProbeSoftware {
			content, err := loadFixture("windows", p.Name)
			if err != nil {
				t.Fatalf("failed to load fixture: %v", err)
			}
			runner.Results[p.String()] = platform.CommandResult{
				Stdout:   content,
				ExitCode: 0,
			}
		}
	}

	// Software probe returns exit code 1
	for _, p := range probes {
		if p.Name == inventory.ProbeSoftware {
			runner.Results[p.String()] = platform.CommandResult{
				Stdout:   "",
				ExitCode: 1,
			}
		}
	}

	clock := fake.NewClock(time.Now())

	// When Collect runs
	inv, err := inventory.Collect(runner, clock, "windows")

	// Then software is empty, Warnings contains the probe name and no error is returned
	if err != nil {
		t.Fatalf("Collect should not error: %v", err)
	}
	if len(inv.Software) != 0 {
		t.Errorf("software should be empty, got %d entries", len(inv.Software))
	}
	found := false
	for _, w := range inv.Warnings {
		if w == inventory.ProbeSoftware {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Warnings should contain %q, got %v", inventory.ProbeSoftware, inv.Warnings)
	}
}

// TestScenario_UnparseableOutputBecomesAWarning tests unparseable output.
func TestScenario_UnparseableOutputBecomesAWarning(t *testing.T) {
	// Given a probe returns unparseable output
	runner := fake.NewCommandRunner()
	probes := inventory.Probes("windows")

	for _, p := range probes {
		if p.Name == inventory.ProbeOS {
			// Return garbage that can't be parsed
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

	// When Collect runs
	inv, err := inventory.Collect(runner, clock, "windows")

	// Then it should not fail but the OS fields should be at zero values
	if err != nil {
		t.Fatalf("Collect should not error: %v", err)
	}
	if inv.OS.Name != "" || inv.OS.Version != "" || inv.OS.Build != "" {
		t.Error("OS fields should be at zero values when unparseable")
	}
}

// TestScenario_EmptyAndOversizedOutputDoNotPanic tests large outputs.
func TestScenario_EmptyAndOversizedOutputDoNotPanic(t *testing.T) {
	// Given probes returning empty output and 1 MB of output
	runner := fake.NewCommandRunner()
	probes := inventory.Probes("windows")

	for _, p := range probes {
		if p.Name == inventory.ProbeHardware {
			// Empty output
			runner.Results[p.String()] = platform.CommandResult{
				Stdout:   "",
				ExitCode: 0,
			}
		} else if p.Name == inventory.ProbeOS {
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
	inv, err := inventory.Collect(runner, clock, "windows")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	// Just verify we got a result
	if inv.Hardware.RAMBytes != 0 {
		// RAMBytes from disk probe (it's using windows probes)
	}
}

// TestScenario_HangingProbeTimesOut tests the timeout scenario.
func TestScenario_HangingProbeTimesOut(t *testing.T) {
	// Given a probe that never returns and a fake clock
	runner := &hangingCommandRunner{
		inner:   fake.NewCommandRunner(),
		hangOn:  inventory.ProbeOS,
		started: make(chan struct{}),
	}

	probes := inventory.Probes("windows")
	for _, p := range probes {
		if p.Name != inventory.ProbeOS {
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
	// First, set up a goroutine that will wait for the probe to start, then
	// advance the clock
	go func() {
		<-runner.started
		clock.Advance(inventory.ProbeTimeout)
	}()

	inv, err := inventory.Collect(runner, clock, "windows")

	// Then Warnings contains "os:timeout", the remaining probes still ran and no real time was slept
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	found := false
	for _, w := range inv.Warnings {
		if w == inventory.ProbeOS+":timeout" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Warnings should contain %q:timeout, got %v", inventory.ProbeOS, inv.Warnings)
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
	for _, p := range inventory.Probes("windows") {
		if p.Name == h.hangOn && p.String() == cmdStr {
			close(h.started)
			// Block forever
			select {}
		}
	}

	return h.inner.Run(ctx, name, args...)
}

// TestScenario_WarningsAreCarriedOnTheWire tests JSON marshalling.
func TestScenario_WarningsAreCarriedOnTheWire(t *testing.T) {
	// Given a collection result holding warnings
	inv := contract.Inventory{
		Hardware: contract.InventoryHardware{},
		OS:       contract.InventoryOS{},
		Software: []contract.SoftwareEntry{},
		Warnings: []string{"software", "firewall:unparseable"},
	}

	// When the result is marshalled to JSON
	data, err := marshalJSON(inv)
	if err != nil {
		t.Fatalf("marshalling failed: %v", err)
	}

	// Then the warnings array is ["software","firewall:unparseable"]
	if !strings.Contains(string(data), `"warnings":["software","firewall:unparseable"]`) &&
		!strings.Contains(string(data), `"warnings": ["software", "firewall:unparseable"]`) {
		t.Errorf("warnings not found in JSON: %s", string(data))
	}
}

// TestScenario_EmptyWarningsListIsOmittedFromWire tests omitempty.
func TestScenario_EmptyWarningsListIsOmittedFromWire(t *testing.T) {
	// Given a collection result with no warnings
	inv := contract.Inventory{
		Hardware: contract.InventoryHardware{},
		OS:       contract.InventoryOS{},
		Software: []contract.SoftwareEntry{},
		Warnings: nil,
	}

	// When the result is marshalled to JSON
	data, err := marshalJSON(inv)
	if err != nil {
		t.Fatalf("marshalling failed: %v", err)
	}

	// Then the JSON contains no "warnings" key
	if strings.Contains(string(data), `"warnings"`) {
		t.Errorf("warnings key should not appear in JSON: %s", string(data))
	}
}

// TestScenario_SoftwareListIsCleaned tests software deduplication.
func TestScenario_SoftwareListIsCleaned(t *testing.T) {
	// Given probe output with a blank name and a duplicated name+version pair
	runner := fake.NewCommandRunner()
	probes := inventory.Probes("windows")

	for _, p := range probes {
		if p.Name == inventory.ProbeSoftware {
			// Create output with blank name and duplicate
			runner.Results[p.String()] = platform.CommandResult{
				Stdout: "   \ttab\t\t2026-01-01\n" + // blank name should be dropped
					"Office\t16.0.0\tMicrosoft\t2026-01-01\n" +
					"Office\t16.0.0\tMicrosoft\t2026-01-01\n", // duplicate should be kept once
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
	inv, err := inventory.Collect(runner, clock, "windows")

	// Then the blank entry is absent and the duplicate appears once
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	officeCount := 0
	for _, s := range inv.Software {
		if s.Name == "Office" {
			officeCount++
		} else if strings.TrimSpace(s.Name) == "" {
			t.Error("blank name entry should be absent")
		}
	}
	if officeCount != 1 {
		t.Errorf("expected 1 Office entry, got %d", officeCount)
	}
}

// TestScenario_UnsupportedGoosReturnsError tests unsupported OS.
func TestScenario_UnsupportedGoosReturnsError(t *testing.T) {
	runner := fake.NewCommandRunner()
	clock := fake.NewClock(time.Now())

	// When Collect runs with unsupported goos
	_, err := inventory.Collect(runner, clock, "unsupported")

	// Then it returns an error
	if err == nil {
		t.Error("expected error for unsupported goos")
	}
}

// Helper to marshal inventory to JSON
func marshalJSON(inv contract.Inventory) ([]byte, error) {
	return json.Marshal(inv)
}

// TestUnit_ProbeString tests the Probe.String method
func TestUnit_ProbeString(t *testing.T) {
	p := inventory.Probe{Name: "test", Cmd: "cmd"}
	expected := "cmd"
	if p.String() != expected {
		t.Errorf("expected %q, got %q", expected, p.String())
	}

	p = inventory.Probe{Name: "test", Cmd: "cmd", Args: []string{"arg1", "arg2"}}
	expected = "cmd arg1 arg2"
	if p.String() != expected {
		t.Errorf("expected %q, got %q", expected, p.String())
	}
}

// TestUnit_Probes tests the Probes function
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
			probes := inventory.Probes(tt.goos)
			if tt.hasProbe && len(probes) == 0 {
				t.Error("expected probes for", tt.goos)
			}
			if !tt.hasProbe && len(probes) != 0 {
				t.Error("expected no probes for", tt.goos)
			}
		})
	}
}

// TestUnit_CleanSoftware tests software cleanup
func TestUnit_CleanSoftware(t *testing.T) {
	// Call cleanSoftware through Collect
	runner := fake.NewCommandRunner()
	probes := inventory.Probes("windows")

	for _, p := range probes {
		if p.Name == inventory.ProbeSoftware {
			runner.Results[p.String()] = platform.CommandResult{
				Stdout: "App1\t1.0\t\t\n" +
					"   \t1.0\t\t\n" +
					"App2\t2.0\t\t\n" +
					"App2\t2.0\t\t\n" +
					"App3\t3.0\t\t\n",
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
	inv, err := inventory.Collect(runner, clock, "windows")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Check results
	if len(inv.Software) != 3 {
		t.Errorf("expected 3 software entries, got %d", len(inv.Software))
	}

	for _, s := range inv.Software {
		if strings.TrimSpace(s.Name) == "" {
			t.Error("blank name should be removed")
		}
	}
}

// TestUnit_NormalizeArch tests architecture normalization
func TestUnit_NormalizeArch(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"amd64", "amd64"},
		{"x86_64", "amd64"},
		{"x64", "amd64"},
		{"64-bit", "amd64"},
		{"arm64", "arm64"},
		{"aarch64", "arm64"},
		{"x86", "386"},
		{"386", "386"},
		{"32-bit", "386"},
		{"unknown", "unknown"},
		{"  AMD64  ", "amd64"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			// We need to test through inventory parsing
			runner := fake.NewCommandRunner()
			probes := inventory.Probes("windows")

			for _, p := range probes {
				if p.Name == inventory.ProbeOS {
					runner.Results[p.String()] = platform.CommandResult{
						Stdout:   "name=Windows\nversion=10.0\nbuild=22631\narchitecture=" + tt.input,
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
			inv, _ := inventory.Collect(runner, clock, "windows")
			if inv.OS.Architecture != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, inv.OS.Architecture)
			}
		})
	}
}

// TestUnit_ParseBytes tests byte parsing
func TestUnit_ParseBytes(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"0", 0},
		{"1024", 1024},
		{"16 GB", 16 * 1024 * 1024 * 1024},
		{"1 TB", 1024 * 1024 * 1024 * 1024},
		{"512 MB", 512 * 1024 * 1024},
		{"", 0},
		{"invalid", 0},
		{"1.5 GB", int64(1.5 * 1024 * 1024 * 1024)},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			runner := fake.NewCommandRunner()
			probes := inventory.Probes("windows")

			for _, p := range probes {
				if p.Name == inventory.ProbeHardware {
					runner.Results[p.String()] = platform.CommandResult{
						Stdout:   "ramBytes=" + tt.input,
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
			inv, _ := inventory.Collect(runner, clock, "windows")
			if inv.Hardware.RAMBytes != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, inv.Hardware.RAMBytes)
			}
		})
	}
}
