package analytics_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/analytics"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// loadFixture reads a fixture file from testdata.
func loadFixture(goos string, probeName string) (string, error) {
	path := filepath.Join("testdata", goos, probeName+".txt")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// --- Probe tests ---

// TestScenario_ProbeListsPerOS verifies probe lists for each OS.
func TestScenario_ProbeListsPerOS(t *testing.T) {
	// Given nothing special

	// When we get probes for each OS
	winProbes := analytics.Probes("windows")
	darwinProbes := analytics.Probes("darwin")
	linuxProbes := analytics.Probes("linux")

	// Then Windows probes are boot, performance, crashes with powershell.exe
	if len(winProbes) != 3 {
		t.Fatalf("Windows: expected 3 probes, got %d", len(winProbes))
	}
	if winProbes[0].Name != analytics.ProbeBoot || winProbes[0].Cmd != "powershell.exe" {
		t.Errorf("Windows boot probe incorrect: %v", winProbes[0])
	}
	if winProbes[1].Name != analytics.ProbePerformance {
		t.Errorf("Windows perf probe incorrect: %v", winProbes[1])
	}
	if winProbes[2].Name != analytics.ProbeCrashes {
		t.Errorf("Windows crashes probe incorrect: %v", winProbes[2])
	}
	// Check that Windows probes use -NoProfile -NonInteractive -Command
	for i, p := range winProbes {
		if len(p.Args) < 4 {
			t.Errorf("Windows probe %d has too few args", i)
		}
		if p.Args[0] != "-NoProfile" || p.Args[1] != "-NonInteractive" || p.Args[2] != "-Command" {
			t.Errorf("Windows probe %d has wrong args prefix: %v", i, p.Args[:3])
		}
	}

	// Darwin probes are boot, performance, crashes
	if len(darwinProbes) != 3 {
		t.Fatalf("Darwin: expected 3 probes, got %d", len(darwinProbes))
	}
	if darwinProbes[0].Name != analytics.ProbeBoot || darwinProbes[0].Cmd != "/usr/sbin/sysctl" {
		t.Errorf("Darwin boot probe incorrect: %v", darwinProbes[0])
	}
	if darwinProbes[1].Name != analytics.ProbePerformance {
		t.Errorf("Darwin perf probe incorrect: %v", darwinProbes[1])
	}
	if darwinProbes[2].Name != analytics.ProbeCrashes {
		t.Errorf("Darwin crashes probe incorrect: %v", darwinProbes[2])
	}

	// Linux returns nil
	if linuxProbes != nil {
		t.Errorf("Linux should return nil, got %v", linuxProbes)
	}
}

// TestScenario_UnsupportedGoosIsAnError tests that unsupported goos returns error.
func TestScenario_UnsupportedGoosIsAnError(t *testing.T) {
	// Given a fake runner and clock
	runner := fake.NewCommandRunner()
	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))

	// When Collect runs for unsupported goos
	_, _, err := analytics.Collect(runner, clock, "linux", time.Time{})

	// Then it returns an error
	if err == nil {
		t.Fatal("Expected error for unsupported goos, got nil")
	}

	// And the runner recorded no call
	if len(runner.Calls()) != 0 {
		t.Errorf("Expected no runner calls, got %d", len(runner.Calls()))
	}
}

// --- Windows happy path ---

// TestScenario_WindowsFixturesProduceFullBlock tests Windows with fixtures.
func TestScenario_WindowsFixturesProduceFullBlock(t *testing.T) {
	// Given the recorded Windows probes answer with fixtures
	runner := fake.NewCommandRunner()
	probes := analytics.Probes("windows")

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

	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))

	// When Collect runs for "windows" with since zero
	a, _, err := analytics.Collect(runner, clock, "windows", time.Time{})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then every boot and performance value is non-nil
	if a.Boot.LastBootAt == nil {
		t.Error("lastBootAt should not be nil")
	}
	if a.Boot.UptimeSeconds == nil {
		t.Error("uptimeSeconds should not be nil")
	}
	if a.Boot.BootDurationSeconds == nil {
		t.Error("bootDurationSeconds should not be nil")
	}

	if a.Performance.CPUPercent == nil {
		t.Error("cpuPercent should not be nil")
	}
	if a.Performance.MemoryTotalBytes == nil {
		t.Error("memoryTotalBytes should not be nil")
	}
	if a.Performance.MemoryUsedBytes == nil {
		t.Error("memoryUsedBytes should not be nil")
	}
	if a.Performance.SystemDiskTotalBytes == nil {
		t.Error("systemDiskTotalBytes should not be nil")
	}
	if a.Performance.SystemDiskFreeBytes == nil {
		t.Error("systemDiskFreeBytes should not be nil")
	}

	// And crashes are oldest first with kind "crash" for event 1000 and "hang" for event 1002
	if len(a.Crashes) != 3 {
		t.Fatalf("Expected 3 crashes, got %d", len(a.Crashes))
	}

	// Crashes should be oldest first: EXCEL (2026-09-28), ms-teams (2026-10-01), OUTLOOK (2026-10-02)
	if !strings.Contains(a.Crashes[0].AppName, "EXCEL") {
		t.Errorf("First crash should be EXCEL, got %s", a.Crashes[0].AppName)
	}
	if a.Crashes[0].Kind != analytics.KindCrash {
		t.Errorf("EXCEL should be kind crash, got %s", a.Crashes[0].Kind)
	}

	if !strings.Contains(a.Crashes[1].AppName, "ms-teams") {
		t.Errorf("Second crash should be ms-teams, got %s", a.Crashes[1].AppName)
	}
	if a.Crashes[1].Kind != analytics.KindHang {
		t.Errorf("ms-teams should be kind hang, got %s", a.Crashes[1].Kind)
	}

	if !strings.Contains(a.Crashes[2].AppName, "OUTLOOK") {
		t.Errorf("Third crash should be OUTLOOK, got %s", a.Crashes[2].AppName)
	}
	if a.Crashes[2].Kind != analytics.KindCrash {
		t.Errorf("OUTLOOK should be kind crash, got %s", a.Crashes[2].Kind)
	}

	// And Warnings is nil
	if a.Warnings != nil {
		t.Errorf("Warnings should be nil, got %v", a.Warnings)
	}
}

// --- Darwin happy path ---

// TestScenario_DarwinFixturesProduceBlockWithNullBootDuration tests Darwin with fixtures.
func TestScenario_DarwinFixturesProduceBlockWithNullBootDuration(t *testing.T) {
	// Given the recorded Darwin probes answer with fixtures
	runner := fake.NewCommandRunner()
	probes := analytics.Probes("darwin")

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

	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))

	// When Collect runs for "darwin" with since zero
	a, _, err := analytics.Collect(runner, clock, "darwin", time.Time{})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then lastBootAt is the kern.boottime sec formatted whole-second RFC3339 UTC
	if a.Boot.LastBootAt == nil {
		t.Fatal("lastBootAt should not be nil")
	}
	if *a.Boot.LastBootAt != "2026-10-02T06:41:09Z" {
		t.Errorf("lastBootAt should be 2026-10-02T06:41:09Z, got %s", *a.Boot.LastBootAt)
	}

	// And bootDurationSeconds is nil
	if a.Boot.BootDurationSeconds != nil {
		t.Errorf("bootDurationSeconds should be nil, got %v", *a.Boot.BootDurationSeconds)
	}

	// And performance values are non-nil and match the fixture
	if a.Performance.CPUPercent == nil {
		t.Error("cpuPercent should not be nil")
	}
	if a.Performance.CPUPercent != nil {
		if *a.Performance.CPUPercent != 23.45 {
			t.Errorf("cpuPercent should be 23.45, got %f", *a.Performance.CPUPercent)
		}
	}

	// And crashes hold only bug_type 309 and 109 headers, each with kind "crash"
	if len(a.Crashes) != 2 {
		t.Fatalf("Expected 2 crashes, got %d", len(a.Crashes))
	}
	for i, c := range a.Crashes {
		if c.Kind != analytics.KindCrash {
			t.Errorf("Crash %d should be kind crash, got %s", i, c.Kind)
		}
	}

	// And Warnings does not contain "bootDuration:unavailable"
	for _, w := range a.Warnings {
		if strings.Contains(w, "bootDuration") {
			t.Errorf("Warnings should not contain bootDuration:unavailable, got %s", w)
		}
	}
}

// --- Boot tests ---

// TestScenario_UptimeIsDerivedFromTheClock tests uptime calculation.
func TestScenario_UptimeIsDerivedFromTheClock(t *testing.T) {
	// Given the boot probe reports lastBootAt "2026-10-02T06:41:09Z"
	runner := fake.NewCommandRunner()
	bootOutput := "lastBootAt=2026-10-02T06:41:09Z"
	for _, p := range analytics.Probes("windows") {
		if p.Name == analytics.ProbeBoot {
			runner.Results[p.String()] = platform.CommandResult{Stdout: bootOutput, ExitCode: 0}
		} else {
			runner.Results[p.String()] = platform.CommandResult{Stdout: "", ExitCode: 0}
		}
	}

	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))

	// When Collect runs
	a, _, err := analytics.Collect(runner, clock, "windows", time.Time{})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then uptimeSeconds is 2331
	if a.Boot.UptimeSeconds == nil {
		t.Fatal("uptimeSeconds should not be nil")
	}
	if *a.Boot.UptimeSeconds != 2331 {
		t.Errorf("uptimeSeconds should be 2331, got %d", *a.Boot.UptimeSeconds)
	}
}

// TestScenario_BootTimeInTheFutureIsRejected tests future boot time.
func TestScenario_BootTimeInTheFutureIsRejected(t *testing.T) {
	// Given the boot probe reports lastBootAt "2026-10-03T00:00:00Z" (in the future)
	runner := fake.NewCommandRunner()
	bootOutput := "lastBootAt=2026-10-03T00:00:00Z"
	for _, p := range analytics.Probes("windows") {
		if p.Name == analytics.ProbeBoot {
			runner.Results[p.String()] = platform.CommandResult{Stdout: bootOutput, ExitCode: 0}
		} else {
			runner.Results[p.String()] = platform.CommandResult{Stdout: "", ExitCode: 0}
		}
	}

	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))

	// When Collect runs
	a, _, err := analytics.Collect(runner, clock, "windows", time.Time{})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then lastBootAt and uptimeSeconds are nil
	if a.Boot.LastBootAt != nil {
		t.Errorf("lastBootAt should be nil, got %s", *a.Boot.LastBootAt)
	}
	if a.Boot.UptimeSeconds != nil {
		t.Errorf("uptimeSeconds should be nil, got %d", *a.Boot.UptimeSeconds)
	}

	// And Warnings contains "boot:unparseable"
	found := false
	for _, w := range a.Warnings {
		if w == "boot:unparseable" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Warnings should contain boot:unparseable, got %v", a.Warnings)
	}
}

// TestScenario_WindowsBootDurationFromEvent100 tests normal boot duration.
func TestScenario_WindowsBootDurationFromEvent100(t *testing.T) {
	// Given the windows boot probe reports lastBootAt, bootDurationMs and bootEventAt
	runner := fake.NewCommandRunner()
	bootOutput := `lastBootAt=2026-10-02T06:41:09Z
bootDurationMs=38400
bootEventAt=2026-10-02T06:43:00Z`

	for _, p := range analytics.Probes("windows") {
		if p.Name == analytics.ProbeBoot {
			runner.Results[p.String()] = platform.CommandResult{Stdout: bootOutput, ExitCode: 0}
		} else {
			runner.Results[p.String()] = platform.CommandResult{Stdout: "", ExitCode: 0}
		}
	}

	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))

	// When Collect runs for "windows"
	a, _, err := analytics.Collect(runner, clock, "windows", time.Time{})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then bootDurationSeconds is 38.4
	if a.Boot.BootDurationSeconds == nil {
		t.Fatal("bootDurationSeconds should not be nil")
	}
	if *a.Boot.BootDurationSeconds != 38.4 {
		t.Errorf("bootDurationSeconds should be 38.4, got %f", *a.Boot.BootDurationSeconds)
	}
}

// TestScenario_WindowsBootDurationUnavailable tests various duration unavailable scenarios.
func TestScenario_WindowsBootDurationUnavailable(t *testing.T) {
	tests := []struct {
		name          string
		bootOutput    string
		expectNil     bool
		expectWarning bool
	}{
		{
			name:          "no bootDurationMs line",
			bootOutput:    "lastBootAt=2026-10-02T06:41:09Z",
			expectNil:     true,
			expectWarning: true,
		},
		{
			name:          "bootEventAt before bootTime",
			bootOutput:    "lastBootAt=2026-10-02T06:41:09Z\nbootDurationMs=30000\nbootEventAt=2026-10-01T09:00:00Z",
			expectNil:     true,
			expectWarning: true,
		},
		{
			name:          "bootDurationMs 0",
			bootOutput:    "lastBootAt=2026-10-02T06:41:09Z\nbootDurationMs=0\nbootEventAt=2026-10-02T06:43:00Z",
			expectNil:     true,
			expectWarning: true,
		},
		{
			name:          "bootDurationMs 3600001",
			bootOutput:    "lastBootAt=2026-10-02T06:41:09Z\nbootDurationMs=3600001\nbootEventAt=2026-10-02T06:43:00Z",
			expectNil:     true,
			expectWarning: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := fake.NewCommandRunner()
			for _, p := range analytics.Probes("windows") {
				if p.Name == analytics.ProbeBoot {
					runner.Results[p.String()] = platform.CommandResult{Stdout: tc.bootOutput, ExitCode: 0}
				} else {
					runner.Results[p.String()] = platform.CommandResult{Stdout: "", ExitCode: 0}
				}
			}

			clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))

			// When Collect runs for "windows"
			a, _, err := analytics.Collect(runner, clock, "windows", time.Time{})
			if err != nil {
				t.Fatalf("Collect failed: %v", err)
			}

			// Then bootDurationSeconds is nil
			if tc.expectNil && a.Boot.BootDurationSeconds != nil {
				t.Errorf("bootDurationSeconds should be nil, got %f", *a.Boot.BootDurationSeconds)
			}

			// And Warnings contains "bootDuration:unavailable"
			if tc.expectWarning {
				found := false
				for _, w := range a.Warnings {
					if w == "bootDuration:unavailable" {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Warnings should contain bootDuration:unavailable, got %v", a.Warnings)
				}
			}
		})
	}
}

// --- Performance tests ---

// TestScenario_PerformanceValuesAreBounded tests performance value bounds.
func TestScenario_PerformanceValuesAreBounded(t *testing.T) {
	tests := []struct {
		name        string
		perfOutput  string
		field       string
		expectNil   bool
		expectValue *int64
	}{
		{
			name:       "cpuPercent=150",
			perfOutput: "cpuPercent=150",
			field:      "cpuPercent",
			expectNil:  true,
		},
		{
			name:       "cpuPercent=high",
			perfOutput: "cpuPercent=high",
			field:      "cpuPercent",
			expectNil:  true,
		},
		{
			name:       "memoryTotalBytes=0",
			perfOutput: "memoryTotalBytes=0 memoryUsedBytes=100",
			field:      "memoryUsedBytes",
			expectNil:  true,
		},
		{
			name:       "memoryTotalBytes=1000 memoryUsedBytes=2000",
			perfOutput: "memoryTotalBytes=1000 memoryUsedBytes=2000",
			field:      "memoryUsedBytes",
			expectNil:  true,
		},
		{
			name:        "diskTotalBytes=8000 diskFreeBytes=9000",
			perfOutput:  "diskTotalBytes=8000 diskFreeBytes=9000",
			field:       "systemDiskFreeBytes",
			expectNil:   true,
			expectValue: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := fake.NewCommandRunner()
			for _, p := range analytics.Probes("windows") {
				if p.Name == analytics.ProbePerformance {
					runner.Results[p.String()] = platform.CommandResult{Stdout: tc.perfOutput, ExitCode: 0}
				} else {
					runner.Results[p.String()] = platform.CommandResult{Stdout: "", ExitCode: 0}
				}
			}

			clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))

			// When Collect runs
			a, _, err := analytics.Collect(runner, clock, "windows", time.Time{})
			if err != nil {
				t.Fatalf("Collect failed: %v", err)
			}

			// Then the field is as expected
			// Check the specific field
			switch tc.field {
			case "cpuPercent":
				if tc.expectNil && a.Performance.CPUPercent != nil {
					t.Errorf("cpuPercent should be nil, got %f", *a.Performance.CPUPercent)
				}
			case "memoryUsedBytes":
				if tc.expectNil && a.Performance.MemoryUsedBytes != nil {
					t.Errorf("memoryUsedBytes should be nil, got %d", *a.Performance.MemoryUsedBytes)
				}
			case "systemDiskFreeBytes":
				if tc.expectNil && a.Performance.SystemDiskFreeBytes != nil {
					t.Errorf("systemDiskFreeBytes should be nil, got %d", *a.Performance.SystemDiskFreeBytes)
				}
			}
		})
	}
}

// --- Crash tests ---

// TestScenario_TimestampsAreWholeSectionUTC tests timestamp formatting.
func TestScenario_TimestampsAreWholeSectionUTC(t *testing.T) {
	// Given the windows crashes probe prints an event with fractional seconds
	runner := fake.NewCommandRunner()
	crashOutput := `{"eventId":1000,"occurredAt":"2026-10-02T06:58:12.2500000Z","appName":"Teams","appVersion":"1.0"}`

	for _, p := range analytics.Probes("windows") {
		if p.Name == analytics.ProbeCrashes {
			runner.Results[p.String()] = platform.CommandResult{Stdout: crashOutput, ExitCode: 0}
		} else {
			runner.Results[p.String()] = platform.CommandResult{Stdout: "", ExitCode: 0}
		}
	}

	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))

	// When Collect runs for "windows"
	a, _, err := analytics.Collect(runner, clock, "windows", time.Time{})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then that crash occurredAt is "2026-10-02T06:58:12Z" (whole-second)
	if len(a.Crashes) != 1 {
		t.Fatalf("Expected 1 crash, got %d", len(a.Crashes))
	}
	if a.Crashes[0].OccurredAt != "2026-10-02T06:58:12Z" {
		t.Errorf("occurredAt should be 2026-10-02T06:58:12Z, got %s", a.Crashes[0].OccurredAt)
	}
}

// TestScenario_CrashNamesAreTrimmedAndEmptyVersionsAreNull tests crash name/version trimming.
func TestScenario_CrashNamesAreTrimmedAndEmptyVersionsAreNull(t *testing.T) {
	// Given the crashes probe prints a crash with appName "  Teams  " and appVersion "   "
	runner := fake.NewCommandRunner()
	crashOutput := `{"eventId":1000,"occurredAt":"2026-10-02T06:58:12Z","appName":"  Teams  ","appVersion":"   "}`

	for _, p := range analytics.Probes("windows") {
		if p.Name == analytics.ProbeCrashes {
			runner.Results[p.String()] = platform.CommandResult{Stdout: crashOutput, ExitCode: 0}
		} else {
			runner.Results[p.String()] = platform.CommandResult{Stdout: "", ExitCode: 0}
		}
	}

	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))

	// When Collect runs
	a, _, err := analytics.Collect(runner, clock, "windows", time.Time{})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then the crash appName is "Teams" and appVersion is nil
	if len(a.Crashes) != 1 {
		t.Fatalf("Expected 1 crash, got %d", len(a.Crashes))
	}
	if a.Crashes[0].AppName != "Teams" {
		t.Errorf("appName should be 'Teams', got '%s'", a.Crashes[0].AppName)
	}
	if a.Crashes[0].AppVersion != nil {
		t.Errorf("appVersion should be nil, got %v", a.Crashes[0].AppVersion)
	}
}

// TestScenario_BadCrashLinesAreDroppedWithOneWarning tests crash line dropping.
func TestScenario_BadCrashLinesAreDroppedWithOneWarning(t *testing.T) {
	// Given the windows crashes probe prints a valid line, a non-JSON line, an empty name line, and an unparseable time line
	runner := fake.NewCommandRunner()
	crashOutput := `{"eventId":1000,"occurredAt":"2026-10-02T06:58:12Z","appName":"Valid","appVersion":"1"}
not-json
{"eventId":1000,"occurredAt":"2026-10-02T06:58:12Z","appName":"","appVersion":"1"}
{"eventId":1000,"occurredAt":"yesterday","appName":"Bad","appVersion":"1"}`

	for _, p := range analytics.Probes("windows") {
		if p.Name == analytics.ProbeCrashes {
			runner.Results[p.String()] = platform.CommandResult{Stdout: crashOutput, ExitCode: 0}
		} else {
			runner.Results[p.String()] = platform.CommandResult{Stdout: "", ExitCode: 0}
		}
	}

	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))

	// When Collect runs for "windows"
	a, _, err := analytics.Collect(runner, clock, "windows", time.Time{})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then crashes holds only the valid line
	if len(a.Crashes) != 1 {
		t.Fatalf("Expected 1 crash, got %d", len(a.Crashes))
	}
	if a.Crashes[0].AppName != "Valid" {
		t.Errorf("Valid crash should be present, got %s", a.Crashes[0].AppName)
	}

	// And Warnings contains "crashes:unparseable" exactly once
	count := 0
	for _, w := range a.Warnings {
		if w == "crashes:unparseable" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("Warnings should contain crashes:unparseable exactly once, found %d", count)
	}
}

// TestScenario_UnrelatedEventsAndReportTypesAreSkippedSilently tests filtering.
func TestScenario_UnrelatedEventsAndReportTypesAreSkippedSilently(t *testing.T) {
	// Test Windows with wrong eventId
	t.Run("windows_wrong_eventId", func(t *testing.T) {
		runner := fake.NewCommandRunner()
		crashOutput := `{"eventId":1001,"occurredAt":"2026-10-02T06:58:12Z","appName":"App","appVersion":"1"}`

		for _, p := range analytics.Probes("windows") {
			if p.Name == analytics.ProbeCrashes {
				runner.Results[p.String()] = platform.CommandResult{Stdout: crashOutput, ExitCode: 0}
			} else {
				runner.Results[p.String()] = platform.CommandResult{Stdout: "", ExitCode: 0}
			}
		}

		clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))

		// When Collect runs for "windows"
		a, _, err := analytics.Collect(runner, clock, "windows", time.Time{})
		if err != nil {
			t.Fatalf("Collect failed: %v", err)
		}

		// Then crashes is empty
		if len(a.Crashes) != 0 {
			t.Errorf("Expected 0 crashes, got %d", len(a.Crashes))
		}

		// And Warnings contains no "crashes" entry
		for _, w := range a.Warnings {
			if strings.Contains(w, "crashes") {
				t.Errorf("Warnings should not contain crashes warning, got %s", w)
			}
		}
	})

	// Test Darwin with wrong bug_type
	t.Run("darwin_wrong_bug_type", func(t *testing.T) {
		runner := fake.NewCommandRunner()
		crashOutput := `{"bug_type":"288","app_name":"App","timestamp":"2026-10-02 06:58:12.00 -0600","app_version":"1"}`

		for _, p := range analytics.Probes("darwin") {
			if p.Name == analytics.ProbeCrashes {
				runner.Results[p.String()] = platform.CommandResult{Stdout: crashOutput, ExitCode: 0}
			} else {
				runner.Results[p.String()] = platform.CommandResult{Stdout: "", ExitCode: 0}
			}
		}

		clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))

		// When Collect runs for "darwin"
		a, _, err := analytics.Collect(runner, clock, "darwin", time.Time{})
		if err != nil {
			t.Fatalf("Collect failed: %v", err)
		}

		// Then crashes is empty
		if len(a.Crashes) != 0 {
			t.Errorf("Expected 0 crashes, got %d", len(a.Crashes))
		}

		// And Warnings contains no "crashes" entry
		for _, w := range a.Warnings {
			if strings.Contains(w, "crashes") {
				t.Errorf("Warnings should not contain crashes warning, got %s", w)
			}
		}
	})
}

// TestScenario_CrashWindowBoundsAndFutureSkew tests crash time window selection.
func TestScenario_CrashWindowBoundsAndFutureSkew(t *testing.T) {
	// Given since is "2026-10-01T00:00:00Z" and crashes at different times
	runner := fake.NewCommandRunner()
	crashOutput := `{"eventId":1000,"occurredAt":"2026-09-30T23:59:59Z","appName":"A","appVersion":"1"}
{"eventId":1000,"occurredAt":"2026-10-01T00:00:00Z","appName":"B","appVersion":"1"}
{"eventId":1000,"occurredAt":"2026-10-01T12:00:00Z","appName":"C","appVersion":"1"}
{"eventId":1000,"occurredAt":"2026-10-04T00:00:00Z","appName":"D","appVersion":"1"}`

	for _, p := range analytics.Probes("windows") {
		if p.Name == analytics.ProbeCrashes {
			runner.Results[p.String()] = platform.CommandResult{Stdout: crashOutput, ExitCode: 0}
		} else {
			runner.Results[p.String()] = platform.CommandResult{Stdout: "", ExitCode: 0}
		}
	}

	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	// When Collect runs
	a, candidate, err := analytics.Collect(runner, clock, "windows", since)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then crashes holds only "2026-10-01T12:00:00Z" (C)
	// A is before since, B is equal to since (not strictly after), C is in range, D is beyond future skew
	if len(a.Crashes) != 1 {
		t.Fatalf("Expected 1 crash, got %d", len(a.Crashes))
	}
	if a.Crashes[0].AppName != "C" {
		t.Errorf("Expected crash C, got %s", a.Crashes[0].AppName)
	}

	// And the watermark candidate is "2026-10-01T12:00:00Z"
	expectedCandidate := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	if candidate != expectedCandidate {
		t.Errorf("Expected candidate %v, got %v", expectedCandidate, candidate)
	}
}

// TestScenario_CrashesOlderThan30DaysAreExcluded tests 30-day lookback.
func TestScenario_CrashesOlderThan30DaysAreExcluded(t *testing.T) {
	// Given since is zero and crashes at "2026-08-01T00:00:00Z" and "2026-10-01T00:00:00Z"
	runner := fake.NewCommandRunner()
	crashOutput := `{"eventId":1000,"occurredAt":"2026-08-01T00:00:00Z","appName":"Old","appVersion":"1"}
{"eventId":1000,"occurredAt":"2026-10-01T00:00:00Z","appName":"New","appVersion":"1"}`

	for _, p := range analytics.Probes("windows") {
		if p.Name == analytics.ProbeCrashes {
			runner.Results[p.String()] = platform.CommandResult{Stdout: crashOutput, ExitCode: 0}
		} else {
			runner.Results[p.String()] = platform.CommandResult{Stdout: "", ExitCode: 0}
		}
	}

	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))

	// When Collect runs
	a, _, err := analytics.Collect(runner, clock, "windows", time.Time{})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then crashes holds only "2026-10-01T00:00:00Z"
	if len(a.Crashes) != 1 {
		t.Fatalf("Expected 1 crash, got %d", len(a.Crashes))
	}
	if a.Crashes[0].AppName != "New" {
		t.Errorf("Expected crash New, got %s", a.Crashes[0].AppName)
	}
}

// TestScenario_The50CrashCapCarriesRemainder tests 50-crash cap.
func TestScenario_The50CrashCapCarriesRemainder(t *testing.T) {
	// Given 55 eligible crashes one minute apart
	runner := fake.NewCommandRunner()
	var crashLines []string
	baseTime := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 55; i++ {
		t := baseTime.Add(time.Duration(i) * time.Minute)
		crashLines = append(crashLines, `{"eventId":1000,"occurredAt":"`+t.Format(time.RFC3339)+`","appName":"App`+fmt.Sprintf("%d", i)+`","appVersion":"1"}`)
	}
	crashOutput := strings.Join(crashLines, "\n")

	for _, p := range analytics.Probes("windows") {
		if p.Name == analytics.ProbeCrashes {
			runner.Results[p.String()] = platform.CommandResult{Stdout: crashOutput, ExitCode: 0}
		} else {
			runner.Results[p.String()] = platform.CommandResult{Stdout: "", ExitCode: 0}
		}
	}

	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))

	// When Collect runs with since zero
	a, candidate, err := analytics.Collect(runner, clock, "windows", time.Time{})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then crashes holds the 50 oldest, oldest first
	if len(a.Crashes) != 50 {
		t.Fatalf("Expected 50 crashes, got %d", len(a.Crashes))
	}

	// And the watermark candidate is the time of the 50th
	expectedCandidate := baseTime.Add(time.Duration(49) * time.Minute)
	if candidate != expectedCandidate {
		t.Errorf("Expected candidate %v, got %v", expectedCandidate, candidate)
	}

	// When Collect runs again with that candidate as since
	a2, _, err := analytics.Collect(runner, clock, "windows", candidate)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then crashes holds exactly the remaining 5
	if len(a2.Crashes) != 5 {
		t.Fatalf("Expected 5 crashes, got %d", len(a2.Crashes))
	}
}

// TestScenario_NoCrashesKeepsTheWatermark tests no crashes scenario.
func TestScenario_NoCrashesKeepsTheWatermark(t *testing.T) {
	// Given the crashes probe prints nothing
	runner := fake.NewCommandRunner()
	crashOutput := ""

	for _, p := range analytics.Probes("windows") {
		if p.Name == analytics.ProbeCrashes {
			runner.Results[p.String()] = platform.CommandResult{Stdout: crashOutput, ExitCode: 0}
		} else {
			runner.Results[p.String()] = platform.CommandResult{Stdout: "", ExitCode: 0}
		}
	}

	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	// When Collect runs with since "2026-10-01T00:00:00Z"
	a, candidate, err := analytics.Collect(runner, clock, "windows", since)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then crashes is non-nil and empty and marshals as "crashes":[]
	if a.Crashes == nil {
		t.Fatal("crashes should be non-nil")
	}
	if len(a.Crashes) != 0 {
		t.Errorf("crashes should be empty, got %d", len(a.Crashes))
	}

	// And the watermark candidate is "2026-10-01T00:00:00Z"
	if candidate != since {
		t.Errorf("Expected candidate %v, got %v", since, candidate)
	}

	// And Warnings contains no "crashes" entry
	for _, w := range a.Warnings {
		if strings.Contains(w, "crashes") {
			t.Errorf("Warnings should not contain crashes warning, got %s", w)
		}
	}
}

// --- Probe failure tests ---

// TestScenario_AFailingProbNullsItsSubBlockOnly tests probe failures.
func TestScenario_AFailingProbeNullsItsSubBlockOnly(t *testing.T) {
	tests := []struct {
		name      string
		failProbe string
		goos      string
	}{
		{name: "boot_error", failProbe: analytics.ProbeBoot, goos: "windows"},
		{name: "performance_exit1", failProbe: analytics.ProbePerformance, goos: "windows"},
		{name: "crashes_error", failProbe: analytics.ProbeCrashes, goos: "darwin"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := fake.NewCommandRunner()
			probes := analytics.Probes(tc.goos)

			for _, p := range probes {
				if p.Name == tc.failProbe {
					// Cause this probe to fail
					runner.Errors[p.String()] = errors.New("test error")
				} else {
					// Other probes succeed with empty output
					runner.Results[p.String()] = platform.CommandResult{Stdout: "", ExitCode: 0}
				}
			}

			clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))

			// When Collect runs
			a, _, err := analytics.Collect(runner, clock, tc.goos, time.Time{})
			if err != nil {
				t.Fatalf("Collect failed: %v", err)
			}

			// Then Warnings contains the probe name
			found := false
			for _, w := range a.Warnings {
				if w == tc.failProbe {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Warnings should contain %s, got %v", tc.failProbe, a.Warnings)
			}

			// And the other probes were still run
			calls := runner.Calls()
			if len(calls) != len(probes) {
				t.Errorf("Expected %d probe calls, got %d", len(probes), len(calls))
			}
		})
	}
}

// TestScenario_AHangingProbeTimesOut tests probe timeout.
func TestScenario_AHangingProbeTimesOut(t *testing.T) {
	// Given a probe that never returns and a fake clock
	runner := &hangingCommandRunner{
		inner:   fake.NewCommandRunner(),
		hangOn:  analytics.ProbeBoot,
		started: make(chan struct{}),
	}

	probes := analytics.Probes("windows")
	for _, p := range probes {
		if p.Name != analytics.ProbeBoot {
			runner.inner.Results[p.String()] = platform.CommandResult{
				Stdout:   "",
				ExitCode: 0,
			}
		}
	}

	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))

	// When Collect runs and the test advances the fake clock by ProbeTimeout
	go func() {
		<-runner.started
		clock.Advance(analytics.ProbeTimeout)
	}()

	a, _, err := analytics.Collect(runner, clock, "windows", time.Time{})

	// Then Warnings contains "boot:timeout"
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	found := false
	for _, w := range a.Warnings {
		if w == analytics.ProbeBoot+":timeout" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Warnings should contain %q:timeout, got %v", analytics.ProbeBoot, a.Warnings)
	}

	// And the performance and crashes probes were still run and parsed
	calls := runner.inner.Calls()
	if len(calls) != 2 {
		t.Errorf("Expected 2 probe calls (perf and crashes run after boot timeout), got %d", len(calls))
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
	for _, p := range analytics.Probes("windows") {
		if p.Name == h.hangOn && p.String() == cmdStr {
			close(h.started)
			// Block forever
			select {}
		}
	}

	return h.inner.Run(ctx, name, args...)
}

// --- Unparseable output tests ---

// TestScenario_UnparseablePerformanceNullsAllFields tests unparseable performance.
func TestScenario_UnparseablePerformanceNullsAllFields(t *testing.T) {
	tests := []struct {
		name       string
		perfOutput string
	}{
		{name: "garbage", perfOutput: "garbage"},
		{name: "only_invalid_cpu", perfOutput: "cpuPercent=150"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := fake.NewCommandRunner()
			for _, p := range analytics.Probes("windows") {
				if p.Name == analytics.ProbePerformance {
					runner.Results[p.String()] = platform.CommandResult{Stdout: tc.perfOutput, ExitCode: 0}
				} else {
					runner.Results[p.String()] = platform.CommandResult{Stdout: "", ExitCode: 0}
				}
			}

			clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))

			// When Collect runs
			a, _, err := analytics.Collect(runner, clock, "windows", time.Time{})
			if err != nil {
				t.Fatalf("Collect failed: %v", err)
			}

			// Then all performance values are nil
			if a.Performance.CPUPercent != nil {
				t.Errorf("cpuPercent should be nil, got %f", *a.Performance.CPUPercent)
			}

			// And Warnings contains "performance:unparseable" exactly once
			count := 0
			for _, w := range a.Warnings {
				if w == "performance:unparseable" {
					count++
				}
			}
			if count != 1 {
				t.Errorf("Warnings should contain performance:unparseable exactly once, found %d", count)
			}
		})
	}
}

// TestScenario_UnparseableBootNullsBootFields tests unparseable boot.
func TestScenario_UnparseableBootNullsBootFields(t *testing.T) {
	tests := []struct {
		name       string
		bootOutput string
		goos       string
	}{
		{name: "windows_invalid_date", bootOutput: "lastBootAt=yesterday", goos: "windows"},
		{name: "darwin_no_sec", bootOutput: "kern.boottime: unknown", goos: "darwin"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := fake.NewCommandRunner()
			for _, p := range analytics.Probes(tc.goos) {
				if p.Name == analytics.ProbeBoot {
					runner.Results[p.String()] = platform.CommandResult{Stdout: tc.bootOutput, ExitCode: 0}
				} else {
					runner.Results[p.String()] = platform.CommandResult{Stdout: "", ExitCode: 0}
				}
			}

			clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))

			// When Collect runs
			a, _, err := analytics.Collect(runner, clock, tc.goos, time.Time{})
			if err != nil {
				t.Fatalf("Collect failed: %v", err)
			}

			// Then lastBootAt and uptimeSeconds are nil
			if a.Boot.LastBootAt != nil {
				t.Errorf("lastBootAt should be nil, got %s", *a.Boot.LastBootAt)
			}
			if a.Boot.UptimeSeconds != nil {
				t.Errorf("uptimeSeconds should be nil, got %d", *a.Boot.UptimeSeconds)
			}

			// And Warnings contains "boot:unparseable"
			found := false
			for _, w := range a.Warnings {
				if w == "boot:unparseable" {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Warnings should contain boot:unparseable, got %v", a.Warnings)
			}

			// On Windows, bootDurationSeconds should also be nil without bootDuration:unavailable
			if tc.goos == "windows" && a.Boot.BootDurationSeconds != nil {
				t.Errorf("bootDurationSeconds should be nil, got %f", *a.Boot.BootDurationSeconds)
			}
			if tc.goos == "windows" {
				for _, w := range a.Warnings {
					if w == "bootDuration:unavailable" {
						t.Error("Warnings should not contain bootDuration:unavailable when boot is unparseable")
					}
				}
			}
		})
	}
}
