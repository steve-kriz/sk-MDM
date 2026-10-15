// E2E cucumber-style tests for TASK-044's analytics.CollectPerformance: the
// performance-only probe the heartbeat uses.
package analytics_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/analytics"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// seedPerformanceOnly arranges the runner so only the performance probe of
// goos answers with the fixture content loaded by loadFixture; every other
// probe for that goos is never invoked by CollectPerformance, so nothing else
// needs seeding.
func seedPerformanceOnly(t *testing.T, goos string) *fake.CommandRunner {
	t.Helper()
	runner := fake.NewCommandRunner()
	fixture, err := loadFixture(goos, analytics.ProbePerformance)
	if err != nil {
		t.Fatalf("loadFixture: %v", err)
	}
	for _, p := range analytics.Probes(goos) {
		if p.Name == analytics.ProbePerformance {
			runner.Results[p.String()] = platform.CommandResult{Stdout: fixture, ExitCode: 0}
		}
	}
	return runner
}

// TestScenario_CollectPerformanceMatchesCollect verifies that for a
// supported goos, CollectPerformance returns exactly the values Collect puts
// in Analytics.Performance, with no warnings.
func TestScenario_CollectPerformanceMatchesCollect(t *testing.T) {
	for _, goos := range []string{"windows", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			runner := seedPerformanceOnly(t, goos)
			clock := fake.NewClock(time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC))

			got, warnings := analytics.CollectPerformance(runner, clock, goos)

			// Collect() runs every probe; only the performance probe is
			// seeded here, so boot/crashes come back empty but that does not
			// affect Performance.
			collectRunner := seedPerformanceOnly(t, goos)
			full, _, err := analytics.Collect(collectRunner, clock, goos, time.Time{})
			if err != nil {
				t.Fatalf("Collect failed: %v", err)
			}

			if !reflect.DeepEqual(got, full.Performance) {
				t.Errorf("CollectPerformance = %+v, want %+v (Collect's Performance)", got, full.Performance)
			}
			if len(warnings) != 0 {
				t.Errorf("warnings = %v, want none", warnings)
			}
		})
	}
}

// TestScenario_CollectPerformanceProbeFails verifies that a non-zero exit
// yields an all-nil sample and the warning "performance".
func TestScenario_CollectPerformanceProbeFails(t *testing.T) {
	runner := fake.NewCommandRunner()
	for _, p := range analytics.Probes("windows") {
		if p.Name == analytics.ProbePerformance {
			runner.Results[p.String()] = platform.CommandResult{Stdout: "", ExitCode: 1}
		}
	}
	clock := fake.NewClock(time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC))

	got, warnings := analytics.CollectPerformance(runner, clock, "windows")

	if got.CPUPercent != nil || got.MemoryUsedBytes != nil || got.MemoryTotalBytes != nil ||
		got.SystemDiskFreeBytes != nil || got.SystemDiskTotalBytes != nil {
		t.Errorf("expected every field nil, got %+v", got)
	}
	if len(warnings) != 1 || warnings[0] != analytics.ProbePerformance {
		t.Errorf("warnings = %v, want [%q]", warnings, analytics.ProbePerformance)
	}
}

// TestScenario_CollectPerformanceUnsupportedGOOS verifies that an
// unsupported goos runs no probe and returns an all-nil sample with the
// warning "performance".
func TestScenario_CollectPerformanceUnsupportedGOOS(t *testing.T) {
	runner := fake.NewCommandRunner()
	clock := fake.NewClock(time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC))

	got, warnings := analytics.CollectPerformance(runner, clock, "linux")

	if got.CPUPercent != nil || got.MemoryUsedBytes != nil || got.MemoryTotalBytes != nil ||
		got.SystemDiskFreeBytes != nil || got.SystemDiskTotalBytes != nil {
		t.Errorf("expected every field nil, got %+v", got)
	}
	if len(warnings) != 1 || warnings[0] != analytics.ProbePerformance {
		t.Errorf("warnings = %v, want [%q]", warnings, analytics.ProbePerformance)
	}
	if calls := runner.Calls(); len(calls) != 0 {
		t.Errorf("expected no probe run for an unsupported goos, got %d calls", len(calls))
	}
}
