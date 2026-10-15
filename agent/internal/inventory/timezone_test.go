// E2E cucumber-style tests and unit tests for CollectTimeZone (TASK-046).
// Given/When/Then scenarios cover AC2, AC3 and AC4; no real OS command is run
// and no real clock is slept on -- everything goes through fake.CommandRunner
// and fake.Clock.
package inventory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/inventory"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

const windowsTimeZoneCmd = "powershell.exe"

var windowsTimeZoneArgs = []string{"-NoProfile", "-NonInteractive", "-Command", "(Get-TimeZone).Id"}

func windowsTimeZoneCall() fake.Command {
	return fake.Command{Name: windowsTimeZoneCmd, Args: windowsTimeZoneArgs}
}

func darwinTimeZoneCall() fake.Command {
	return fake.Command{Name: "/usr/bin/readlink", Args: []string{"/etc/localtime"}}
}

// AC2: Scenario Outline: Windows zone ids map to IANA names.
func TestScenario_WindowsZoneIdsMapToIANANames(t *testing.T) {
	cases := []struct {
		windowsID string
		iana      string
	}{
		{"AUS Eastern Standard Time", "Australia/Sydney"},
		{"Pacific Standard Time", "America/Los_Angeles"},
		{"UTC", "Etc/UTC"},
	}

	for _, c := range cases {
		t.Run(c.windowsID, func(t *testing.T) {
			// Given the Windows time zone probe prints "<windowsId>"
			runner := fake.NewCommandRunner()
			runner.Results[windowsTimeZoneCall().String()] = platform.CommandResult{Stdout: c.windowsID + "\n", ExitCode: 0}
			clock := fake.NewClock(time.Now())

			// When the time zone collector runs for goos "windows"
			got := inventory.CollectTimeZone(runner, clock, "windows")

			// Then it returns "<iana>"
			if got != c.iana {
				t.Errorf("CollectTimeZone(%q) = %q, want %q", c.windowsID, got, c.iana)
			}
		})
	}
}

// AC3: Scenario Outline: Windows collection failures return an empty zone.
func TestScenario_WindowsCollectionFailuresReturnEmptyZone(t *testing.T) {
	t.Run("prints an ID not in the mapping table", func(t *testing.T) {
		// Given the Windows time zone probe prints "Not A Real Zone Standard Time"
		runner := fake.NewCommandRunner()
		runner.Results[windowsTimeZoneCall().String()] = platform.CommandResult{
			Stdout: "Not A Real Zone Standard Time\n", ExitCode: 0,
		}
		clock := fake.NewClock(time.Now())

		// When the time zone collector runs for goos "windows"
		got := inventory.CollectTimeZone(runner, clock, "windows")

		// Then it returns ""
		if got != "" {
			t.Errorf("got %q, want \"\"", got)
		}
	})

	t.Run("exits with code 1", func(t *testing.T) {
		// Given the Windows time zone probe exits with code 1
		runner := fake.NewCommandRunner()
		runner.Results[windowsTimeZoneCall().String()] = platform.CommandResult{Stdout: "", ExitCode: 1}
		clock := fake.NewClock(time.Now())

		// When the time zone collector runs for goos "windows"
		got := inventory.CollectTimeZone(runner, clock, "windows")

		// Then it returns ""
		if got != "" {
			t.Errorf("got %q, want \"\"", got)
		}
	})

	t.Run("returns an error", func(t *testing.T) {
		// Given the Windows time zone probe returns an error
		runner := fake.NewCommandRunner()
		runner.Errors[windowsTimeZoneCall().String()] = errors.New("boom")
		clock := fake.NewClock(time.Now())

		// When the time zone collector runs for goos "windows"
		got := inventory.CollectTimeZone(runner, clock, "windows")

		// Then it returns ""
		if got != "" {
			t.Errorf("got %q, want \"\"", got)
		}
	})

	t.Run("does not answer within ProbeTimeout", func(t *testing.T) {
		// Given the Windows time zone probe does not answer within ProbeTimeout
		started := make(chan struct{})
		runner := &hangingTimeZoneRunner{started: started}
		clock := fake.NewClock(time.Now())

		go func() {
			<-started
			clock.Advance(inventory.ProbeTimeout)
		}()

		// When the time zone collector runs for goos "windows"
		got := inventory.CollectTimeZone(runner, clock, "windows")

		// Then it returns ""
		if got != "" {
			t.Errorf("got %q, want \"\"", got)
		}
	})
}

// hangingTimeZoneRunner never answers the timezone probe, letting a test drive
// the fake clock past ProbeTimeout.
type hangingTimeZoneRunner struct {
	started chan struct{}
	once    bool
}

func (h *hangingTimeZoneRunner) Run(ctx context.Context, name string, args ...string) (platform.CommandResult, error) {
	close(h.started)
	select {}
}

// AC4: Scenario: macOS zone is read from the /etc/localtime link, and the
// no-zoneinfo / failed-probe edge cases.
func TestScenario_MacOSZoneFromLocaltimeLink(t *testing.T) {
	// Given the macOS probe "readlink /etc/localtime" prints the zoneinfo path
	runner := fake.NewCommandRunner()
	runner.Results[darwinTimeZoneCall().String()] = platform.CommandResult{
		Stdout: "/var/db/timezone/zoneinfo/Australia/Sydney\n", ExitCode: 0,
	}
	clock := fake.NewClock(time.Now())

	// When the time zone collector runs for goos "darwin"
	got := inventory.CollectTimeZone(runner, clock, "darwin")

	// Then it returns "Australia/Sydney"
	if got != "Australia/Sydney" {
		t.Errorf("got %q, want %q", got, "Australia/Sydney")
	}
}

func TestScenario_MacOSLinkWithoutZoneinfoOrFailedProbeReturnsEmptyZone(t *testing.T) {
	t.Run("no zoneinfo segment", func(t *testing.T) {
		// Given the macOS probe prints a path with no "zoneinfo/" segment
		runner := fake.NewCommandRunner()
		runner.Results[darwinTimeZoneCall().String()] = platform.CommandResult{
			Stdout: "/etc/somewhere/else\n", ExitCode: 0,
		}
		clock := fake.NewClock(time.Now())

		// When the time zone collector runs for goos "darwin"
		got := inventory.CollectTimeZone(runner, clock, "darwin")

		// Then it returns ""
		if got != "" {
			t.Errorf("got %q, want \"\"", got)
		}
	})

	t.Run("probe fails", func(t *testing.T) {
		// Given the macOS probe exits with code 1
		runner := fake.NewCommandRunner()
		runner.Results[darwinTimeZoneCall().String()] = platform.CommandResult{Stdout: "", ExitCode: 1}
		clock := fake.NewClock(time.Now())

		// When the time zone collector runs for goos "darwin"
		got := inventory.CollectTimeZone(runner, clock, "darwin")

		// Then it returns ""
		if got != "" {
			t.Errorf("got %q, want \"\"", got)
		}
	})
}

// Edge cases beyond the frozen Gherkin: unsupported goos and nil runner/clock.
func TestCollectTimeZone_UnsupportedGoosAndNilDependencies(t *testing.T) {
	runner := fake.NewCommandRunner()
	clock := fake.NewClock(time.Now())

	if got := inventory.CollectTimeZone(runner, clock, "linux"); got != "" {
		t.Errorf("unsupported goos: got %q, want \"\"", got)
	}
	if got := inventory.CollectTimeZone(nil, clock, "windows"); got != "" {
		t.Errorf("nil runner: got %q, want \"\"", got)
	}
	if got := inventory.CollectTimeZone(runner, nil, "windows"); got != "" {
		t.Errorf("nil clock: got %q, want \"\"", got)
	}
}

// Unit: a handful of CLDR territory="001" spot checks beyond AC2's frozen three.
func TestWindowsZones_SpotChecks(t *testing.T) {
	cases := map[string]string{
		"GMT Standard Time":              "Europe/London",
		"Eastern Standard Time":          "America/New_York",
		"Central European Standard Time": "Europe/Warsaw",
		"W. Australia Standard Time":     "Australia/Perth",
		"New Zealand Standard Time":      "Pacific/Auckland",
		"India Standard Time":            "Asia/Calcutta",
	}
	for windowsID, want := range cases {
		runner := fake.NewCommandRunner()
		runner.Results[windowsTimeZoneCall().String()] = platform.CommandResult{Stdout: windowsID, ExitCode: 0}
		clock := fake.NewClock(time.Now())
		got := inventory.CollectTimeZone(runner, clock, "windows")
		if got != want {
			t.Errorf("windowsZones[%q] = %q, want %q", windowsID, got, want)
		}
	}
}
