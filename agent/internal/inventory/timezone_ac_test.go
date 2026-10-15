// E2E cucumber-style tests and unit tests for TASK-052 (timezone bug
// hardening): AC1-AC5. Given/When/Then comments trace each Gherkin scenario in
// the ticket; no real OS command is run and no real clock is slept on --
// everything goes through fake.CommandRunner and fake.Clock, reusing the
// windowsTimeZoneCall/darwinTimeZoneCall/hangingTimeZoneRunner helpers already
// defined in timezone_test.go (same package).
//
// timezone_test.go itself is left untouched, which is the regression lock
// AC5's "every existing TASK-046 time zone test passes" asks for.
package inventory_test

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/officehq/sk-mdm/agent/internal/inventory"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// utf16leBytes renders s as UTF-16LE bytes, with a leading FF FE byte order
// mark when bom is true.
func utf16leBytes(s string, bom bool) []byte {
	var b []byte
	if bom {
		b = append(b, 0xFF, 0xFE)
	}
	for _, u := range utf16.Encode([]rune(s)) {
		b = append(b, byte(u), byte(u>>8))
	}
	return b
}

// AC1: Scenario Outline: Windows probe output with BOM, padding, blank lines
// or other casing maps to IANA.
func TestScenario_AC1_WindowsOutputVariantsMapToSydney(t *testing.T) {
	// utf8BOM is U+FEFF encoded as UTF-8 (EF BB BF), built from raw bytes so
	// no literal byte order mark character ever lands inside this source file.
	utf8BOM := string([]byte{0xEF, 0xBB, 0xBF})

	cases := map[string]string{
		"UTF-8 BOM then the id": utf8BOM + "AUS Eastern Standard Time\r\n",
		"trailing spaces":       "AUS Eastern Standard Time   \r\n",
		"leading blank lines":   "\r\n\r\nAUS Eastern Standard Time\r\n",
		"different casing":      "aus eastern standard time\r\n",
	}

	for name, stdout := range cases {
		t.Run(name, func(t *testing.T) {
			// Given the Windows time zone probe prints <stdout> and exits 0
			runner := fake.NewCommandRunner()
			runner.Results[windowsTimeZoneCall().String()] = platform.CommandResult{Stdout: stdout, ExitCode: 0}
			clock := fake.NewClock(time.Now())

			// When the time zone collector runs for goos "windows"
			got := inventory.CollectTimeZone(runner, clock, "windows")

			// Then it returns "Australia/Sydney"
			if got != "Australia/Sydney" {
				t.Errorf("CollectTimeZone(%q) = %q, want Australia/Sydney", stdout, got)
			}
		})
	}
}

// AC2: Scenario Outline: UTF-16LE probe output maps to IANA.
func TestScenario_AC2_UTF16LEOutputMapsToSydney(t *testing.T) {
	cases := map[string]bool{
		"with a leading FF FE":    true,
		"without a leading FF FE": false,
	}

	for name, bom := range cases {
		t.Run(name, func(t *testing.T) {
			// Given the Windows time zone probe prints the UTF-16LE bytes of
			// "AUS Eastern Standard Time\r\n" <bom>
			runner := fake.NewCommandRunner()
			runner.Results[windowsTimeZoneCall().String()] = platform.CommandResult{
				Stdout:   string(utf16leBytes("AUS Eastern Standard Time\r\n", bom)),
				ExitCode: 0,
			}
			clock := fake.NewClock(time.Now())

			// When the time zone collector runs for goos "windows"
			got := inventory.CollectTimeZone(runner, clock, "windows")

			// Then it returns "Australia/Sydney"
			if got != "Australia/Sydney" {
				t.Errorf("CollectTimeZone(UTF-16LE, bom=%v) = %q, want Australia/Sydney", bom, got)
			}
		})
	}
}

// AC3: Scenario Outline: Every Australian Windows zone maps to its IANA name.
// This is the regression lock the ticket calls out: windowszones.go is
// read-only, and this proves none of the eight Australian entries moved.
func TestScenario_AC3_EveryAustralianWindowsZoneMapsToIANA(t *testing.T) {
	cases := []struct{ windowsID, iana string }{
		{"AUS Eastern Standard Time", "Australia/Sydney"},
		{"E. Australia Standard Time", "Australia/Brisbane"},
		{"Cen. Australia Standard Time", "Australia/Adelaide"},
		{"AUS Central Standard Time", "Australia/Darwin"},
		{"W. Australia Standard Time", "Australia/Perth"},
		{"Tasmania Standard Time", "Australia/Hobart"},
		{"Lord Howe Standard Time", "Australia/Lord_Howe"},
		{"Aus Central W. Standard Time", "Australia/Eucla"},
	}

	for _, c := range cases {
		t.Run(c.windowsID, func(t *testing.T) {
			// Given the Windows time zone probe prints "<windowsId>\r\n"
			runner := fake.NewCommandRunner()
			runner.Results[windowsTimeZoneCall().String()] = platform.CommandResult{
				Stdout: c.windowsID + "\r\n", ExitCode: 0,
			}
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

// AC4: Scenario Outline: ResolveTimeZone names why no zone was produced.
func TestScenario_AC4_ResolveTimeZoneNamesWhyNoZone(t *testing.T) {
	t.Run("the Windows probe prints AUS Eastern Standard Time", func(t *testing.T) {
		runner := fake.NewCommandRunner()
		runner.Results[windowsTimeZoneCall().String()] = platform.CommandResult{
			Stdout: "AUS Eastern Standard Time\r\n", ExitCode: 0,
		}
		clock := fake.NewClock(time.Now())

		// When ResolveTimeZone runs for goos "windows"
		got := inventory.ResolveTimeZone(runner, clock, "windows")

		// Then Zone is "Australia/Sydney", Reason is "" and Detail is ""
		want := inventory.TimeZoneResult{Zone: "Australia/Sydney"}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("the Windows probe prints an unmapped id", func(t *testing.T) {
		runner := fake.NewCommandRunner()
		runner.Results[windowsTimeZoneCall().String()] = platform.CommandResult{
			Stdout: "Not A Real Zone Standard Time\r\n", ExitCode: 0,
		}
		clock := fake.NewClock(time.Now())

		got := inventory.ResolveTimeZone(runner, clock, "windows")

		want := inventory.TimeZoneResult{Reason: inventory.TimeZoneUnmapped, Detail: "Not A Real Zone Standard Time"}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("the Windows probe exits with code 1", func(t *testing.T) {
		runner := fake.NewCommandRunner()
		runner.Results[windowsTimeZoneCall().String()] = platform.CommandResult{Stdout: "", ExitCode: 1}
		clock := fake.NewClock(time.Now())

		got := inventory.ResolveTimeZone(runner, clock, "windows")

		want := inventory.TimeZoneResult{Reason: inventory.TimeZoneProbeFailed}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("the Windows probe returns a runner error", func(t *testing.T) {
		runner := fake.NewCommandRunner()
		runner.Errors[windowsTimeZoneCall().String()] = errBoom
		clock := fake.NewClock(time.Now())

		got := inventory.ResolveTimeZone(runner, clock, "windows")

		want := inventory.TimeZoneResult{Reason: inventory.TimeZoneProbeFailed}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("the Windows probe does not answer within ProbeTimeout", func(t *testing.T) {
		started := make(chan struct{})
		runner := &hangingTimeZoneRunner{started: started}
		clock := fake.NewClock(time.Now())

		go func() {
			<-started
			clock.Advance(inventory.ProbeTimeout)
		}()

		got := inventory.ResolveTimeZone(runner, clock, "windows")

		want := inventory.TimeZoneResult{Reason: inventory.TimeZoneTimeout}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run(`the Windows probe prints "\r\n"`, func(t *testing.T) {
		runner := fake.NewCommandRunner()
		runner.Results[windowsTimeZoneCall().String()] = platform.CommandResult{Stdout: "\r\n", ExitCode: 0}
		clock := fake.NewClock(time.Now())

		got := inventory.ResolveTimeZone(runner, clock, "windows")

		want := inventory.TimeZoneResult{Reason: inventory.TimeZoneEmptyOutput}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("the macOS readlink probe prints a path with no zoneinfo segment", func(t *testing.T) {
		runner := fake.NewCommandRunner()
		runner.Results[darwinTimeZoneCall().String()] = platform.CommandResult{
			Stdout: "/etc/somewhere/else", ExitCode: 0,
		}
		clock := fake.NewClock(time.Now())

		got := inventory.ResolveTimeZone(runner, clock, "darwin")

		want := inventory.TimeZoneResult{Reason: inventory.TimeZoneNoZoneinfo, Detail: "/etc/somewhere/else"}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a working runner, goos linux", func(t *testing.T) {
		runner := fake.NewCommandRunner()
		clock := fake.NewClock(time.Now())

		got := inventory.ResolveTimeZone(runner, clock, "linux")

		want := inventory.TimeZoneResult{Reason: inventory.TimeZoneUnsupportedOS, Detail: "linux"}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a nil runner", func(t *testing.T) {
		clock := fake.NewClock(time.Now())

		got := inventory.ResolveTimeZone(nil, clock, "windows")

		want := inventory.TimeZoneResult{Reason: inventory.TimeZoneNoCollector}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a nil clock", func(t *testing.T) {
		runner := fake.NewCommandRunner()

		got := inventory.ResolveTimeZone(runner, nil, "windows")

		want := inventory.TimeZoneResult{Reason: inventory.TimeZoneNoCollector}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})
}

// errBoom is a plain sentinel for the "runner error" scenario.
var errBoom = errors.New("boom")

// Scenario: An over-long unknown Windows ID is cut to 64 characters in Detail.
func TestScenario_AC4Edge_OverLongUnknownIDCutTo64Characters(t *testing.T) {
	// Given the Windows probe prints a 100-character unknown ID
	id := strings.Repeat("Z", 100)
	runner := fake.NewCommandRunner()
	runner.Results[windowsTimeZoneCall().String()] = platform.CommandResult{Stdout: id + "\r\n", ExitCode: 0}
	clock := fake.NewClock(time.Now())

	// When ResolveTimeZone runs for goos "windows"
	got := inventory.ResolveTimeZone(runner, clock, "windows")

	// Then Reason is "unmapped" and Detail is the first 64 characters of that ID
	if got.Reason != inventory.TimeZoneUnmapped {
		t.Fatalf("Reason = %q, want unmapped", got.Reason)
	}
	if got.Detail != id[:64] {
		t.Errorf("Detail = %q (%d runes), want the first 64 characters of the 100-character ID", got.Detail, len([]rune(got.Detail)))
	}
	if len([]rune(got.Detail)) != 64 {
		t.Errorf("Detail has %d runes, want 64", len([]rune(got.Detail)))
	}
}

// AC5: Scenario: CollectTimeZone returns ResolveTimeZone's zone.
func TestScenario_AC5_CollectTimeZoneReturnsResolveTimeZonesZone(t *testing.T) {
	// Given the Windows probe prints "Not A Real Zone Standard Time\r\n"
	runner := fake.NewCommandRunner()
	runner.Results[windowsTimeZoneCall().String()] = platform.CommandResult{
		Stdout: "Not A Real Zone Standard Time\r\n", ExitCode: 0,
	}
	clock := fake.NewClock(time.Now())

	// When CollectTimeZone and ResolveTimeZone run for goos "windows"
	collected := inventory.CollectTimeZone(runner, clock, "windows")
	resolved := inventory.ResolveTimeZone(runner, clock, "windows")

	// Then CollectTimeZone returns "" which equals ResolveTimeZone's Zone
	if collected != "" {
		t.Errorf("CollectTimeZone = %q, want \"\"", collected)
	}
	if collected != resolved.Zone {
		t.Errorf("CollectTimeZone = %q, ResolveTimeZone.Zone = %q, want equal", collected, resolved.Zone)
	}
	// And every existing TASK-046 time zone test passes: left to
	// timezone_test.go, which this file does not touch.
}

// Unit: unspecified extras the coder's hand-off calls out -- an empty darwin
// probe output, and a darwin link that ends in the zoneinfo/ segment with
// nothing after it.
func TestUnit_DarwinEmptyOutputAndBareZoneinfoSegment(t *testing.T) {
	t.Run("empty darwin output", func(t *testing.T) {
		runner := fake.NewCommandRunner()
		runner.Results[darwinTimeZoneCall().String()] = platform.CommandResult{Stdout: "", ExitCode: 0}
		clock := fake.NewClock(time.Now())

		got := inventory.ResolveTimeZone(runner, clock, "darwin")

		if got.Reason != inventory.TimeZoneEmptyOutput {
			t.Errorf("Reason = %q, want empty_output", got.Reason)
		}
	})

	t.Run("link ends in zoneinfo/ with nothing after", func(t *testing.T) {
		link := "/var/db/timezone/zoneinfo/"
		runner := fake.NewCommandRunner()
		runner.Results[darwinTimeZoneCall().String()] = platform.CommandResult{Stdout: link, ExitCode: 0}
		clock := fake.NewClock(time.Now())

		got := inventory.ResolveTimeZone(runner, clock, "darwin")

		want := inventory.TimeZoneResult{Reason: inventory.TimeZoneNoZoneinfo, Detail: link}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})
}
