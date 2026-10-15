// E2E cucumber-style tests for the scheduler's time zone wiring (TASK-046,
// AC5). No real HTTP, filesystem or OS clock is used: Client, Store, FS and
// Clock are all fakes.
package scheduler

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/inventory"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

func timeZoneTestDeps(clock *fake.Clock, fsys *fake.FS, transport *mockTransport, collect func() inventory.TimeZoneResult) *Deps {
	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("windows"), stateData)

	return &Deps{
		Client: transport,
		Store:  &fakeStore{state: st},
		FS:     fsys,
		Clock:  clock,
		GOOS:   "windows",
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
		CollectTimeZone: collect,
	}
}

// AC5: Scenario: The check-in carries the collected time zone.
func TestScenario_CheckInCarriesCollectedTimeZone(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	var checkinBody []byte
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinBody = body
				return fake.Response(http.StatusOK, "{}"), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	// Given the time zone collector returns "Australia/Sydney"
	deps := timeZoneTestDeps(clock, fsys, transport, func() inventory.TimeZoneResult { return inventory.TimeZoneResult{Zone: "Australia/Sydney"} })

	// When the scheduler runs one cycle
	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then the posted check-in body has "timeZone" equal to "Australia/Sydney"
	var req contract.CheckInRequest
	if err := json.Unmarshal(checkinBody, &req); err != nil {
		t.Fatalf("failed to unmarshal checkin body: %v", err)
	}
	if req.TimeZone != "Australia/Sydney" {
		t.Errorf("TimeZone = %q, want %q", req.TimeZone, "Australia/Sydney")
	}
	if !strings.Contains(string(checkinBody), `"timeZone":"Australia/Sydney"`) {
		t.Errorf("checkin body missing timeZone key: %s", checkinBody)
	}
}

// AC5: Scenario: The check-in omits the time zone when none was collected.
func TestScenario_CheckInOmitsTimeZoneWhenNoneCollected(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	var checkinBody []byte
	var posted bool
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "POST" && strings.Contains(path, "checkin") {
				posted = true
				checkinBody = body
				return fake.Response(http.StatusOK, "{}"), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	// Given the time zone collector returns ""
	deps := timeZoneTestDeps(clock, fsys, transport, func() inventory.TimeZoneResult { return inventory.TimeZoneResult{Reason: inventory.TimeZoneTimeout} })

	// When the scheduler runs one cycle
	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then the check-in is posted
	if !posted {
		t.Fatal("expected the check-in to be posted")
	}
	// And the posted check-in body has no "timeZone" key
	if strings.Contains(string(checkinBody), `"timeZone"`) {
		t.Errorf("checkin body should carry no timeZone key, got: %s", checkinBody)
	}
}

// Edge: with no CollectTimeZone override and no Runner, the cycle still posts
// and carries no timeZone (the "neither is set" rule collectTimeZone documents).
func TestScheduler_NoCollectorAndNoRunnerYieldsNoTimeZone(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	var checkinBody []byte
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinBody = body
				return fake.Response(http.StatusOK, "{}"), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	deps := timeZoneTestDeps(clock, fsys, transport, nil)
	deps.CollectTimeZone = nil // Runner is also left nil by timeZoneTestDeps

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}
	if strings.Contains(string(checkinBody), `"timeZone"`) {
		t.Errorf("checkin body should carry no timeZone key, got: %s", checkinBody)
	}
}

// ============================================================================
// TASK-052: diagnostics for the time zone collector -- AC6-AC10.
//
// E2E cucumber-style tests and unit-style helpers. No real HTTP, filesystem,
// clock or OS command is used: Client, Store, FS and Clock are all fakes, and
// the agent log is read back from fake.FS exactly as the existing scheduler
// tests do with logging.New (see signin_wait_test.go).
// ============================================================================

// withTimeZoneLogger adds a scheduler-component logger over fsys to deps, so
// a test can read the agent log back afterwards.
func withTimeZoneLogger(deps *Deps, clock *fake.Clock, fsys *fake.FS) *Deps {
	deps.Logger = logging.New(fsys, clock, "agent.log", logging.LevelInfo, "scheduler")
	return deps
}

// readLogLines decodes every JSON line fsys's agent.log holds.
func readLogLines(t *testing.T, fsys *fake.FS) []map[string]any {
	t.Helper()
	data, _ := fsys.Content("agent.log")
	var lines []map[string]any
	for _, raw := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if raw == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatalf("bad log line %q: %v", raw, err)
		}
		lines = append(lines, m)
	}
	return lines
}

// filterByMsg returns the log lines whose "msg" field equals msg.
func filterByMsg(lines []map[string]any, msg string) []map[string]any {
	var out []map[string]any
	for _, l := range lines {
		if l["msg"] == msg {
			out = append(out, l)
		}
	}
	return out
}

// quietCheckInTransport posts 200 to every request and records the last
// checkin body.
func quietCheckInTransport(body *[]byte, posted *bool) *mockTransport {
	return &mockTransport{
		doFunc: func(method, path string, b []byte) (*http.Response, error) {
			if method == "POST" && strings.Contains(path, "checkin") {
				if posted != nil {
					*posted = true
				}
				*body = b
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}
}

// AC6: Scenario: A collected zone is logged once at info.
func TestScenario_AC6_CollectedZoneLoggedOnceAtInfo(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	var body []byte

	// Given the time zone collector resolves "Australia/Sydney"
	deps := timeZoneTestDeps(clock, fsys, quietCheckInTransport(&body, nil), func() inventory.TimeZoneResult {
		return inventory.TimeZoneResult{Zone: "Australia/Sydney"}
	})
	deps = withTimeZoneLogger(deps, clock, fsys)

	// When the scheduler runs its first cycle
	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then the agent log has exactly one info record "time zone collected"
	// from component "scheduler" with zone "Australia/Sydney"
	lines := readLogLines(t, fsys)
	collected := filterByMsg(lines, "time zone collected")
	if len(collected) != 1 {
		t.Fatalf("got %d 'time zone collected' records, want 1: %v", len(collected), lines)
	}
	rec := collected[0]
	if rec["level"] != "info" {
		t.Errorf("level = %v, want info", rec["level"])
	}
	if rec["component"] != "scheduler" {
		t.Errorf("component = %v, want scheduler", rec["component"])
	}
	if rec["zone"] != "Australia/Sydney" {
		t.Errorf("zone = %v, want Australia/Sydney", rec["zone"])
	}
}

// AC7: Scenario: An uncollected zone is logged once at warn with its reason
// and detail.
func TestScenario_AC7_UncollectedZoneLoggedOnceAtWarnWithReasonAndDetail(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	var body []byte

	// Given the time zone collector returns Reason "unmapped" and Detail "Foo Standard Time"
	deps := timeZoneTestDeps(clock, fsys, quietCheckInTransport(&body, nil), func() inventory.TimeZoneResult {
		return inventory.TimeZoneResult{Reason: inventory.TimeZoneUnmapped, Detail: "Foo Standard Time"}
	})
	deps = withTimeZoneLogger(deps, clock, fsys)

	// When the scheduler runs its first cycle
	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then the agent log has exactly one warn record "time zone not collected"
	// with reason "unmapped" and detail "Foo Standard Time"
	lines := readLogLines(t, fsys)
	warned := filterByMsg(lines, "time zone not collected")
	if len(warned) != 1 {
		t.Fatalf("got %d 'time zone not collected' records, want 1: %v", len(warned), lines)
	}
	rec := warned[0]
	if rec["level"] != "warn" {
		t.Errorf("level = %v, want warn", rec["level"])
	}
	if rec["reason"] != "unmapped" {
		t.Errorf("reason = %v, want unmapped", rec["reason"])
	}
	if rec["detail"] != "Foo Standard Time" {
		t.Errorf("detail = %v, want %q", rec["detail"], "Foo Standard Time")
	}
}

// Scenario: A reason with no detail is logged without a detail field.
func TestScenario_AC7Edge_ReasonWithNoDetailLoggedWithoutDetailField(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	var body []byte

	// Given the time zone collector returns Reason "timeout" and an empty Detail
	deps := timeZoneTestDeps(clock, fsys, quietCheckInTransport(&body, nil), func() inventory.TimeZoneResult {
		return inventory.TimeZoneResult{Reason: inventory.TimeZoneTimeout}
	})
	deps = withTimeZoneLogger(deps, clock, fsys)

	// When the scheduler runs its first cycle
	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then the warn record "time zone not collected" has reason "timeout" and
	// no detail field
	lines := readLogLines(t, fsys)
	warned := filterByMsg(lines, "time zone not collected")
	if len(warned) != 1 {
		t.Fatalf("got %d 'time zone not collected' records, want 1: %v", len(warned), lines)
	}
	rec := warned[0]
	if rec["reason"] != "timeout" {
		t.Errorf("reason = %v, want timeout", rec["reason"])
	}
	if _, ok := rec["detail"]; ok {
		t.Errorf("detail field present, want absent: %v", rec)
	}
}

// AC8: Scenario: An unchanged result is not logged again, a changed one is.
func TestScenario_AC8_UnchangedResultNotLoggedAgainChangedOneIs(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	var body []byte

	cycle := 0
	// Given the time zone collector returns Reason "timeout" on cycles 1 and 2
	// and resolves "Australia/Sydney" on cycle 3
	deps := timeZoneTestDeps(clock, fsys, quietCheckInTransport(&body, nil), func() inventory.TimeZoneResult {
		cycle++
		if cycle <= 2 {
			return inventory.TimeZoneResult{Reason: inventory.TimeZoneTimeout}
		}
		return inventory.TimeZoneResult{Zone: "Australia/Sydney"}
	})
	deps = withTimeZoneLogger(deps, clock, fsys)

	// When the scheduler runs three cycles (the same Deps, so the
	// de-duplication state survives between RunOnce calls)
	for i := 1; i <= 3; i++ {
		if err := RunOnce(context.Background(), deps); err != nil {
			t.Fatalf("cycle %d: RunOnce failed: %v", i, err)
		}
	}

	lines := readLogLines(t, fsys)
	notCollected := filterByMsg(lines, "time zone not collected")
	collected := filterByMsg(lines, "time zone collected")

	// Then cycle 2 writes no time zone record: only cycle 1's warning is logged
	if len(notCollected) != 1 {
		t.Errorf("'time zone not collected' logged %d times, want 1: %v", len(notCollected), lines)
	}
	// And cycle 3 writes exactly one info record "time zone collected" with
	// zone "Australia/Sydney"
	if len(collected) != 1 {
		t.Fatalf("'time zone collected' logged %d times, want 1: %v", len(collected), lines)
	}
	if collected[0]["zone"] != "Australia/Sydney" {
		t.Errorf("zone = %v, want Australia/Sydney", collected[0]["zone"])
	}
}

// AC9: Scenario: An uncollected zone adds one timezone warning to the
// check-in inventory.
func TestScenario_AC9_UncollectedZoneAddsOneTimezoneWarning(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	var body []byte

	// Given the inventory collector returns warnings ["software"]
	// And the time zone collector returns Reason "unmapped" and Detail "Foo Standard Time"
	deps := timeZoneTestDeps(clock, fsys, quietCheckInTransport(&body, nil), func() inventory.TimeZoneResult {
		return inventory.TimeZoneResult{Reason: inventory.TimeZoneUnmapped, Detail: "Foo Standard Time"}
	})
	deps.CollectInventory = func() (contract.Inventory, error) {
		return contract.Inventory{Warnings: []string{"software"}}, nil
	}

	// When the scheduler runs one cycle
	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then the posted inventory.warnings is ["software", "timezone:unmapped:Foo Standard Time"]
	var req contract.CheckInRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("failed to unmarshal checkin body: %v", err)
	}
	want := []string{"software", "timezone:unmapped:Foo Standard Time"}
	if !reflect.DeepEqual(req.Inventory.Warnings, want) {
		t.Errorf("warnings = %v, want %v", req.Inventory.Warnings, want)
	}
}

// Scenario: A timeout adds timezone:timeout. Also exercises the "nil
// Warnings" edge case: CollectInventory returns no Warnings slice at all.
func TestScenario_AC9Edge_TimeoutAddsTimezoneTimeoutWithNilWarnings(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	var body []byte

	// Given the time zone collector returns Reason "timeout"
	deps := timeZoneTestDeps(clock, fsys, quietCheckInTransport(&body, nil), func() inventory.TimeZoneResult {
		return inventory.TimeZoneResult{Reason: inventory.TimeZoneTimeout}
	})
	// A CollectInventory that returns nil Warnings.
	deps.CollectInventory = func() (contract.Inventory, error) {
		return contract.Inventory{}, nil
	}

	// When the scheduler runs one cycle
	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then the posted inventory.warnings contains "timezone:timeout"
	var req contract.CheckInRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("failed to unmarshal checkin body: %v", err)
	}
	want := []string{"timezone:timeout"}
	if !reflect.DeepEqual(req.Inventory.Warnings, want) {
		t.Errorf("warnings = %v, want %v", req.Inventory.Warnings, want)
	}
}

// Scenario: A collected zone adds no timezone warning.
func TestScenario_AC9Edge_CollectedZoneAddsNoTimezoneWarning(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	var body []byte

	// Given the inventory collector returns warnings ["software"]
	// And the time zone collector resolves "Australia/Sydney"
	deps := timeZoneTestDeps(clock, fsys, quietCheckInTransport(&body, nil), func() inventory.TimeZoneResult {
		return inventory.TimeZoneResult{Zone: "Australia/Sydney"}
	})
	deps.CollectInventory = func() (contract.Inventory, error) {
		return contract.Inventory{Warnings: []string{"software"}}, nil
	}

	// When the scheduler runs one cycle
	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then the posted inventory.warnings is ["software"]
	// And the posted body has "timeZone" equal to "Australia/Sydney"
	var req contract.CheckInRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("failed to unmarshal checkin body: %v", err)
	}
	want := []string{"software"}
	if !reflect.DeepEqual(req.Inventory.Warnings, want) {
		t.Errorf("warnings = %v, want %v", req.Inventory.Warnings, want)
	}
	if req.TimeZone != "Australia/Sydney" {
		t.Errorf("TimeZone = %q, want Australia/Sydney", req.TimeZone)
	}
}

// AC10: Scenario: No collector and no runner still posts, with a diagnostic.
func TestScenario_AC10_NoCollectorAndNoRunnerStillPostsWithDiagnostic(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	var body []byte
	var posted bool

	// Given scheduler deps with no time zone override and a nil Runner
	deps := timeZoneTestDeps(clock, fsys, quietCheckInTransport(&body, &posted), nil)
	deps.CollectTimeZone = nil // Runner is also left nil by timeZoneTestDeps
	deps = withTimeZoneLogger(deps, clock, fsys)

	// When the scheduler runs one cycle
	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then the check-in is posted with no "timeZone" key
	if !posted {
		t.Fatal("expected the check-in to be posted")
	}
	if strings.Contains(string(body), `"timeZone"`) {
		t.Errorf("checkin body should carry no timeZone key, got: %s", body)
	}

	// And the posted inventory.warnings contains "timezone:no_collector"
	var req contract.CheckInRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("failed to unmarshal checkin body: %v", err)
	}
	found := false
	for _, w := range req.Inventory.Warnings {
		if w == "timezone:no_collector" {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings = %v, want to contain timezone:no_collector", req.Inventory.Warnings)
	}

	// And one warn record "time zone not collected" with reason "no_collector" is logged
	lines := readLogLines(t, fsys)
	warned := filterByMsg(lines, "time zone not collected")
	if len(warned) != 1 {
		t.Fatalf("got %d 'time zone not collected' records, want 1: %v", len(warned), lines)
	}
	if warned[0]["reason"] != "no_collector" {
		t.Errorf("reason = %v, want no_collector", warned[0]["reason"])
	}
}
