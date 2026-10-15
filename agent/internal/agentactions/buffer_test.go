package agentactions

import (
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// ============================================================================
// AC3: New, Record, RecordAt, Collect.
// ============================================================================

// TestScenario_AC3_TheBufferStampsOrdersAndDrainsActions covers:
//
//	Given a buffer on a fake clock reading 2026-10-12T01:00:00.700Z
//	When "enforce.domains_updated" is recorded with details blockedCount "4"
//	And "agent.update_rolled_back" is recorded at 2026-10-12T00:59:00Z
//	Then Collect returns the rollback first and then the domains action with
//	     occurredAt "2026-10-12T01:00:00Z"
//	And a second Collect returns nil
func TestScenario_AC3_TheBufferStampsOrdersAndDrainsActions(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 12, 1, 0, 0, 700_000_000, time.UTC))
	buf := New(clock)

	buf.Record("enforce.domains_updated", map[string]string{"blockedCount": "4"})
	buf.RecordAt("agent.update_rolled_back", map[string]string{"installedVersion": "1.5.0"},
		time.Date(2026, 10, 12, 0, 59, 0, 0, time.UTC))

	actions := buf.Collect()
	if len(actions) != 2 {
		t.Fatalf("Collect returned %d actions, want 2: %+v", len(actions), actions)
	}
	if actions[0].Type != "agent.update_rolled_back" {
		t.Errorf("first action type = %q, want the rollback (earlier occurredAt)", actions[0].Type)
	}
	if actions[1].Type != "enforce.domains_updated" {
		t.Errorf("second action type = %q, want the domains update", actions[1].Type)
	}
	// The fake clock's sub-second time is truncated to the second on Record.
	if actions[1].OccurredAt != "2026-10-12T01:00:00Z" {
		t.Errorf("domains action occurredAt = %q, want truncated to the second", actions[1].OccurredAt)
	}
	if actions[0].OccurredAt != "2026-10-12T00:59:00Z" {
		t.Errorf("rollback action occurredAt = %q", actions[0].OccurredAt)
	}

	// And a second Collect returns nil
	if second := buf.Collect(); second != nil {
		t.Errorf("second Collect = %+v, want nil", second)
	}
}

// TestScenario_AC3_EqualTimesKeepRecordOrder covers the "equal times in
// record order" clause of Collect's ordering guarantee.
func TestScenario_AC3_EqualTimesKeepRecordOrder(t *testing.T) {
	at := time.Date(2026, 10, 12, 1, 0, 0, 0, time.UTC)
	clock := fake.NewClock(at)
	buf := New(clock)

	buf.Record("enforce.firewall_enabled", nil)
	buf.Record("enforce.antivirus_enabled", nil)

	actions := buf.Collect()
	if len(actions) != 2 {
		t.Fatalf("Collect returned %d actions, want 2", len(actions))
	}
	if actions[0].Type != "enforce.firewall_enabled" || actions[1].Type != "enforce.antivirus_enabled" {
		t.Errorf("actions in the wrong order for equal occurredAt: %+v", actions)
	}
}

// TestScenario_AC3_CollectOnAnEmptyBufferReturnsNil covers Collect's nil
// return on an empty buffer, directly (not only as "a second Collect").
func TestScenario_AC3_CollectOnAnEmptyBufferReturnsNil(t *testing.T) {
	buf := New(fake.NewClock(time.Now()))
	if got := buf.Collect(); got != nil {
		t.Errorf("Collect on an empty buffer = %+v, want nil", got)
	}
}

// TestScenario_AC3_NewWithNilClockUsesSystemTime covers "New(clock) (nil ->
// SystemClock)": a nil clock still stamps a real, recent time rather than
// panicking or zero-valuing.
func TestScenario_AC3_NewWithNilClockUsesSystemTime(t *testing.T) {
	buf := New(nil)
	before := time.Now().UTC().Add(-time.Minute)
	buf.Record("enforce.firewall_enabled", nil)
	actions := buf.Collect()
	if len(actions) != 1 {
		t.Fatalf("Collect returned %d actions, want 1", len(actions))
	}
	at, err := time.Parse(timeFormat, actions[0].OccurredAt)
	if err != nil {
		t.Fatalf("occurredAt %q did not parse: %v", actions[0].OccurredAt, err)
	}
	if at.Before(before) {
		t.Errorf("occurredAt %s looks stale for the system clock (before %s)", at, before)
	}
}

// TestScenario_AC3_DetailsAreNormalised covers: at most 8 entries in sorted
// key order, keys cut to 64 runes, values cut to 256 runes, and a nil map
// becomes an empty non-nil map.
func TestScenario_AC3_DetailsAreNormalised(t *testing.T) {
	clock := fake.NewClock(time.Now())
	buf := New(clock)

	details := map[string]string{}
	for i := 0; i < 10; i++ {
		details["k"+strconv.Itoa(i)] = "v" + strconv.Itoa(i)
	}
	longKey := strings.Repeat("k", 100)
	longValue := strings.Repeat("v", 300)
	details[longKey] = longValue

	buf.Record("enforce.domains_updated", details)
	actions := buf.Collect()
	if len(actions) != 1 {
		t.Fatalf("Collect returned %d actions, want 1", len(actions))
	}
	got := actions[0].Details
	if len(got) != MaxDetails {
		t.Fatalf("kept %d details, want %d: %+v", len(got), MaxDetails, got)
	}
	for k, v := range got {
		if len([]rune(k)) > MaxKeyRunes {
			t.Errorf("key %q longer than %d runes", k, MaxKeyRunes)
		}
		if len([]rune(v)) > MaxValueRunes {
			t.Errorf("value for key %q longer than %d runes", k, MaxValueRunes)
		}
	}
}

// TestScenario_AC3_NilDetailsBecomeEmptyNonNilMap covers the "nil map becomes
// an empty non-nil map" clause directly.
func TestScenario_AC3_NilDetailsBecomeEmptyNonNilMap(t *testing.T) {
	buf := New(fake.NewClock(time.Now()))
	buf.Record("enforce.firewall_enabled", nil)
	actions := buf.Collect()
	if actions[0].Details == nil {
		t.Fatal("Details should never be nil after Collect")
	}
	if len(actions[0].Details) != 0 {
		t.Errorf("Details = %+v, want empty", actions[0].Details)
	}
}

// TestScenario_AC3_ConcurrentRecordsAreAllKept covers:
//
//	When two goroutines each record 10 actions
//	Then Collect returns 20 actions
func TestScenario_AC3_ConcurrentRecordsAreAllKept(t *testing.T) {
	buf := New(fake.NewClock(time.Now()))
	var wg sync.WaitGroup
	const perGoroutine = 10

	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				buf.Record("enforce.firewall_enabled", map[string]string{"g": strconv.Itoa(g), "i": strconv.Itoa(i)})
			}
		}(g)
	}
	wg.Wait()

	actions := buf.Collect()
	if len(actions) != 2*perGoroutine {
		t.Fatalf("Collect returned %d actions, want %d", len(actions), 2*perGoroutine)
	}
}

// ============================================================================
// AC4: the buffer evicts the oldest entry beyond MaxActions.
// ============================================================================

// TestScenario_AC4_TheBufferEvictsTheOldestBeyond20 covers:
//
//	Given the buffer holds 20 actions
//	When a 21st action is recorded with a later time
//	Then Collect returns 20 actions including the new one and not the oldest
func TestScenario_AC4_TheBufferEvictsTheOldestBeyond20(t *testing.T) {
	buf := New(fake.NewClock(time.Now()))
	base := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)

	for i := 0; i < MaxActions; i++ {
		buf.RecordAt("enforce.firewall_enabled", map[string]string{"i": strconv.Itoa(i)}, base.Add(time.Duration(i)*time.Minute))
	}

	// The 21st action, with a later time than every one already buffered.
	buf.RecordAt("enforce.antivirus_enabled", map[string]string{"i": "20"}, base.Add(time.Duration(MaxActions)*time.Minute))

	actions := buf.Collect()
	if len(actions) != MaxActions {
		t.Fatalf("Collect returned %d actions, want %d", len(actions), MaxActions)
	}

	var sawNewest, sawOldest bool
	for _, a := range actions {
		if a.Details["i"] == "20" {
			sawNewest = true
		}
		if a.Details["i"] == "0" {
			sawOldest = true
		}
	}
	if !sawNewest {
		t.Error("expected the newly recorded (21st) action to be present")
	}
	if sawOldest {
		t.Error("expected the oldest action (occurredAt 0) to have been evicted")
	}
}

// TestScenario_AC4_EvictionTiesRemoveTheEarliestRecorded covers the eviction
// tie-break: "ties -> earliest-recorded goes".
func TestScenario_AC4_EvictionTiesRemoveTheEarliestRecorded(t *testing.T) {
	buf := New(fake.NewClock(time.Now()))
	at := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)

	for i := 0; i < MaxActions; i++ {
		buf.RecordAt("enforce.firewall_enabled", map[string]string{"i": strconv.Itoa(i)}, at)
	}
	// The 21st, at the very same instant as every other buffered entry: the
	// tie-break must still make room for it.
	buf.RecordAt("enforce.antivirus_enabled", map[string]string{"i": "20"}, at)

	actions := buf.Collect()
	if len(actions) != MaxActions {
		t.Fatalf("Collect returned %d actions, want %d", len(actions), MaxActions)
	}
	var sawNewest, sawEarliestRecorded bool
	for _, a := range actions {
		if a.Details["i"] == "20" {
			sawNewest = true
		}
		if a.Details["i"] == "0" {
			sawEarliestRecorded = true
		}
	}
	if !sawNewest {
		t.Error("expected the new entry to be kept even when every occurredAt ties")
	}
	if sawEarliestRecorded {
		t.Error("expected the earliest-recorded entry among the tied occurredAt values to be evicted")
	}
}
