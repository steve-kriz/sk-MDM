// E2E cucumber-style tests for TASK-064's Run loop scheduling of drain
// attempts between full cycles (AC1, AC3, AC4, AC5, AC6). Every scenario
// below implements a Gherkin scenario from the ticket by name. Client, Store,
// FS and Clock are all fakes, driven deterministically (no AutoAdvance, no
// real sleeps): the goroutine running Run is synchronised purely through
// fake.Clock.Waits() and condition polling. No real network, filesystem or
// database is used anywhere in this file.
package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/client"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

// scheduleTestDeps builds Deps for an enrolled darwin agent with the spool at
// "/spool" and a debug-level logger, driven through the Run loop.
func scheduleTestDeps(clock *fake.Clock, fsys *fake.FS, transport Transport) *Deps {
	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	return &Deps{
		Client:   transport,
		Store:    &fakeStore{state: st},
		FS:       fsys,
		Clock:    clock,
		GOOS:     "darwin",
		SpoolDir: "/spool",
		Logger:   logging.New(fsys, clock, "agent.log", logging.LevelDebug, "scheduler"),
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
	}
}

// alwaysFailCheckIn answers every checkin POST with a transport error and
// every other request with 200.
func alwaysFailCheckIn() func(method, path string, body []byte) (*http.Response, error) {
	return func(method, path string, body []byte) (*http.Response, error) {
		if method == http.MethodPost && strings.Contains(path, "checkin") {
			return nil, errors.New("network unreachable")
		}
		return fake.Response(http.StatusOK, "{}"), nil
	}
}

// countGETs is how many requests in transport.requests were GETs: full
// cycles alone send one (to the policies path), so a delta of 1 across a
// tick is unambiguous proof that tick ran a full cycle rather than a drain
// attempt, whatever the outage does to the checkin POSTs.
func countGETs(transport *mockTransport) int {
	n := 0
	for _, r := range transport.requests {
		if r.method == http.MethodGet {
			n++
		}
	}
	return n
}

// advanceTick waits for the wait at index idx to be recorded, advances the
// clock by exactly that amount (firing the timer Run is blocked on) and
// waits for the following wait to be recorded, so the caller knows this
// tick's processing (a full cycle or a drain attempt) has completed. It
// returns the wait that was advanced and whether that tick's processing sent
// a GET request, i.e. ran a full cycle.
func advanceTick(t *testing.T, clock *fake.Clock, transport *mockTransport, idx int) (wait time.Duration, isFull bool) {
	t.Helper()
	waitUntil(t, "wait recorded", func() bool { return len(clock.Waits()) > idx })
	wait = clock.Waits()[idx]
	before := countGETs(transport)
	clock.Advance(wait)
	waitUntil(t, "tick processed", func() bool { return len(clock.Waits()) > idx+1 })
	return wait, countGETs(transport) > before
}

// ----------------------------------------------------------------------------
// Scenario: A failed check-in schedules a drain attempt after about 60
// seconds (AC1)
// ----------------------------------------------------------------------------

func TestRun_FailedCheckInSchedulesDrainAttemptAfterSixtySeconds_AC1(t *testing.T) {
	// Given every POST fails with a transport error
	clock := fake.NewClock(time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	transport := &mockTransport{doFunc: alwaysFailCheckIn()}
	deps := scheduleTestDeps(clock, fsys, transport)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, deps) }()

	// When the Run loop completes one full cycle
	waitUntil(t, "first wait recorded", func() bool { return len(clock.Waits()) == 1 })
	cancel()
	<-done

	// Then the spool holds 1 file
	files, err := deps.spool().List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 spool file, got %v", files)
	}
	// And: the spool directory holds only checkin-*.json files (AC14)
	for _, f := range files {
		if !strings.Contains(f, "checkin-") || !strings.HasSuffix(f, ".json") {
			t.Errorf("unexpected spool file name %q", f)
		}
	}

	// And: the loop waits between 60 and 66 seconds before its next wake
	wait := clock.Waits()[0]
	if wait < 60*time.Second || wait > 66*time.Second {
		t.Errorf("wait = %v, want [60s,66s]", wait)
	}

	// And: the debug record names it a drain-attempt wait, not a check-in wait
	lines := readLogLines(t, fsys)
	if n := len(filterByMsg(lines, "waiting for next spool drain attempt")); n != 1 {
		t.Errorf("got %d 'waiting for next spool drain attempt' records, want 1: %v", n, lines)
	}
}

// ----------------------------------------------------------------------------
// Scenario: Failing drain attempts back off exponentially, capped by the
// next full cycle (AC3)
// ----------------------------------------------------------------------------

func TestRun_FailingDrainAttemptsBackOffExponentiallyCappedByFullCycle_AC3(t *testing.T) {
	// Given every POST fails with a transport error, and the check-in
	// interval is large enough that four drain attempts' worth of backoff
	// cannot run into the next full cycle's due time (keeping this scenario
	// about the doubling itself; the cap is exercised by the restart
	// scenario below).
	clock := fake.NewClock(time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	transport := &mockTransport{doFunc: alwaysFailCheckIn()}
	deps := scheduleTestDeps(clock, fsys, transport)
	deps.IntervalSeconds = 100000

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, deps) }()

	// When the first full cycle and then 4 drain attempts run
	wantRanges := []struct{ min, max time.Duration }{
		{60 * time.Second, 66 * time.Second},
		{120 * time.Second, 132 * time.Second},
		{240 * time.Second, 264 * time.Second},
		{480 * time.Second, 528 * time.Second},
	}
	var cumulative time.Duration
	for i, want := range wantRanges {
		wait, isFull := advanceTick(t, clock, transport, i)
		if isFull {
			t.Fatalf("tick %d unexpectedly ran a full cycle", i)
		}
		// Then the waits before the drain attempts are in the given ranges
		if wait < want.min || wait > want.max {
			t.Errorf("wait[%d] = %v, want [%v,%v]", i, wait, want.min, want.max)
		}
		cumulative += wait
		// And: no wait ends later than the next full cycle's due time
		if cumulative >= time.Duration(deps.IntervalSeconds)*time.Second {
			t.Fatalf("cumulative wait %v reached the full cycle interval; test setup needs a larger interval", cumulative)
		}
	}

	cancel()
	<-done
}

// ----------------------------------------------------------------------------
// Scenario: Every full cycle restarts the drain backoff at 60 seconds (AC3)
// ----------------------------------------------------------------------------

func TestRun_EveryFullCycleRestartsDrainBackoffAtSixty_AC3(t *testing.T) {
	// Given every POST fails with a transport error for at least two full
	// check-in intervals of fake time: the interval is kept short enough
	// that the drain backoff's doubling is eventually capped by the next
	// full cycle's due time, which is what ends the first run of drain
	// attempts and starts the second full cycle.
	clock := fake.NewClock(time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	transport := &mockTransport{doFunc: alwaysFailCheckIn()}
	deps := scheduleTestDeps(clock, fsys, transport)
	deps.IntervalSeconds = 3600

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, deps) }()
	defer func() { cancel(); <-done }()

	// When the Run loop runs the first full cycle, its failing drain
	// attempts, the second full cycle and the drain attempts after it
	type tick struct {
		wait   time.Duration
		isFull bool
	}
	var ticks []tick
	fullCount := 0
	for i := 0; i < 40 && fullCount < 1; i++ {
		wait, isFull := advanceTick(t, clock, transport, i)
		ticks = append(ticks, tick{wait, isFull})
		if isFull {
			fullCount++
		}
	}
	if fullCount == 0 {
		t.Fatal("the second full cycle never ran within 40 ticks")
	}
	// Two more ticks, so the drain attempts after the second full cycle are
	// observed too. The target is computed once: the loop body appends to
	// ticks, so a condition that re-read len(ticks) every iteration would
	// never terminate.
	target := len(ticks) + 2
	for i := len(ticks); i < target; i++ {
		wait, isFull := advanceTick(t, clock, transport, i)
		ticks = append(ticks, tick{wait, isFull})
	}

	// Then the wait before the first drain attempt after the first full
	// cycle is between 60 and 66 seconds
	if ticks[0].isFull {
		t.Fatalf("tick 0 should be a drain attempt, not a full cycle")
	}
	if ticks[0].wait < 60*time.Second || ticks[0].wait > 66*time.Second {
		t.Errorf("wait before the first drain attempt = %v, want [60s,66s]", ticks[0].wait)
	}

	capIdx := -1
	for i, tk := range ticks {
		if tk.isFull {
			capIdx = i
			break
		}
	}
	if capIdx == -1 || capIdx+2 >= len(ticks) {
		t.Fatalf("did not observe the second full cycle followed by two more ticks: %+v", ticks)
	}

	// And: the wait before the first drain attempt after the second full
	// cycle is between 60 and 66 seconds
	first := ticks[capIdx+1]
	if first.isFull {
		t.Fatalf("tick after the second full cycle should be a drain attempt, got full cycle: %+v", ticks)
	}
	if first.wait < 60*time.Second || first.wait > 66*time.Second {
		t.Errorf("wait before the first drain attempt after the second full cycle = %v, want [60s,66s]", first.wait)
	}

	// And: the wait before the second drain attempt after the second full
	// cycle is between 120 and 132 seconds
	second := ticks[capIdx+2]
	if second.isFull {
		t.Fatalf("tick after the first post-cycle-2 drain attempt should also be a drain attempt, got full cycle: %+v", ticks)
	}
	if second.wait < 120*time.Second || second.wait > 132*time.Second {
		t.Errorf("wait before the second drain attempt after the second full cycle = %v, want [120s,132s]", second.wait)
	}
}

// ----------------------------------------------------------------------------
// Scenario: Full cycles keep their schedule during an outage (AC4)
// ----------------------------------------------------------------------------

func TestRun_FullCyclesKeepScheduleDuringOutage_AC4(t *testing.T) {
	// Given every POST fails with a transport error for 2000 seconds of
	// fake time
	clock := fake.NewClock(time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	transport := &mockTransport{doFunc: alwaysFailCheckIn()}
	deps := scheduleTestDeps(clock, fsys, transport)
	deps.IntervalSeconds = 200 // short enough that several full cycles fit in 2000s

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, deps) }()

	// Then full cycles started at 0 s and at each nextWait() after the
	// previous one, and each of them added one spool file: drive the loop
	// for 2000s of fake time and count.
	var elapsed time.Duration
	fullCycles := 0
	for i := 0; elapsed < 2000*time.Second && i < 200; i++ {
		wait, isFull := advanceTick(t, clock, transport, i)
		elapsed += wait
		if isFull {
			fullCycles++
			files, err := deps.spool().List()
			if err != nil {
				t.Fatalf("List failed: %v", err)
			}
			// Cycle 0 (before the loop's first wait) already spooled one
			// file; each observed full cycle here spools exactly one more.
			if len(files) != fullCycles+1 {
				t.Errorf("after full cycle %d, spool holds %d files, want %d", fullCycles, len(files), fullCycles+1)
			}
		}
	}
	cancel()
	<-done

	if fullCycles < 2 {
		t.Fatalf("expected at least 2 full cycles over 2000s at a 200s interval, got %d", fullCycles)
	}
}

// ----------------------------------------------------------------------------
// Scenario: A successful drain attempt runs a full cycle immediately (AC5)
// ----------------------------------------------------------------------------

func TestRun_SuccessfulDrainAttemptRunsFullCycleImmediately_AC5(t *testing.T) {
	// Given the backend fails the first check-in, then succeeds (emptying
	// the spool on the first drain attempt), then fails again later
	clock := fake.NewClock(time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	phase := 0 // 0: failing, 1: succeeding, 2: failing again
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == http.MethodPost && strings.Contains(path, "checkin") {
				if phase == 1 {
					return fake.Response(http.StatusOK, "{}"), nil
				}
				return nil, errors.New("network unreachable")
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}
	deps := scheduleTestDeps(clock, fsys, transport)
	deps.IntervalSeconds = 900

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, deps) }()
	defer func() { cancel(); <-done }()

	// When the Run loop completes its first (failing) cycle, Waits()[0] is
	// the drain wait that follows it.
	wait0, isFull0 := advanceTick(t, clock, transport, 0)
	if isFull0 {
		t.Fatalf("tick 0 should be a drain attempt")
	}
	if wait0 < 60*time.Second || wait0 > 66*time.Second {
		t.Errorf("first drain wait = %v, want [60s,66s]", wait0)
	}

	// Consuming Waits()[0] fires the first drain attempt, which still fails
	// (the backend has not come back up yet), so Waits()[1] is the doubled
	// backoff.
	wait1, isFull1 := advanceTick(t, clock, transport, 1)
	if isFull1 {
		t.Fatalf("tick 1 should be a second drain attempt, not a full cycle")
	}
	if wait1 < 120*time.Second || wait1 > 132*time.Second {
		t.Errorf("second drain wait = %v, want [120s,132s]", wait1)
	}

	// And then the backend starts answering 200: the drain attempt that
	// fires from Waits()[1] must empty the spool and run a full cycle with
	// no wait in between.
	phase = 1
	if _, isFull := advanceTick(t, clock, transport, 2); !isFull {
		t.Fatalf("expected the tick right after the drain attempt succeeded to be a full cycle (no wait in between)")
	}

	// Then the spool is empty
	files, err := deps.spool().List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected the spool empty after the successful cycle, got %v", files)
	}

	// And: the recorded wait right after the drain-emptied tick (Waits()[3])
	// is the full cycle's own interval, not another drain delay -- proof
	// that no drain wait happened "in between" the empty-spool and the full
	// cycle: the very next thing Run waited on already belongs to the next
	// full cycle.
	waitAfterEmptied := clock.Waits()[3]
	if waitAfterEmptied < 900*time.Second || waitAfterEmptied > 990*time.Second {
		t.Errorf("wait after the drain-emptied full cycle = %v, want [900s,990s]", waitAfterEmptied)
	}

	// And: one info record "spool drained, connectivity restored" was
	// logged exactly once
	lines := readLogLines(t, fsys)
	if n := len(filterByMsg(lines, "spool drained, connectivity restored")); n != 1 {
		t.Errorf("got %d 'spool drained, connectivity restored' records, want 1: %v", n, lines)
	}

	// And: after a later failed check-in the next drain attempt waits
	// between 60 and 66 seconds (the backoff restarted at 60s). Consuming
	// Waits()[3] (the full cycle's own interval) runs that next full cycle;
	// it fails (phase reverts to failing) and spools again.
	phase = 2
	if _, isFull := advanceTick(t, clock, transport, 3); !isFull {
		t.Fatalf("tick 3 should run the next full cycle")
	}
	wait4 := clock.Waits()[4]
	if wait4 < 60*time.Second || wait4 > 66*time.Second {
		t.Errorf("wait after the later failed check-in = %v, want [60s,66s]", wait4)
	}
}

// ----------------------------------------------------------------------------
// Scenario: An empty spool means the normal interval (AC6)
// ----------------------------------------------------------------------------

func TestRun_EmptySpoolMeansNormalInterval_AC6(t *testing.T) {
	// Given the backend answers 200
	clock := fake.NewClock(time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	transport := &mockTransport{}
	deps := scheduleTestDeps(clock, fsys, transport)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, deps) }()

	// When a full cycle completes
	waitUntil(t, "first wait recorded", func() bool { return len(clock.Waits()) == 1 })
	cancel()
	<-done

	// Then no drain attempt is scheduled and the next wait is between 900
	// and 990 seconds
	wait := clock.Waits()[0]
	if wait < 900*time.Second || wait > 990*time.Second {
		t.Errorf("wait = %v, want [900s,990s]", wait)
	}
	lines := readLogLines(t, fsys)
	if n := len(filterByMsg(lines, "waiting for next spool drain attempt")); n != 0 {
		t.Errorf("expected no drain-attempt wait logged, got %d: %v", n, lines)
	}
	if n := len(filterByMsg(lines, "waiting for next check-in")); n != 1 {
		t.Errorf("expected exactly one check-in wait logged, got %d: %v", n, lines)
	}
}

// ----------------------------------------------------------------------------
// Scenario: An unlistable spool means the normal interval (AC6)
// ----------------------------------------------------------------------------

func TestRun_UnlistableSpoolMeansNormalInterval_AC6(t *testing.T) {
	// Given listing "/spool" returns a permission error
	clock := fake.NewClock(time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	fsys.ReadErr = func(p string) error {
		if p == "/spool" {
			return errors.New("permission denied")
		}
		return nil
	}
	transport := &mockTransport{}
	deps := scheduleTestDeps(clock, fsys, transport)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, deps) }()

	// When a full cycle completes
	waitUntil(t, "first wait recorded", func() bool { return len(clock.Waits()) == 1 })
	cancel()
	<-done

	// Then no drain attempt is scheduled and the next wait is between 900
	// and 990 seconds
	wait := clock.Waits()[0]
	if wait < 900*time.Second || wait > 990*time.Second {
		t.Errorf("wait = %v, want [900s,990s]", wait)
	}
	lines := readLogLines(t, fsys)
	if n := len(filterByMsg(lines, "waiting for next spool drain attempt")); n != 0 {
		t.Errorf("expected no drain-attempt wait logged, got %d: %v", n, lines)
	}
}

// ----------------------------------------------------------------------------
// Scenario: 401 during a drain attempt clears the credential (AC12), driven
// through the real Run loop rather than attemptDrain called directly.
// ----------------------------------------------------------------------------

// historyStore is a Store that remembers every state Save was called with, in
// order, so a test can prove a credential was cleared (saved empty) before a
// later re-enrollment overwrote it.
type historyStore struct {
	mu    sync.Mutex
	state state.State
	saves []state.State
}

func (s *historyStore) Load() (state.State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state, nil
}

func (s *historyStore) Save(st state.State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = st
	s.saves = append(s.saves, st)
	return nil
}

func TestRun_DrainAttempt401ClearsCredentialAndRunsFullCycleImmediately_AC12(t *testing.T) {
	// Given the spool holds 1 file (from a first failed cycle) and the
	// backend answers 401 to the drain attempt that follows
	clock := fake.NewClock(time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	store := &historyStore{state: state.State{DeviceID: "d1", DeviceSecret: "secret"}}

	checkinCalls := 0
	transport := &scriptedEnroll{
		mockTransport: mockTransport{
			doFunc: func(method, path string, body []byte) (*http.Response, error) {
				if method == http.MethodPost && strings.Contains(path, "checkin") {
					checkinCalls++
					if checkinCalls == 1 {
						// The first full cycle's own check-in fails, so it
						// spools.
						return nil, errors.New("network unreachable")
					}
					if checkinCalls == 2 {
						// The drain attempt's re-send of that spooled file is
						// rejected as unauthorized.
						return nil, client.ErrUnauthorized
					}
					// The re-enrolled cycle's drainSpool re-send, and then
					// its own check-in, both succeed.
					return fake.Response(http.StatusOK, "{}"), nil
				}
				return fake.Response(http.StatusOK, "{}"), nil
			},
		},
		answer: func(int) error {
			return store.Save(state.State{DeviceID: "d2", DeviceSecret: "secret2"})
		},
		called: make(chan int, 8),
	}

	deps := &Deps{
		Client:   transport,
		Store:    store,
		FS:       fsys,
		Clock:    clock,
		GOOS:     "darwin",
		SpoolDir: "/spool",
		Logger:   logging.New(fsys, clock, "agent.log", logging.LevelDebug, "scheduler"),
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, deps) }()
	defer func() { cancel(); <-done }()

	// When the drain attempt that follows the first failed cycle fires
	wait0, isFull0 := advanceTick(t, clock, &transport.mockTransport, 0)
	if wait0 < 60*time.Second || wait0 > 66*time.Second {
		t.Errorf("wait before the drain attempt = %v, want [60s,66s]", wait0)
	}

	// Then the next full cycle starts with no wait (the drainUnauthorized
	// outcome is handled by the same "full = true; continue" branch as
	// drainEmptied) -- proven by this very tick, which consumed the drain
	// wait, itself running a full cycle (a GET to the policies path).
	if !isFull0 {
		t.Fatalf("expected the tick that delivered the 401 to run a full cycle immediately, with no further drain attempt scheduled before it")
	}

	// And: the state store held an empty state before the re-enrolled
	// credential was saved
	if len(store.saves) < 2 {
		t.Fatalf("expected at least 2 saves (clear, then re-enroll), got %d: %+v", len(store.saves), store.saves)
	}
	cleared := store.saves[0]
	if cleared.DeviceID != "" || cleared.DeviceSecret != "" {
		t.Errorf("expected the first save to be an empty state, got %+v", cleared)
	}
	reenrolled := store.saves[len(store.saves)-1]
	if reenrolled.DeviceID != "d2" {
		t.Errorf("expected the device to have re-enrolled as d2, got %+v", reenrolled)
	}
}
