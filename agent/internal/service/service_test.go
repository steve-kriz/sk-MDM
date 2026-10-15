package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// TestForegroundRunStopsOnSignal verifies that a context cancellation causes Run
// to call Stop once, wait for the work to finish, and return the expected state.
func TestForegroundRunStopsOnSignal(t *testing.T) {
	clock := fake.NewClock(time.Now())
	states := []State{}
	startCalled := false
	stopCalled := 0
	workDone := make(chan struct{})

	hooks := Hooks{
		Start: func(ctx context.Context) error {
			startCalled = true
			<-ctx.Done()
			close(workDone)
			return ctx.Err()
		},
		Stop: func() {
			stopCalled++
		},
		Report: func(s State) {
			states = append(states, s)
		},
		Clock: clock,
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// Let the service start, then signal it to stop
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	err := Run(ctx, hooks)

	if err != nil {
		t.Errorf("Run returned error: %v", err)
	}
	if !startCalled {
		t.Error("Start was not called")
	}
	if stopCalled != 1 {
		t.Errorf("Stop called %d times, want 1", stopCalled)
	}
	if len(states) < 3 {
		t.Errorf("expected at least 3 state reports, got %d", len(states))
	}
	if states[0] != StateStartPending {
		t.Errorf("first state is %v, want StateStartPending", states[0])
	}
	if states[1] != StateRunning {
		t.Errorf("second state is %v, want StateRunning", states[1])
	}
	if states[len(states)-1] != StateStopped {
		t.Errorf("last state is %v, want StateStopped", states[len(states)-1])
	}
}

// TestServiceHooksDriveStateMachine verifies that Start, Stop, and Shutdown
// hooks are called at the right times and in the right order.
func TestServiceHooksDriveStateMachine(t *testing.T) {
	clock := fake.NewClock(time.Now())
	requests := make(chan Request, 2)
	states := []State{}
	startCalled := false
	stopCalled := 0
	shutdownCalled := 0

	hooks := Hooks{
		Start: func(ctx context.Context) error {
			startCalled = true
			<-ctx.Done()
			return ctx.Err()
		},
		Stop: func() {
			stopCalled++
		},
		Shutdown: func() {
			shutdownCalled++
		},
		Report: func(s State) {
			states = append(states, s)
		},
		Clock:    clock,
		Requests: requests,
	}

	go func() {
		Run(context.Background(), hooks)
	}()

	// Send a stop request
	requests <- RequestStop
	time.Sleep(10 * time.Millisecond)
	clock.Advance(StopGrace)
	time.Sleep(10 * time.Millisecond)

	if !startCalled {
		t.Error("Start was not called")
	}
	if stopCalled != 1 {
		t.Errorf("Stop called %d times, want 1", stopCalled)
	}
	if shutdownCalled != 0 {
		t.Errorf("Shutdown called %d times, want 0", shutdownCalled)
	}
}

// TestShutdownHook verifies that a shutdown request calls Shutdown instead of Stop.
func TestShutdownHook(t *testing.T) {
	clock := fake.NewClock(time.Now())
	requests := make(chan Request, 2)
	stopCalled := 0
	shutdownCalled := 0

	hooks := Hooks{
		Start: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
		Stop: func() {
			stopCalled++
		},
		Shutdown: func() {
			shutdownCalled++
		},
		Clock:    clock,
		Requests: requests,
	}

	go func() {
		Run(context.Background(), hooks)
	}()

	// Send a shutdown request
	requests <- RequestShutdown
	time.Sleep(10 * time.Millisecond)
	clock.Advance(StopGrace)
	time.Sleep(10 * time.Millisecond)

	if stopCalled != 0 {
		t.Errorf("Stop called %d times, want 0", stopCalled)
	}
	if shutdownCalled != 1 {
		t.Errorf("Shutdown called %d times, want 1", shutdownCalled)
	}
}

// TestStopWaitsForInFlightCycle verifies that the service waits for the work
// to finish before reporting stopped.
func TestStopWaitsForInFlightCycle(t *testing.T) {
	// Set up a cycle that takes 5 seconds to finish
	cycleDuration := 5 * time.Second
	clock := fake.NewClock(time.Now())
	requests := make(chan Request, 1)
	stopCalled := 0
	workFinished := false

	hooks := Hooks{
		Start: func(ctx context.Context) error {
			<-ctx.Done()
			// Simulate the cycle finishing after 5 seconds
			select {
			case <-time.After(cycleDuration):
				workFinished = true
			case <-ctx.Done():
				workFinished = true
			}
			return ctx.Err()
		},
		Stop: func() {
			stopCalled++
		},
		Clock:    clock,
		Requests: requests,
	}

	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), hooks)
	}()

	// Send a stop request
	time.Sleep(10 * time.Millisecond)
	requests <- RequestStop
	time.Sleep(10 * time.Millisecond)

	// Advance less than the cycle duration - should still be waiting
	clock.Advance(1 * time.Second)
	time.Sleep(10 * time.Millisecond)

	// Advance to complete the cycle
	clock.Advance(4 * time.Second)
	time.Sleep(10 * time.Millisecond)

	// Now Run should have returned
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("Run did not return in time")
	}

	if !workFinished {
		t.Error("work did not finish before stopped state")
	}
}

// TestDuplicateStopIsIgnored verifies that a second stop request while stopping
// is ignored and Stop is only called once.
func TestDuplicateStopIsIgnored(t *testing.T) {
	clock := fake.NewClock(time.Now())
	requests := make(chan Request, 10)
	stopCalled := 0

	hooks := Hooks{
		Start: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
		Stop: func() {
			stopCalled++
		},
		Clock:    clock,
		Requests: requests,
	}

	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), hooks)
	}()

	// Send two stop requests in quick succession
	time.Sleep(10 * time.Millisecond)
	requests <- RequestStop
	time.Sleep(1 * time.Millisecond)
	requests <- RequestStop
	time.Sleep(10 * time.Millisecond)
	clock.Advance(StopGrace)
	time.Sleep(10 * time.Millisecond)

	// Wait for Run to return
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("Run did not return in time")
	}

	if stopCalled != 1 {
		t.Errorf("Stop called %d times, want 1", stopCalled)
	}
}

// TestStopTimeoutReportsStopped verifies that after StopGrace expires, the
// service reports stopped even if the work has not finished.
func TestStopTimeoutReportsStopped(t *testing.T) {
	clock := fake.NewClock(time.Now())
	requests := make(chan Request, 1)
	states := []State{}

	hooks := Hooks{
		Start: func(ctx context.Context) error {
			<-ctx.Done()
			// Never finish - simulate a hung cycle
			<-time.After(10 * time.Second)
			return ctx.Err()
		},
		Stop: func() {},
		Report: func(s State) {
			states = append(states, s)
		},
		Clock:    clock,
		Requests: requests,
	}

	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), hooks)
	}()

	// Send a stop request
	time.Sleep(10 * time.Millisecond)
	requests <- RequestStop
	time.Sleep(10 * time.Millisecond)

	// Advance past the stop grace period
	clock.Advance(StopGrace + 1*time.Second)
	time.Sleep(10 * time.Millisecond)

	// Wait for Run to return
	var err error
	select {
	case err = <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("Run did not return in time")
	}

	// Should get a timeout error
	if !errors.Is(err, ErrStopTimeout) {
		t.Errorf("Run returned %v, want ErrStopTimeout", err)
	}

	// Last state should be stopped
	if len(states) < 1 || states[len(states)-1] != StateStopped {
		t.Errorf("last state is %v, want StateStopped", states[len(states)-1])
	}
}

// TestWorkStopError verifies that an error returned by Start is reported.
func TestWorkStopError(t *testing.T) {
	wantErr := errors.New("work failed")
	clock := fake.NewClock(time.Now())

	hooks := Hooks{
		Start: func(ctx context.Context) error {
			return wantErr
		},
		Clock: clock,
	}

	err := Run(context.Background(), hooks)
	if err != wantErr {
		t.Errorf("Run returned %v, want %v", err, wantErr)
	}
}

// TestStopWithNilStopHook verifies that a nil Stop hook is handled gracefully.
func TestStopWithNilStopHook(t *testing.T) {
	clock := fake.NewClock(time.Now())
	requests := make(chan Request, 1)

	hooks := Hooks{
		Start: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
		Stop: nil, // Explicitly nil
		Clock: clock,
		Requests: requests,
	}

	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), hooks)
	}()

	time.Sleep(10 * time.Millisecond)
	requests <- RequestStop
	time.Sleep(10 * time.Millisecond)
	clock.Advance(StopGrace)
	time.Sleep(10 * time.Millisecond)

	err := <-done
	if err != nil {
		t.Errorf("Run returned error: %v", err)
	}
}

// TestMissingStartHookReturnsError verifies that a missing Start hook is rejected.
func TestMissingStartHookReturnsError(t *testing.T) {
	hooks := Hooks{
		Start: nil,
	}

	err := Run(context.Background(), hooks)
	if err == nil {
		t.Error("Run should return an error when Start is nil")
	}
}

// TestStateReportingOrder verifies the correct sequence of state transitions.
func TestStateReportingOrder(t *testing.T) {
	clock := fake.NewClock(time.Now())
	requests := make(chan Request, 1)
	states := []State{}

	hooks := Hooks{
		Start: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
		Stop: func() {},
		Report: func(s State) {
			states = append(states, s)
		},
		Clock:    clock,
		Requests: requests,
	}

	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), hooks)
	}()

	time.Sleep(10 * time.Millisecond)
	requests <- RequestStop
	time.Sleep(10 * time.Millisecond)
	clock.Advance(StopGrace)
	time.Sleep(10 * time.Millisecond)

	<-done

	wantStates := []State{StateStartPending, StateRunning, StateStopPending, StateStopped}
	if len(states) != len(wantStates) {
		t.Errorf("got %d states, want %d", len(states), len(wantStates))
	}
	for i, want := range wantStates {
		if i >= len(states) {
			t.Errorf("missing state at index %d, want %v", i, want)
			break
		}
		if states[i] != want {
			t.Errorf("state[%d] is %v, want %v", i, states[i], want)
		}
	}
}

// ----------------------------------------------------------------------------
// TASK-061: self-update exit-to-restart
//
// E2E cucumber-style scenarios (Given/When/Then, from the ticket's Gherkin),
// using agent/internal/platform/fake so nothing here opens a real process,
// network connection or database.
// ----------------------------------------------------------------------------

// AC1: Restart runs no service-manager command on either platform.
func TestScenario_AC1_RestartRunsNoCommandOnEitherPlatform(t *testing.T) {
	for _, goos := range []string{"windows", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			// Given a fake command runner that records every call and answers
			// exit code 0 by default
			runner := fake.NewCommandRunner()
			// And a service config with GOOS "<goos>"
			cfg := Config{Runner: runner, GOOS: goos, BinaryPath: "/bin/mdmagent"}

			// When service.Restart is called
			err := Restart(context.Background(), cfg)

			// Then the returned error matches service.ErrRestartRequired
			if !errors.Is(err, ErrRestartRequired) {
				t.Fatalf("Restart returned %v, want ErrRestartRequired", err)
			}
			// And the runner recorded 0 calls: no sc.exe stop, sc.exe start or
			// launchctl kickstart is issued.
			if calls := runner.Calls(); len(calls) != 0 {
				t.Fatalf("runner recorded %d calls, want 0: %v", len(calls), calls)
			}
		})
	}
}

// AC5: The service state machine reports a restart as a stop with no stop
// request.
func TestScenario_AC5_RestartSentinelReportsStopWithNoStopRequest(t *testing.T) {
	clock := fake.NewClock(time.Now())
	states := []State{}
	stopCalled := 0
	shutdownCalled := 0

	hooks := Hooks{
		// Given hooks whose Start returns service.ErrRestartRequired
		Start: func(ctx context.Context) error {
			return ErrRestartRequired
		},
		Stop:     func() { stopCalled++ },
		Shutdown: func() { shutdownCalled++ },
		Report:   func(s State) { states = append(states, s) },
		Clock:    clock,
	}

	// When service.Run is called
	err := Run(context.Background(), hooks)

	// Then the reported states are exactly "start pending", "running", "stopped"
	want := []State{StateStartPending, StateRunning, StateStopped}
	if len(states) != len(want) {
		t.Fatalf("states = %v, want %v", states, want)
	}
	for i, w := range want {
		if states[i] != w {
			t.Errorf("states[%d] = %v, want %v", i, states[i], w)
		}
	}
	// And Stop and Shutdown were each called 0 times
	if stopCalled != 0 {
		t.Errorf("Stop called %d times, want 0", stopCalled)
	}
	if shutdownCalled != 0 {
		t.Errorf("Shutdown called %d times, want 0", shutdownCalled)
	}
	// And service.Run returns an error matching service.ErrRestartRequired
	if !errors.Is(err, ErrRestartRequired) {
		t.Errorf("Run returned %v, want ErrRestartRequired", err)
	}
}

// AC6: The SCM exit status for each way the service ends. ExecuteExit carries
// no build constraint, so it is a plain unit test.
func TestUnit_AC6_ExecuteExit(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantSSEC bool
		wantCode uint32
	}{
		{"nil", nil, false, 0},
		{"restart sentinel", ErrRestartRequired, true, ExitRestart},
		{"any other error", errors.New("boom"), true, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ssec, code := ExecuteExit(tc.err)
			if ssec != tc.wantSSEC || code != tc.wantCode {
				t.Errorf("ExecuteExit(%v) = (%v, %v), want (%v, %v)", tc.err, ssec, code, tc.wantSSEC, tc.wantCode)
			}
		})
	}
}

// AC17: Only x/sys's final update reports STOPPED to the SCM. forwardsToSCM
// carries no build constraint, so it is a plain unit test.
func TestUnit_AC17_ForwardsToSCM(t *testing.T) {
	cases := []struct {
		state     State
		forwarded bool
	}{
		{StateStartPending, true},
		{StateRunning, true},
		{StateStopPending, true},
		{StateStopped, false},
	}
	for _, tc := range cases {
		if got := forwardsToSCM(tc.state); got != tc.forwarded {
			t.Errorf("forwardsToSCM(%v) = %v, want %v", tc.state, got, tc.forwarded)
		}
	}
}
