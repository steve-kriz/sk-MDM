// E2E cucumber-style tests for TASK-061's self-update sentinel (AC3, AC4): the
// scheduler loop ends -- rather than keeps going -- when ApplyUpdate reports
// that the agent must exit to be restarted, and otherwise logs and carries on
// exactly as it did before. Client, Store, FS and Clock are all fakes; no real
// network, filesystem or database is used.
package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/service"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

// restartTestDeps builds Deps for an enrolled agent on darwin, with the
// collectors stubbed out and a checkin/policies transport wired to answer.
func restartTestDeps(clock *fake.Clock, fsys *fake.FS, doFunc func(method, path string, body []byte) (*http.Response, error)) *Deps {
	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	return &Deps{
		Client:           &mockTransport{doFunc: doFunc},
		Store:            &fakeStore{state: st},
		FS:               fsys,
		Clock:            clock,
		GOOS:             "darwin",
		Logger:           logging.New(fsys, clock, "agent.log", logging.LevelInfo, "scheduler"),
		CollectInventory: func() (contract.Inventory, error) { return contract.Inventory{}, nil },
		CollectPosture:   func() (contract.Posture, error) { return contract.Posture{}, nil },
	}
}

// checkInAdvertising answers the policies GET with an empty bundle and the
// checkin POST with a release advertised at version.
func checkInAdvertising(version string) func(method, path string, body []byte) (*http.Response, error) {
	return func(method, path string, body []byte) (*http.Response, error) {
		if method == "GET" && strings.Contains(path, "policies") {
			data, _ := json.Marshal(contract.PolicyBundleResponse{})
			return fake.Response(http.StatusOK, string(data)), nil
		}
		if method == "POST" && strings.Contains(path, "checkin") {
			data, _ := json.Marshal(contract.CheckInResponse{
				CheckInIntervalSeconds: 900,
				AgentRelease: &contract.AgentRelease{
					Version: version,
					URL:     "https://example.com/agent",
					SHA256:  "a" + strings.Repeat("0", 63),
				},
			})
			return fake.Response(http.StatusOK, string(data)), nil
		}
		return fake.Response(http.StatusOK, "{}"), nil
	}
}

// AC3: The restart sentinel ends the scheduler loop without polling commands.
func TestScenario_AC3_RestartSentinelEndsSchedulerLoop(t *testing.T) {
	// Given a check-in response advertising release "1.0.9"
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	afterCheckInCalls := 0

	deps := restartTestDeps(clock, fsys, checkInAdvertising("1.0.9"))
	// And ApplyUpdate returns service.ErrRestartRequired
	deps.ApplyUpdate = func(ctx context.Context, rel contract.AgentRelease) error {
		return service.ErrRestartRequired
	}
	deps.AfterCheckIn = func(ctx context.Context, resp contract.CheckInResponse) error {
		afterCheckInCalls++
		return nil
	}

	// When scheduler.Run executes
	err := Run(context.Background(), deps)

	// Then exactly one info line "agent restarting to apply update" with
	// version "1.0.9" is logged
	lines := readLogLines(t, fsys)
	restarting := filterByMsg(lines, "agent restarting to apply update")
	if len(restarting) != 1 {
		t.Fatalf("got %d 'agent restarting to apply update' lines, want 1: %v", len(restarting), lines)
	}
	if restarting[0]["level"] != "info" {
		t.Errorf("level = %v, want info", restarting[0]["level"])
	}
	if restarting[0]["version"] != "1.0.9" {
		t.Errorf("version = %v, want 1.0.9", restarting[0]["version"])
	}
	// And no "agent update failed" line is logged
	if failed := filterByMsg(lines, "agent update failed"); len(failed) != 0 {
		t.Errorf("got %d 'agent update failed' lines, want 0: %v", len(failed), failed)
	}
	// And AfterCheckIn is not called
	if afterCheckInCalls != 0 {
		t.Errorf("AfterCheckIn called %d times, want 0", afterCheckInCalls)
	}
	// And scheduler.Run returns an error matching service.ErrRestartRequired
	// without the fake clock being advanced (no further RunOnce call, and it
	// returns without waiting for the next cycle)
	if !errors.Is(err, service.ErrRestartRequired) {
		t.Errorf("Run returned %v, want ErrRestartRequired", err)
	}
	if waits := clock.Waits(); len(waits) != 0 {
		t.Errorf("clock.After was called %d times, want 0 (Run must not wait for a next cycle)", len(waits))
	}
}

// AC4: Any other update failure is logged and the cycle carries on.
func TestScenario_AC4_OtherUpdateFailureLoggedCycleContinues(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	afterCheckInCalls := 0
	wantErr := errors.New("update: checksum mismatch: expected a, downloaded b")

	deps := restartTestDeps(clock, fsys, checkInAdvertising("1.0.9"))
	// And ApplyUpdate returns the error "update: checksum mismatch: expected a, downloaded b"
	deps.ApplyUpdate = func(ctx context.Context, rel contract.AgentRelease) error {
		return wantErr
	}
	deps.AfterCheckIn = func(ctx context.Context, resp contract.CheckInResponse) error {
		afterCheckInCalls++
		return nil
	}

	// When one scheduler cycle runs
	err := RunOnce(context.Background(), deps)
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then exactly one warn line "agent update failed" with version "1.0.9"
	// and that error is logged
	lines := readLogLines(t, fsys)
	failed := filterByMsg(lines, "agent update failed")
	if len(failed) != 1 {
		t.Fatalf("got %d 'agent update failed' lines, want 1: %v", len(failed), lines)
	}
	if failed[0]["level"] != "warn" {
		t.Errorf("level = %v, want warn", failed[0]["level"])
	}
	if failed[0]["version"] != "1.0.9" {
		t.Errorf("version = %v, want 1.0.9", failed[0]["version"])
	}
	if failed[0]["error"] != wantErr.Error() {
		t.Errorf("error = %v, want %q", failed[0]["error"], wantErr.Error())
	}
	// And AfterCheckIn is called once
	if afterCheckInCalls != 1 {
		t.Errorf("AfterCheckIn called %d times, want 1", afterCheckInCalls)
	}
}

// AC4 (loop continuation): scheduler.Run does not stop after a non-sentinel
// update failure -- it waits and runs a second cycle.
func TestScenario_AC4_RunKeepsLoopingAfterOtherUpdateFailure(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	applyUpdateCalls := 0

	deps := restartTestDeps(clock, fsys, checkInAdvertising("1.0.9"))
	deps.ApplyUpdate = func(ctx context.Context, rel contract.AgentRelease) error {
		applyUpdateCalls++
		return errors.New("update: checksum mismatch: expected a, downloaded b")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, deps) }()

	// When one scheduler cycle runs
	waitUntil(t, "first wait", func() bool { return len(clock.Waits()) == 1 })
	if applyUpdateCalls != 1 {
		t.Fatalf("applyUpdate calls = %d, want 1", applyUpdateCalls)
	}

	// Then scheduler.Run is still waiting for the next cycle: advancing the
	// clock past the wait runs a second cycle rather than Run having returned.
	clock.Advance(clock.Waits()[0])
	waitUntil(t, "second wait", func() bool { return len(clock.Waits()) == 2 })
	if applyUpdateCalls != 2 {
		t.Errorf("applyUpdate calls = %d, want 2 (the loop must continue)", applyUpdateCalls)
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}
