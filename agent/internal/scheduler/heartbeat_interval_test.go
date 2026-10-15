// E2E cucumber-style tests for TASK-044's scheduler.Deps.OnHeartbeatInterval
// seam: it is called once after a 2xx check-in whose body decodes, with the
// decoded HeartbeatIntervalSeconds or 0 when absent, and never otherwise.
package scheduler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

func heartbeatTestDeps(t *testing.T, doFunc func(method, path string, body []byte) (*http.Response, error)) (*Deps, *[]int) {
	t.Helper()
	clock := fake.NewClock(time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	calls := []int{}
	deps := &Deps{
		Client: &mockTransport{doFunc: doFunc},
		Store:  &fakeStore{state: st},
		FS:     fsys,
		Clock:  clock,
		GOOS:   "darwin",
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
		OnHeartbeatInterval: func(seconds int) {
			calls = append(calls, seconds)
		},
	}
	return deps, &calls
}

func checkinAnswering(body string, status int) func(method, path string, b []byte) (*http.Response, error) {
	return func(method, path string, _ []byte) (*http.Response, error) {
		if method == "GET" && strings.Contains(path, "policies") {
			return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
		}
		if method == "POST" && strings.Contains(path, "checkin") {
			return fake.Response(status, body), nil
		}
		return fake.Response(http.StatusOK, "{}"), nil
	}
}

// TestScenario_CheckInResponseFeedsHeartbeatInterval covers:
//   - 200 with heartbeatIntervalSeconds present -> called once with that value
//   - 200 without it -> called once with 0
//   - 200 with a non-JSON body -> not called
//   - 500 -> not called
//   - 400 -> not called
func TestScenario_CheckInResponseFeedsHeartbeatInterval(t *testing.T) {
	testCases := []struct {
		name   string
		status int
		body   string
		want   []int // nil means "not called"
	}{
		{
			name:   "heartbeatIntervalSeconds present",
			status: http.StatusOK,
			body:   `{"checkInIntervalSeconds":900,"pendingCommandCount":0,"heartbeatIntervalSeconds":300}`,
			want:   []int{300},
		},
		{
			name:   "heartbeatIntervalSeconds absent",
			status: http.StatusOK,
			body:   `{"checkInIntervalSeconds":900,"pendingCommandCount":0}`,
			want:   []int{0},
		},
		{
			name:   "not json",
			status: http.StatusOK,
			body:   "not json",
			want:   nil,
		},
		{
			name:   "500",
			status: http.StatusInternalServerError,
			body:   "error",
			want:   nil,
		},
		{
			name:   "400",
			status: http.StatusBadRequest,
			body:   "bad",
			want:   nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			deps, calls := heartbeatTestDeps(t, checkinAnswering(tc.body, tc.status))

			if err := RunOnce(context.Background(), deps); err != nil {
				t.Fatalf("RunOnce failed: %v", err)
			}

			if len(*calls) != len(tc.want) {
				t.Fatalf("OnHeartbeatInterval calls = %v, want %v", *calls, tc.want)
			}
			for i, v := range tc.want {
				if (*calls)[i] != v {
					t.Errorf("call %d = %d, want %d", i, (*calls)[i], v)
				}
			}
		})
	}
}

// TestScenario_CheckInTransportErrorDoesNotCallOnHeartbeatInterval covers a
// transport error: the handler is never reached.
func TestScenario_CheckInTransportErrorDoesNotCallOnHeartbeatInterval(t *testing.T) {
	deps, calls := heartbeatTestDeps(t, func(method, path string, _ []byte) (*http.Response, error) {
		if method == "GET" && strings.Contains(path, "policies") {
			return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
		}
		if method == "POST" && strings.Contains(path, "checkin") {
			return nil, context.DeadlineExceeded
		}
		return fake.Response(http.StatusOK, "{}"), nil
	})

	// A transport error on enroll/check-in surfaces as an error from RunOnce
	// in some code paths; either way OnHeartbeatInterval must not fire.
	_ = RunOnce(context.Background(), deps)

	if len(*calls) != 0 {
		t.Errorf("OnHeartbeatInterval calls = %v, want none", *calls)
	}
}

// TestScenario_SchedulerWithoutHeartbeatSeamIsUnchanged verifies that a nil
// OnHeartbeatInterval never panics.
func TestScenario_SchedulerWithoutHeartbeatSeamIsUnchanged(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	deps := &Deps{
		Client: &mockTransport{doFunc: checkinAnswering(`{"checkInIntervalSeconds":900,"pendingCommandCount":0,"heartbeatIntervalSeconds":300}`, http.StatusOK)},
		Store:  &fakeStore{state: st},
		FS:     fsys,
		Clock:  clock,
		GOOS:   "darwin",
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
		// OnHeartbeatInterval intentionally left nil.
	}

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}
}
