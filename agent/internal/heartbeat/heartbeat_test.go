// E2E cucumber-style and unit tests for TASK-044's agent/internal/heartbeat
// package: the per-device performance heartbeat loop beside the scheduler.
package heartbeat

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

const logPath = "log.txt"

// mockTransport is a local, minimal implementation of Transport.
type mockTransport struct {
	doFunc func(method, path string, body []byte) (*http.Response, error)
	calls  []call
	mu     sync.Mutex
}

type call struct {
	method string
	path   string
	body   []byte
}

func (m *mockTransport) Do(method, path string, body []byte) (*http.Response, error) {
	m.mu.Lock()
	m.calls = append(m.calls, call{method, path, body})
	m.mu.Unlock()
	return m.doFunc(method, path, body)
}

func (m *mockTransport) Calls() []call {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]call(nil), m.calls...)
}

// fakeStore is a local, minimal implementation of Store.
type fakeStore struct {
	state State
	err   error
}

// State is a type alias so fakeStore reads naturally; it is simply state.State.
type State = state.State

func (s *fakeStore) Load() (state.State, error) {
	if s.err != nil {
		return state.State{}, s.err
	}
	return s.state, nil
}

func enrolledStore() *fakeStore {
	return &fakeStore{state: state.State{DeviceID: "dev-1", DeviceSecret: "secret"}}
}

func newLogger(fsys *fake.FS, clock *fake.Clock) *logging.Logger {
	return logging.New(fsys, clock, logPath, logging.LevelDebug, "heartbeat")
}

func warnLines(fsys *fake.FS) []string {
	data, ok := fsys.Content(logPath)
	if !ok {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err == nil && record["level"] == "warn" {
			lines = append(lines, line)
		}
	}
	return lines
}

func noopCollect() (contract.AnalyticsPerformance, []string) {
	return contract.AnalyticsPerformance{}, nil
}

// ============================================================================
// Scenario Outline: The interval is clamped (AC35)
// ============================================================================

func TestScenario_IntervalIsClamped(t *testing.T) {
	cases := []struct {
		given, want int
	}{
		{-5, 0},
		{0, 0},
		{30, MinIntervalSeconds},
		{300, 300},
	}
	for _, tc := range cases {
		var d Deps
		d.SetInterval(tc.given)
		if got := d.Interval(); got != tc.want {
			t.Errorf("SetInterval(%d): Interval() = %d, want %d", tc.given, got, tc.want)
		}
	}
}

// TestScenario_IntervalIsRaceFree runs SetInterval and Interval concurrently;
// run with -race to catch a data race.
func TestScenario_IntervalIsRaceFree(t *testing.T) {
	var d Deps
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			d.SetInterval(n)
		}(i)
		go func() {
			defer wg.Done()
			_ = d.Interval()
		}()
	}
	wg.Wait()
}

// ============================================================================
// Scenario: Heartbeat does nothing while off (AC36)
// ============================================================================

func TestScenario_RunOnceDoesNothingWhileOff(t *testing.T) {
	transport := &mockTransport{doFunc: func(string, string, []byte) (*http.Response, error) {
		t.Fatal("Client.Do should not be called while off")
		return nil, nil
	}}
	collectCalled := false
	deps := &Deps{
		Client: transport,
		Store:  enrolledStore(),
		Clock:  fake.NewClock(time.Now()),
		Collect: func() (contract.AnalyticsPerformance, []string) {
			collectCalled = true
			return contract.AnalyticsPerformance{}, nil
		},
	}
	// Interval defaults to 0.

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce returned %v, want nil", err)
	}
	if collectCalled {
		t.Error("Collect was called while the heartbeat is off")
	}
	if len(transport.Calls()) != 0 {
		t.Error("Client.Do was called while the heartbeat is off")
	}
}

// ============================================================================
// Scenario Outline: Heartbeat posts a sample and adopts the answered interval (AC36)
// ============================================================================

func TestScenario_RunOnceAdoptsTheAnsweredInterval(t *testing.T) {
	cases := []struct {
		name         string
		body         string
		wantInterval int
	}{
		{"off", `{"heartbeatIntervalSeconds":0}`, 0},
		{"900", `{"heartbeatIntervalSeconds":900}`, 900},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := fake.NewClock(time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC))
			collectCalls := 0
			perf := contract.AnalyticsPerformance{}
			deps := &Deps{
				Client: &mockTransport{doFunc: func(method, path string, body []byte) (*http.Response, error) {
					if method != http.MethodPost {
						t.Errorf("method = %q, want POST", method)
					}
					if path != "/api/v1/devices/dev-1/heartbeat" {
						t.Errorf("path = %q, want /api/v1/devices/dev-1/heartbeat", path)
					}
					var req contract.HeartbeatRequest
					if err := json.Unmarshal(body, &req); err != nil {
						t.Fatalf("posted body did not decode into HeartbeatRequest: %v", err)
					}
					if req.CollectedAt != "2026-10-11T12:00:00Z" {
						t.Errorf("collectedAt = %q, want 2026-10-11T12:00:00Z", req.CollectedAt)
					}
					return fake.Response(http.StatusOK, tc.body), nil
				}},
				Store: enrolledStore(),
				Clock: clock,
				Collect: func() (contract.AnalyticsPerformance, []string) {
					collectCalls++
					return perf, nil
				},
			}
			deps.SetInterval(300)

			if err := RunOnce(context.Background(), deps); err != nil {
				t.Fatalf("RunOnce returned %v, want nil", err)
			}
			if collectCalls != 1 {
				t.Errorf("Collect called %d times, want 1", collectCalls)
			}
			if got := deps.Interval(); got != tc.wantInterval {
				t.Errorf("Interval() = %d, want %d", got, tc.wantInterval)
			}
		})
	}
}

// ============================================================================
// Scenario Outline: A failed heartbeat changes nothing and is never spooled (AC37)
// ============================================================================

func TestScenario_FailedHeartbeatLeavesIntervalAndSpoolsNothing(t *testing.T) {
	cases := []struct {
		name   string
		doFunc func(method, path string, body []byte) (*http.Response, error)
	}{
		{"transport error", func(string, string, []byte) (*http.Response, error) {
			return nil, errors.New("connection refused")
		}},
		{"ErrNotEnrolled", func(string, string, []byte) (*http.Response, error) {
			return nil, client.ErrNotEnrolled
		}},
		{"ErrUnauthorized", func(string, string, []byte) (*http.Response, error) {
			return nil, client.ErrUnauthorized
		}},
		{"400", func(string, string, []byte) (*http.Response, error) {
			return fake.Response(http.StatusBadRequest, "bad"), nil
		}},
		{"404", func(string, string, []byte) (*http.Response, error) {
			return fake.Response(http.StatusNotFound, "not found"), nil
		}},
		{"500", func(string, string, []byte) (*http.Response, error) {
			return fake.Response(http.StatusInternalServerError, "boom"), nil
		}},
		{"200 not json", func(string, string, []byte) (*http.Response, error) {
			return fake.Response(http.StatusOK, "nope"), nil
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fake.NewFS()
			clock := fake.NewClock(time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC))
			deps := &Deps{
				Client:  &mockTransport{doFunc: tc.doFunc},
				Store:   enrolledStore(),
				Clock:   clock,
				Logger:  newLogger(fsys, clock),
				Collect: noopCollect,
			}
			deps.SetInterval(300)

			err := RunOnce(context.Background(), deps)
			if err != nil {
				t.Errorf("RunOnce returned %v, want nil", err)
			}
			if got := deps.Interval(); got != 300 {
				t.Errorf("Interval() = %d, want unchanged 300", got)
			}

			warns := warnLines(fsys)
			if len(warns) != 1 {
				t.Fatalf("warn lines = %v, want exactly one", warns)
			}
			if !strings.Contains(warns[0], `"msg":"heartbeat failed"`) {
				t.Errorf("warn line = %q, want it to contain heartbeat failed", warns[0])
			}

			// Nothing beyond the log file was written: no spool directory file,
			// and Store.Save does not even exist on the Store interface this
			// package uses, so there is nothing to spool to.
			paths := fsys.Paths()
			for _, p := range paths {
				if p != logPath {
					t.Errorf("unexpected file written: %s", p)
				}
			}
		})
	}
}

// ============================================================================
// Scenario: An unenrolled agent sends nothing
// ============================================================================

func TestScenario_UnenrolledAgentSendsNothing(t *testing.T) {
	transport := &mockTransport{doFunc: func(string, string, []byte) (*http.Response, error) {
		t.Fatal("Client.Do should not be called for an unenrolled agent")
		return nil, nil
	}}
	deps := &Deps{
		Client:  transport,
		Store:   &fakeStore{state: state.State{}}, // no device id/secret
		Clock:   fake.NewClock(time.Now()),
		Collect: noopCollect,
	}
	deps.SetInterval(300)

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce returned %v, want nil", err)
	}
	if len(transport.Calls()) != 0 {
		t.Error("Client.Do was called for an unenrolled agent")
	}
}

func TestScenario_StoreLoadErrorSendsNothing(t *testing.T) {
	transport := &mockTransport{doFunc: func(string, string, []byte) (*http.Response, error) {
		t.Fatal("Client.Do should not be called when Store.Load errors")
		return nil, nil
	}}
	deps := &Deps{
		Client:  transport,
		Store:   &fakeStore{err: errors.New("disk error")},
		Clock:   fake.NewClock(time.Now()),
		Collect: noopCollect,
	}
	deps.SetInterval(300)

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce returned %v, want nil", err)
	}
	if len(transport.Calls()) != 0 {
		t.Error("Client.Do was called when Store.Load errored")
	}
}

// ============================================================================
// Scenario Outline: The heartbeat loop waits the interval or idles (AC38)
// ============================================================================

func TestScenario_RunWaitsTheIntervalOrIdles(t *testing.T) {
	cases := []struct {
		interval int
		wantWait time.Duration
	}{
		{0, IdlePoll},
		{900, 900 * time.Second},
	}

	for _, tc := range cases {
		clock := fake.NewClock(time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC))
		deps := &Deps{
			Client:  &mockTransport{doFunc: func(string, string, []byte) (*http.Response, error) { return fake.Response(http.StatusOK, `{"heartbeatIntervalSeconds":0}`), nil }},
			Store:   &fakeStore{state: state.State{}}, // unenrolled: RunOnce is a no-op either way
			Clock:   clock,
			Collect: noopCollect,
		}
		deps.SetInterval(tc.interval)

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- Run(ctx, deps) }()

		// Give Run a chance to call RunOnce and reach Clock.After.
		deadline := time.Now().Add(2 * time.Second)
		for len(clock.Waits()) == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}

		waits := clock.Waits()
		if len(waits) == 0 {
			t.Fatal("Clock.After was never called")
		}
		if waits[0] != tc.wantWait {
			t.Errorf("interval %d: waited %v, want %v", tc.interval, waits[0], tc.wantWait)
		}
	}
}

// ============================================================================
// Scenario: The heartbeat loop stops on cancel
// ============================================================================

func TestScenario_RunStopsOnCancel(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC))
	deps := &Deps{
		Client:  &mockTransport{doFunc: func(string, string, []byte) (*http.Response, error) { return fake.Response(http.StatusOK, `{}`), nil }},
		Store:   &fakeStore{state: state.State{}},
		Clock:   clock,
		Collect: noopCollect,
	}
	// Off: Run idles on IdlePoll, which never fires without Advance, so this
	// exercises the cancel path while Run is blocked waiting.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, deps) }()

	deadline := time.Now().Add(2 * time.Second)
	for len(clock.Waits()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

// ============================================================================
// HeartbeatPath
// ============================================================================

func TestUnit_HeartbeatPathEscapesTheDeviceID(t *testing.T) {
	if got, want := HeartbeatPath("dev 1"), "/api/v1/devices/dev%201/heartbeat"; got != want {
		t.Errorf("HeartbeatPath(%q) = %q, want %q", "dev 1", got, want)
	}
}

// ============================================================================
// Scenario: The heartbeat carries the network sample and its warnings
// ============================================================================

func TestScenario_RunOnceSendsNetworkSample(t *testing.T) {
	cases := []struct {
		name         string
		network      func() ([]contract.HeartbeatNetworkAdapter, []string)
		wantNetwork  bool
		wantWarnings []string
	}{
		{"sampled", func() ([]contract.HeartbeatNetworkAdapter, []string) {
			speed := int64(1_000_000_000)
			return []contract.HeartbeatNetworkAdapter{{Name: "Ethernet", LinkSpeedBitsPerSecond: &speed}}, nil
		}, true, []string{"performance"}},
		{"probe failed", func() ([]contract.HeartbeatNetworkAdapter, []string) {
			return nil, []string{"network"}
		}, false, []string{"performance", "network"}},
		{"not wired", nil, false, []string{"performance"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var posted []byte
			deps := &Deps{
				Client: &mockTransport{doFunc: func(_, _ string, body []byte) (*http.Response, error) {
					posted = body
					return fake.Response(http.StatusOK, `{"heartbeatIntervalSeconds":300}`), nil
				}},
				Store: enrolledStore(),
				Clock: fake.NewClock(time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)),
				Collect: func() (contract.AnalyticsPerformance, []string) {
					return contract.AnalyticsPerformance{}, []string{"performance"}
				},
				CollectNetwork: tc.network,
			}
			deps.SetInterval(300)

			if err := RunOnce(context.Background(), deps); err != nil {
				t.Fatalf("RunOnce returned %v, want nil", err)
			}

			var raw map[string]json.RawMessage
			if err := json.Unmarshal(posted, &raw); err != nil {
				t.Fatalf("posted body is not a JSON object: %v", err)
			}
			if _, has := raw["network"]; has != tc.wantNetwork {
				t.Errorf("network present = %v, want %v (body %s)", has, tc.wantNetwork, posted)
			}
			var req contract.HeartbeatRequest
			if err := json.Unmarshal(posted, &req); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if strings.Join(req.Warnings, ",") != strings.Join(tc.wantWarnings, ",") {
				t.Errorf("warnings = %v, want %v", req.Warnings, tc.wantWarnings)
			}
			if tc.wantNetwork && (len(req.Network) != 1 || req.Network[0].Name != "Ethernet") {
				t.Errorf("network = %+v, want one Ethernet adapter", req.Network)
			}
		})
	}
}
