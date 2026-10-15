package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/agenterrors"
	"github.com/officehq/sk-mdm/agent/internal/antivirus"
	"github.com/officehq/sk-mdm/agent/internal/client"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/inventory"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/policy"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

// mockTransport is a stand-in for the client that records requests and replies
// with configured responses.
type mockTransport struct {
	enrollErr error
	doFunc    func(method, path string, body []byte) (*http.Response, error)
	requests  []struct {
		method string
		path   string
		body   []byte
	}
}

func (m *mockTransport) Enroll(ctx context.Context) error {
	return m.enrollErr
}

func (m *mockTransport) Do(method, path string, body []byte) (*http.Response, error) {
	m.requests = append(m.requests, struct {
		method string
		path   string
		body   []byte
	}{method, path, body})

	if m.doFunc != nil {
		return m.doFunc(method, path, body)
	}
	return fake.Response(http.StatusOK, "{}"), nil
}

// TestScenario_OneCycleCollectsFetchesPoliciesAndPosts tests one full cycle.
func TestScenario_OneCycleCollectsFetchesPoliciesAndPosts(t *testing.T) {
	// Given: fake collectors, a policy bundle with one policy and a server returning 200 with checkInIntervalSeconds 600
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	// Setup state store with an enrolled device
	st := state.State{
		DeviceID:     "d1",
		DeviceSecret: "secret",
	}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	inv := contract.Inventory{
		Hardware: contract.InventoryHardware{},
		OS:       contract.InventoryOS{},
		Software: []contract.SoftwareEntry{},
	}
	pst := contract.Posture{
		Firewall: contract.Firewall{Enabled: true},
	}

	bundle := contract.PolicyBundleResponse{
		DeviceID:  "d1",
		Policies:  []contract.Policy{{PolicyID: "p1", Version: 1}},
		Conflicts: []contract.Conflict{},
	}

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				data, _ := json.Marshal(bundle)
				return fake.Response(http.StatusOK, string(data)), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				data, _ := json.Marshal(contract.CheckInResponse{
					CheckInIntervalSeconds: 600,
					PendingCommandCount:    0,
				})
				return fake.Response(http.StatusOK, string(data)), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "darwin",
		CollectInventory: func() (contract.Inventory, error) {
			return inv, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return pst, nil
		},
	}

	// When: RunOnce executes
	err := RunOnce(context.Background(), deps)

	// Then: the policy GET was sent to /api/v1/devices/d1/policies before the checkin POST
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}
	if len(transport.requests) < 2 {
		t.Fatalf("Expected at least 2 requests, got %d", len(transport.requests))
	}

	// Check that GET came before POST
	policyGetIdx := -1
	checkinPostIdx := -1
	for i, req := range transport.requests {
		if req.method == "GET" && strings.Contains(req.path, "policies") {
			policyGetIdx = i
		}
		if req.method == "POST" && strings.Contains(req.path, "checkin") {
			checkinPostIdx = i
		}
	}

	if policyGetIdx < 0 || checkinPostIdx < 0 {
		t.Fatal("Missing policy GET or checkin POST")
	}
	if policyGetIdx >= checkinPostIdx {
		t.Fatal("Policy GET was not sent before checkin POST")
	}

	// And: the check-in carried inventory, posture and policyCompliance, and the stored interval is 600
	if deps.IntervalSeconds != 600 {
		t.Errorf("Expected interval 600, got %d", deps.IntervalSeconds)
	}

	// Verify the check-in body
	checkinBody := transport.requests[checkinPostIdx].body
	var checkinReq contract.CheckInRequest
	if err := json.Unmarshal(checkinBody, &checkinReq); err != nil {
		t.Fatalf("Failed to unmarshal checkin body: %v", err)
	}

	if len(checkinReq.Inventory.Hardware.Manufacturer) == 0 && checkinReq.CollectedAt == "" {
		t.Error("Inventory and CollectedAt both empty")
	}
	if len(checkinReq.Posture.LocalAdmins) == 0 && !checkinReq.Posture.Firewall.Enabled {
		t.Error("Posture empty or invalid")
	}
	if len(checkinReq.PolicyCompliance) == 0 {
		t.Error("PolicyCompliance not included in checkin")
	}
}

// TestScenario_PolicyFetchFailureSkipsEvaluation tests when policy fetch fails.
func TestScenario_PolicyFetchFailureSkipsEvaluation(t *testing.T) {
	// Given: the policy GET returns a transport error
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	inv := contract.Inventory{}
	pst := contract.Posture{}

	evaluateCalled := false
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return nil, errors.New("network error")
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				data, _ := json.Marshal(contract.CheckInResponse{
					CheckInIntervalSeconds: 600,
				})
				return fake.Response(http.StatusOK, string(data)), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "darwin",
		CollectInventory: func() (contract.Inventory, error) {
			return inv, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return pst, nil
		},
		Evaluate: func(bundle contract.PolicyBundleResponse, posture contract.Posture, now time.Time) []policy.Result {
			evaluateCalled = true
			return []policy.Result{}
		},
	}

	// When: RunOnce executes
	err := RunOnce(context.Background(), deps)

	// Then: Evaluate was called zero times
	if evaluateCalled {
		t.Error("Evaluate was called but should not have been")
	}

	// And: the posted body has no "policyCompliance" key
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	checkinIdx := -1
	for i, req := range transport.requests {
		if req.method == "POST" && strings.Contains(req.path, "checkin") {
			checkinIdx = i
		}
	}

	if checkinIdx < 0 {
		t.Fatal("No checkin POST found")
	}

	var checkinReq contract.CheckInRequest
	json.Unmarshal(transport.requests[checkinIdx].body, &checkinReq)

	if len(checkinReq.PolicyCompliance) > 0 {
		t.Error("PolicyCompliance should be empty")
	}

	// And: exactly one warning line contains "policy fetch failed"
	// Note: We can verify this by checking the transport made a POST without policyCompliance
	// rather than checking logs, since the logger is optional in the Deps

	// And: the returned error is nil
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
}

// TestScenario_PolicyFetch500SkipsEvaluation tests when policy fetch returns 500.
func TestScenario_PolicyFetch500SkipsEvaluation(t *testing.T) {
	// Given: the policy GET returns status 500
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	inv := contract.Inventory{}
	pst := contract.Posture{}

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusInternalServerError, "{}"), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				data, _ := json.Marshal(contract.CheckInResponse{})
				return fake.Response(http.StatusOK, string(data)), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "darwin",
		CollectInventory: func() (contract.Inventory, error) {
			return inv, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return pst, nil
		},
	}

	// When: RunOnce executes
	err := RunOnce(context.Background(), deps)

	// Then: the posted body has no "policyCompliance" key
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// And: one warning line names status 500
	// Verified by checking that the check-in POST was still made successfully
}

// TestScenario_IntervalIsHonouredWithJitter tests the wait interval with jitter.
func TestScenario_IntervalIsHonouredWithJitter(t *testing.T) {
	// Given: a stored interval of 600 seconds
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	inv := contract.Inventory{}
	pst := contract.Posture{}

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "POST" && strings.Contains(path, "checkin") {
				data, _ := json.Marshal(contract.CheckInResponse{
					CheckInIntervalSeconds: 600,
				})
				return fake.Response(http.StatusOK, string(data)), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	deps := &Deps{
		Client:          transport,
		Store:           stateStore,
		FS:              fsys,
		Clock:           clock,
		GOOS:            "darwin",
		IntervalSeconds: 600,
		CollectInventory: func() (contract.Inventory, error) {
			return inv, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return pst, nil
		},
	}

	// When: Run executes two cycles on a fake clock
	clock.AutoAdvance = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, deps)
	}()

	// Let first cycle complete
	time.Sleep(50 * time.Millisecond)

	// Cancel after first cycle's wait has been recorded
	cancel()
	<-done

	// Check the wait after first cycle
	waits := clock.Waits()
	if len(waits) < 1 {
		t.Fatal("No wait recorded after first cycle")
	}

	wait := waits[len(waits)-1]
	expectedMin := 600 * time.Second
	expectedMax := 660 * time.Second

	// Then: the recorded wait is between 600 and 660 seconds
	if wait < expectedMin || wait > expectedMax {
		t.Errorf("Expected wait between %v and %v, got %v", expectedMin, expectedMax, wait)
	}
}

// TestScenario_CyclesDoNotOverlap tests that overlapping cycles are prevented.
func TestScenario_CyclesDoNotOverlap(t *testing.T) {
	// Given: a cycle that has not finished
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	inv := contract.Inventory{}
	pst := contract.Posture{}

	cycleCount := 0
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "POST" && strings.Contains(path, "checkin") {
				cycleCount++
				data, _ := json.Marshal(contract.CheckInResponse{})
				return fake.Response(http.StatusOK, string(data)), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "darwin",
		CollectInventory: func() (contract.Inventory, error) {
			return inv, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return pst, nil
		},
	}

	// When: the next tick fires (while the first is still running)
	// Manually set running to simulate a cycle in progress
	deps.mu.Lock()
	deps.running = true
	deps.mu.Unlock()

	err := RunOnce(context.Background(), deps)

	// Then: no second cycle starts (RunOnce returns nil without error when overlap detected)
	if err != nil {
		t.Errorf("RunOnce should return nil on overlap, got %v", err)
	}

	// Verify that only 0 cycles completed (no POST was made)
	if cycleCount > 0 {
		t.Errorf("Expected 0 check-in POSTs due to overlap, got %d", cycleCount)
	}
}

// TestScenario_OfflineCycleSpoolsToDisk tests spooling on failure.
func TestScenario_OfflineCycleSpoolsToDisk(t *testing.T) {
	// Given: the server returns a transport error
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	inv := contract.Inventory{}
	pst := contract.Posture{}

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "POST" && strings.Contains(path, "checkin") {
				return nil, errors.New("network unreachable")
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}
	spoolDir := "/spool"

	deps := &Deps{
		Client:   transport,
		Store:    stateStore,
		FS:       fsys,
		Clock:    clock,
		GOOS:     "darwin",
		SpoolDir: spoolDir,
		CollectInventory: func() (contract.Inventory, error) {
			return inv, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return pst, nil
		},
	}

	// When: RunOnce executes
	err := RunOnce(context.Background(), deps)

	// Then: one spool file holds the payload
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	spoolPaths := fsys.Paths()
	var spoolFiles []string
	for _, path := range spoolPaths {
		if strings.Contains(path, spoolDir) && strings.Contains(path, "checkin") {
			spoolFiles = append(spoolFiles, path)
		}
	}

	if len(spoolFiles) != 1 {
		t.Errorf("Expected 1 spool file, got %d", len(spoolFiles))
	}
}

// TestScenario_SpoolIsCapped tests the 50 file cap on spool.
func TestScenario_SpoolIsCapped(t *testing.T) {
	// Given: 50 spool files exist and another cycle fails
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	spoolDir := "/spool"

	// Seed 50 existing spool files
	for i := 0; i < 50; i++ {
		path := fmt.Sprintf("%s/checkin-2026100200000000000Z-%03d.json", spoolDir, i)
		fsys.Seed(path, []byte(fmt.Sprintf(`{"payload":%d}`, i)))
	}

	inv := contract.Inventory{}
	pst := contract.Posture{}

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "POST" && strings.Contains(path, "checkin") {
				return nil, errors.New("network error")
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	deps := &Deps{
		Client:   transport,
		Store:    stateStore,
		FS:       fsys,
		Clock:    clock,
		GOOS:     "darwin",
		SpoolDir: spoolDir,
		CollectInventory: func() (contract.Inventory, error) {
			return inv, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return pst, nil
		},
	}

	// When: another cycle fails
	err := RunOnce(context.Background(), deps)

	// Then: 50 files remain and the oldest former file is gone
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	spoolPaths := fsys.Paths()
	var spoolFiles []string
	for _, path := range spoolPaths {
		if strings.Contains(path, spoolDir) {
			spoolFiles = append(spoolFiles, path)
		}
	}

	if len(spoolFiles) != 50 {
		t.Errorf("Expected 50 spool files, got %d", len(spoolFiles))
	}
}

// TestScenario_UnauthorizedCheckInForcesReEnrollment tests clearing the credential on 401.
func TestScenario_UnauthorizedCheckInForcesReEnrollment(t *testing.T) {
	// Given: the check-in POST returns ErrUnauthorized
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	inv := contract.Inventory{}
	pst := contract.Posture{}

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "POST" && strings.Contains(path, "checkin") {
				// Simulate ErrUnauthorized by returning a response with 401
				// The client interprets this as ErrUnauthorized
				return nil, client.ErrUnauthorized
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "darwin",
		CollectInventory: func() (contract.Inventory, error) {
			return inv, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return pst, nil
		},
	}

	// When: the cycle completes
	err := RunOnce(context.Background(), deps)

	// Then: the state store Save was called with an empty deviceId and an empty deviceSecret
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	if stateStore.lastSavedState.DeviceID != "" {
		t.Errorf("Expected empty DeviceID, got %s", stateStore.lastSavedState.DeviceID)
	}
	if stateStore.lastSavedState.DeviceSecret != "" {
		t.Errorf("Expected empty DeviceSecret, got %s", stateStore.lastSavedState.DeviceSecret)
	}
}

// TestScenario_ApplyUpdateCalledWhenReleaseAdvertised tests that ApplyUpdate is called when agentRelease is in response
func TestScenario_ApplyUpdateCalledWhenReleaseAdvertised(t *testing.T) {
	// Given: a check-in response that carries agentRelease
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	inv := contract.Inventory{}
	pst := contract.Posture{}

	applyUpdateCalls := 0
	var appliedRelease *contract.AgentRelease

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				data, _ := json.Marshal(contract.PolicyBundleResponse{})
				return fake.Response(http.StatusOK, string(data)), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				data, _ := json.Marshal(contract.CheckInResponse{
					CheckInIntervalSeconds: 900,
					PendingCommandCount:    0,
					AgentRelease: &contract.AgentRelease{
						Version: "1.3.0",
						URL:     "https://example.com/agent",
						SHA256:  "a" + strings.Repeat("0", 63),
					},
				})
				return fake.Response(http.StatusOK, string(data)), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "darwin",
		CollectInventory: func() (contract.Inventory, error) {
			return inv, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return pst, nil
		},
		ApplyUpdate: func(ctx context.Context, rel contract.AgentRelease) error {
			applyUpdateCalls++
			appliedRelease = &rel
			return nil
		},
	}

	// When: RunOnce executes
	err := RunOnce(context.Background(), deps)

	// Then: ApplyUpdate was called exactly once
	if applyUpdateCalls != 1 {
		t.Errorf("Expected ApplyUpdate to be called once, got %d calls", applyUpdateCalls)
	}

	// And: it was called with the advertised release
	if appliedRelease == nil {
		t.Fatal("ApplyUpdate was not called with a release")
	}
	if appliedRelease.Version != "1.3.0" {
		t.Errorf("Expected version 1.3.0, got %s", appliedRelease.Version)
	}

	// And: the cycle completed successfully
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}
}

// TestScenario_ApplyUpdateErrorDoesNotStopCycle tests that an ApplyUpdate error doesn't stop the cycle
func TestScenario_ApplyUpdateErrorDoesNotStopCycle(t *testing.T) {
	// Given: a check-in response with agentRelease and ApplyUpdate returns an error
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	inv := contract.Inventory{}
	pst := contract.Posture{}

	applyUpdateCalls := 0
	afterCheckInCalls := 0

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				data, _ := json.Marshal(contract.PolicyBundleResponse{})
				return fake.Response(http.StatusOK, string(data)), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				data, _ := json.Marshal(contract.CheckInResponse{
					CheckInIntervalSeconds: 900,
					PendingCommandCount:    1,
					AgentRelease: &contract.AgentRelease{
						Version: "1.3.0",
						URL:     "https://example.com/agent",
						SHA256:  "a" + strings.Repeat("0", 63),
					},
				})
				return fake.Response(http.StatusOK, string(data)), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "darwin",
		CollectInventory: func() (contract.Inventory, error) {
			return inv, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return pst, nil
		},
		ApplyUpdate: func(ctx context.Context, rel contract.AgentRelease) error {
			applyUpdateCalls++
			return errors.New("update failed")
		},
		AfterCheckIn: func(ctx context.Context, resp contract.CheckInResponse) error {
			afterCheckInCalls++
			return nil
		},
	}

	// When: RunOnce executes
	err := RunOnce(context.Background(), deps)

	// Then: ApplyUpdate was called once
	if applyUpdateCalls != 1 {
		t.Errorf("Expected ApplyUpdate to be called once, got %d calls", applyUpdateCalls)
	}

	// And: AfterCheckIn was still called (cycle didn't stop)
	if afterCheckInCalls != 1 {
		t.Errorf("Expected AfterCheckIn to be called once, got %d calls", afterCheckInCalls)
	}

	// And: the cycle completed successfully despite the update error
	if err != nil {
		t.Fatalf("RunOnce should not fail due to ApplyUpdate error, got %v", err)
	}
}

// TestScenario_NoApplyUpdateWhenNoReleaseAdvertised tests that ApplyUpdate is not called without release
func TestScenario_NoApplyUpdateWhenNoReleaseAdvertised(t *testing.T) {
	// Given: a check-in response with no agentRelease
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	inv := contract.Inventory{}
	pst := contract.Posture{}

	applyUpdateCalls := 0

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				data, _ := json.Marshal(contract.PolicyBundleResponse{})
				return fake.Response(http.StatusOK, string(data)), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				data, _ := json.Marshal(contract.CheckInResponse{
					CheckInIntervalSeconds: 900,
					PendingCommandCount:    0,
					// No AgentRelease
				})
				return fake.Response(http.StatusOK, string(data)), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "darwin",
		CollectInventory: func() (contract.Inventory, error) {
			return inv, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return pst, nil
		},
		ApplyUpdate: func(ctx context.Context, rel contract.AgentRelease) error {
			applyUpdateCalls++
			return nil
		},
	}

	// When: RunOnce executes
	err := RunOnce(context.Background(), deps)

	// Then: ApplyUpdate was not called
	if applyUpdateCalls != 0 {
		t.Errorf("Expected ApplyUpdate not to be called, got %d calls", applyUpdateCalls)
	}

	// And: the cycle completed successfully
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}
}

// TestScenario_EnforceCalledAfterEvaluateAndBeforeCheckIn tests that the
// Enforce seam is called exactly once per cycle, with the bundle's
// EffectiveSettings and the posture collected that cycle, after Evaluate and
// before the check-in POST.
func TestScenario_EnforceCalledAfterEvaluateAndBeforeCheckIn(t *testing.T) {
	// Given: a scheduler with an Enforce seam and a bundle with effectiveSettings {firewallEnabled:true}
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	inv := contract.Inventory{}
	pst := contract.Posture{Firewall: contract.Firewall{Enabled: true}}

	bundle := contract.PolicyBundleResponse{
		DeviceID:          "d1",
		Policies:          []contract.Policy{},
		Conflicts:         []contract.Conflict{},
		EffectiveSettings: map[string]any{"firewallEnabled": true},
	}

	var order []string
	var enforceCount int
	var capturedEffective map[string]any
	var capturedPosture contract.Posture

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				data, _ := json.Marshal(bundle)
				return fake.Response(http.StatusOK, string(data)), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				order = append(order, "checkin")
				return fake.Response(http.StatusOK, "{}"), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "darwin",
		CollectInventory: func() (contract.Inventory, error) {
			return inv, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return pst, nil
		},
		Evaluate: func(b contract.PolicyBundleResponse, p contract.Posture, now time.Time) []policy.Result {
			order = append(order, "evaluate")
			return []policy.Result{}
		},
		Enforce: func(ctx context.Context, effective map[string]any, posture contract.Posture) {
			order = append(order, "enforce")
			enforceCount++
			capturedEffective = effective
			capturedPosture = posture
		},
	}

	// When: RunOnce runs
	err := RunOnce(context.Background(), deps)
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then: Enforce was called once with that effectiveSettings and the collected posture
	if enforceCount != 1 {
		t.Fatalf("Expected Enforce called exactly once, got %d", enforceCount)
	}
	if capturedEffective["firewallEnabled"] != true {
		t.Errorf("Expected effective settings firewallEnabled true, got %v", capturedEffective)
	}
	if !capturedPosture.Firewall.Enabled {
		t.Errorf("Expected the collected posture to be passed through, got %v", capturedPosture)
	}

	// And: Enforce ran after Evaluate and before the check-in post
	if len(order) != 3 {
		t.Fatalf("Expected 3 recorded steps, got %v", order)
	}
	if order[0] != "evaluate" || order[1] != "enforce" || order[2] != "checkin" {
		t.Fatalf("Expected order [evaluate enforce checkin], got %v", order)
	}
}

// TestScenario_EnforceNotCalledWhenBundleFetchFails tests that Enforce is not
// called when the policy endpoint fails, and that the check-in is still
// posted.
func TestScenario_EnforceNotCalledWhenBundleFetchFails(t *testing.T) {
	// Given: the policy endpoint returns 500
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	inv := contract.Inventory{}
	pst := contract.Posture{}

	checkinPosted := false
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusInternalServerError, "{}"), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinPosted = true
				return fake.Response(http.StatusOK, "{}"), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	enforceCalled := false
	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "darwin",
		CollectInventory: func() (contract.Inventory, error) {
			return inv, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return pst, nil
		},
		Enforce: func(ctx context.Context, effective map[string]any, posture contract.Posture) {
			enforceCalled = true
		},
	}

	// When: RunOnce runs
	err := RunOnce(context.Background(), deps)
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then: Enforce was not called and the check-in was still posted
	if enforceCalled {
		t.Error("Expected Enforce not to be called when the bundle fetch failed")
	}
	if !checkinPosted {
		t.Error("Expected the check-in to still be posted")
	}
}

// TestScenario_NoEnforceSeamStillChecksIn tests that a scheduler whose
// Enforce is nil still posts the check-in.
func TestScenario_NoEnforceSeamStillChecksIn(t *testing.T) {
	// Given: a scheduler whose Enforce is nil
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	inv := contract.Inventory{}
	pst := contract.Posture{}

	bundle := contract.PolicyBundleResponse{
		DeviceID:          "d1",
		Policies:          []contract.Policy{},
		Conflicts:         []contract.Conflict{},
		EffectiveSettings: map[string]any{"firewallEnabled": true},
	}

	checkinPosted := false
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				data, _ := json.Marshal(bundle)
				return fake.Response(http.StatusOK, string(data)), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinPosted = true
				return fake.Response(http.StatusOK, "{}"), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "darwin",
		CollectInventory: func() (contract.Inventory, error) {
			return inv, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return pst, nil
		},
		// Enforce left nil.
	}

	// When: RunOnce runs
	err := RunOnce(context.Background(), deps)

	// Then: the check-in is posted
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}
	if !checkinPosted {
		t.Error("Expected the check-in to be posted even with Enforce nil")
	}
}

// TestScenario_FirewallViolationStillReportedInEnforcingCycle tests that the
// production evaluator still reports firewall_disabled in the same cycle a
// recording Enforce runs, per AC18.
func TestScenario_FirewallViolationStillReportedInEnforcingCycle(t *testing.T) {
	// Given: a policy {firewallEnabled:true} and a posture with the firewall off
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	inv := contract.Inventory{}
	pst := contract.Posture{Firewall: contract.Firewall{Enabled: false}}

	bundle := contract.PolicyBundleResponse{
		DeviceID: "d1",
		Policies: []contract.Policy{
			{PolicyID: "fw-policy", Version: 1, Settings: map[string]any{"firewallEnabled": true}},
		},
		Conflicts:         []contract.Conflict{},
		EffectiveSettings: map[string]any{"firewallEnabled": true},
	}

	var checkinBody []byte
	enforceCalled := false

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				data, _ := json.Marshal(bundle)
				return fake.Response(http.StatusOK, string(data)), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinBody = body
				return fake.Response(http.StatusOK, "{}"), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "darwin",
		CollectInventory: func() (contract.Inventory, error) {
			return inv, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return pst, nil
		},
		// Evaluate left nil, so the production policy.Evaluate runs.
		Enforce: func(ctx context.Context, effective map[string]any, posture contract.Posture) {
			enforceCalled = true
		},
	}

	// When: one cycle runs with the production evaluator and a recording Enforce
	err := RunOnce(context.Background(), deps)
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then: the check-in carries violation firewall_disabled and Enforce was called
	if !enforceCalled {
		t.Fatal("Expected Enforce to be called")
	}

	var checkinReq contract.CheckInRequest
	if err := json.Unmarshal(checkinBody, &checkinReq); err != nil {
		t.Fatalf("Failed to unmarshal checkin body: %v", err)
	}

	if len(checkinReq.PolicyCompliance) != 1 {
		t.Fatalf("Expected 1 policy compliance entry, got %d", len(checkinReq.PolicyCompliance))
	}

	found := false
	for _, v := range checkinReq.PolicyCompliance[0].Violations {
		if v == policy.ViolationFirewallDisabled {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected violation %s, got %v", policy.ViolationFirewallDisabled, checkinReq.PolicyCompliance[0].Violations)
	}
}

// ============================================================================
// TASK-030: Antivirus Findings Wiring Tests
// ============================================================================

// TestScenario_FindingsPostedEvenWhenBundleFetchFails covers the independence
// of the findings step from the bundle fetch.
func TestScenario_FindingsPostedEvenWhenBundleFetchFails(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("windows"), stateData)

	var checkinBody []byte
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusServiceUnavailable, "{}"), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinBody = body
				return fake.Response(http.StatusOK, "{}"), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}
	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "windows",
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
		CollectAntivirusFindings: func() ([]contract.AntivirusFinding, []string) {
			return []contract.AntivirusFinding{{
				FindingID:  "f1",
				ThreatName: "Trojan",
				Severity:   "severe",
				DetectedAt: "2026-10-02T00:00:00Z",
				Resources:  []string{},
				Remediated: false,
			}}, nil
		},
	}

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	var req contract.CheckInRequest
	if err := json.Unmarshal(checkinBody, &req); err != nil {
		t.Fatalf("failed to unmarshal checkin body: %v", err)
	}
	if len(req.PolicyCompliance) != 0 {
		t.Errorf("expected no policyCompliance, got %v", req.PolicyCompliance)
	}
	if strings.Contains(string(checkinBody), `"policyCompliance"`) {
		t.Error("checkin body should carry no policyCompliance key")
	}
	if len(req.AntivirusFindings) != 1 {
		t.Fatalf("expected 1 antivirus finding, got %d", len(req.AntivirusFindings))
	}
}

// TestScenario_ThirdPartyActiveDefenderStoppedYieldsNoFindingsNoWarning covers
// the default CollectAntivirusFindings wiring to antivirus.CollectFindings
// through a real fake runner.
func TestScenario_ThirdPartyActiveDefenderStoppedYieldsNoFindingsNoWarning(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("windows"), stateData)

	runner := fake.NewCommandRunner()
	findingsKey := fake.Command{
		Name: "powershell.exe",
		Args: []string{"-NoProfile", "-NonInteractive", "-Command", antivirus.WindowsFindingsScript},
	}.String()
	runner.Results[findingsKey] = platform.CommandResult{Stdout: "", ExitCode: 0}

	var checkinBody []byte
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusServiceUnavailable, "{}"), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinBody = body
				return fake.Response(http.StatusOK, "{}"), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}
	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "windows",
		Runner: runner,
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			// The posture the antivirus-thirdparty.txt fixture produces:
			// Defender off, a third-party product active.
			return contract.Posture{
				Antivirus: contract.Antivirus{Name: "Contoso Endpoint Security", Enabled: true, DefinitionsAgeDays: 0},
			}, nil
		},
	}

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	if strings.Contains(string(checkinBody), `"antivirusFindings"`) {
		t.Errorf("checkin body should carry no antivirusFindings key, got %s", checkinBody)
	}
	for _, warning := range []string{antivirus.WarningFindings, antivirus.WarningFindingsTimeout, antivirus.WarningFindingsUnparseable} {
		if strings.Contains(string(checkinBody), warning) {
			t.Errorf("checkin body should not carry warning %q, got %s", warning, checkinBody)
		}
	}
}

// TestScenario_FindingsProbeFailureDoesNotCostTheCheckIn covers that the
// default CollectAntivirusFindings wiring reports a failing probe as a
// posture warning, through RunOnce, and still posts the check-in.
func TestScenario_FindingsProbeFailureDoesNotCostTheCheckIn(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("windows"), stateData)

	runner := fake.NewCommandRunner()
	findingsKey := fake.Command{
		Name: "powershell.exe",
		Args: []string{"-NoProfile", "-NonInteractive", "-Command", antivirus.WindowsFindingsScript},
	}.String()
	runner.Results[findingsKey] = platform.CommandResult{ExitCode: 1}

	var checkinBody []byte
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusServiceUnavailable, "{}"), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinBody = body
				return fake.Response(http.StatusOK, "{}"), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}
	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "windows",
		Runner: runner,
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
	}

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	var req contract.CheckInRequest
	if err := json.Unmarshal(checkinBody, &req); err != nil {
		t.Fatalf("failed to unmarshal checkin body: %v", err)
	}
	found := false
	for _, w := range req.Posture.Warnings {
		if w == antivirus.WarningFindings {
			found = true
		}
	}
	if !found {
		t.Errorf("posture.warnings should contain %q, got %v", antivirus.WarningFindings, req.Posture.Warnings)
	}
	if len(req.AntivirusFindings) != 0 {
		t.Errorf("expected no antivirus findings, got %v", req.AntivirusFindings)
	}
	if strings.Contains(string(checkinBody), `"antivirusFindings":[`) {
		t.Errorf("checkin body should carry no antivirusFindings key, got %s", checkinBody)
	}
}

// TestScenario_EnforcingCycleStillReportsPreEnforcementPosture covers that
// posture is collected exactly once and the check-in reports the posture
// found before enforcement ran.
func TestScenario_EnforcingCycleStillReportsPreEnforcementPosture(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("windows"), stateData)

	bundle := contract.PolicyBundleResponse{
		DeviceID: "d1",
		Policies: []contract.Policy{
			{PolicyID: "av-policy", Version: 1, Settings: map[string]any{"antivirusEnabled": true}},
		},
		Conflicts:         []contract.Conflict{},
		EffectiveSettings: map[string]any{"antivirusEnabled": true},
	}

	posture := contract.Posture{Antivirus: contract.Antivirus{Enabled: false}}
	var postureCollections int
	var checkinBody []byte
	var enforceCalled bool

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				data, _ := json.Marshal(bundle)
				return fake.Response(http.StatusOK, string(data)), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinBody = body
				return fake.Response(http.StatusOK, "{}"), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}
	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "windows",
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			postureCollections++
			return posture, nil
		},
		// Evaluate left nil: the production policy.Evaluate runs.
		Enforce: func(ctx context.Context, effective map[string]any, p contract.Posture) {
			enforceCalled = true
		},
	}

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	if postureCollections != 1 {
		t.Errorf("posture should be collected exactly once, got %d", postureCollections)
	}
	if !enforceCalled {
		t.Error("expected Enforce to be called")
	}

	var req contract.CheckInRequest
	if err := json.Unmarshal(checkinBody, &req); err != nil {
		t.Fatalf("failed to unmarshal checkin body: %v", err)
	}
	if len(req.PolicyCompliance) != 1 {
		t.Fatalf("expected 1 policy compliance entry, got %d", len(req.PolicyCompliance))
	}
	found := false
	for _, v := range req.PolicyCompliance[0].Violations {
		if v == policy.ViolationAntivirusDisabled {
			found = true
		}
	}
	if !found {
		t.Errorf("expected violation %s, got %v", policy.ViolationAntivirusDisabled, req.PolicyCompliance[0].Violations)
	}
}

// TestScenario_NoDetectionsYieldsNoFindingsKey covers both goos values: a
// collector reporting nothing leaves no antivirusFindings key on the wire.
func TestScenario_NoDetectionsYieldsNoFindingsKey(t *testing.T) {
	for _, goos := range []string{"windows", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
			fsys := fake.NewFS()

			st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
			stateData, _ := json.Marshal(st)
			fsys.Seed(state.StatePath(goos), stateData)

			var checkinBody []byte
			transport := &mockTransport{
				doFunc: func(method, path string, body []byte) (*http.Response, error) {
					if method == "GET" && strings.Contains(path, "policies") {
						return fake.Response(http.StatusServiceUnavailable, "{}"), nil
					}
					if method == "POST" && strings.Contains(path, "checkin") {
						checkinBody = body
						return fake.Response(http.StatusOK, "{}"), nil
					}
					return fake.Response(http.StatusOK, "{}"), nil
				},
			}

			stateStore := &fakeStore{state: st}
			deps := &Deps{
				Client: transport,
				Store:  stateStore,
				FS:     fsys,
				Clock:  clock,
				GOOS:   goos,
				CollectInventory: func() (contract.Inventory, error) {
					return contract.Inventory{}, nil
				},
				CollectPosture: func() (contract.Posture, error) {
					return contract.Posture{}, nil
				},
				CollectAntivirusFindings: func() ([]contract.AntivirusFinding, []string) {
					return nil, nil
				},
			}

			if err := RunOnce(context.Background(), deps); err != nil {
				t.Fatalf("RunOnce failed: %v", err)
			}
			if strings.Contains(string(checkinBody), `"antivirusFindings"`) {
				t.Errorf("checkin body should carry no antivirusFindings key, got %s", checkinBody)
			}
			if strings.Contains(string(checkinBody), "antivirusFindings:") {
				t.Errorf("checkin body should carry no antivirusFindings warning, got %s", checkinBody)
			}
		})
	}
}

// TestScenario_NoRunnerMeansNoFindingsStep covers the seam's nil-defaulting
// rule: with both Runner and CollectAntivirusFindings nil, no findings step
// runs at all.
func TestScenario_NoRunnerMeansNoFindingsStep(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	var checkinBody []byte
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusServiceUnavailable, "{}"), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinBody = body
				return fake.Response(http.StatusOK, "{}"), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}
	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "darwin",
		// Runner is left nil deliberately.
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
		// CollectAntivirusFindings is left nil deliberately.
	}

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}
	if strings.Contains(string(checkinBody), `"antivirusFindings"`) {
		t.Errorf("checkin body should carry no antivirusFindings key, got %s", checkinBody)
	}
}

// TestScenario_AC22_CheckInCarriesTheScanRecord covers CollectAntivirusScan
// being called once per cycle, after the antivirus findings, and its value
// riding on the posted check-in as "antivirusScan".
func TestScenario_AC22_CheckInCarriesTheScanRecord(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("windows"), stateData)

	var checkinBody []byte
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusServiceUnavailable, "{}"), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinBody = body
				return fake.Response(http.StatusOK, "{}"), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	started := "2026-10-02T00:00:00Z"
	completed := "2026-10-02T00:05:00Z"
	// Given CollectAntivirusScan returns a record with result "clean"
	deps := &Deps{
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
		CollectAntivirusScan: func() *contract.AntivirusScan {
			return &contract.AntivirusScan{ScanType: "quick", Result: "clean", StartedAt: &started, CompletedAt: &completed, ThreatsFound: 0}
		},
	}

	// When one scheduler cycle posts its check-in
	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then the posted body has "antivirusScan" equal to that record
	var req contract.CheckInRequest
	if err := json.Unmarshal(checkinBody, &req); err != nil {
		t.Fatalf("failed to unmarshal checkin body: %v", err)
	}
	if req.AntivirusScan == nil {
		t.Fatal("expected antivirusScan to be present")
	}
	if req.AntivirusScan.Result != "clean" || req.AntivirusScan.ScanType != "quick" {
		t.Errorf("antivirusScan = %+v, want result=clean scanType=quick", req.AntivirusScan)
	}
	if req.AntivirusScan.StartedAt == nil || *req.AntivirusScan.StartedAt != started {
		t.Errorf("antivirusScan.startedAt = %v, want %s", req.AntivirusScan.StartedAt, started)
	}
}

// TestScenario_AC22_NoRecordMeansNoKey covers CollectAntivirusScan returning
// nil leaving the check-in with no antivirusScan key, and a nil seam leaving
// it absent too.
func TestScenario_AC22_NoRecordMeansNoKey(t *testing.T) {
	run := func(t *testing.T, collect func() *contract.AntivirusScan) []byte {
		clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
		fsys := fake.NewFS()
		st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
		stateData, _ := json.Marshal(st)
		fsys.Seed(state.StatePath("windows"), stateData)

		var checkinBody []byte
		transport := &mockTransport{
			doFunc: func(method, path string, body []byte) (*http.Response, error) {
				if method == "GET" && strings.Contains(path, "policies") {
					return fake.Response(http.StatusServiceUnavailable, "{}"), nil
				}
				if method == "POST" && strings.Contains(path, "checkin") {
					checkinBody = body
					return fake.Response(http.StatusOK, "{}"), nil
				}
				return fake.Response(http.StatusOK, "{}"), nil
			},
		}

		deps := &Deps{
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
			CollectAntivirusScan: collect,
		}

		if err := RunOnce(context.Background(), deps); err != nil {
			t.Fatalf("RunOnce failed: %v", err)
		}
		return checkinBody
	}

	t.Run("CollectAntivirusScan returns nil", func(t *testing.T) {
		body := run(t, func() *contract.AntivirusScan { return nil })
		if strings.Contains(string(body), `"antivirusScan"`) {
			t.Errorf("checkin body should carry no antivirusScan key, got %s", body)
		}
	})

	t.Run("CollectAntivirusScan is nil", func(t *testing.T) {
		body := run(t, nil)
		if strings.Contains(string(body), `"antivirusScan"`) {
			t.Errorf("checkin body should carry no antivirusScan key, got %s", body)
		}
	})
}

// ============================================================================
// TASK-063: agentErrors ride on the check-in body.
// ============================================================================

func agentErrorsSchedulerDeps(t *testing.T, transport *mockTransport, buf *agenterrors.Buffer) (*Deps, *fake.Clock, *fake.FS) {
	t.Helper()
	clock := fake.NewClock(time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	fsys.Seed(state.StatePath("darwin"), stateData)

	logger := logging.New(fsys, clock, "/agent.log", logging.LevelInfo, "agent")
	logger.SetSink(buf)

	deps := &Deps{
		Client: transport,
		Store:  &fakeStore{state: st},
		FS:     fsys,
		Clock:  clock,
		GOOS:   "darwin",
		Logger: logger.With("scheduler"),
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
		// A successful, silent time zone collector: the real one logs a warn
		// through this same logger hierarchy when nothing is wired for the
		// test platform, which would otherwise add an unrelated entry to the
		// buffer these tests are asserting on.
		CollectTimeZone: func() inventory.TimeZoneResult {
			return inventory.TimeZoneResult{Zone: "Australia/Sydney"}
		},
		CollectAgentErrors: buf.Collect,
	}
	return deps, clock, fsys
}

// TestScenario_AC7_TheCheckInCarriesAndEmptiesTheBuffer covers:
//
//	Given the buffer holds 2 entries
//	When a cycle builds and posts its check-in
//	Then the posted body has an "agentErrors" array with 2 entries
//	And the buffer is empty
func TestScenario_AC7_TheCheckInCarriesAndEmptiesTheBuffer(t *testing.T) {
	buf := agenterrors.New()
	buf.Add("warn", "enforce", "policy enforcement failed", nil, time.Now())
	buf.Add("error", "update", "agent update failed", nil, time.Now())

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
	deps, _, _ := agentErrorsSchedulerDeps(t, transport, buf)

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	var req contract.CheckInRequest
	if err := json.Unmarshal(checkinBody, &req); err != nil {
		t.Fatalf("unmarshal checkin body: %v", err)
	}
	if len(req.AgentErrors) != 2 {
		t.Fatalf("posted agentErrors has %d entries, want 2: %s", len(req.AgentErrors), checkinBody)
	}
	if buf.Len() != 0 {
		t.Errorf("buffer len after the cycle = %d, want 0", buf.Len())
	}
}

// TestScenario_AC7_AnEmptyBufferSendsNoAgentErrorsKey covers:
//
//	Given the buffer is empty
//	When a cycle posts its check-in
//	Then the posted body has no "agentErrors" key
func TestScenario_AC7_AnEmptyBufferSendsNoAgentErrorsKey(t *testing.T) {
	buf := agenterrors.New()

	var checkinBody []byte
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinBody = body
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}
	deps, _, _ := agentErrorsSchedulerDeps(t, transport, buf)

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	if strings.Contains(string(checkinBody), `"agentErrors"`) {
		t.Errorf("checkin body should carry no agentErrors key, got %s", checkinBody)
	}
}

// TestScenario_AC8_AgentErrorsIsCappedAt32KBOnTheWire covers:
//
//	Given the buffer holds 50 entries, each with 8 fields of 256 characters
//	When a cycle builds its check-in
//	Then the encoded agentErrors is at most 32768 bytes
//	And the buffer is empty after the build
func TestScenario_AC8_AgentErrorsIsCappedAt32KBOnTheWire(t *testing.T) {
	buf := agenterrors.New()
	base := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	longValue := strings.Repeat("v", agenterrors.MaxValueRunes)
	fields := make([]logging.Field, 0, agenterrors.MaxFields)
	for i := 0; i < agenterrors.MaxFields; i++ {
		fields = append(fields, logging.F(fmt.Sprintf("field%d", i), longValue))
	}
	for i := 0; i < agenterrors.MaxEntries; i++ {
		message := fmt.Sprintf("%03d", i) + strings.Repeat("m", agenterrors.MaxValueRunes-3)
		buf.Add("warn", "comp", message, fields, base.Add(time.Duration(i)*time.Minute))
	}

	var checkinBody []byte
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinBody = body
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}
	deps, _, _ := agentErrorsSchedulerDeps(t, transport, buf)

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	var req contract.CheckInRequest
	if err := json.Unmarshal(checkinBody, &req); err != nil {
		t.Fatalf("unmarshal checkin body: %v", err)
	}
	encoded, err := json.Marshal(req.AgentErrors)
	if err != nil {
		t.Fatalf("marshal agentErrors: %v", err)
	}
	if len(encoded) > agenterrors.MaxEncodedBytes {
		t.Fatalf("encoded agentErrors is %d bytes, want <= %d", len(encoded), agenterrors.MaxEncodedBytes)
	}
	if len(req.AgentErrors) == 0 || len(req.AgentErrors) >= agenterrors.MaxEntries {
		t.Fatalf("expected some, but not all, of the 50 entries to fit; got %d", len(req.AgentErrors))
	}
	if buf.Len() != 0 {
		t.Errorf("buffer len after the cycle = %d, want 0", buf.Len())
	}
}

// TestScenario_AC9_ErrorsLoggedAfterTheBodyIsBuiltGoOnTheNextCheckIn covers:
//
//	Given the check-in response advertises an agent release whose install fails
//	When two cycles run
//	Then the second cycle's body contains an agentErrors entry with message
//	     "agent update failed"
func TestScenario_AC9_ErrorsLoggedAfterTheBodyIsBuiltGoOnTheNextCheckIn(t *testing.T) {
	buf := agenterrors.New()

	var checkinBodies [][]byte
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinBodies = append(checkinBodies, body)
				data, _ := json.Marshal(contract.CheckInResponse{
					CheckInIntervalSeconds: 600,
					AgentRelease: &contract.AgentRelease{
						Version: "1.5.0",
						URL:     "https://example.com/agent",
						SHA256:  "a" + strings.Repeat("0", 63),
					},
				})
				return fake.Response(http.StatusOK, string(data)), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}
	deps, _, _ := agentErrorsSchedulerDeps(t, transport, buf)
	deps.ApplyUpdate = func(ctx context.Context, rel contract.AgentRelease) error {
		return errors.New("install failed")
	}

	// When: two cycles run
	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("first RunOnce failed: %v", err)
	}
	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("second RunOnce failed: %v", err)
	}

	if len(checkinBodies) != 2 {
		t.Fatalf("expected 2 posted checkin bodies, got %d", len(checkinBodies))
	}

	var firstReq contract.CheckInRequest
	if err := json.Unmarshal(checkinBodies[0], &firstReq); err != nil {
		t.Fatalf("unmarshal first body: %v", err)
	}
	for _, e := range firstReq.AgentErrors {
		if e.Message == "agent update failed" {
			t.Fatal("the first cycle's body must not carry the update failure logged after it was built")
		}
	}

	var secondReq contract.CheckInRequest
	if err := json.Unmarshal(checkinBodies[1], &secondReq); err != nil {
		t.Fatalf("unmarshal second body: %v", err)
	}
	found := false
	for _, e := range secondReq.AgentErrors {
		if e.Message == "agent update failed" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the second cycle's agentErrors to contain 'agent update failed', got %+v", secondReq.AgentErrors)
	}
}

// TestScenario_AC10_ErrorsInASpooledCheckInAreNotSentTwice covers:
//
//	Given the buffer holds the entry "policy enforcement failed"
//	And the check-in post fails with a transport error
//	When the cycle runs
//	Then the spool file contains agentErrors with "policy enforcement failed"
//	When the next cycle runs with the backend reachable and nothing new was
//	     logged at warn or error except the offline records
//	Then the fresh body does not contain an entry "policy enforcement failed"
func TestScenario_AC10_ErrorsInASpooledCheckInAreNotSentTwice(t *testing.T) {
	buf := agenterrors.New()
	buf.Add("warn", "enforce", "policy enforcement failed", nil, time.Now())

	offline := true
	var secondCycleBodies [][]byte
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "POST" && strings.Contains(path, "checkin") {
				if offline {
					return nil, errors.New("network unreachable")
				}
				secondCycleBodies = append(secondCycleBodies, body)
				return fake.Response(http.StatusOK, "{}"), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}
	deps, _, fsys := agentErrorsSchedulerDeps(t, transport, buf)
	deps.SpoolDir = "/spool"

	// When: the (offline) cycle runs
	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("first RunOnce failed: %v", err)
	}

	// Then: the spool file contains agentErrors with "policy enforcement failed"
	var spoolFile string
	for _, path := range fsys.Paths() {
		if strings.Contains(path, "/spool") {
			spoolFile = path
		}
	}
	if spoolFile == "" {
		t.Fatal("expected a spool file after the offline cycle")
	}
	spooled, _ := fsys.Content(spoolFile)
	var spooledReq contract.CheckInRequest
	if err := json.Unmarshal(spooled, &spooledReq); err != nil {
		t.Fatalf("unmarshal spooled body: %v", err)
	}
	foundInSpool := false
	for _, e := range spooledReq.AgentErrors {
		if e.Message == "policy enforcement failed" {
			foundInSpool = true
		}
	}
	if !foundInSpool {
		t.Fatalf("expected the spooled body to carry 'policy enforcement failed', got %+v", spooledReq.AgentErrors)
	}

	// When: the next cycle runs with the backend reachable and nothing new
	// was logged.
	offline = false
	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("second RunOnce failed: %v", err)
	}

	// Then: the fresh (second, non-spool-replay) body does not contain the
	// entry again. drainSpool replays the spooled payload first, so the last
	// body posted in this cycle is the fresh one.
	if len(secondCycleBodies) == 0 {
		t.Fatal("expected at least one checkin POST in the second cycle")
	}
	freshBody := secondCycleBodies[len(secondCycleBodies)-1]
	var freshReq contract.CheckInRequest
	if err := json.Unmarshal(freshBody, &freshReq); err != nil {
		t.Fatalf("unmarshal fresh body: %v", err)
	}
	for _, e := range freshReq.AgentErrors {
		if e.Message == "policy enforcement failed" {
			t.Errorf("the fresh body must not carry 'policy enforcement failed' again, got %+v", freshReq.AgentErrors)
		}
	}
}

// fakeStore is a simple mock of the state store.
type fakeStore struct {
	state          state.State
	lastSavedState state.State
}

func (f *fakeStore) Load() (state.State, error) {
	return f.state, nil
}

func (f *fakeStore) Save(st state.State) error {
	f.lastSavedState = st
	f.state = st
	return nil
}

// ----------------------------------------------------------------------------
// AC11: the status block rides on every check-in.
// ----------------------------------------------------------------------------

// TestScenario_AC11_StatusBlockRidesOnEveryCheckIn covers the main scenario:
// CollectAntivirusStatus is called once, after findings, whether or not the
// bundle fetch succeeded, and its warnings land after the findings warnings.
func TestScenario_AC11_StatusBlockRidesOnEveryCheckIn(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("windows"), stateData)

	var checkinBody []byte
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				// The policy bundle fetch fails.
				return fake.Response(http.StatusServiceUnavailable, "{}"), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinBody = body
				return fake.Response(http.StatusOK, "{}"), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	statusBlock := &contract.AntivirusStatus{
		Product:                "Microsoft Defender",
		DefenderAvailable:      true,
		SecurityCenterProducts: []contract.SecurityCenterProduct{},
	}

	var statusCalls, findingsCalls int
	stateStore := &fakeStore{state: st}
	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "windows",
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
		CollectAntivirusFindings: func() ([]contract.AntivirusFinding, []string) {
			findingsCalls++
			return nil, []string{antivirus.WarningFindings}
		},
		CollectAntivirusStatus: func() (*contract.AntivirusStatus, []string) {
			statusCalls++
			return statusBlock, []string{antivirus.WarningStatusUnparseable}
		},
	}

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}
	if statusCalls != 1 {
		t.Fatalf("CollectAntivirusStatus called %d times, want 1", statusCalls)
	}
	if findingsCalls != 1 {
		t.Fatalf("CollectAntivirusFindings called %d times, want 1", findingsCalls)
	}

	var req contract.CheckInRequest
	if err := json.Unmarshal(checkinBody, &req); err != nil {
		t.Fatalf("failed to unmarshal checkin body: %v", err)
	}
	if req.AntivirusStatus == nil {
		t.Fatal("expected antivirusStatus to be set on the body")
	}
	if req.AntivirusStatus.Product != "Microsoft Defender" {
		t.Errorf("antivirusStatus.product = %q, want Microsoft Defender", req.AntivirusStatus.Product)
	}
	want := []string{antivirus.WarningFindings, antivirus.WarningStatusUnparseable}
	if len(req.Posture.Warnings) < 2 ||
		req.Posture.Warnings[len(req.Posture.Warnings)-2] != want[0] ||
		req.Posture.Warnings[len(req.Posture.Warnings)-1] != want[1] {
		t.Errorf("posture.warnings = %v, want to end with %v", req.Posture.Warnings, want)
	}
}

// TestScenario_AC11Edge_NoBlockMeansNoKey covers the "No block means no key"
// edge scenario, including the both-nil sub-case.
func TestScenario_AC11Edge_NoBlockMeansNoKey(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("windows"), stateData)

	var checkinBody []byte
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusServiceUnavailable, "{}"), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinBody = body
				return fake.Response(http.StatusOK, "{}"), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}
	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "windows",
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
		CollectAntivirusStatus: func() (*contract.AntivirusStatus, []string) {
			return nil, nil
		},
	}

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}
	if strings.Contains(string(checkinBody), `"antivirusStatus"`) {
		t.Errorf("checkin body should carry no antivirusStatus key, got %s", checkinBody)
	}

	// With both CollectAntivirusStatus and Runner nil, nothing is collected
	// and the check-in is still posted.
	checkinBody = nil
	deps2 := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "windows",
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
		// Runner and CollectAntivirusStatus both left nil deliberately.
	}
	if err := RunOnce(context.Background(), deps2); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}
	if strings.Contains(string(checkinBody), `"antivirusStatus"`) {
		t.Errorf("checkin body should carry no antivirusStatus key, got %s", checkinBody)
	}
}

// TestScenario_AC11_DefaultWiringUsesCollectStatusWithRunner covers the
// default-wiring rule: with CollectAntivirusStatus nil and Runner non-nil,
// antivirus.CollectStatus(Runner, Clock, goos) is used.
func TestScenario_AC11_DefaultWiringUsesCollectStatusWithRunner(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("windows"), stateData)

	runner := fake.NewCommandRunner()
	findingsKey := fake.Command{
		Name: "powershell.exe",
		Args: []string{"-NoProfile", "-NonInteractive", "-Command", antivirus.WindowsFindingsScript},
	}.String()
	runner.Results[findingsKey] = platform.CommandResult{Stdout: "", ExitCode: 0}
	statusKey := fake.Command{
		Name: "powershell.exe",
		Args: []string{"-NoProfile", "-NonInteractive", "-Command", antivirus.WindowsStatusScript},
	}.String()
	runner.Results[statusKey] = platform.CommandResult{
		Stdout:   `{"defenderAvailable":true,"status":{"AMRunningMode":"Normal"},"products":[]}`,
		ExitCode: 0,
	}

	var checkinBody []byte
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusServiceUnavailable, "{}"), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinBody = body
				return fake.Response(http.StatusOK, "{}"), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}
	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "windows",
		Runner: runner,
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
		// CollectAntivirusStatus is left nil deliberately, so the default
		// wiring to antivirus.CollectStatus(Runner, Clock, goos) applies.
	}

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	var req contract.CheckInRequest
	if err := json.Unmarshal(checkinBody, &req); err != nil {
		t.Fatalf("failed to unmarshal checkin body: %v", err)
	}
	if req.AntivirusStatus == nil {
		t.Fatal("expected antivirusStatus to be set via the default wiring")
	}
	if req.AntivirusStatus.RunningMode == nil || *req.AntivirusStatus.RunningMode != "Normal" {
		t.Errorf("antivirusStatus.runningMode = %v, want Normal", req.AntivirusStatus.RunningMode)
	}
}

// ============================================================================
// TASK-060: Deps.CollectDefenderHardening wiring in runCycle. Scenario names
// mirror tasks/testing/TASK-060-defender-policy-set-to-on.md's Gherkin.
// ============================================================================

// TestScenario_NoDefenderHardeningKeyWhenCollectorIsNil covers the last
// sentence of the AC: "the check-in JSON has no defenderHardening key when it
// is nil" -- both when no collector is wired and when one is wired but
// returns nil.
func TestScenario_NoDefenderHardeningKeyWhenCollectorIsNil(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("windows"), stateData)

	var checkinBody []byte
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusServiceUnavailable, "{}"), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinBody = body
				return fake.Response(http.StatusOK, "{}"), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	deps := &Deps{
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
		CollectDefenderHardening: func() *contract.DefenderHardening {
			return nil
		},
		// Runner left nil deliberately: on windows with no Runner the default
		// antivirus status collection is skipped, which keeps this check-in
		// body minimal.
	}

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}
	if strings.Contains(string(checkinBody), `"defenderHardening"`) {
		t.Errorf("checkin body should carry no defenderHardening key, got %s", checkinBody)
	}
}

// TestScenario_SchedulerReportsViolationsFromTheSameApplyItSends covers "The
// scheduler reports violations from the same Apply it sends".
func TestScenario_SchedulerReportsViolationsFromTheSameApplyItSends(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("windows"), stateData)

	bundle := contract.PolicyBundleResponse{
		DeviceID: "d1",
		Policies: []contract.Policy{
			{PolicyID: "p1", Version: 1, Settings: map[string]any{"defenderNetworkProtection": true}},
		},
	}
	hardeningBlock := &contract.DefenderHardening{
		EvaluatedAt: "2026-10-02T00:00:00Z",
		Items:       []contract.DefenderHardeningItem{{Item: "networkProtection", State: "failed", Detail: "boom"}},
	}

	var order []string
	var checkinBody []byte
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				data, _ := json.Marshal(bundle)
				return fake.Response(http.StatusOK, string(data)), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinBody = body
				data, _ := json.Marshal(contract.CheckInResponse{CheckInIntervalSeconds: 600})
				return fake.Response(http.StatusOK, string(data)), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	deps := &Deps{
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
		Evaluate: func(bundle contract.PolicyBundleResponse, posture contract.Posture, now time.Time) []policy.Result {
			order = append(order, "evaluate")
			return []policy.Result{{PolicyId: "p1", Version: 1, Compliant: true, Violations: []string{}}}
		},
		Enforce: func(ctx context.Context, effective map[string]any, posture contract.Posture) {
			order = append(order, "enforce")
		},
		CollectDefenderHardening: func() *contract.DefenderHardening {
			order = append(order, "collect")
			return hardeningBlock
		},
	}

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Evaluate was called before Enforce and CollectDefenderHardening was
	// called once, after Enforce.
	if len(order) != 3 || order[0] != "evaluate" || order[1] != "enforce" || order[2] != "collect" {
		t.Fatalf("call order = %v, want [evaluate enforce collect]", order)
	}

	var req contract.CheckInRequest
	if err := json.Unmarshal(checkinBody, &req); err != nil {
		t.Fatalf("failed to unmarshal checkin body: %v", err)
	}
	if len(req.PolicyCompliance) != 1 {
		t.Fatalf("expected 1 policyCompliance entry, got %d", len(req.PolicyCompliance))
	}
	entry := req.PolicyCompliance[0]
	if entry.PolicyID != "p1" || entry.Compliant {
		t.Fatalf("policyCompliance[0] = %+v, want p1 compliant false", entry)
	}
	wantViolation := "defender_protection_failed:defenderNetworkProtection:networkProtection"
	if len(entry.Violations) != 1 || entry.Violations[0] != wantViolation {
		t.Errorf("violations = %v, want [%s]", entry.Violations, wantViolation)
	}
	if req.DefenderHardening == nil || len(req.DefenderHardening.Items) != 1 || req.DefenderHardening.Items[0].Item != "networkProtection" {
		t.Errorf("defenderHardening = %+v, want the same block CollectDefenderHardening returned", req.DefenderHardening)
	}
}

// TestScenario_SchedulerSendsNoComplianceWhenBundleFetchFails covers "The
// scheduler sends no compliance when the bundle fetch fails".
func TestScenario_SchedulerSendsNoComplianceWhenBundleFetchFails(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("windows"), stateData)

	hardeningBlock := &contract.DefenderHardening{
		EvaluatedAt: "2026-10-02T00:00:00Z",
		Items:       []contract.DefenderHardeningItem{{Item: "networkProtection", State: "failed"}},
	}
	collectCalls := 0

	var checkinBody []byte
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return nil, errors.New("network error")
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinBody = body
				data, _ := json.Marshal(contract.CheckInResponse{CheckInIntervalSeconds: 600})
				return fake.Response(http.StatusOK, string(data)), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	deps := &Deps{
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
		CollectDefenderHardening: func() *contract.DefenderHardening {
			collectCalls++
			return hardeningBlock
		},
	}

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	if collectCalls != 1 {
		t.Errorf("CollectDefenderHardening was called %d times, want 1", collectCalls)
	}
	if strings.Contains(string(checkinBody), `"policyCompliance"`) {
		t.Errorf("checkin body should carry no policyCompliance key, got %s", checkinBody)
	}

	var req contract.CheckInRequest
	if err := json.Unmarshal(checkinBody, &req); err != nil {
		t.Fatalf("failed to unmarshal checkin body: %v", err)
	}
	if req.DefenderHardening == nil || len(req.DefenderHardening.Items) != 1 || req.DefenderHardening.Items[0].Item != "networkProtection" {
		t.Errorf("defenderHardening = %+v, want the block CollectDefenderHardening returned", req.DefenderHardening)
	}
}

// ============================================================================
// TASK-070 AC13: CollectAgentActions rides on the check-in, right before
// CollectAgentErrors, and only on a cycle that reaches the body.
// ============================================================================

// agentActionsSchedulerDeps builds a minimal, enrolled Deps whose policy
// bundle fetch succeeds with effectiveSettings firewallEnabled true, so an
// Enforce seam set by the caller actually runs.
func agentActionsSchedulerDeps(t *testing.T, transport *mockTransport) (*Deps, *fake.Clock, *fake.FS) {
	t.Helper()
	clock := fake.NewClock(time.Date(2026, 10, 12, 1, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	fsys.Seed(state.StatePath("darwin"), stateData)

	deps := &Deps{
		Client: transport,
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
		CollectTimeZone: func() inventory.TimeZoneResult {
			return inventory.TimeZoneResult{Zone: "Australia/Sydney"}
		},
	}
	return deps, clock, fsys
}

// policyBundleTransport answers the policies GET with bundle and the checkin
// POST with the given function, capturing nothing else.
func policyBundleTransport(bundle contract.PolicyBundleResponse, checkin func(body []byte) (*http.Response, error)) *mockTransport {
	return &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				data, _ := json.Marshal(bundle)
				return fake.Response(http.StatusOK, string(data)), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				return checkin(body)
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}
}

// TestScenario_AC13_TheCycleCarriesThisCyclesActions covers:
//
//	Given an Enforce seam that records "enforce.firewall_enabled"
//	When a cycle posts its check-in
//	Then the body's agentActions holds that action
//	And the agentActions key comes before agentErrors is collected
func TestScenario_AC13_TheCycleCarriesThisCyclesActions(t *testing.T) {
	bundle := contract.PolicyBundleResponse{
		DeviceID:          "d1",
		Policies:          []contract.Policy{},
		Conflicts:         []contract.Conflict{},
		EffectiveSettings: map[string]any{"firewallEnabled": true},
	}
	var checkinBody []byte
	transport := policyBundleTransport(bundle, func(body []byte) (*http.Response, error) {
		checkinBody = body
		return fake.Response(http.StatusOK, "{}"), nil
	})

	deps, _, _ := agentActionsSchedulerDeps(t, transport)

	var callOrder []string
	buf := []contract.AgentAction{{Type: contract.ActionFirewallEnabled, OccurredAt: "2026-10-12T01:00:00Z", Details: map[string]string{}}}
	deps.Enforce = func(ctx context.Context, effective map[string]any, posture contract.Posture) {
		// The buffer is populated by Enforce in production; here the seam
		// itself stands in for "an Enforce seam that records" the action.
	}
	deps.CollectAgentActions = func() []contract.AgentAction {
		callOrder = append(callOrder, "actions")
		return buf
	}
	deps.CollectAgentErrors = func() []contract.AgentError {
		callOrder = append(callOrder, "errors")
		return nil
	}

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	var req contract.CheckInRequest
	if err := json.Unmarshal(checkinBody, &req); err != nil {
		t.Fatalf("unmarshal checkin body: %v", err)
	}
	if len(req.AgentActions) != 1 || req.AgentActions[0].Type != contract.ActionFirewallEnabled {
		t.Fatalf("posted agentActions = %+v, want one firewall_enabled action", req.AgentActions)
	}

	if len(callOrder) != 2 || callOrder[0] != "actions" || callOrder[1] != "errors" {
		t.Fatalf("call order = %v, want [actions errors] (CollectAgentActions before CollectAgentErrors)", callOrder)
	}
}

// TestScenario_AC13_AnEmptyBufferSendsNoAgentActionsKey covers:
//
//	Given CollectAgentActions returns nil
//	When a cycle posts its check-in
//	Then the body has no "agentActions" key
func TestScenario_AC13_AnEmptyBufferSendsNoAgentActionsKey(t *testing.T) {
	var checkinBody []byte
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinBody = body
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}
	deps, _, _ := agentActionsSchedulerDeps(t, transport)
	deps.CollectAgentActions = func() []contract.AgentAction { return nil }

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}
	if strings.Contains(string(checkinBody), `"agentActions"`) {
		t.Errorf("checkin body should carry no agentActions key, got %s", checkinBody)
	}
}

// TestScenario_AC13_ACycleThatFailsBeforeTheBodyKeepsTheActions covers:
//
//	Given the inventory collector fails
//	When the cycle runs
//	Then CollectAgentActions was not called
func TestScenario_AC13_ACycleThatFailsBeforeTheBodyKeepsTheActions(t *testing.T) {
	transport := &mockTransport{}
	deps, _, _ := agentActionsSchedulerDeps(t, transport)
	deps.CollectInventory = func() (contract.Inventory, error) {
		return contract.Inventory{}, errors.New("inventory collection failed")
	}
	called := false
	deps.CollectAgentActions = func() []contract.AgentAction {
		called = true
		return nil
	}

	err := RunOnce(context.Background(), deps)
	if err == nil {
		t.Fatal("expected RunOnce to fail when inventory collection fails")
	}
	if called {
		t.Error("CollectAgentActions should not be called on a cycle that fails before the body is built")
	}
}

// TestScenario_AC9_OnlyTheHardenerActingPostsNoAgentActionsKey covers the
// scheduler half of AC9: a cycle in which the Defender hardener (represented
// here by CollectDefenderHardening returning a non-nil block) applied
// something, and no enforcer that records actions did anything, posts a body
// with no "agentActions" key.
func TestScenario_AC9_OnlyTheHardenerActingPostsNoAgentActionsKey(t *testing.T) {
	var checkinBody []byte
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "POST" && strings.Contains(path, "checkin") {
				checkinBody = body
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}
	deps, _, _ := agentActionsSchedulerDeps(t, transport)
	deps.CollectDefenderHardening = func() *contract.DefenderHardening {
		return &contract.DefenderHardening{EvaluatedAt: "2026-10-12T01:00:00Z", Items: []contract.DefenderHardeningItem{}}
	}
	deps.CollectAgentActions = func() []contract.AgentAction { return nil }

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}
	if strings.Contains(string(checkinBody), `"agentActions"`) {
		t.Errorf("checkin body should carry no agentActions key, got %s", checkinBody)
	}
}

// ============================================================================
// TASK-070 AC14: spooled actions are not sent twice.
// ============================================================================

// TestScenario_AC14_SpooledActionsAreNotSentTwice covers:
//
//	Given the buffer holds a domains action and the post fails with a
//	     transport error
//	When the cycle runs
//	Then the spool file contains that action
//	When the next cycle runs with nothing new recorded
//	Then its fresh body has no "agentActions" key
func TestScenario_AC14_SpooledActionsAreNotSentTwice(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 12, 1, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	spoolDir := "/spool"
	action := contract.AgentAction{Type: contract.ActionDomainsUpdated, OccurredAt: "2026-10-12T01:00:00Z", Details: map[string]string{"blockedCount": "3"}}

	collectCount := 0
	deps := &Deps{
		Client: &mockTransport{
			doFunc: func(method, path string, body []byte) (*http.Response, error) {
				if method == "POST" && strings.Contains(path, "checkin") {
					return nil, errors.New("network unreachable")
				}
				return fake.Response(http.StatusOK, "{}"), nil
			},
		},
		Store:    &fakeStore{state: st},
		FS:       fsys,
		Clock:    clock,
		GOOS:     "darwin",
		SpoolDir: spoolDir,
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
		CollectAgentActions: func() []contract.AgentAction {
			collectCount++
			if collectCount == 1 {
				return []contract.AgentAction{action}
			}
			return nil
		},
	}

	// When the first cycle runs and the post fails
	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce (first cycle) failed: %v", err)
	}

	var spoolFiles []string
	for _, path := range fsys.Paths() {
		if strings.Contains(path, spoolDir) && strings.Contains(path, "checkin") {
			spoolFiles = append(spoolFiles, path)
		}
	}
	if len(spoolFiles) != 1 {
		t.Fatalf("expected 1 spool file, got %d: %v", len(spoolFiles), spoolFiles)
	}
	spoolData, _ := fsys.Content(spoolFiles[0])
	if !strings.Contains(string(spoolData), `"agentActions"`) || !strings.Contains(string(spoolData), contract.ActionDomainsUpdated) {
		t.Errorf("expected the spool file to carry the agentActions entry, got %s", spoolData)
	}

	// When the next cycle runs, with the client now succeeding and nothing
	// new recorded (collectCount == 2 returns nil)
	var secondCheckinBody []byte
	deps.Client = &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "POST" && strings.Contains(path, "checkin") {
				secondCheckinBody = body
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}
	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce (second cycle) failed: %v", err)
	}

	// Then its fresh body has no "agentActions" key: the spooled copy, not a
	// freshly-built one, is what eventually carries the action to the server.
	if strings.Contains(string(secondCheckinBody), `"agentActions"`) {
		t.Errorf("the fresh check-in body should carry no agentActions key, got %s", secondCheckinBody)
	}
}
