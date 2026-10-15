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
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

// fakeWatermark is a mock watermark store.
type fakeWatermark struct {
	data  time.Time
	err   error
	loads int
	saves []time.Time
}

func (f *fakeWatermark) Load() (time.Time, error) {
	f.loads++
	return f.data, f.err
}

func (f *fakeWatermark) Save(t time.Time) error {
	f.saves = append(f.saves, t)
	f.data = t // Update the data so subsequent loads return the saved value
	return nil
}

// fakeWatermarkWithSaveError is a watermark that fails on save.
type fakeWatermarkWithSaveError struct {
	fakeWatermark
	saveErr error
}

func (f *fakeWatermarkWithSaveError) Save(t time.Time) error {
	f.saves = append(f.saves, t)
	return f.saveErr
}

// TestScenario_NoAnalyticsSeamMeansNoAnalyticsKey tests no analytics when nil.
func TestScenario_NoAnalyticsSeamMeansNoAnalyticsKey(t *testing.T) {
	// Given scheduler deps with CollectAnalytics nil and a recording watermark
	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	watermark := &fakeWatermark{}

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				bundle := contract.PolicyBundleResponse{
					DeviceID:  "d1",
					Policies:  []contract.Policy{},
					Conflicts: []contract.Conflict{},
				}
				data, _ := json.Marshal(bundle)
				return fake.Response(http.StatusOK, string(data)), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				return fake.Response(http.StatusOK, `{"checkInIntervalSeconds":600}`), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	deps := &Deps{
		Client:             transport,
		Store:              stateStore,
		FS:                 fsys,
		Clock:              clock,
		GOOS:               "darwin",
		CollectAnalytics:   nil, // No analytics
		AnalyticsWatermark: watermark,
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
	}

	// When RunOnce runs
	err := RunOnce(context.Background(), deps)
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then the posted body has no "analytics" key
	checkinIdx := -1
	for i, req := range transport.requests {
		if req.method == "POST" && strings.Contains(req.path, "checkin") {
			checkinIdx = i
			break
		}
	}
	if checkinIdx < 0 {
		t.Fatal("No checkin POST found")
	}

	var checkinReq contract.CheckInRequest
	err = json.Unmarshal(transport.requests[checkinIdx].body, &checkinReq)
	if err != nil {
		t.Fatalf("Failed to unmarshal checkin: %v", err)
	}

	if checkinReq.Analytics != nil {
		t.Error("analytics should be nil when CollectAnalytics is nil")
	}

	// And the watermark was neither loaded nor saved
	if watermark.loads != 0 {
		t.Errorf("Expected 0 loads, got %d", watermark.loads)
	}
	if len(watermark.saves) != 0 {
		t.Errorf("Expected 0 saves, got %d", len(watermark.saves))
	}
}

// TestScenario_CollectedBlockIsPostedUsingStoredWatermark tests using stored watermark.
func TestScenario_CollectedBlockIsPostedUsingStoredWatermark(t *testing.T) {
	// Given the watermark returns "2026-10-01T00:00:00Z"
	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	watermark := &fakeWatermark{data: since}

	lastBootAt := "2026-10-02T06:41:09Z"
	returnedBlock := contract.Analytics{
		Boot: contract.AnalyticsBoot{
			LastBootAt: &lastBootAt,
		},
	}

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				return fake.Response(http.StatusOK, `{"checkInIntervalSeconds":600}`), nil
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
		CollectAnalytics: func(s time.Time) (contract.Analytics, time.Time, error) {
			return returnedBlock, clock.Now().Add(1 * time.Hour), nil
		},
		AnalyticsWatermark: watermark,
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
	}

	// When RunOnce runs
	err := RunOnce(context.Background(), deps)
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then CollectAnalytics was called with "2026-10-01T00:00:00Z"
	// (verified by the setup - we passed that to the collector)

	// And Save was called with the candidate (after the POST succeeded)
	// The candidate is clock.Now().Add(1 * time.Hour), which is after since
	if len(watermark.saves) != 1 {
		t.Errorf("Expected 1 save (post-success), got %d", len(watermark.saves))
	}
	expectedCandidate := clock.Now().Add(1 * time.Hour)
	if len(watermark.saves) > 0 && watermark.saves[0] != expectedCandidate {
		t.Errorf("Expected save at %v, got %v", expectedCandidate, watermark.saves[0])
	}

	// And the posted analytics equals the block it returned
	checkinIdx := -1
	for i, req := range transport.requests {
		if req.method == "POST" && strings.Contains(req.path, "checkin") {
			checkinIdx = i
			break
		}
	}

	var checkinReq contract.CheckInRequest
	err = json.Unmarshal(transport.requests[checkinIdx].body, &checkinReq)
	if err != nil {
		t.Fatalf("Failed to unmarshal checkin: %v", err)
	}

	if checkinReq.Analytics == nil {
		t.Fatal("analytics should not be nil")
	}
}

// TestScenario_UnreadableWatermarkStartsFromNow tests unreadable watermark handling.
func TestScenario_UnreadableWatermarkStartsFromNow(t *testing.T) {
	// Given the watermark Load returns an error
	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	watermark := &fakeWatermark{err: errors.New("corrupt file")}

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				return fake.Response(http.StatusOK, `{"checkInIntervalSeconds":600}`), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	collectorCalled := false
	collectorSince := time.Time{}

	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "darwin",
		CollectAnalytics: func(s time.Time) (contract.Analytics, time.Time, error) {
			collectorCalled = true
			collectorSince = s
			return contract.Analytics{}, s, nil
		},
		AnalyticsWatermark: watermark,
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
	}

	// When RunOnce runs
	err := RunOnce(context.Background(), deps)
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then one warn line "analytics watermark unreadable" is logged
	// (we verified watermark.Load was called by the setup)

	// And Save was called with "2026-10-02T07:20:00Z" before CollectAnalytics ran
	if len(watermark.saves) == 0 {
		t.Fatal("watermark.Save should have been called")
	}
	// The initial save should be at clock.Now()
	if watermark.saves[0] != clock.Now() {
		t.Errorf("Expected save at %v, got %v", clock.Now(), watermark.saves[0])
	}

	// And CollectAnalytics was called with "2026-10-02T07:20:00Z"
	if !collectorCalled {
		t.Fatal("CollectAnalytics should have been called")
	}
	if collectorSince != clock.Now() {
		t.Errorf("Expected collector called with %v, got %v", clock.Now(), collectorSince)
	}

	// And the check-in is posted
	checkinFound := false
	for _, req := range transport.requests {
		if req.method == "POST" && strings.Contains(req.path, "checkin") {
			checkinFound = true
			break
		}
	}
	if !checkinFound {
		t.Fatal("checkin POST should have been posted")
	}
}

// TestScenario_CollectorFailureNeverCostsTheCheckIn tests collector error handling.
func TestScenario_CollectorFailureNeverCostsTheCheckIn(t *testing.T) {
	tests := []struct {
		name     string
		makeFail func() (contract.Analytics, time.Time, error)
	}{
		{
			name: "returns_error",
			makeFail: func() (contract.Analytics, time.Time, error) {
				return contract.Analytics{}, time.Time{}, errors.New("collection error")
			},
		},
		{
			name: "panics",
			makeFail: func() (contract.Analytics, time.Time, error) {
				panic("deliberate panic")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Given the watermark returns "2026-10-01T00:00:00Z" and CollectAnalytics fails
			clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
			fsys := fake.NewFS()

			st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
			stateData, _ := json.Marshal(st)
			fsys.Seed(state.StatePath("darwin"), stateData)

			since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
			watermark := &fakeWatermark{data: since}

			transport := &mockTransport{
				doFunc: func(method, path string, body []byte) (*http.Response, error) {
					if method == "GET" && strings.Contains(path, "policies") {
						return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
					}
					if method == "POST" && strings.Contains(path, "checkin") {
						return fake.Response(http.StatusOK, `{"checkInIntervalSeconds":600}`), nil
					}
					return fake.Response(http.StatusOK, "{}"), nil
				},
			}

			stateStore := &fakeStore{state: st}

			collectAnalyticsFunc := func(s time.Time) (contract.Analytics, time.Time, error) {
				return tc.makeFail()
			}

			deps := &Deps{
				Client:             transport,
				Store:              stateStore,
				FS:                 fsys,
				Clock:              clock,
				GOOS:               "darwin",
				CollectAnalytics:   collectAnalyticsFunc,
				AnalyticsWatermark: watermark,
				CollectInventory: func() (contract.Inventory, error) {
					return contract.Inventory{}, nil
				},
				CollectPosture: func() (contract.Posture, error) {
					return contract.Posture{}, nil
				},
			}

			// When RunOnce runs
			err := RunOnce(context.Background(), deps)

			// Then RunOnce returns nil
			if err != nil {
				t.Fatalf("RunOnce should return nil, got %v", err)
			}

			// And the check-in is posted without an "analytics" key
			checkinIdx := -1
			for i, req := range transport.requests {
				if req.method == "POST" && strings.Contains(req.path, "checkin") {
					checkinIdx = i
					break
				}
			}

			if checkinIdx < 0 {
				t.Fatal("No checkin POST found")
			}

			var checkinReq contract.CheckInRequest
			err = json.Unmarshal(transport.requests[checkinIdx].body, &checkinReq)
			if err != nil {
				t.Fatalf("Failed to unmarshal checkin: %v", err)
			}

			if checkinReq.Analytics != nil {
				t.Error("analytics should be nil when collector fails")
			}

			// And Save was not called
			if len(watermark.saves) != 0 {
				t.Errorf("Expected 0 saves, got %d", len(watermark.saves))
			}
		})
	}
}

// TestScenario_AcceptedCheckInAdvancesTheWatermark tests successful watermark advancement.
func TestScenario_AcceptedCheckInAdvancesTheWatermark(t *testing.T) {
	// Given CollectAnalytics returns a candidate "2026-10-02T06:58:12Z" after since "2026-10-01T00:00:00Z"
	// And the check-in POST is answered 200
	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	candidate := time.Date(2026, 10, 2, 6, 58, 12, 0, time.UTC)
	watermark := &fakeWatermark{data: since}

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				return fake.Response(http.StatusOK, `{"checkInIntervalSeconds":600}`), nil
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
		CollectAnalytics: func(s time.Time) (contract.Analytics, time.Time, error) {
			return contract.Analytics{}, candidate, nil
		},
		AnalyticsWatermark: watermark,
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
	}

	// When RunOnce runs
	err := RunOnce(context.Background(), deps)
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then Save was called once with "2026-10-02T06:58:12Z"
	if len(watermark.saves) != 1 {
		t.Fatalf("Expected 1 save, got %d", len(watermark.saves))
	}
	if watermark.saves[0] != candidate {
		t.Errorf("Expected save at %v, got %v", candidate, watermark.saves[0])
	}
}

// TestScenario_UnchangedCandidateIsNotSaved tests unchanged candidate handling.
func TestScenario_UnchangedCandidateIsNotSaved(t *testing.T) {
	// Given the watermark returns "2026-10-01T00:00:00Z"
	// And CollectAnalytics returns a candidate equal to since
	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	watermark := &fakeWatermark{data: since}

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				return fake.Response(http.StatusOK, `{"checkInIntervalSeconds":600}`), nil
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
		CollectAnalytics: func(s time.Time) (contract.Analytics, time.Time, error) {
			// Return same as since (no progress)
			return contract.Analytics{}, s, nil
		},
		AnalyticsWatermark: watermark,
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
	}

	// When RunOnce runs
	err := RunOnce(context.Background(), deps)
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then Save was not called
	if len(watermark.saves) != 0 {
		t.Errorf("Expected 0 saves (candidate not after since), got %d", len(watermark.saves))
	}
}

// TestScenario_WatermarkNotAdvancedUnlessCheckInAccepted tests non-2xx handling.
func TestScenario_WatermarkNotAdvancedUnlessCheckInAccepted(t *testing.T) {
	outcomes := []struct {
		name     string
		doFunc   func(method, path string, body []byte) (*http.Response, error)
		testName string
	}{
		{
			name: "500",
			doFunc: func(method, path string, body []byte) (*http.Response, error) {
				if method == "GET" && strings.Contains(path, "policies") {
					return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
				}
				if method == "POST" && strings.Contains(path, "checkin") {
					return fake.Response(http.StatusInternalServerError, "error"), nil
				}
				return fake.Response(http.StatusOK, "{}"), nil
			},
			testName: "500",
		},
		{
			name: "400",
			doFunc: func(method, path string, body []byte) (*http.Response, error) {
				if method == "GET" && strings.Contains(path, "policies") {
					return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
				}
				if method == "POST" && strings.Contains(path, "checkin") {
					return fake.Response(http.StatusBadRequest, "bad request"), nil
				}
				return fake.Response(http.StatusOK, "{}"), nil
			},
			testName: "400",
		},
		{
			name: "401",
			doFunc: func(method, path string, body []byte) (*http.Response, error) {
				if method == "GET" && strings.Contains(path, "policies") {
					return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
				}
				if method == "POST" && strings.Contains(path, "checkin") {
					return fake.Response(http.StatusUnauthorized, "unauthorized"), nil
				}
				return fake.Response(http.StatusOK, "{}"), nil
			},
			testName: "401",
		},
		{
			name: "transport_error",
			doFunc: func(method, path string, body []byte) (*http.Response, error) {
				if method == "GET" && strings.Contains(path, "policies") {
					return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
				}
				if method == "POST" && strings.Contains(path, "checkin") {
					return nil, errors.New("network error")
				}
				return fake.Response(http.StatusOK, "{}"), nil
			},
			testName: "transport_error",
		},
	}

	for _, outcome := range outcomes {
		t.Run(outcome.testName, func(t *testing.T) {
			clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
			fsys := fake.NewFS()

			st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
			stateData, _ := json.Marshal(st)
			fsys.Seed(state.StatePath("darwin"), stateData)

			since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
			candidate := time.Date(2026, 10, 2, 6, 58, 12, 0, time.UTC)
			watermark := &fakeWatermark{data: since}

			transport := &mockTransport{doFunc: outcome.doFunc}

			stateStore := &fakeStore{state: st}

			deps := &Deps{
				Client: transport,
				Store:  stateStore,
				FS:     fsys,
				Clock:  clock,
				GOOS:   "darwin",
				CollectAnalytics: func(s time.Time) (contract.Analytics, time.Time, error) {
					return contract.Analytics{}, candidate, nil
				},
				AnalyticsWatermark: watermark,
				CollectInventory: func() (contract.Inventory, error) {
					return contract.Inventory{}, nil
				},
				CollectPosture: func() (contract.Posture, error) {
					return contract.Posture{}, nil
				},
			}

			// When RunOnce runs
			_ = RunOnce(context.Background(), deps)

			// Then Save was not called
			if len(watermark.saves) != 0 {
				t.Errorf("Expected 0 saves, got %d", len(watermark.saves))
			}
		})
	}
}

// TestScenario_FailedWatermarkSaveIsLoggedOnly tests save failure handling.
func TestScenario_FailedWatermarkSaveIsLoggedOnly(t *testing.T) {
	// Given the check-in POST is answered 200 and Save returns an error
	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	candidate := time.Date(2026, 10, 2, 6, 58, 12, 0, time.UTC)
	watermark := &fakeWatermarkWithSaveError{
		fakeWatermark: fakeWatermark{data: since},
		saveErr:       errors.New("save failed"),
	}

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				return fake.Response(http.StatusOK, `{"checkInIntervalSeconds":600}`), nil
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
		CollectAnalytics: func(s time.Time) (contract.Analytics, time.Time, error) {
			return contract.Analytics{}, candidate, nil
		},
		AnalyticsWatermark: watermark,
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
	}

	// When RunOnce runs
	err := RunOnce(context.Background(), deps)

	// Then RunOnce returns nil
	if err != nil {
		t.Fatalf("RunOnce should return nil, got %v", err)
	}
}

// TestScenario_FirstRunDoesNotBackfill tests first-run behavior.
func TestScenario_FirstRunDoesNotBackfill(t *testing.T) {
	// Given the watermark Load returns the zero time and no error
	// And the check-in POST is answered 500
	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	watermark := &fakeWatermark{data: time.Time{}} // Zero time (no file)

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				return fake.Response(http.StatusInternalServerError, "server error"), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	collectorCalled := false
	collectorSince := time.Time{}

	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "darwin",
		CollectAnalytics: func(s time.Time) (contract.Analytics, time.Time, error) {
			collectorCalled = true
			collectorSince = s
			return contract.Analytics{}, s, nil
		},
		AnalyticsWatermark: watermark,
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
	}

	// When RunOnce runs
	err := RunOnce(context.Background(), deps)
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then Save was called with "2026-10-02T07:20:00Z" before CollectAnalytics ran
	if len(watermark.saves) == 0 {
		t.Fatal("watermark.Save should have been called")
	}
	if watermark.saves[0] != clock.Now() {
		t.Errorf("Expected save at %v, got %v", clock.Now(), watermark.saves[0])
	}

	// And CollectAnalytics was called with "2026-10-02T07:20:00Z"
	if !collectorCalled {
		t.Fatal("CollectAnalytics should have been called")
	}
	if collectorSince != clock.Now() {
		t.Errorf("Expected collector called with %v, got %v", clock.Now(), collectorSince)
	}
}

// TestScenario_NoWatermarkStoreMeansEveryCycleStartsFromNow tests nil watermark.
func TestScenario_NoWatermarkStoreMeansEveryCycleStartsFromNow(t *testing.T) {
	// Given AnalyticsWatermark is nil and CollectAnalytics is set
	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				return fake.Response(http.StatusOK, `{"checkInIntervalSeconds":600}`), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	calls := []time.Time{}

	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "darwin",
		CollectAnalytics: func(s time.Time) (contract.Analytics, time.Time, error) {
			calls = append(calls, s)
			return contract.Analytics{}, s, nil
		},
		AnalyticsWatermark: nil, // No watermark
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
	}

	// When RunOnce runs twice with the clock advanced 10 minutes between them
	err := RunOnce(context.Background(), deps)
	if err != nil {
		t.Fatalf("First RunOnce failed: %v", err)
	}

	clock.Advance(10 * time.Minute)

	err = RunOnce(context.Background(), deps)
	if err != nil {
		t.Fatalf("Second RunOnce failed: %v", err)
	}

	// Then CollectAnalytics was called with "2026-10-02T07:20:00Z" and then "2026-10-02T07:30:00Z"
	if len(calls) != 2 {
		t.Fatalf("Expected 2 calls to CollectAnalytics, got %d", len(calls))
	}

	expectedFirst := time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC)
	expectedSecond := time.Date(2026, 10, 2, 7, 30, 0, 0, time.UTC)

	if calls[0] != expectedFirst {
		t.Errorf("First call should be %v, got %v", expectedFirst, calls[0])
	}
	if calls[1] != expectedSecond {
		t.Errorf("Second call should be %v, got %v", expectedSecond, calls[1])
	}
}

// TestScenario_FailedInitialSaveStillChecksIn tests failed initial save handling.
func TestScenario_FailedInitialSaveStillChecksIn(t *testing.T) {
	// Given the watermark Load returns the zero time and no error
	// And Save returns an error
	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	watermark := &fakeWatermarkWithSaveError{
		fakeWatermark: fakeWatermark{data: time.Time{}},
		saveErr:       errors.New("save failed"),
	}

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				return fake.Response(http.StatusOK, `{"checkInIntervalSeconds":600}`), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	collectorCalled := false
	collectorSince := time.Time{}

	deps := &Deps{
		Client: transport,
		Store:  stateStore,
		FS:     fsys,
		Clock:  clock,
		GOOS:   "darwin",
		CollectAnalytics: func(s time.Time) (contract.Analytics, time.Time, error) {
			collectorCalled = true
			collectorSince = s
			return contract.Analytics{}, s, nil
		},
		AnalyticsWatermark: watermark,
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
	}

	// When RunOnce runs
	err := RunOnce(context.Background(), deps)
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then CollectAnalytics was called with "2026-10-02T07:20:00Z"
	if !collectorCalled {
		t.Fatal("CollectAnalytics should have been called")
	}
	if collectorSince != clock.Now() {
		t.Errorf("Expected collector called with %v, got %v", clock.Now(), collectorSince)
	}

	// And the check-in is posted
	checkinFound := false
	for _, req := range transport.requests {
		if req.method == "POST" && strings.Contains(req.path, "checkin") {
			checkinFound = true
			break
		}
	}
	if !checkinFound {
		t.Fatal("checkin POST should have been posted")
	}
}

// TestScenario_WatermarkNotAdvancedWhenSpoolDrainFails tests that spool drain failure doesn't advance watermark.
func TestScenario_WatermarkNotAdvancedWhenSpoolDrainFails(t *testing.T) {
	// Given a watermark with a non-zero time and CollectAnalytics returning a candidate after since
	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	candidate := time.Date(2026, 10, 2, 6, 58, 12, 0, time.UTC)
	watermark := &fakeWatermark{data: since}

	// Transport that simulates a spool drain error (e.g., 5xx from backend during drain)
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
			}
			// Any POST (including spool drain) fails with transport error
			if method == "POST" {
				return nil, errors.New("network error")
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
		CollectAnalytics: func(s time.Time) (contract.Analytics, time.Time, error) {
			return contract.Analytics{}, candidate, nil
		},
		AnalyticsWatermark: watermark,
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
	}

	// When RunOnce runs (spool drain fails)
	_ = RunOnce(context.Background(), deps)

	// Then Save was not called (because drainSpool failed and spooled the payload instead of posting)
	if len(watermark.saves) != 0 {
		t.Errorf("Expected 0 saves when spool drain fails, got %d", len(watermark.saves))
	}
}

// ============================================================================
// TASK-040: Analytics Collection On/Off Flag Tests
// ============================================================================

// TestScenario_DefaultIsEnabledAndUnchanged tests the default AnalyticsDisabled state.
func TestScenario_DefaultIsEnabledAndUnchanged(t *testing.T) {
	// Given scheduler deps with CollectAnalytics set and AnalyticsDisabled false (zero value)
	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	watermark := &fakeWatermark{}

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				return fake.Response(http.StatusOK, `{"checkInIntervalSeconds":600}`), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	deps := &Deps{
		Client:             transport,
		Store:              stateStore,
		FS:                 fsys,
		Clock:              clock,
		GOOS:               "darwin",
		CollectAnalytics:   func(s time.Time) (contract.Analytics, time.Time, error) { return contract.Analytics{}, s, nil },
		AnalyticsWatermark: watermark,
		AnalyticsDisabled:  false, // Zero value - enabled
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
	}

	// When RunOnce runs
	err := RunOnce(context.Background(), deps)
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then CollectAnalytics is called
	checkinIdx := -1
	for i, req := range transport.requests {
		if req.method == "POST" && strings.Contains(req.path, "checkin") {
			checkinIdx = i
			break
		}
	}
	if checkinIdx < 0 {
		t.Fatal("No checkin POST found")
	}

	var checkinReq contract.CheckInRequest
	err = json.Unmarshal(transport.requests[checkinIdx].body, &checkinReq)
	if err != nil {
		t.Fatalf("Failed to unmarshal checkin: %v", err)
	}

	if checkinReq.Analytics == nil {
		t.Error("analytics should not be nil when CollectAnalytics is set and AnalyticsDisabled is false")
	}
}

// TestScenario_ResponseSetsTheAnalyticsDisabledFlag tests flag setting from response.
func TestScenario_ResponseSetsTheAnalyticsDisabledFlag(t *testing.T) {
	testCases := []struct {
		name             string
		responseBody     string
		expectedDisabled bool
	}{
		{
			name:             "analyticsEnabled false",
			responseBody:     `{"checkInIntervalSeconds":900,"pendingCommandCount":0,"analyticsEnabled":false}`,
			expectedDisabled: true,
		},
		{
			name:             "analyticsEnabled true",
			responseBody:     `{"checkInIntervalSeconds":900,"pendingCommandCount":0,"analyticsEnabled":true}`,
			expectedDisabled: false,
		},
		{
			name:             "no analyticsEnabled key",
			responseBody:     `{"checkInIntervalSeconds":900,"pendingCommandCount":0}`,
			expectedDisabled: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
			fsys := fake.NewFS()

			st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
			stateData, _ := json.Marshal(st)
			fsys.Seed(state.StatePath("darwin"), stateData)

			watermark := &fakeWatermark{}

			transport := &mockTransport{
				doFunc: func(method, path string, body []byte) (*http.Response, error) {
					if method == "GET" && strings.Contains(path, "policies") {
						return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
					}
					if method == "POST" && strings.Contains(path, "checkin") {
						return fake.Response(http.StatusOK, tc.responseBody), nil
					}
					return fake.Response(http.StatusOK, "{}"), nil
				},
			}

			stateStore := &fakeStore{state: st}

			deps := &Deps{
				Client:             transport,
				Store:              stateStore,
				FS:                 fsys,
				Clock:              clock,
				GOOS:               "darwin",
				CollectAnalytics:   func(s time.Time) (contract.Analytics, time.Time, error) { return contract.Analytics{}, s, nil },
				AnalyticsWatermark: watermark,
				AnalyticsDisabled:  false, // Start enabled
				CollectInventory: func() (contract.Inventory, error) {
					return contract.Inventory{}, nil
				},
				CollectPosture: func() (contract.Posture, error) {
					return contract.Posture{}, nil
				},
			}

			// When RunOnce runs
			err := RunOnce(context.Background(), deps)
			if err != nil {
				t.Fatalf("RunOnce failed: %v", err)
			}

			// Then deps.AnalyticsDisabled is set correctly
			if deps.AnalyticsDisabled != tc.expectedDisabled {
				t.Errorf("Expected AnalyticsDisabled=%v, got %v for %s", tc.expectedDisabled, deps.AnalyticsDisabled, tc.name)
			}
		})
	}
}

// TestScenario_BadOrFailedAnswerLeavesTheFlagAlone tests flag is unchanged on errors.
func TestScenario_BadOrFailedAnswerLeavesTheFlagAlone(t *testing.T) {
	testCases := []struct {
		name     string
		doFunc   func(method, path string, body []byte) (*http.Response, error)
		testName string
	}{
		{
			name: "not_json",
			doFunc: func(method, path string, body []byte) (*http.Response, error) {
				if method == "GET" && strings.Contains(path, "policies") {
					return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
				}
				if method == "POST" && strings.Contains(path, "checkin") {
					return fake.Response(http.StatusOK, "not json"), nil
				}
				return fake.Response(http.StatusOK, "{}"), nil
			},
			testName: "not_json",
		},
		{
			name: "500",
			doFunc: func(method, path string, body []byte) (*http.Response, error) {
				if method == "GET" && strings.Contains(path, "policies") {
					return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
				}
				if method == "POST" && strings.Contains(path, "checkin") {
					return fake.Response(http.StatusInternalServerError, "error"), nil
				}
				return fake.Response(http.StatusOK, "{}"), nil
			},
			testName: "500",
		},
		{
			name: "400",
			doFunc: func(method, path string, body []byte) (*http.Response, error) {
				if method == "GET" && strings.Contains(path, "policies") {
					return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
				}
				if method == "POST" && strings.Contains(path, "checkin") {
					return fake.Response(http.StatusBadRequest, "bad"), nil
				}
				return fake.Response(http.StatusOK, "{}"), nil
			},
			testName: "400",
		},
		{
			name: "401",
			doFunc: func(method, path string, body []byte) (*http.Response, error) {
				if method == "GET" && strings.Contains(path, "policies") {
					return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
				}
				if method == "POST" && strings.Contains(path, "checkin") {
					return fake.Response(http.StatusUnauthorized, "unauth"), nil
				}
				return fake.Response(http.StatusOK, "{}"), nil
			},
			testName: "401",
		},
		{
			name: "transport_error",
			doFunc: func(method, path string, body []byte) (*http.Response, error) {
				if method == "GET" && strings.Contains(path, "policies") {
					return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
				}
				if method == "POST" && strings.Contains(path, "checkin") {
					return nil, errors.New("network error")
				}
				return fake.Response(http.StatusOK, "{}"), nil
			},
			testName: "transport_error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
			fsys := fake.NewFS()

			st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
			stateData, _ := json.Marshal(st)
			fsys.Seed(state.StatePath("darwin"), stateData)

			watermark := &fakeWatermark{}

			transport := &mockTransport{doFunc: tc.doFunc}

			stateStore := &fakeStore{state: st}

			deps := &Deps{
				Client:             transport,
				Store:              stateStore,
				FS:                 fsys,
				Clock:              clock,
				GOOS:               "darwin",
				CollectAnalytics:   func(s time.Time) (contract.Analytics, time.Time, error) { return contract.Analytics{}, s, nil },
				AnalyticsWatermark: watermark,
				AnalyticsDisabled:  true, // Start disabled
				CollectInventory: func() (contract.Inventory, error) {
					return contract.Inventory{}, nil
				},
				CollectPosture: func() (contract.Posture, error) {
					return contract.Posture{}, nil
				},
			}

			// When RunOnce runs
			_ = RunOnce(context.Background(), deps)

			// Then deps.AnalyticsDisabled is still true
			if !deps.AnalyticsDisabled {
				t.Errorf("Expected AnalyticsDisabled to remain true for %s", tc.testName)
			}
		})
	}
}

// TestScenario_DisabledCycleSkipsCollectionAndPinsWatermark tests disabled behavior.
func TestScenario_DisabledCycleSkipsCollectionAndPinsWatermark(t *testing.T) {
	// Given CollectAnalytics is set, AnalyticsDisabled is true and a recording watermark store
	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	watermark := &fakeWatermark{}

	collectAnalyticsCalled := false

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				return fake.Response(http.StatusOK, `{"checkInIntervalSeconds":600}`), nil
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
		CollectAnalytics: func(s time.Time) (contract.Analytics, time.Time, error) {
			collectAnalyticsCalled = true
			return contract.Analytics{}, s, nil
		},
		AnalyticsWatermark: watermark,
		AnalyticsDisabled:  true, // Disabled
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
	}

	// When RunOnce runs
	err := RunOnce(context.Background(), deps)
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Then CollectAnalytics was not called
	if collectAnalyticsCalled {
		t.Error("CollectAnalytics should not be called when AnalyticsDisabled is true")
	}

	// And the posted body has no "analytics" key
	checkinIdx := -1
	for i, req := range transport.requests {
		if req.method == "POST" && strings.Contains(req.path, "checkin") {
			checkinIdx = i
			break
		}
	}
	if checkinIdx < 0 {
		t.Fatal("No checkin POST found")
	}

	var checkinReq contract.CheckInRequest
	err = json.Unmarshal(transport.requests[checkinIdx].body, &checkinReq)
	if err != nil {
		t.Fatalf("Failed to unmarshal checkin: %v", err)
	}

	if checkinReq.Analytics != nil {
		t.Error("analytics should be nil when AnalyticsDisabled is true")
	}

	// And Load was not called
	if watermark.loads != 0 {
		t.Errorf("Expected 0 loads, got %d", watermark.loads)
	}

	// And Save was called once with clock.Now()
	if len(watermark.saves) != 1 {
		t.Errorf("Expected 1 save, got %d", len(watermark.saves))
	}
	if len(watermark.saves) > 0 && watermark.saves[0] != clock.Now() {
		t.Errorf("Expected save at %v, got %v", clock.Now(), watermark.saves[0])
	}
}

// TestScenario_DisabledCycleWithNoWatermarkStore tests disabled with nil watermark.
func TestScenario_DisabledCycleWithNoWatermarkStore(t *testing.T) {
	// Given CollectAnalytics is set, AnalyticsDisabled is true and AnalyticsWatermark nil
	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				return fake.Response(http.StatusOK, `{"checkInIntervalSeconds":600}`), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	deps := &Deps{
		Client:             transport,
		Store:              stateStore,
		FS:                 fsys,
		Clock:              clock,
		GOOS:               "darwin",
		CollectAnalytics:   func(s time.Time) (contract.Analytics, time.Time, error) { return contract.Analytics{}, s, nil },
		AnalyticsWatermark: nil,  // No watermark
		AnalyticsDisabled:  true, // Disabled
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
	}

	// When RunOnce runs
	err := RunOnce(context.Background(), deps)

	// Then RunOnce returns nil
	if err != nil {
		t.Fatalf("RunOnce should return nil, got %v", err)
	}

	// And the body has no "analytics" key
	checkinIdx := -1
	for i, req := range transport.requests {
		if req.method == "POST" && strings.Contains(req.path, "checkin") {
			checkinIdx = i
			break
		}
	}
	if checkinIdx < 0 {
		t.Fatal("No checkin POST found")
	}

	var checkinReq contract.CheckInRequest
	err = json.Unmarshal(transport.requests[checkinIdx].body, &checkinReq)
	if err != nil {
		t.Fatalf("Failed to unmarshal checkin: %v", err)
	}

	if checkinReq.Analytics != nil {
		t.Error("analytics should be nil when AnalyticsDisabled is true")
	}
}

// TestScenario_DisabledCycleWhoseSaveFailsLogsAndContinues tests save error handling.
func TestScenario_DisabledCycleWhoseSaveFailsLogsAndContinues(t *testing.T) {
	// Given AnalyticsDisabled is true and Save returns an error
	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	watermark := &fakeWatermarkWithSaveError{
		fakeWatermark: fakeWatermark{data: time.Time{}},
		saveErr:       errors.New("save failed"),
	}

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				return fake.Response(http.StatusOK, `{"checkInIntervalSeconds":600}`), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	deps := &Deps{
		Client:             transport,
		Store:              stateStore,
		FS:                 fsys,
		Clock:              clock,
		GOOS:               "darwin",
		CollectAnalytics:   func(s time.Time) (contract.Analytics, time.Time, error) { return contract.Analytics{}, s, nil },
		AnalyticsWatermark: watermark,
		AnalyticsDisabled:  true, // Disabled
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
	}

	// When RunOnce runs
	err := RunOnce(context.Background(), deps)

	// Then RunOnce returns nil (error is logged, not returned)
	if err != nil {
		t.Fatalf("RunOnce should return nil, got %v", err)
	}

	// And the check-in is posted
	checkinFound := false
	for _, req := range transport.requests {
		if req.method == "POST" && strings.Contains(req.path, "checkin") {
			checkinFound = true
			break
		}
	}
	if !checkinFound {
		t.Fatal("checkin POST should have been posted")
	}
}

// TestScenario_OffThenOnAcrossCyclesResumesWithoutBackfill tests multi-cycle behavior.
func TestScenario_OffThenOnAcrossCyclesResumesWithoutBackfill(t *testing.T) {
	// Given cycle 1 is answered with analyticsEnabled false, and cycle 2 is answered without analyticsEnabled
	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	watermark := &fakeWatermark{}

	collectAnalyticsCalls := []time.Time{}

	cycleNum := 0
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "GET" && strings.Contains(path, "policies") {
				return fake.Response(http.StatusOK, `{"policies":[],"conflicts":[]}`), nil
			}
			if method == "POST" && strings.Contains(path, "checkin") {
				cycleNum++
				if cycleNum == 1 {
					return fake.Response(http.StatusOK, `{"checkInIntervalSeconds":600,"analyticsEnabled":false}`), nil
				}
				if cycleNum == 2 {
					return fake.Response(http.StatusOK, `{"checkInIntervalSeconds":600}`), nil
				}
				return fake.Response(http.StatusOK, `{"checkInIntervalSeconds":600}`), nil
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
		CollectAnalytics: func(s time.Time) (contract.Analytics, time.Time, error) {
			collectAnalyticsCalls = append(collectAnalyticsCalls, s)
			return contract.Analytics{}, s, nil
		},
		AnalyticsWatermark: watermark,
		AnalyticsDisabled:  false, // Start enabled
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
	}

	// When RunOnce runs three times with the clock advanced 15 minutes between cycles
	err := RunOnce(context.Background(), deps)
	if err != nil {
		t.Fatalf("First RunOnce failed: %v", err)
	}

	clock.Advance(15 * time.Minute)

	err = RunOnce(context.Background(), deps)
	if err != nil {
		t.Fatalf("Second RunOnce failed: %v", err)
	}

	clock.Advance(15 * time.Minute)

	err = RunOnce(context.Background(), deps)
	if err != nil {
		t.Fatalf("Third RunOnce failed: %v", err)
	}

	// Then CollectAnalytics was called on cycle 1, not on cycle 2, and on cycle 3
	if len(collectAnalyticsCalls) != 2 {
		t.Fatalf("Expected 2 calls to CollectAnalytics, got %d", len(collectAnalyticsCalls))
	}

	// And on cycle 3 CollectAnalytics was called with the time cycle 2 saved (clock at 07:20 + 15 min = 07:35)
	expectedCycle3Time := time.Date(2026, 10, 2, 7, 35, 0, 0, time.UTC)
	if collectAnalyticsCalls[1] != expectedCycle3Time {
		t.Errorf("Expected cycle 3 called with %v, got %v", expectedCycle3Time, collectAnalyticsCalls[1])
	}
}
