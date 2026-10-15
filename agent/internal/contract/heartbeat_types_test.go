// E2E cucumber-style tests for TASK-044's heartbeat contract types (AC3):
// CheckInResponse.HeartbeatIntervalSeconds is a nil-omitted pointer, and
// HeartbeatRequest/HeartbeatResponse carry the documented fields and tags.
package contract

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestScenario_CheckInResponseHeartbeatIntervalSecondsNilMarshalling verifies
// that a nil HeartbeatIntervalSeconds produces no key, and a set one produces
// the documented key and value.
func TestScenario_CheckInResponseHeartbeatIntervalSecondsNilMarshalling(t *testing.T) {
	// Given a CheckInResponse with HeartbeatIntervalSeconds == nil
	resp := CheckInResponse{CheckInIntervalSeconds: 900, PendingCommandCount: 0}

	// When it is marshalled
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Then the JSON has no "heartbeatIntervalSeconds" key
	if strings.Contains(string(data), "heartbeatIntervalSeconds") {
		t.Errorf("nil HeartbeatIntervalSeconds should be omitted, got %s", data)
	}

	// And when HeartbeatIntervalSeconds is set
	seconds := 300
	respOn := CheckInResponse{CheckInIntervalSeconds: 900, PendingCommandCount: 0, HeartbeatIntervalSeconds: &seconds}
	dataOn, err := json.Marshal(respOn)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if !strings.Contains(string(dataOn), `"heartbeatIntervalSeconds":300`) {
		t.Errorf(`expected "heartbeatIntervalSeconds":300, got %s`, dataOn)
	}
}

// TestScenario_HeartbeatRequestRoundTrips verifies HeartbeatRequest's fields
// and that Warnings is omitted when empty.
func TestScenario_HeartbeatRequestRoundTrips(t *testing.T) {
	req := HeartbeatRequest{
		CollectedAt: "2026-10-11T11:59:58Z",
		Performance: AnalyticsPerformance{},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if strings.Contains(string(data), "warnings") {
		t.Errorf("empty Warnings should be omitted, got %s", data)
	}

	var decoded HeartbeatRequest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&decoded); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decoded.CollectedAt != req.CollectedAt {
		t.Errorf("CollectedAt = %q, want %q", decoded.CollectedAt, req.CollectedAt)
	}

	withWarnings := HeartbeatRequest{CollectedAt: "2026-10-11T11:59:58Z", Performance: AnalyticsPerformance{}, Warnings: []string{"performance"}}
	data2, err := json.Marshal(withWarnings)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if !strings.Contains(string(data2), `"warnings":["performance"]`) {
		t.Errorf(`expected warnings key, got %s`, data2)
	}
}

// TestScenario_HeartbeatResponseRoundTrips verifies HeartbeatResponse's
// required field.
func TestScenario_HeartbeatResponseRoundTrips(t *testing.T) {
	resp := HeartbeatResponse{HeartbeatIntervalSeconds: 0}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if string(data) != `{"heartbeatIntervalSeconds":0}` {
		t.Errorf("got %s, want {\"heartbeatIntervalSeconds\":0}", data)
	}
}
