package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

// TestUnit_EnrollPathConstant validates the enrollment path constant.
func TestUnit_EnrollPathConstant(t *testing.T) {
	if EnrollPath != "/api/v1/enroll" {
		t.Errorf("EnrollPath = %q, expected %q", EnrollPath, "/api/v1/enroll")
	}
}

// TestUnit_MaxEnrollAttemptsConstant validates the max attempts constant.
func TestUnit_MaxEnrollAttemptsConstant(t *testing.T) {
	if MaxEnrollAttempts != 6 {
		t.Errorf("MaxEnrollAttempts = %d, expected 6", MaxEnrollAttempts)
	}
}

// TestUnit_PlatformNameMapping validates the PlatformName function.
func TestUnit_PlatformNameMapping(t *testing.T) {
	tests := []struct {
		goos     string
		expected string
	}{
		{"windows", "windows"},
		{"darwin", "darwin"},
		{"linux", "darwin"},
		{"", "darwin"},
		{"freebsd", "darwin"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("goos=%s", tt.goos), func(t *testing.T) {
			result := PlatformName(tt.goos)
			if result != tt.expected {
				t.Errorf("PlatformName(%q) = %q, expected %q", tt.goos, result, tt.expected)
			}
		})
	}
}

// TestUnit_HostFactsDefaults validates that HostFacts apply defaults correctly.
func TestUnit_HostFactsDefaults(t *testing.T) {
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, "state.json")

	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		var enrollReq contract.EnrollRequest
		json.Unmarshal(body, &enrollReq)

		// Platform should default to PlatformName(runtime.GOOS) if empty
		if enrollReq.Platform == "" {
			t.Error("Platform should be set to default")
		}

		// AgentVersion should be set to version.Version if empty
		if enrollReq.AgentVersion == "" {
			t.Error("AgentVersion should be set to default")
		}

		// Return success
		resp := contract.EnrollResponse{
			DeviceID:               "d1",
			DeviceSecret:           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			CheckInIntervalSeconds: 900,
		}
		data, _ := json.Marshal(resp)
		return fake.Response(http.StatusOK, string(data)), nil
	}

	client := New(cfg, store, doer, clock)
	client.Host = HostFacts{
		Hostname:     "test-host",
		OSVersion:    "10.0",
		HardwareUUID: "uuid-123",
		// Platform and AgentVersion are intentionally empty to test defaults
	}

	err := client.Enroll(context.Background())
	if err != nil {
		t.Errorf("Enroll failed: %v", err)
	}
}

// TestUnit_EnrollFailsOnTransportError validates that transport errors are retryable.
func TestUnit_EnrollFailsOnTransportError(t *testing.T) {
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	clock.AutoAdvance = true
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, "state.json")

	// Always fail with a network error
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	}

	client := New(cfg, store, doer, clock)

	err := client.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "enrollment failed after 6 attempts") {
		t.Errorf("error should contain 'enrollment failed after 6 attempts', got %q", err.Error())
	}

	// Should have attempted 6 times
	if len(doer.Requests()) != 6 {
		t.Errorf("expected 6 requests, got %d", len(doer.Requests()))
	}
}

// TestUnit_Enroll5xxIsRetryable validates that 5xx errors are retried.
func TestUnit_Enroll5xxIsRetryable(t *testing.T) {
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	clock.AutoAdvance = true
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, "state.json")

	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return fake.Response(http.StatusServiceUnavailable, `{"error":"service_down"}`), nil
	}

	client := New(cfg, store, doer, clock)

	err := client.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Should have attempted 6 times
	if len(doer.Requests()) != 6 {
		t.Errorf("expected 6 requests, got %d", len(doer.Requests()))
	}
}

// TestUnit_Enroll4xxIsNotRetryable validates that 4xx errors are NOT retried (except 429).
func TestUnit_Enroll4xxIsNotRetryable(t *testing.T) {
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, "state.json")

	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return fake.Response(http.StatusBadRequest, `{"error":"bad_request"}`), nil
	}

	client := New(cfg, store, doer, clock)

	err := client.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "enrollment refused") {
		t.Errorf("error should contain 'enrollment refused', got %q", err.Error())
	}

	// Should NOT retry: only 1 attempt
	if len(doer.Requests()) != 1 {
		t.Errorf("expected 1 request, got %d", len(doer.Requests()))
	}
}

// TestUnit_EnrollResponseMissingFields validates that missing deviceId or deviceSecret fails.
func TestUnit_EnrollResponseMissingFields(t *testing.T) {
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	clock.AutoAdvance = true
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, "state.json")

	// Missing deviceSecret
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return fake.Response(http.StatusOK, `{"deviceId":"d1"}`), nil
	}

	client := New(cfg, store, doer, clock)

	err := client.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error for missing deviceSecret, got nil")
	}
	if !strings.Contains(err.Error(), "missing deviceId or deviceSecret") {
		t.Errorf("error should contain 'missing deviceId or deviceSecret', got %q", err.Error())
	}
}

// TestUnit_EnrollResponseInvalidJSON fails gracefully.
func TestUnit_EnrollResponseInvalidJSON(t *testing.T) {
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	clock.AutoAdvance = true
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, "state.json")

	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return fake.Response(http.StatusOK, `{invalid json`), nil
	}

	client := New(cfg, store, doer, clock)

	err := client.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "enrollment response") {
		t.Errorf("error should contain 'enrollment response', got %q", err.Error())
	}
}

// TestUnit_EnrollContextCancellation validates that cancelled context stops retries.
func TestUnit_EnrollContextCancellation(t *testing.T) {
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, "state.json")

	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return fake.Response(http.StatusServiceUnavailable, `{"error":"server_down"}`), nil
	}

	client := New(cfg, store, doer, clock)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := client.Enroll(ctx)
	if err == nil {
		t.Fatal("expected context cancellation error, got nil")
	}
}

// TestUnit_EnrollSetsCheckInInterval validates that CheckInIntervalSeconds is set after enroll.
func TestUnit_EnrollSetsCheckInInterval(t *testing.T) {
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, "state.json")

	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		resp := contract.EnrollResponse{
			DeviceID:               "d1",
			DeviceSecret:           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			CheckInIntervalSeconds: 1800,
		}
		data, _ := json.Marshal(resp)
		return fake.Response(http.StatusOK, string(data)), nil
	}

	client := New(cfg, store, doer, clock)

	err := client.Enroll(context.Background())
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}

	if client.CheckInIntervalSeconds() != 1800 {
		t.Errorf("CheckInIntervalSeconds = %d, expected 1800", client.CheckInIntervalSeconds())
	}
}

// TestUnit_ErrorSuffixExtraction validates error code extraction from response.
func TestUnit_ErrorSuffixExtraction(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "with error code",
			input:    `{"error":"invalid_token"}`,
			expected: " (invalid_token)",
		},
		{
			name:     "error with the offending fields",
			input:    `{"error":"invalid_request","fields":["osVersion","hardwareUuid"]}`,
			expected: " (invalid_request: osVersion, hardwareUuid)",
		},
		{
			name:     "empty error",
			input:    `{"error":""}`,
			expected: "",
		},
		{
			name:     "no error field",
			input:    `{"message":"error"}`,
			expected: "",
		},
		{
			name:     "malformed JSON",
			input:    `{invalid}`,
			expected: "",
		},
		{
			name:     "empty string",
			input:    ``,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := errorSuffix([]byte(tt.input))
			if result != tt.expected {
				t.Errorf("errorSuffix(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestUnit_EnrollRequestStructure validates the EnrollRequest struct is properly formatted.
func TestUnit_EnrollRequestStructure(t *testing.T) {
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, "state.json")

	var capturedBody []byte
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		capturedBody, _ = io.ReadAll(req.Body)

		resp := contract.EnrollResponse{
			DeviceID:               "d1",
			DeviceSecret:           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			CheckInIntervalSeconds: 900,
		}
		data, _ := json.Marshal(resp)
		return fake.Response(http.StatusOK, string(data)), nil
	}

	client := New(cfg, store, doer, clock)
	client.Host = HostFacts{
		Hostname:     "test-host",
		Platform:     "windows",
		OSVersion:    "10.0.22631",
		HardwareUUID: "uuid-12345",
		AgentVersion: "1.0.0",
	}

	err := client.Enroll(context.Background())
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}

	// Validate the body structure
	var req contract.EnrollRequest
	if err := json.Unmarshal(capturedBody, &req); err != nil {
		t.Fatalf("failed to unmarshal body: %v", err)
	}

	if req.Hostname != "test-host" {
		t.Errorf("Hostname = %q, expected %q", req.Hostname, "test-host")
	}
	if req.Platform != "windows" {
		t.Errorf("Platform = %q, expected %q", req.Platform, "windows")
	}
	if req.OSVersion != "10.0.22631" {
		t.Errorf("OSVersion = %q, expected %q", req.OSVersion, "10.0.22631")
	}
	if req.HardwareUUID != "uuid-12345" {
		t.Errorf("HardwareUUID = %q, expected %q", req.HardwareUUID, "uuid-12345")
	}
	if req.AgentVersion != "1.0.0" {
		t.Errorf("AgentVersion = %q, expected %q", req.AgentVersion, "1.0.0")
	}
}

// TestUnit_DoRejectsEmptyDeviceSecret validates that empty secret triggers ErrNotEnrolled.
func TestUnit_DoRejectsEmptyDeviceSecret(t *testing.T) {
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, "state.json")

	// State with device ID but empty secret
	stateData := state.State{
		DeviceID:     "d1",
		DeviceSecret: "", // Empty
	}
	stateJSON, _ := json.MarshalIndent(stateData, "", "  ")
	fsys.Seed("state.json", append(stateJSON, '\n'))

	client := New(cfg, store, doer, clock)

	_, err := client.Do("GET", "/api/v1/test", nil)
	if !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("expected ErrNotEnrolled, got %v", err)
	}
}

// TestUnit_DoRejectsEmptyDeviceID validates that empty device ID triggers ErrNotEnrolled.
func TestUnit_DoRejectsEmptyDeviceID(t *testing.T) {
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, "state.json")

	// State with empty device ID
	stateData := state.State{
		DeviceID:     "", // Empty
		DeviceSecret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	stateJSON, _ := json.MarshalIndent(stateData, "", "  ")
	fsys.Seed("state.json", append(stateJSON, '\n'))

	client := New(cfg, store, doer, clock)

	_, err := client.Do("GET", "/api/v1/test", nil)
	if !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("expected ErrNotEnrolled, got %v", err)
	}
}

// TestUnit_CheckInIntervalSecondsDefaultsToZero validates the getter.
func TestUnit_CheckInIntervalSecondsDefaultsToZero(t *testing.T) {
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, "state.json")

	client := New(cfg, store, doer, clock)

	if client.CheckInIntervalSeconds() != 0 {
		t.Errorf("CheckInIntervalSeconds() = %d, expected 0", client.CheckInIntervalSeconds())
	}
}

// TestUnit_EnrollToNonHTTPSURL validates that non-HTTPS fails.
func TestUnit_EnrollToNonHTTPSURL(t *testing.T) {
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "http://api.example.com", // HTTP not HTTPS
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, "state.json")

	client := New(cfg, store, doer, clock)

	err := client.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error for non-HTTPS, got nil")
	}
	if !strings.Contains(err.Error(), "insecure transport refused") {
		t.Errorf("error should contain 'insecure transport refused', got %q", err.Error())
	}
}

// TestUnit_LoggerOptional validates that client works without logger.
func TestUnit_LoggerOptional(t *testing.T) {
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, "state.json")

	stateData := state.State{
		DeviceID:     "d1",
		DeviceSecret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	stateJSON, _ := json.MarshalIndent(stateData, "", "  ")
	fsys.Seed("state.json", append(stateJSON, '\n'))

	client := New(cfg, store, doer, clock)
	// Logger is nil by default

	_, err := client.Do("GET", "/api/v1/test", nil)
	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}
}
