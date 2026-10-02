package client

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

const stateFilePath = "state.json"
const enrollmentTokenValue = "0123456789abcdef.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestScenario_RequestsCarryFourSignedHeaders validates that Do sends the four required signed headers.
func TestScenario_RequestsCarryFourSignedHeaders(t *testing.T) {
	// Given
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1764633600, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, stateFilePath)

	// Seed state with enrolled device
	stateData := state.State{
		DeviceID:     "d1",
		DeviceSecret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	stateJSON, _ := json.MarshalIndent(stateData, "", "  ")
	fsys.Seed(stateFilePath, append(stateJSON, '\n'))

	client := New(cfg, store, doer, clock)

	// When
	_, err := client.Do("GET", "/api/v1/test", nil)

	// Then
	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}

	reqs := doer.Requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	req := reqs[0]

	// Check headers exist and have correct format
	if req.Header.Get(HeaderDeviceID) == "" {
		t.Error("missing X-MDM-Device-Id header")
	}
	if req.Header.Get(HeaderTimestamp) == "" {
		t.Error("missing X-MDM-Timestamp header")
	}
	if req.Header.Get(HeaderNonce) == "" {
		t.Error("missing X-MDM-Nonce header")
	}
	sig := req.Header.Get(HeaderSignature)
	if sig == "" {
		t.Error("missing X-MDM-Signature header")
	}
	if !strings.HasPrefix(sig, "v1=") {
		t.Errorf("signature should start with 'v1=', got %q", sig)
	}
}

// TestScenario_TimestampIsNotRFC3339 validates that timestamp is epoch seconds, not RFC3339.
func TestScenario_TimestampIsNotRFC3339(t *testing.T) {
	// Given
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1764633600, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, stateFilePath)

	stateData := state.State{
		DeviceID:     "d1",
		DeviceSecret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	stateJSON, _ := json.MarshalIndent(stateData, "", "  ")
	fsys.Seed(stateFilePath, append(stateJSON, '\n'))

	client := New(cfg, store, doer, clock)

	// When
	_, err := client.Do("GET", "/api/v1/test", nil)

	// Then
	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}

	reqs := doer.Requests()
	timestamp := reqs[0].Header.Get(HeaderTimestamp)

	// Validate format: should be epoch seconds in decimal, matching ^[0-9]{1,11}$
	if !regexp.MustCompile(`^[0-9]{1,11}$`).MatchString(timestamp) {
		t.Errorf("timestamp %q does not match ^[0-9]{1,11}$", timestamp)
	}

	// Should NOT contain RFC3339 characters
	if strings.Contains(timestamp, "T") {
		t.Error("timestamp should not contain 'T'")
	}
	if strings.Contains(timestamp, "Z") {
		t.Error("timestamp should not contain 'Z'")
	}
	if strings.Contains(timestamp, "-") {
		t.Error("timestamp should not contain '-'")
	}
	if strings.Contains(timestamp, ".") {
		t.Error("timestamp should not contain '.'")
	}

	// Verify exact value
	if timestamp != "1764633600" {
		t.Errorf("expected timestamp '1764633600', got %q", timestamp)
	}
}

// TestScenario_PersistedSecretIsSigningKey validates that the signature uses the stored device secret.
func TestScenario_PersistedSecretIsSigningKey(t *testing.T) {
	// Given
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, stateFilePath)

	deviceID := "d1"
	deviceSecret := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	stateData := state.State{
		DeviceID:     deviceID,
		DeviceSecret: deviceSecret,
	}
	stateJSON, _ := json.MarshalIndent(stateData, "", "  ")
	fsys.Seed(stateFilePath, append(stateJSON, '\n'))

	client := New(cfg, store, doer, clock)

	// When
	_, err := client.Do("GET", "/api/v1/test", nil)

	// Then
	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}

	reqs := doer.Requests()
	req := reqs[0]

	// Extract headers that were sent
	timestamp, _ := strconv.ParseInt(req.Header.Get(HeaderTimestamp), 10, 64)
	nonce := req.Header.Get(HeaderNonce)
	signature := req.Header.Get(HeaderSignature)

	// Verify signature by recomputing it
	parts := contract.SigningParts{
		Method:    "GET",
		Path:      "/api/v1/test",
		Query:     "",
		Body:      nil,
		Timestamp: timestamp,
		Nonce:     nonce,
		DeviceID:  deviceID,
	}
	expectedSig, err := contract.SignRequest(deviceSecret, parts)
	if err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	if signature != expectedSig {
		t.Errorf("signature mismatch.\nExpected: %s\nGot:      %s", expectedSig, signature)
	}
}

// TestScenario_DoWithoutCredentialIsRefusedLocally validates that Do returns ErrNotEnrolled when not enrolled.
func TestScenario_DoWithoutCredentialIsRefusedLocally(t *testing.T) {
	// Given
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, stateFilePath)
	// No state file created - not enrolled

	client := New(cfg, store, doer, clock)

	// When
	_, err := client.Do("GET", "/api/v1/test", nil)

	// Then
	if !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("expected ErrNotEnrolled, got %v", err)
	}

	// No HTTP request should have been made
	if len(doer.Requests()) != 0 {
		t.Errorf("expected no requests, got %d", len(doer.Requests()))
	}
}

// TestScenario_NonceChangesPerRequest validates that each Do call sends a different nonce.
func TestScenario_NonceChangesPerRequest(t *testing.T) {
	// Given
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, stateFilePath)

	stateData := state.State{
		DeviceID:     "d1",
		DeviceSecret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	stateJSON, _ := json.MarshalIndent(stateData, "", "  ")
	fsys.Seed(stateFilePath, append(stateJSON, '\n'))

	client := New(cfg, store, doer, clock)

	// When
	_, _ = client.Do("GET", "/api/v1/test", nil)
	_, _ = client.Do("GET", "/api/v1/test", nil)

	// Then
	reqs := doer.Requests()
	if len(reqs) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(reqs))
	}

	nonce1 := reqs[0].Header.Get(HeaderNonce)
	nonce2 := reqs[1].Header.Get(HeaderNonce)

	if nonce1 == nonce2 {
		t.Errorf("nonces should differ, both got %q", nonce1)
	}
}

// TestScenario_NonHTTPSEndpointIsRefused validates that non-HTTPS endpoints are rejected.
func TestScenario_NonHTTPSEndpointIsRefused(t *testing.T) {
	// Given
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "http://api.example.com", // HTTP not HTTPS
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, stateFilePath)

	stateData := state.State{
		DeviceID:     "d1",
		DeviceSecret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	stateJSON, _ := json.MarshalIndent(stateData, "", "  ")
	fsys.Seed(stateFilePath, append(stateJSON, '\n'))

	client := New(cfg, store, doer, clock)

	// When
	_, err := client.Do("GET", "/api/v1/test", nil)

	// Then
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "insecure transport refused") {
		t.Errorf("error should contain 'insecure transport refused', got %q", err.Error())
	}

	// No HTTP request should have been made
	if len(doer.Requests()) != 0 {
		t.Errorf("expected no requests, got %d", len(doer.Requests()))
	}
}

// TestScenario_UnauthorizedCallSurfacesForReenrollment validates that 401 response returns ErrUnauthorized.
func TestScenario_UnauthorizedCallSurfacesForReenrollment(t *testing.T) {
	// Given
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, stateFilePath)

	stateData := state.State{
		DeviceID:     "d1",
		DeviceSecret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	stateJSON, _ := json.MarshalIndent(stateData, "", "  ")
	fsys.Seed(stateFilePath, append(stateJSON, '\n'))

	// Setup doer to return 401
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return fake.Response(http.StatusUnauthorized, ""), nil
	}

	client := New(cfg, store, doer, clock)

	// When
	_, err := client.Do("GET", "/api/v1/test", nil)

	// Then
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

// TestScenario_EnrollSendsTokenHeaderAlone validates that Enroll sends only the enrollment token header.
func TestScenario_EnrollSendsTokenHeaderAlone(t *testing.T) {
	// Given
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, stateFilePath)

	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		// Respond with enrollment success
		body := contract.EnrollResponse{
			DeviceID:               "d1",
			DeviceSecret:           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			CheckInIntervalSeconds: 900,
		}
		data, _ := json.Marshal(body)
		return fake.Response(http.StatusOK, string(data)), nil
	}

	client := New(cfg, store, doer, clock)

	// When
	err := client.Enroll(context.Background())

	// Then
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}

	reqs := doer.Requests()
	if len(reqs) == 0 {
		t.Fatal("no request was sent")
	}
	req := reqs[0]

	// Check path
	if !strings.Contains(req.URL.Path, "/api/v1/enroll") {
		t.Errorf("expected path to contain /api/v1/enroll, got %s", req.URL.Path)
	}

	// Check that only X-MDM-Enrollment-Token is set
	if req.Header.Get(HeaderEnrollmentToken) != enrollmentTokenValue {
		t.Errorf("X-MDM-Enrollment-Token should be %q, got %q", enrollmentTokenValue, req.Header.Get(HeaderEnrollmentToken))
	}

	// Check that other X-MDM headers are NOT set
	if req.Header.Get(HeaderSignature) != "" {
		t.Error("X-MDM-Signature should not be set")
	}
	if req.Header.Get(HeaderTimestamp) != "" {
		t.Error("X-MDM-Timestamp should not be set")
	}
	if req.Header.Get(HeaderNonce) != "" {
		t.Error("X-MDM-Nonce should not be set")
	}
	if req.Header.Get(HeaderDeviceID) != "" {
		t.Error("X-MDM-Device-Id should not be set")
	}
}

// TestScenario_EnrollmentStoresCredential validates that successful enrollment stores deviceId and deviceSecret.
func TestScenario_EnrollmentStoresCredential(t *testing.T) {
	// Given
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, stateFilePath)

	deviceID := "d1"
	deviceSecret := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	checkInInterval := 900

	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		body := contract.EnrollResponse{
			DeviceID:               deviceID,
			DeviceSecret:           deviceSecret,
			CheckInIntervalSeconds: checkInInterval,
		}
		data, _ := json.Marshal(body)
		return fake.Response(http.StatusOK, string(data)), nil
	}

	client := New(cfg, store, doer, clock)

	// When
	err := client.Enroll(context.Background())

	// Then
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}

	// Check that state was saved
	savedState, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if savedState.DeviceID != deviceID {
		t.Errorf("saved DeviceID %q, expected %q", savedState.DeviceID, deviceID)
	}
	if savedState.DeviceSecret != deviceSecret {
		t.Errorf("saved DeviceSecret does not match (length mismatch: got %d, expected %d)", len(savedState.DeviceSecret), len(deviceSecret))
	}
}

// TestScenario_SecondEnrollmentIsRefusedLocally validates that second Enroll returns ErrAlreadyEnrolled.
func TestScenario_SecondEnrollmentIsRefusedLocally(t *testing.T) {
	// Given
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, stateFilePath)

	// State already holds a device id
	stateData := state.State{
		DeviceID:     "d1",
		DeviceSecret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	stateJSON, _ := json.MarshalIndent(stateData, "", "  ")
	fsys.Seed(stateFilePath, append(stateJSON, '\n'))

	client := New(cfg, store, doer, clock)

	// When
	err := client.Enroll(context.Background())

	// Then
	if !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("expected ErrAlreadyEnrolled, got %v", err)
	}

	// No request should have been made
	if len(doer.Requests()) != 0 {
		t.Errorf("expected no requests, got %d", len(doer.Requests()))
	}
}

// TestScenario_RejectedTokenLeavesAgentUnenrolled validates that 401 to Enroll leaves state unenrolled.
func TestScenario_RejectedTokenLeavesAgentUnenrolled(t *testing.T) {
	// Given
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, stateFilePath)

	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return fake.Response(http.StatusUnauthorized, `{"error":"invalid_enrollment_token"}`), nil
	}

	client := New(cfg, store, doer, clock)

	// When
	err := client.Enroll(context.Background())

	// Then
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid_enrollment_token") {
		t.Errorf("error should contain 'invalid_enrollment_token', got %q", err.Error())
	}

	// State should have no device ID
	savedState, _ := store.Load()
	if savedState.DeviceID != "" {
		t.Errorf("state should have no DeviceID, got %q", savedState.DeviceID)
	}
}

// TestScenario_EnrollmentRetriesWithBackoff validates that Enroll retries with exponential backoff.
func TestScenario_EnrollmentRetriesWithBackoff(t *testing.T) {
	// Given
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	clock.AutoAdvance = true // Single goroutine mode: auto-advance time
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, stateFilePath)

	attemptCount := 0
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		attemptCount++
		if attemptCount < 6 {
			// Fail the first 5 attempts
			return fake.Response(http.StatusInternalServerError, `{"error":"temp_error"}`), nil
		}
		// Success on the 6th attempt
		body := contract.EnrollResponse{
			DeviceID:               "d1",
			DeviceSecret:           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			CheckInIntervalSeconds: 900,
		}
		data, _ := json.Marshal(body)
		return fake.Response(http.StatusOK, string(data)), nil
	}

	client := New(cfg, store, doer, clock)

	// When
	err := client.Enroll(context.Background())

	// Then
	if err != nil {
		t.Fatalf("Enroll should succeed after retries, got %v", err)
	}

	// Check that the correct delays were applied
	waits := clock.Waits()
	expectedWaits := []time.Duration{
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
	}

	if len(waits) != len(expectedWaits) {
		t.Errorf("expected %d waits, got %d", len(expectedWaits), len(waits))
	}

	for i, w := range waits {
		if i >= len(expectedWaits) {
			break
		}
		if w != expectedWaits[i] {
			t.Errorf("wait[%d] = %v, expected %v", i, w, expectedWaits[i])
		}
	}
}

// TestScenario_EnrollmentFailsAfterSixAttempts validates that Enroll fails after 6 attempts with proper error message.
func TestScenario_EnrollmentFailsAfterSixAttempts(t *testing.T) {
	// Given
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	clock.AutoAdvance = true
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, stateFilePath)

	// All attempts fail
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return fake.Response(http.StatusInternalServerError, `{"error":"server_error"}`), nil
	}

	client := New(cfg, store, doer, clock)

	// When
	err := client.Enroll(context.Background())

	// Then
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "enrollment failed after 6 attempts") {
		t.Errorf("error should contain 'enrollment failed after 6 attempts', got %q", err.Error())
	}

	// Verify we made exactly 6 requests
	if len(doer.Requests()) != 6 {
		t.Errorf("expected 6 requests, got %d", len(doer.Requests()))
	}
}

// TestScenario_EnrollSendsCorrectBody validates that Enroll sends the correct request body.
func TestScenario_EnrollSendsCorrectBody(t *testing.T) {
	// Given
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, stateFilePath)

	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		// Verify the request body
		body, _ := io.ReadAll(req.Body)
		var enrollReq contract.EnrollRequest
		json.Unmarshal(body, &enrollReq)

		// All required fields should be present
		if enrollReq.Hostname == "" {
			t.Error("Hostname not set in request body")
		}
		if enrollReq.Platform == "" {
			t.Error("Platform not set in request body")
		}
		if enrollReq.OSVersion == "" {
			t.Error("OSVersion not set in request body")
		}
		if enrollReq.HardwareUUID == "" {
			t.Error("HardwareUUID not set in request body")
		}
		if enrollReq.AgentVersion == "" {
			t.Error("AgentVersion not set in request body")
		}

		// Respond with success
		body = []byte(`{"deviceId":"d1","deviceSecret":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","checkInIntervalSeconds":900}`)
		return fake.Response(http.StatusOK, string(body)), nil
	}

	client := New(cfg, store, doer, clock)
	client.Host = HostFacts{
		Hostname:     "test-host",
		Platform:     "windows",
		OSVersion:    "10.0.22631",
		HardwareUUID: "uuid-12345",
		AgentVersion: "1.0.0",
	}

	// When
	err := client.Enroll(context.Background())

	// Then
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}
}

// TestScenario_NoNonceReuse validates that even in a single request, fresh nonce is generated.
func TestScenario_NoNonceReuse(t *testing.T) {
	// Given
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, stateFilePath)

	stateData := state.State{
		DeviceID:     "d1",
		DeviceSecret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	stateJSON, _ := json.MarshalIndent(stateData, "", "  ")
	fsys.Seed(stateFilePath, append(stateJSON, '\n'))

	client := New(cfg, store, doer, clock)

	// When: Make 3 requests
	for i := 0; i < 3; i++ {
		_, _ = client.Do("GET", "/api/v1/test", nil)
	}

	// Then: All nonces should be unique
	reqs := doer.Requests()
	nonces := make(map[string]bool)
	for i, req := range reqs {
		nonce := req.Header.Get(HeaderNonce)
		if nonces[nonce] {
			t.Errorf("nonce %q was reused (first at request 0, again at request %d)", nonce, i)
		}
		nonces[nonce] = true

		// Verify nonce is 32 lower-case hex characters
		if len(nonce) != 32 {
			t.Errorf("request %d: nonce length is %d, expected 32", i, len(nonce))
		}
		if _, err := hex.DecodeString(nonce); err != nil {
			t.Errorf("request %d: nonce is not valid hex: %v", i, err)
		}
	}
}

// TestScenario_BodyIsSignedCorrectly validates that the request body is included in the signature.
func TestScenario_BodyIsSignedCorrectly(t *testing.T) {
	// Given
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{
		CollectionURL:   "https://api.example.com",
		EnrollmentToken: enrollmentTokenValue,
	}
	store := state.NewStore(fsys, stateFilePath)

	deviceID := "d1"
	deviceSecret := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	stateData := state.State{
		DeviceID:     deviceID,
		DeviceSecret: deviceSecret,
	}
	stateJSON, _ := json.MarshalIndent(stateData, "", "  ")
	fsys.Seed(stateFilePath, append(stateJSON, '\n'))

	client := New(cfg, store, doer, clock)

	// When: Send a request with a body
	body := []byte(`{"key":"value"}`)
	_, _ = client.Do("POST", "/api/v1/test", body)

	// Then: Verify signature includes the body
	req := doer.Requests()[0]
	timestamp, _ := strconv.ParseInt(req.Header.Get(HeaderTimestamp), 10, 64)
	nonce := req.Header.Get(HeaderNonce)
	signature := req.Header.Get(HeaderSignature)

	parts := contract.SigningParts{
		Method:    "POST",
		Path:      "/api/v1/test",
		Query:     "",
		Body:      body,
		Timestamp: timestamp,
		Nonce:     nonce,
		DeviceID:  deviceID,
	}
	expectedSig, _ := contract.SignRequest(deviceSecret, parts)

	if signature != expectedSig {
		t.Error("signature does not match expected (body not properly included)")
	}
}
