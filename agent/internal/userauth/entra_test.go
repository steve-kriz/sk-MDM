package userauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// TestScenario_StartSignIn_ValidDeviceCode validates the device code request.
func TestScenario_StartSignIn_ValidDeviceCode(t *testing.T) {
	// Given an Entra instance and a mock HTTP doer
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	entra := &Entra{Doer: doer, Clock: clock}

	// Prepare the device code response
	deviceCodeResp := map[string]interface{}{
		"device_code":      "ABC123DEF456",
		"user_code":        "WXYZ-1234",
		"verification_uri": "https://microsoft.com/devicelogin",
		"expires_in":       900,
		"interval":         5,
	}
	respBody, _ := json.Marshal(deviceCodeResp)

	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respBody))),
			Header:     make(http.Header),
		}, nil
	}

	// When a sign-in starts
	code, err := entra.StartSignIn(context.Background(), "t-1", "c-1", []string{"api://c-1/MDM.Agent", "offline_access"})

	// Then it succeeds and returns the device code
	if err != nil {
		t.Fatalf("StartSignIn failed: %v", err)
	}
	if code.DeviceCode != "ABC123DEF456" {
		t.Errorf("expected device_code ABC123DEF456, got %q", code.DeviceCode)
	}
	if code.UserCode != "WXYZ-1234" {
		t.Errorf("expected user_code WXYZ-1234, got %q", code.UserCode)
	}
	if code.VerificationURI != "https://microsoft.com/devicelogin" {
		t.Errorf("expected verification_uri https://microsoft.com/devicelogin, got %q", code.VerificationURI)
	}
	if code.ExpiresIn != 900 {
		t.Errorf("expected expires_in 900, got %d", code.ExpiresIn)
	}
	if code.Interval != 5 {
		t.Errorf("expected interval 5, got %d", code.Interval)
	}
}

// TestScenario_StartSignIn_MalformedResponse returns ErrSignInFailed.
func TestScenario_StartSignIn_MalformedResponse(t *testing.T) {
	// Given a device code response missing device_code
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	entra := &Entra{Doer: doer, Clock: clock}

	deviceCodeResp := map[string]interface{}{
		"user_code":        "WXYZ-1234",
		"verification_uri": "https://microsoft.com/devicelogin",
	}
	respBody, _ := json.Marshal(deviceCodeResp)

	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(respBody))),
			Header:     make(http.Header),
		}, nil
	}

	// When a sign-in starts
	_, err := entra.StartSignIn(context.Background(), "t-1", "c-1", []string{})

	// Then it returns ErrSignInFailed
	if err != ErrSignInFailed {
		t.Errorf("expected ErrSignInFailed, got %v", err)
	}
}

// TestScenario_Refresh_Success validates token refresh.
func TestScenario_Refresh_Success(t *testing.T) {
	// Given a clock and a mock HTTP doer
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	entra := &Entra{Doer: doer, Clock: clock}

	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		resp := map[string]interface{}{
			"access_token":  "new-a-token",
			"refresh_token": "new-r-token",
			"id_token":      "id.token.value",
			"expires_in":    3600,
		}
		body, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(body))),
			Header:     make(http.Header),
		}, nil
	}

	// When refresh runs
	token, err := entra.Refresh(context.Background(), "t-1", "c-1", "r-old", []string{"api://c-1/MDM.Agent"})

	// Then it succeeds
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}
	if token.AccessToken != "new-a-token" {
		t.Errorf("expected new-a-token, got %q", token.AccessToken)
	}
	if token.RefreshToken != "new-r-token" {
		t.Errorf("expected new-r-token, got %q", token.RefreshToken)
	}
}

// TestScenario_Refresh_InvalidGrant returns ErrRefreshRejected.
func TestScenario_Refresh_InvalidGrant(t *testing.T) {
	// Given a clock and a mock HTTP doer
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	entra := &Entra{Doer: doer, Clock: clock}

	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		resp := map[string]interface{}{"error": "invalid_grant"}
		body, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 400,
			Body:       io.NopCloser(strings.NewReader(string(body))),
			Header:     make(http.Header),
		}, nil
	}

	// When refresh runs
	_, err := entra.Refresh(context.Background(), "t-1", "c-1", "r-old", []string{})

	// Then it returns ErrRefreshRejected
	if err != ErrRefreshRejected {
		t.Errorf("expected ErrRefreshRejected, got %v", err)
	}
}

// TestScenario_Refresh_TransientError returns ErrRefreshUnavailable.
func TestScenario_Refresh_TransientError(t *testing.T) {
	// Given a clock and a mock HTTP doer
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()
	entra := &Entra{Doer: doer, Clock: clock}

	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		resp := map[string]interface{}{"error": "service_unavailable"}
		body, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 503,
			Body:       io.NopCloser(strings.NewReader(string(body))),
			Header:     make(http.Header),
		}, nil
	}

	// When refresh runs
	_, err := entra.Refresh(context.Background(), "t-1", "c-1", "r-old", []string{})

	// Then it returns ErrRefreshUnavailable
	if err != ErrRefreshUnavailable {
		t.Errorf("expected ErrRefreshUnavailable, got %v", err)
	}
}

// TestScenario_UsernameFromIDToken_Valid extracts preferred_username.
func TestScenario_UsernameFromIDToken_Valid(t *testing.T) {
	// Given an id_token with preferred_username
	payload := map[string]interface{}{
		"preferred_username": "amy@contoso.com",
	}
	payloadJSON, _ := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	idToken := "header." + encodedPayload + ".signature"

	// When UsernameFromIDToken is called
	username := UsernameFromIDToken(idToken)

	// Then it returns the username
	if username != "amy@contoso.com" {
		t.Errorf("expected amy@contoso.com, got %q", username)
	}
}

// TestScenario_UsernameFromIDToken_Malformed returns empty string.
func TestScenario_UsernameFromIDToken_Malformed(t *testing.T) {
	// Given a malformed id_token
	idToken := "not.a.jwt"

	// When UsernameFromIDToken is called
	username := UsernameFromIDToken(idToken)

	// Then it returns empty string
	if username != "" {
		t.Errorf("expected empty string, got %q", username)
	}
}

// TestScenario_UsernameFromIDToken_NoPreferredUsername returns empty string.
func TestScenario_UsernameFromIDToken_NoPreferredUsername(t *testing.T) {
	// Given an id_token without preferred_username
	payload := map[string]interface{}{
		"name": "Amy Smith",
	}
	payloadJSON, _ := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	idToken := "header." + encodedPayload + ".signature"

	// When UsernameFromIDToken is called
	username := UsernameFromIDToken(idToken)

	// Then it returns empty string
	if username != "" {
		t.Errorf("expected empty string, got %q", username)
	}
}

// tokenRequestForm decodes the x-www-form-urlencoded body of a token-endpoint
// POST, so a test can assert on grant_type, client_id and device_code without
// caring about header plumbing.
func tokenRequestForm(t *testing.T, req *http.Request) url.Values {
	t.Helper()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		t.Fatalf("parse request body: %v", err)
	}
	return form
}

// TestScenario_PollToken_PendingSlowDownDefaultInterval is the A4 Gherkin
// scenario: "Polling honours pending, slow_down and the default interval".
func TestScenario_PollToken_PendingSlowDownDefaultInterval(t *testing.T) {
	// Given the devicecode response has no interval and expires_in 900
	clock := fake.NewClock(time.Unix(1000000, 0))
	clock.AutoAdvance = true
	doer := fake.NewHTTPDoer()
	entra := &Entra{Doer: doer, Clock: clock}

	// And the token endpoint answers authorization_pending, then slow_down,
	// then a token
	var calls int
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		form := tokenRequestForm(t, req)
		if got := form.Get("grant_type"); got != DeviceCodeGrantType {
			t.Errorf("expected grant_type %q, got %q", DeviceCodeGrantType, got)
		}
		if got := form.Get("client_id"); got != "c-1" {
			t.Errorf("expected client_id c-1, got %q", got)
		}
		if got := form.Get("device_code"); got != "dc-1" {
			t.Errorf("expected device_code dc-1, got %q", got)
		}

		calls++
		var resp map[string]interface{}
		switch calls {
		case 1:
			resp = map[string]interface{}{"error": "authorization_pending"}
		case 2:
			resp = map[string]interface{}{"error": "slow_down"}
		default:
			resp = map[string]interface{}{"access_token": "tok", "expires_in": 3600}
		}
		body, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(body))),
			Header:     make(http.Header),
		}, nil
	}

	code := DeviceCode{DeviceCode: "dc-1", ExpiresIn: 900}

	// When polling runs
	tok, err := entra.PollToken(context.Background(), "t-1", "c-1", code)

	// Then it returns the token after exactly three token POSTs
	if err != nil {
		t.Fatalf("PollToken failed: %v", err)
	}
	if tok.AccessToken != "tok" {
		t.Errorf("expected access token %q, got %q", "tok", tok.AccessToken)
	}
	if calls != 3 {
		t.Fatalf("expected 3 token requests, got %d", calls)
	}

	// And the clock waits were 5s, 5s and 10s
	waits := clock.Waits()
	want := []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second}
	if len(waits) != len(want) {
		t.Fatalf("expected waits %v, got %v", want, waits)
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Errorf("wait %d: expected %v, got %v", i, want[i], waits[i])
		}
	}
}

// TestScenario_PollToken_TerminalOutcomes is the A4 Gherkin scenario outline
// "Polling terminal outcomes".
func TestScenario_PollToken_TerminalOutcomes(t *testing.T) {
	cases := []struct {
		name    string
		answer  string // OAuth error code the token endpoint answers with
		wantErr error
	}{
		{name: "authorization_declined", answer: "authorization_declined", wantErr: ErrSignInDeclined},
		{name: "access_denied", answer: "access_denied", wantErr: ErrSignInDeclined},
		{name: "expired_token", answer: "expired_token", wantErr: ErrSignInExpired},
		{name: "invalid_client", answer: "invalid_client", wantErr: ErrSignInFailed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given the token endpoint answers <answer>
			clock := fake.NewClock(time.Unix(1000000, 0))
			clock.AutoAdvance = true
			doer := fake.NewHTTPDoer()
			entra := &Entra{Doer: doer, Clock: clock}

			var calls int
			doer.DoFunc = func(req *http.Request) (*http.Response, error) {
				calls++
				body, _ := json.Marshal(map[string]interface{}{"error": tc.answer})
				return &http.Response{
					StatusCode: 400,
					Body:       io.NopCloser(strings.NewReader(string(body))),
					Header:     make(http.Header),
				}, nil
			}

			code := DeviceCode{DeviceCode: "dc-1", ExpiresIn: 900, Interval: 5}

			// When polling runs
			_, err := entra.PollToken(context.Background(), "t-1", "c-1", code)

			// Then it returns <error>
			if err != tc.wantErr {
				t.Errorf("expected %v, got %v", tc.wantErr, err)
			}
			if calls != 1 {
				t.Errorf("expected exactly 1 request, got %d", calls)
			}
		})
	}

	// Given a non-JSON body
	t.Run("non-JSON body", func(t *testing.T) {
		clock := fake.NewClock(time.Unix(1000000, 0))
		clock.AutoAdvance = true
		doer := fake.NewHTTPDoer()
		entra := &Entra{Doer: doer, Clock: clock}
		doer.DoFunc = func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader("not json")),
				Header:     make(http.Header),
			}, nil
		}

		code := DeviceCode{DeviceCode: "dc-1", ExpiresIn: 900, Interval: 5}
		_, err := entra.PollToken(context.Background(), "t-1", "c-1", code)
		if err != ErrSignInFailed {
			t.Errorf("expected ErrSignInFailed, got %v", err)
		}
	})

	// Given a transport error
	t.Run("transport error", func(t *testing.T) {
		clock := fake.NewClock(time.Unix(1000000, 0))
		clock.AutoAdvance = true
		doer := fake.NewHTTPDoer()
		entra := &Entra{Doer: doer, Clock: clock}
		doer.DoFunc = func(req *http.Request) (*http.Response, error) {
			return nil, errTransport
		}

		code := DeviceCode{DeviceCode: "dc-1", ExpiresIn: 900, Interval: 5}
		_, err := entra.PollToken(context.Background(), "t-1", "c-1", code)
		if err != ErrSignInFailed {
			t.Errorf("expected ErrSignInFailed, got %v", err)
		}
	})

	// Given authorization_pending answered until the clock reaches expires_in
	t.Run("authorization_pending until expires_in", func(t *testing.T) {
		clock := fake.NewClock(time.Unix(1000000, 0))
		clock.AutoAdvance = true
		doer := fake.NewHTTPDoer()
		entra := &Entra{Doer: doer, Clock: clock}

		var calls int
		doer.DoFunc = func(req *http.Request) (*http.Response, error) {
			calls++
			body, _ := json.Marshal(map[string]interface{}{"error": "authorization_pending"})
			return &http.Response{
				StatusCode: 400,
				Body:       io.NopCloser(strings.NewReader(string(body))),
				Header:     make(http.Header),
			}, nil
		}

		// Interval 5s, expires_in 6s: the first wait (5s) is still inside the
		// deadline, so one request is made and answers pending; the second
		// wait (another 5s, pending does not change the interval) carries the
		// clock past the 6s deadline, so no second request is made.
		code := DeviceCode{DeviceCode: "dc-1", ExpiresIn: 6, Interval: 5}

		// When polling runs
		_, err := entra.PollToken(context.Background(), "t-1", "c-1", code)

		// Then it returns ErrSignInExpired with no further request
		if err != ErrSignInExpired {
			t.Errorf("expected ErrSignInExpired, got %v", err)
		}
		if calls != 1 {
			t.Errorf("expected exactly 1 request before the deadline, got %d", calls)
		}
	})

	// Given the context is cancelled before polling
	t.Run("context cancelled", func(t *testing.T) {
		clock := fake.NewClock(time.Unix(1000000, 0))
		doer := fake.NewHTTPDoer()
		entra := &Entra{Doer: doer, Clock: clock}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		code := DeviceCode{DeviceCode: "dc-1", ExpiresIn: 900, Interval: 5}

		// When polling runs
		_, err := entra.PollToken(ctx, "t-1", "c-1", code)

		// Then it returns context.Canceled with no further request
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
		if len(doer.Requests()) != 0 {
			t.Errorf("expected no request after cancellation, got %d", len(doer.Requests()))
		}
	})
}

// errTransport is a stand-in network failure that carries no sensitive text.
var errTransport = &transportError{}

type transportError struct{}

func (e *transportError) Error() string { return "simulated transport failure" }
