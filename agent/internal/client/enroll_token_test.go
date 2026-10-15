package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

const testDeviceSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func enrollOK() *http.Response {
	data, _ := json.Marshal(contract.EnrollResponse{
		DeviceID:               "d1",
		DeviceSecret:           testDeviceSecret,
		CheckInIntervalSeconds: 600,
	})
	return fake.Response(http.StatusOK, string(data))
}

// The EnrollmentToken source wins over the config copy, so a token the sign-in
// wrote after the agent started is used without a restart. It is sent as the
// enrollment-token header and no Authorization header is ever sent.
func TestEnroll_TokenSourceIsReadPerCall(t *testing.T) {
	doer := fake.NewHTTPDoer()
	doer.DoFunc = func(req *http.Request) (*http.Response, error) { return enrollOK(), nil }
	c := New(config.Config{CollectionURL: "https://api.example.com"},
		state.NewStore(fake.NewFS(), "state.json"), doer, fake.NewClock(time.Unix(1000000, 0)))

	token := ""
	c.EnrollmentToken = func() string { return token }

	if err := c.Enroll(context.Background()); !errors.Is(err, ErrAwaitingSignIn) {
		t.Fatalf("no token: err = %v, want ErrAwaitingSignIn", err)
	}
	if n := len(doer.Requests()); n != 0 {
		t.Fatalf("no token: requests = %d, want 0", n)
	}

	token = enrollmentTokenValue
	if err := c.Enroll(context.Background()); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	req := doer.Requests()[0]
	if got := req.Header.Get(HeaderEnrollmentToken); got != enrollmentTokenValue {
		t.Errorf("enrollment token header = %q", got)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization must be absent, got %q", got)
	}
}

// With no token configured and no source, Enroll makes no request.
func TestEnroll_NoTokenWaitsForSignIn(t *testing.T) {
	doer := fake.NewHTTPDoer()
	c := New(config.Config{CollectionURL: "https://api.example.com"},
		state.NewStore(fake.NewFS(), "state.json"), doer, fake.NewClock(time.Unix(1000000, 0)))
	if err := c.Enroll(context.Background()); !errors.Is(err, ErrAwaitingSignIn) {
		t.Errorf("err = %v, want ErrAwaitingSignIn", err)
	}
	if n := len(doer.Requests()); n != 0 {
		t.Errorf("requests = %d, want 0", n)
	}
}

// A 401 or 403 naming a token-related error is ErrEnrollmentTokenRejected,
// is not retried and never carries the token; any other refusal is not.
func TestEnroll_TokenRejected(t *testing.T) {
	cases := []struct {
		status   int
		code     string
		rejected bool
	}{
		{http.StatusUnauthorized, "invalid_enrollment_token", true},
		{http.StatusForbidden, "invalid_enrollment_token", true},
		{http.StatusUnauthorized, "enrollment_token_expired", true},
		{http.StatusForbidden, "enrollment_token_exhausted", true},
		{http.StatusForbidden, "enrollment_token_revoked", true},
		{http.StatusUnauthorized, "something_else", false},
		{http.StatusBadRequest, "invalid_enrollment_token", false},
	}
	for _, tc := range cases {
		fsys := fake.NewFS()
		doer := fake.NewHTTPDoer()
		doer.DoFunc = func(req *http.Request) (*http.Response, error) {
			return fake.Response(tc.status, `{"error":"`+tc.code+`"}`), nil
		}
		clock := fake.NewClock(time.Unix(1000000, 0))
		c := New(config.Config{CollectionURL: "https://api.example.com", EnrollmentToken: enrollmentTokenValue},
			state.NewStore(fsys, "state.json"), doer, clock)
		c.Logger = logging.New(fsys, clock, "agent.log", logging.LevelDebug, "client")

		err := c.Enroll(context.Background())
		if err == nil {
			t.Fatalf("%d %s: expected an error", tc.status, tc.code)
		}
		if got := errors.Is(err, ErrEnrollmentTokenRejected); got != tc.rejected {
			t.Errorf("%d %s: rejected = %v, want %v (err %v)", tc.status, tc.code, got, tc.rejected, err)
		}
		if tc.rejected && !strings.Contains(err.Error(), tc.code) {
			t.Errorf("%d %s: error %q does not name the code", tc.status, tc.code, err)
		}
		if n := len(doer.Requests()); n != 1 {
			t.Errorf("%d %s: requests = %d, want 1", tc.status, tc.code, n)
		}
		logged, _ := fsys.Content("agent.log")
		if strings.Contains(string(logged), enrollmentTokenValue) || strings.Contains(err.Error(), enrollmentTokenValue) {
			t.Errorf("%d %s: token leaked", tc.status, tc.code)
		}
	}
}

// Signed requests carry no Authorization header any more.
func TestDo_SendsNoAuthorization(t *testing.T) {
	fsys := fake.NewFS()
	store := state.NewStore(fsys, "state.json")
	if err := store.Save(state.State{DeviceID: "d1", DeviceSecret: testDeviceSecret}); err != nil {
		t.Fatal(err)
	}
	doer := fake.NewHTTPDoer()
	c := New(config.Config{CollectionURL: "https://api.example.com"}, store, doer, fake.NewClock(time.Unix(1000000, 0)))
	resp, err := c.Do(http.MethodPost, "/api/v1/devices/d1/checkin", []byte(`{}`))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if got := doer.Requests()[0].Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want none", got)
	}
}

// TASK-041 AC20: "enrollment_token_revoked" is one of EnrollmentTokenErrors.
func TestEnrollmentTokenErrors_IncludesRevoked(t *testing.T) {
	for _, code := range EnrollmentTokenErrors {
		if code == "enrollment_token_revoked" {
			return
		}
	}
	t.Fatalf("EnrollmentTokenErrors = %v, want it to contain enrollment_token_revoked", EnrollmentTokenErrors)
}
