package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
	"github.com/officehq/sk-mdm/agent/internal/userauth"
)

// seedEnrolledAgent writes a config and state file an enrolled agent would
// have, so newAgent assembles a working client without touching a real
// network or disk.
func seedEnrolledAgent(t *testing.T, fsys *fake.FS, goos string) {
	t.Helper()
	cfg := config.Config{
		CollectionURL:          "https://collector.example",
		EnrollmentToken:        "irrelevant",
		CheckInIntervalSeconds: 900,
		LogLevel:               "debug",
	}
	if err := config.Save(fsys, config.Path(goos), cfg); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	st := state.State{DeviceID: "d1", DeviceSecret: strings.Repeat("ab", 32)}
	if err := state.NewStore(fsys, state.StatePath(goos)).Save(st); err != nil {
		t.Fatalf("seed state: %v", err)
	}
}

// seedSignedInVault writes a fresh (not-near-expiry) user token, so
// Session.BearerToken returns true with no refresh call.
func seedSignedInVault(t *testing.T, fsys *fake.FS, protector platform.SecretProtector, clock *fake.Clock, goos string) {
	t.Helper()
	vault := userauth.NewVault(fsys, protector, userauth.VaultPath(goos))
	rec := userauth.Record{
		AccessToken:  "ACCESS-SENTINEL",
		RefreshToken: "REFRESH-SENTINEL",
		ExpiresAt:    clock.Now().Add(time.Hour),
		Username:     "amy@contoso.com",
		TenantID:     "t-1",
		ClientID:     "c-1",
		Scopes:       []string{"api://c-1/MDM.Agent"},
	}
	if err := vault.Save(rec); err != nil {
		t.Fatalf("seed vault: %v", err)
	}
}

// newTestAgent assembles the production agent (newAgent) over fakes, so a
// test exercises the exact wiring in agent/cmd/mdmagent/run.go: Bearer on the
// transport and AfterCheckIn calling reportUserSession before executor.Poll.
func newTestAgent(t *testing.T, fsys *fake.FS, doer *fake.HTTPDoer, clock *fake.Clock, protector platform.SecretProtector, goos string) *agent {
	t.Helper()
	ag, err := newAgent(agentEnv{
		FS:         fsys,
		Runner:     fake.NewCommandRunner(),
		Clock:      clock,
		Doer:       doer,
		GOOS:       goos,
		ConfigPath: config.Path(goos),
		StatePath:  state.StatePath(goos),
		Hostname:   "test-host",
		BinaryPath: "",
		Protector:  protector,
	})
	if err != nil {
		t.Fatalf("newAgent: %v", err)
	}
	return ag
}

// commandLeaseDoFunc answers any GET to the command-lease path with an empty
// lease, so executor.Poll completes its cycle with nothing to run.
func isLeasePath(path string) bool { return strings.Contains(path, "/commands") }
func isUserSessionPath(path string) bool {
	return strings.HasSuffix(path, "/user-session")
}

// TestScenario_UserSessionReportedAfterCheckIn is the A12 Gherkin scenario
// "User session reported after a successful check-in".
func TestScenario_UserSessionReportedAfterCheckIn(t *testing.T) {
	fsys := fake.NewFS()
	goos := "darwin"
	clock := fake.NewClock(time.Unix(1700000000, 0))
	seedEnrolledAgent(t, fsys, goos)
	protector := fake.NewSecretProtector()
	seedSignedInVault(t, fsys, protector, clock, goos)

	var order []string
	doer := fake.NewHTTPDoer()
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		switch {
		case isUserSessionPath(req.URL.Path):
			order = append(order, "user-session")
			return fake.Response(http.StatusOK, `{"user":{"upn":"amy@contoso.com"}}`), nil
		case isLeasePath(req.URL.Path):
			order = append(order, "lease")
			return fake.Response(http.StatusOK, `{"commands":[]}`), nil
		}
		t.Fatalf("unexpected request to %s", req.URL.Path)
		return nil, nil
	}

	ag := newTestAgent(t, fsys, doer, clock, protector, goos)

	// When one scheduler cycle runs
	if err := ag.deps.AfterCheckIn(context.Background(), contract.CheckInResponse{}); err != nil {
		t.Fatalf("AfterCheckIn: %v", err)
	}

	// Then a signed POST .../user-session with the bearer was sent after the
	// check-in, and executor.Poll ran in the same cycle
	if len(order) != 2 || order[0] != "user-session" || order[1] != "lease" {
		t.Fatalf("expected [user-session, lease] order, got %v", order)
	}

	// And an info record "user session verified" with upn "amy@contoso.com"
	// was logged
	logContent, ok := fsys.Content(agentLogPath(goos))
	if !ok {
		t.Fatalf("expected a log file to exist")
	}
	log := string(logContent)
	if !strings.Contains(log, `"msg":"user session verified"`) {
		t.Errorf("expected 'user session verified' info record, got: %s", log)
	}
	if !strings.Contains(log, `"upn":"amy@contoso.com"`) {
		t.Errorf("expected upn field in log, got: %s", log)
	}
}

// TestScenario_UserSessionFailuresCostNothing is the A12 Gherkin scenario
// outline "User-session failures never cost the device credential or the
// command poll".
func TestScenario_UserSessionFailuresCostNothing(t *testing.T) {
	cases := []struct {
		name            string
		respond         func(req *http.Request) (*http.Response, error)
		wantMarkedStale bool
	}{
		{
			name: "403 user_token_invalid",
			respond: func(req *http.Request) (*http.Response, error) {
				return fake.Response(http.StatusForbidden, `{"error":"user_token_invalid"}`), nil
			},
			// A 403 calls MarkStale, so the very next signed request this
			// same cycle makes (the command lease) finds the session stale
			// and refreshes before it goes out, even though the stored
			// access token is still an hour from expiry.
			wantMarkedStale: true,
		},
		{
			name: "503",
			respond: func(req *http.Request) (*http.Response, error) {
				return fake.Response(http.StatusServiceUnavailable, `{"error":"unavailable"}`), nil
			},
			wantMarkedStale: false,
		},
		{
			name: "transport error",
			respond: func(req *http.Request) (*http.Response, error) {
				return nil, &transportFailure{}
			},
			wantMarkedStale: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fake.NewFS()
			goos := "darwin"
			clock := fake.NewClock(time.Unix(1700000000, 0))
			seedEnrolledAgent(t, fsys, goos)
			protector := fake.NewSecretProtector()
			seedSignedInVault(t, fsys, protector, clock, goos)

			leaseCalls := 0
			userSessionCalls := 0
			refreshCalls := 0
			doer := fake.NewHTTPDoer()
			doer.DoFunc = func(req *http.Request) (*http.Response, error) {
				switch {
				case isUserSessionPath(req.URL.Path):
					userSessionCalls++
					return tc.respond(req)
				case isLeasePath(req.URL.Path):
					leaseCalls++
					return fake.Response(http.StatusOK, `{"commands":[]}`), nil
				case strings.HasSuffix(req.URL.Path, "/oauth2/v2.0/token"):
					refreshCalls++
					return fake.Response(http.StatusOK, `{"access_token":"NEW-ACCESS","expires_in":3600}`), nil
				}
				t.Fatalf("unexpected request to %s", req.URL.Path)
				return nil, nil
			}

			ag := newTestAgent(t, fsys, doer, clock, protector, goos)

			// When one scheduler cycle runs
			if err := ag.deps.AfterCheckIn(context.Background(), contract.CheckInResponse{}); err != nil {
				t.Fatalf("AfterCheckIn: %v", err)
			}

			// Then the device state file still holds its device id and secret
			st, err := state.NewStore(fsys, state.StatePath(goos)).Load()
			if err != nil {
				t.Fatalf("load state: %v", err)
			}
			if st.DeviceID != "d1" || st.DeviceSecret != strings.Repeat("ab", 32) {
				t.Errorf("device credential was cleared: %+v", st)
			}

			// And executor.Poll ran in the same cycle
			if leaseCalls != 1 {
				t.Errorf("expected executor.Poll to lease once, got %d", leaseCalls)
			}
			if userSessionCalls != 1 {
				t.Errorf("expected exactly 1 user-session call, got %d", userSessionCalls)
			}

			// And the vault still exists in every case
			if !fsys.Exists(userauth.VaultPath(goos)) {
				t.Errorf("vault should not be deleted by a user-session failure")
			}

			wantRefreshCalls := 0
			if tc.wantMarkedStale {
				wantRefreshCalls = 1
			}
			if refreshCalls != wantRefreshCalls {
				t.Errorf("expected %d refresh calls (MarkStale effect), got %d", wantRefreshCalls, refreshCalls)
			}
		})
	}
}

// TestScenario_NoUserSessionCallWhenNobodySignedIn is the A12 edge scenario
// "No user-session call when nobody is signed in".
func TestScenario_NoUserSessionCallWhenNobodySignedIn(t *testing.T) {
	fsys := fake.NewFS()
	goos := "darwin"
	clock := fake.NewClock(time.Unix(1700000000, 0))
	seedEnrolledAgent(t, fsys, goos)
	protector := fake.NewSecretProtector()
	// Given an enrolled agent with no vault: nothing is seeded.

	leaseCalls := 0
	doer := fake.NewHTTPDoer()
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		switch {
		case isUserSessionPath(req.URL.Path):
			t.Fatalf("no user-session request should be sent, got one to %s", req.URL.Path)
		case isLeasePath(req.URL.Path):
			leaseCalls++
			return fake.Response(http.StatusOK, `{"commands":[]}`), nil
		}
		return fake.Response(http.StatusNotFound, "{}"), nil
	}

	ag := newTestAgent(t, fsys, doer, clock, protector, goos)

	// When one scheduler cycle runs
	if err := ag.deps.AfterCheckIn(context.Background(), contract.CheckInResponse{}); err != nil {
		t.Fatalf("AfterCheckIn: %v", err)
	}

	// Then no request to a user-session path was sent, and executor.Poll
	// still ran
	if leaseCalls != 1 {
		t.Errorf("expected executor.Poll to still lease, got %d calls", leaseCalls)
	}
}

type transportFailure struct{}

func (e *transportFailure) Error() string { return "simulated transport failure" }
