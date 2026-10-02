package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/client"
	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
	"github.com/officehq/sk-mdm/agent/internal/userauth"
)

// The three sentinels A13 pins: a device code, an access token and a refresh
// token that must never appear anywhere but the vault's encrypted bytes.
const (
	sentinelAccess     = "ACCESS-SENTINEL"
	sentinelRefresh    = "REFRESH-SENTINEL"
	sentinelDeviceCode = "DEVICECODE-SENTINEL"
	sentinelUserCode   = "WXYZ-1234"
)

// assertNoSentinels fails the test if any of the three sentinels, or the raw
// strings "ACCESS-SENTINEL"/"REFRESH-SENTINEL"/"DEVICECODE-SENTINEL", appear
// in where.
func assertNoSentinels(t *testing.T, where, label string) {
	t.Helper()
	for _, s := range []string{sentinelAccess, sentinelRefresh, sentinelDeviceCode} {
		if strings.Contains(where, s) {
			t.Errorf("%s leaked sentinel %q: %s", label, s, where)
		}
	}
}

// TestScenario_SentinelsNeverLeak is the A13 Gherkin scenario "Tokens and
// device codes never reach logs or console", exercised across a successful
// login, a failed login, a successful refresh, a refresh rejected with
// invalid_grant, logout, and a failing user-session call.
func TestScenario_SentinelsNeverLeak(t *testing.T) {
	goos := "darwin"

	// --- A successful login ---------------------------------------------
	loginFsys := fake.NewFS()
	seedLoginConfig(t, loginFsys, goos, "https://collector.example")

	loginClock := fake.NewClock(time.Unix(1700000000, 0))
	loginClock.AutoAdvance = true
	tokenBody, _ := json.Marshal(map[string]interface{}{
		"access_token":  sentinelAccess,
		"refresh_token": sentinelRefresh,
		"expires_in":    3600,
	})
	deviceCodeBody, _ := json.Marshal(map[string]interface{}{
		"device_code":      sentinelDeviceCode,
		"user_code":        sentinelUserCode,
		"verification_uri": "https://microsoft.com/devicelogin",
		"expires_in":       900,
		"interval":         5,
	})
	loginDoerOK := loginDoer(t, validConfigBody, string(deviceCodeBody), string(tokenBody), 200, 200, 200)
	loginProtector := fake.NewSecretProtector()
	swapLoginSeams(t, loginDoerOK, loginClock, loginProtector)

	loginStdout := &bytes.Buffer{}
	loginStderr := &bytes.Buffer{}
	if exit := run(loginFsys, goos, []string{"login"}, loginStdout, loginStderr); exit != 0 {
		t.Fatalf("login setup failed: exit=%d stderr=%s", exit, loginStderr.String())
	}

	// The user_code appears on stdout...
	if !strings.Contains(loginStdout.String(), sentinelUserCode) {
		t.Errorf("expected user_code %q on stdout, got: %s", sentinelUserCode, loginStdout.String())
	}
	// ...but none of the three sentinels appear anywhere in stdout/stderr.
	assertNoSentinels(t, loginStdout.String(), "login stdout")
	assertNoSentinels(t, loginStderr.String(), "login stderr")
	// login never constructs a logging.Logger, so there is no log file at
	// all; the absence of one is itself proof nothing leaked into it.
	if loginFsys.Exists(agentLogPath(goos)) {
		content, _ := loginFsys.Content(agentLogPath(goos))
		t.Errorf("login should not create an agent log file, found: %s", content)
	}

	// --- A failed login (older vault survives, nothing leaks either) -----
	failFsys := fake.NewFS()
	seedLoginConfig(t, failFsys, goos, "https://collector.example")
	failClock := fake.NewClock(time.Unix(1700000000, 0))
	failClock.AutoAdvance = true
	failDeviceCodeBody, _ := json.Marshal(map[string]interface{}{
		"device_code":      sentinelDeviceCode,
		"user_code":        sentinelUserCode,
		"verification_uri": "https://microsoft.com/devicelogin",
		"expires_in":       900,
		"interval":         5,
	})
	failDoer := loginDoer(t, validConfigBody, string(failDeviceCodeBody), `{"error":"invalid_client"}`, 200, 200, 400)
	failProtector := fake.NewSecretProtector()
	swapLoginSeams(t, failDoer, failClock, failProtector)

	failStdout := &bytes.Buffer{}
	failStderr := &bytes.Buffer{}
	exit := run(failFsys, goos, []string{"login"}, failStdout, failStderr)
	if exit != 1 {
		t.Fatalf("expected the failing login to exit 1, got %d", exit)
	}
	assertNoSentinels(t, failStdout.String(), "failed login stdout")
	assertNoSentinels(t, failStderr.String(), "failed login stderr")

	// --- Logout ------------------------------------------------------------
	logoutFsys := fake.NewFS()
	logoutProtector := fake.NewSecretProtector()
	vault := userauth.NewVault(logoutFsys, logoutProtector, userauth.VaultPath(goos))
	if err := vault.Save(userauth.Record{
		AccessToken: sentinelAccess, RefreshToken: sentinelRefresh,
		ExpiresAt: time.Unix(1700003600, 0),
	}); err != nil {
		t.Fatalf("seed vault for logout: %v", err)
	}
	origProtector := newProtector
	newProtector = func() platform.SecretProtector { return logoutProtector }
	t.Cleanup(func() { newProtector = origProtector })

	logoutStdout := &bytes.Buffer{}
	logoutStderr := &bytes.Buffer{}
	if exit := run(logoutFsys, goos, []string{"logout"}, logoutStdout, logoutStderr); exit != 0 {
		t.Fatalf("logout failed: exit=%d", exit)
	}
	assertNoSentinels(t, logoutStdout.String(), "logout stdout")
	assertNoSentinels(t, logoutStderr.String(), "logout stderr")

	// --- A session refresh success and an invalid_grant failure, both
	// --- logged through a real file-backed logger -------------------------
	sessFsys := fake.NewFS()
	sessClock := fake.NewClock(time.Unix(1700000000, 0))
	sessProtector := fake.NewSecretProtector()
	sessVault := userauth.NewVault(sessFsys, sessProtector, "/vault.json")
	if err := sessVault.Save(userauth.Record{
		AccessToken:  "old-access",
		RefreshToken: sentinelRefresh,
		ExpiresAt:    sessClock.Now().Add(100 * time.Second), // due for refresh
		TenantID:     "t-1",
		ClientID:     "c-1",
		Scopes:       []string{"api://c-1/MDM.Agent"},
	}); err != nil {
		t.Fatalf("seed session vault: %v", err)
	}
	const sessLogPath = "/agent.log"
	sessLogger := logging.New(sessFsys, sessClock, sessLogPath, logging.LevelDebug, "userauth")

	refreshDoer := fake.NewHTTPDoer()
	refreshDoer.DoFunc = func(req *http.Request) (*http.Response, error) {
		body, _ := json.Marshal(map[string]interface{}{
			"access_token":  sentinelAccess,
			"refresh_token": "rotated-" + sentinelRefresh,
			"expires_in":    3600,
		})
		return fake.Response(http.StatusOK, string(body)), nil
	}
	session := userauth.NewSession(sessVault, refreshDoer, sessClock, sessLogger)
	if _, ok := session.BearerToken(context.Background()); !ok {
		t.Fatalf("expected the due refresh to succeed")
	}

	// Now push the vault due again and have the token endpoint reject it
	// with invalid_grant, which signs the device out locally.
	if err := sessVault.Save(userauth.Record{
		AccessToken:  "old-access-2",
		RefreshToken: sentinelRefresh,
		ExpiresAt:    sessClock.Now().Add(100 * time.Second),
		TenantID:     "t-1",
		ClientID:     "c-1",
	}); err != nil {
		t.Fatalf("reseed session vault: %v", err)
	}
	refreshDoer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return fake.Response(http.StatusBadRequest, `{"error":"invalid_grant"}`), nil
	}
	if _, ok := session.BearerToken(context.Background()); ok {
		t.Fatalf("expected invalid_grant to sign the session out")
	}

	// --- A failing user-session call, logged through the same logger ------
	usDoer := fake.NewHTTPDoer()
	usDoer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return fake.Response(http.StatusServiceUnavailable, `{"error":"unavailable"}`), nil
	}
	usVault := userauth.NewVault(sessFsys, sessProtector, "/vault2.json")
	if err := usVault.Save(userauth.Record{
		AccessToken: sentinelAccess, RefreshToken: sentinelRefresh,
		ExpiresAt: sessClock.Now().Add(time.Hour),
		TenantID:  "t-1", ClientID: "c-1",
	}); err != nil {
		t.Fatalf("seed user-session vault: %v", err)
	}
	usStore := state.NewStore(sessFsys, "/us-state.json")
	if err := usStore.Save(state.State{DeviceID: "d-us", DeviceSecret: strings.Repeat("cd", 32)}); err != nil {
		t.Fatalf("seed user-session state: %v", err)
	}
	usTransport := client.New(config.Config{CollectionURL: "https://collector.example"}, usStore, usDoer, sessClock)
	usSession := userauth.NewSession(usVault, usDoer, sessClock, sessLogger)
	reportUserSession(context.Background(), usTransport, usSession, "d-us", sessLogger)

	// Then none of the sentinels appear in the agent log file ...
	logContent, _ := sessFsys.Content(sessLogPath)
	assertNoSentinels(t, string(logContent), "agent log file")
	// ... and the user_code never reaches the log file either (none of these
	// flows carry one, so its absence is trivially true; the explicit check
	// documents the requirement).
	if strings.Contains(string(logContent), sentinelUserCode) {
		t.Errorf("user_code must never reach the agent log file, found in: %s", logContent)
	}
}
