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
)

// The sentinels that must never appear in a log or on the console: a device
// code, an access token, a refresh token and the minted enrollment token.
const (
	sentinelAccess     = "ACCESS-SENTINEL"
	sentinelRefresh    = "REFRESH-SENTINEL"
	sentinelDeviceCode = "DEVICECODE-SENTINEL"
	sentinelUserCode   = "WXYZ-1234"
)

// assertNoSentinels fails the test if any secret appears in where.
func assertNoSentinels(t *testing.T, where, label string) {
	t.Helper()
	for _, s := range []string{sentinelAccess, sentinelRefresh, sentinelDeviceCode, loginMintedToken} {
		if strings.Contains(where, s) {
			t.Errorf("%s leaked sentinel %q: %s", label, s, where)
		}
	}
}

// TestScenario_SentinelsNeverLeak: tokens and device codes never reach logs
// or the console, across a successful login, a failed login and a failing
// user-session report.
func TestScenario_SentinelsNeverLeak(t *testing.T) {
	goos := "darwin"
	deviceCodeBody, _ := json.Marshal(map[string]interface{}{
		"device_code":      sentinelDeviceCode,
		"user_code":        sentinelUserCode,
		"verification_uri": "https://microsoft.com/devicelogin",
		"expires_in":       900,
		"interval":         5,
	})

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
	swapLoginSeams(t, loginDoer(t, validConfigBody, string(deviceCodeBody), string(tokenBody), 200, 200, 200), loginClock)

	loginStdout, loginStderr := &bytes.Buffer{}, &bytes.Buffer{}
	if exit := run(loginFsys, goos, []string{"login"}, loginStdout, loginStderr); exit != 0 {
		t.Fatalf("login setup failed: exit=%d stderr=%s", exit, loginStderr.String())
	}
	if !strings.Contains(loginStdout.String(), sentinelUserCode) {
		t.Errorf("expected user_code %q on stdout, got: %s", sentinelUserCode, loginStdout.String())
	}
	assertNoSentinels(t, loginStdout.String(), "login stdout")
	assertNoSentinels(t, loginStderr.String(), "login stderr")
	if loginFsys.Exists(agentLogPath(goos)) {
		content, _ := loginFsys.Content(agentLogPath(goos))
		t.Errorf("login should not create an agent log file, found: %s", content)
	}

	// --- A failed login ---------------------------------------------------
	failFsys := fake.NewFS()
	seedLoginConfig(t, failFsys, goos, "https://collector.example")
	failClock := fake.NewClock(time.Unix(1700000000, 0))
	failClock.AutoAdvance = true
	swapLoginSeams(t, loginDoer(t, validConfigBody, string(deviceCodeBody), `{"error":"invalid_client"}`, 200, 200, 400), failClock)

	failStdout, failStderr := &bytes.Buffer{}, &bytes.Buffer{}
	if exit := run(failFsys, goos, []string{"login"}, failStdout, failStderr); exit != 1 {
		t.Fatalf("expected the failing login to exit 1, got %d", exit)
	}
	assertNoSentinels(t, failStdout.String(), "failed login stdout")
	assertNoSentinels(t, failStderr.String(), "failed login stderr")

	// --- A failing user-session report, through a file-backed logger ------
	usFsys := fake.NewFS()
	usClock := fake.NewClock(time.Unix(1700000000, 0))
	const usLogPath = "/agent.log"
	usLogger := logging.New(usFsys, usClock, usLogPath, logging.LevelDebug, "usersession")
	usStore := state.NewStore(usFsys, "/us-state.json")
	if err := usStore.Save(state.State{DeviceID: "d-us", DeviceSecret: strings.Repeat("cd", 32)}); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	usDoer := fake.NewHTTPDoer()
	usDoer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return fake.Response(http.StatusServiceUnavailable, `{"error":"unavailable"}`), nil
	}
	usTransport := client.New(config.Config{CollectionURL: "https://collector.example", EnrollmentToken: loginMintedToken}, usStore, usDoer, usClock)
	usTransport.Logger = usLogger
	runner := fake.NewCommandRunner()
	runner.Results[darwinProbeKey] = platform.CommandResult{Stdout: "amy\n"}
	(&userReporter{transport: usTransport, runner: runner, goos: goos, logger: usLogger}).report(context.Background(), "d-us")

	logContent, _ := usFsys.Content(usLogPath)
	assertNoSentinels(t, string(logContent), "agent log file")
	if strings.Contains(string(logContent), sentinelUserCode) {
		t.Errorf("user_code must never reach the agent log file, found in: %s", logContent)
	}
}
