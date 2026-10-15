package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/client"
	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

const testLogFile = "test.log"

var testDeviceSecret = strings.Repeat("ab", 32)

func newTestLogger(fsys *fake.FS) *logging.Logger {
	return logging.New(fsys, fake.NewClock(time.Unix(1700000000, 0)), testLogFile, logging.LevelDebug, "usersession")
}

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
	st := state.State{DeviceID: "d1", DeviceSecret: testDeviceSecret}
	if err := state.NewStore(fsys, state.StatePath(goos)).Save(st); err != nil {
		t.Fatalf("seed state: %v", err)
	}
}

// newTestAgent assembles the production agent (newAgent) over fakes, so a
// test exercises the exact wiring in run.go: AfterCheckIn reporting the
// console user before executor.Poll.
func newTestAgent(t *testing.T, fsys *fake.FS, doer *fake.HTTPDoer, runner platform.CommandRunner, clock *fake.Clock, goos string) *agent {
	t.Helper()
	ag, err := newAgent(agentEnv{
		FS:         fsys,
		Runner:     runner,
		Clock:      clock,
		Doer:       doer,
		GOOS:       goos,
		ConfigPath: config.Path(goos),
		StatePath:  state.StatePath(goos),
		Hostname:   "test-host",
	})
	if err != nil {
		t.Fatalf("newAgent: %v", err)
	}
	return ag
}

func isLeasePath(path string) bool { return strings.Contains(path, "/commands") }
func isUserSessionPath(path string) bool {
	return strings.HasSuffix(path, "/user-session")
}

// The probe commands, keyed the way fake.CommandRunner looks them up.
var (
	windowsProbeKey = fake.Command{Name: windowsConsoleUserShell, Args: windowsConsoleUserArgs}.String()
	darwinProbeKey  = fake.Command{Name: darwinConsoleUserCmd, Args: darwinConsoleUserArgs}.String()
)

func TestConsoleUser(t *testing.T) {
	cases := []struct {
		goos, stdout string
		exit         int
		want         *string
	}{
		{"windows", "AzureAD\\amy\r\n", 0, ptr(`AzureAD\amy`)},
		{"windows", "  \r\n", 0, nil},
		{"windows", "", 0, nil},
		{"darwin", "amy\n", 0, ptr("amy")},
		{"darwin", "root\n", 0, nil},
		{"darwin", "loginwindow\n", 0, nil},
		{"darwin", "\n", 0, nil},
	}
	for _, tc := range cases {
		runner := fake.NewCommandRunner()
		key := darwinProbeKey
		if tc.goos == "windows" {
			key = windowsProbeKey
		}
		runner.Results[key] = platform.CommandResult{Stdout: tc.stdout, ExitCode: tc.exit}
		got, err := consoleUser(context.Background(), runner, tc.goos)
		if err != nil {
			t.Errorf("%s %q: %v", tc.goos, tc.stdout, err)
			continue
		}
		if !sameUser(got, tc.want) {
			t.Errorf("%s %q: got %v, want %v", tc.goos, tc.stdout, deref(got), deref(tc.want))
		}
		calls := runner.Calls()
		if len(calls) != 1 || calls[0].String() != key {
			t.Errorf("%s: calls = %v", tc.goos, calls)
		}
	}

	// The exact commands the spec names.
	if windowsProbeKey != "powershell.exe -NoProfile -NonInteractive -Command (Get-CimInstance Win32_ComputerSystem).UserName" {
		t.Errorf("windows probe = %s", windowsProbeKey)
	}
	if darwinProbeKey != "stat -f%Su /dev/console" {
		t.Errorf("darwin probe = %s", darwinProbeKey)
	}

	// A probe that fails or exits non-zero is an error, not "nobody".
	runner := fake.NewCommandRunner()
	runner.Errors[darwinProbeKey] = errors.New("no stat")
	if _, err := consoleUser(context.Background(), runner, "darwin"); err == nil {
		t.Error("start failure: want an error")
	}
	runner = fake.NewCommandRunner()
	runner.Results[windowsProbeKey] = platform.CommandResult{ExitCode: 1, Stderr: "boom"}
	if _, err := consoleUser(context.Background(), runner, "windows"); err == nil {
		t.Error("non-zero exit: want an error")
	}
}

// After a successful check-in the console user is reported in a signed POST
// whose body {"username": ...} is covered by the signature, before the command
// poll; the change is logged once.
func TestScenario_ConsoleUserReportedAfterCheckIn(t *testing.T) {
	fsys := fake.NewFS()
	goos := "windows"
	clock := fake.NewClock(time.Unix(1700000000, 0))
	seedEnrolledAgent(t, fsys, goos)
	runner := fake.NewCommandRunner()
	runner.Results[windowsProbeKey] = platform.CommandResult{Stdout: "OFFICEHQ\\amy\r\n"}

	var order []string
	var bodies []string
	doer := fake.NewHTTPDoer()
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		switch {
		case isUserSessionPath(req.URL.Path):
			order = append(order, "user-session")
			body, _ := io.ReadAll(req.Body)
			bodies = append(bodies, string(body))
			if req.Method != http.MethodPost || req.URL.Path != "/api/v1/devices/d1/user-session" {
				t.Errorf("request = %s %s", req.Method, req.URL.Path)
			}
			if req.Header.Get("Authorization") != "" {
				t.Error("no bearer may be sent")
			}
			ts, _ := strconv.ParseInt(req.Header.Get(client.HeaderTimestamp), 10, 64)
			parts := contract.SigningParts{
				Method: req.Method, Path: req.URL.EscapedPath(), Query: req.URL.RawQuery, Body: body,
				Timestamp: ts, Nonce: req.Header.Get(client.HeaderNonce), DeviceID: req.Header.Get(client.HeaderDeviceID),
			}
			if !contract.VerifySignature(testDeviceSecret, parts, req.Header.Get(client.HeaderSignature)) {
				t.Error("signature does not cover the body")
			}
			return fake.Response(http.StatusOK, `{"user":{"username":"OFFICEHQ\\amy"}}`), nil
		case isLeasePath(req.URL.Path):
			order = append(order, "lease")
			return fake.Response(http.StatusOK, `{"commands":[]}`), nil
		}
		t.Fatalf("unexpected request to %s", req.URL.Path)
		return nil, nil
	}

	ag := newTestAgent(t, fsys, doer, runner, clock, goos)
	for i := 0; i < 2; i++ {
		if err := ag.deps.AfterCheckIn(context.Background(), contract.CheckInResponse{}); err != nil {
			t.Fatalf("AfterCheckIn: %v", err)
		}
	}

	if strings.Join(order, ",") != "user-session,lease,user-session,lease" {
		t.Fatalf("order = %v", order)
	}
	for _, b := range bodies {
		var sent map[string]any
		if err := json.Unmarshal([]byte(b), &sent); err != nil || sent["username"] != `OFFICEHQ\amy` || len(sent) != 1 {
			t.Errorf("body = %s", b)
		}
	}
	logged, _ := fsys.Content(agentLogPath(goos))
	if n := strings.Count(string(logged), msgUserReported); n != 1 {
		t.Errorf("%q logged %d times, want 1:\n%s", msgUserReported, n, logged)
	}
	if !strings.Contains(string(logged), `"username":"OFFICEHQ\\amy"`) {
		t.Errorf("username not logged:\n%s", logged)
	}
}

// Nobody at the console is reported as null, and a change of user is logged
// again.
func TestUserReporter_NullAndChangeLogged(t *testing.T) {
	fsys := fake.NewFS()
	logger := newTestLogger(fsys)
	runner := fake.NewCommandRunner()
	var bodies []string
	transport := doFunc(func(method, path string, body []byte) (*http.Response, error) {
		bodies = append(bodies, string(body))
		return fake.Response(http.StatusOK, `{}`), nil
	})
	r := &userReporter{transport: transport, runner: runner, goos: "darwin", logger: logger}

	for _, user := range []string{"root\n", "root\n", "amy\n", "amy\n", "bob\n"} {
		runner.Results[darwinProbeKey] = platform.CommandResult{Stdout: user}
		r.report(context.Background(), "d1")
	}
	want := []string{`{"username":null}`, `{"username":null}`, `{"username":"amy"}`, `{"username":"amy"}`, `{"username":"bob"}`}
	if strings.Join(bodies, " ") != strings.Join(want, " ") {
		t.Errorf("bodies = %v", bodies)
	}
	logged, _ := fsys.Content(testLogFile)
	if n := strings.Count(string(logged), msgUserReported); n != 3 {
		t.Errorf("reported logged %d times, want 3:\n%s", n, logged)
	}
	if !strings.Contains(string(logged), `"username":null`) {
		t.Errorf("null user not logged:\n%s", logged)
	}
}

// Every failure costs exactly one warning line and never touches the device
// credential or the command poll.
func TestScenario_ConsoleUserFailuresCostNothing(t *testing.T) {
	cases := []struct {
		name    string
		probe   func(r *fake.CommandRunner)
		answer  func() (*http.Response, error)
		posted  bool
		warning string
	}{
		{
			name:    "probe cannot start",
			probe:   func(r *fake.CommandRunner) { r.Errors[windowsProbeKey] = errors.New("no powershell") },
			warning: "signed-in user could not be read",
		},
		{
			name:    "probe exits non-zero",
			probe:   func(r *fake.CommandRunner) { r.Results[windowsProbeKey] = platform.CommandResult{ExitCode: 1} },
			warning: "signed-in user could not be read",
		},
		{
			name:    "transport error",
			answer:  func() (*http.Response, error) { return nil, errors.New("connection reset") },
			posted:  true,
			warning: "signed-in user could not be reported",
		},
		{
			name: "401",
			answer: func() (*http.Response, error) {
				return fake.Response(http.StatusUnauthorized, `{"error":"invalid_signature"}`), nil
			},
			posted:  true,
			warning: "signed-in user could not be reported",
		},
		{
			name: "400",
			answer: func() (*http.Response, error) {
				return fake.Response(http.StatusBadRequest, `{"error":"invalid_request"}`), nil
			},
			posted:  true,
			warning: "signed-in user not accepted",
		},
		{
			name:    "503",
			answer:  func() (*http.Response, error) { return fake.Response(http.StatusServiceUnavailable, `{}`), nil },
			posted:  true,
			warning: "signed-in user not accepted",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fake.NewFS()
			goos := "windows"
			clock := fake.NewClock(time.Unix(1700000000, 0))
			seedEnrolledAgent(t, fsys, goos)
			runner := fake.NewCommandRunner()
			runner.Results[windowsProbeKey] = platform.CommandResult{Stdout: "amy"}
			if tc.probe != nil {
				tc.probe(runner)
			}
			posted, leased := false, false
			doer := fake.NewHTTPDoer()
			doer.DoFunc = func(req *http.Request) (*http.Response, error) {
				switch {
				case isUserSessionPath(req.URL.Path):
					posted = true
					return tc.answer()
				case isLeasePath(req.URL.Path):
					leased = true
					return fake.Response(http.StatusOK, `{"commands":[]}`), nil
				}
				return fake.Response(http.StatusOK, `{}`), nil
			}
			ag := newTestAgent(t, fsys, doer, runner, clock, goos)
			if err := ag.deps.AfterCheckIn(context.Background(), contract.CheckInResponse{}); err != nil {
				t.Fatalf("AfterCheckIn: %v", err)
			}
			if posted != tc.posted {
				t.Errorf("posted = %v, want %v", posted, tc.posted)
			}
			if !leased {
				t.Error("the command poll must still run")
			}
			st, _ := state.NewStore(fsys, state.StatePath(goos)).Load()
			if st.DeviceID != "d1" || st.DeviceSecret != testDeviceSecret {
				t.Errorf("credential changed: %+v", st)
			}
			logged, _ := fsys.Content(agentLogPath(goos))
			if n := strings.Count(string(logged), `"level":"warn","msg":"signed-in user`); n != 1 {
				t.Errorf("warnings = %d, want 1:\n%s", n, logged)
			}
			if !strings.Contains(string(logged), tc.warning) {
				t.Errorf("missing %q:\n%s", tc.warning, logged)
			}
			if strings.Contains(string(logged), msgUserReported) {
				t.Error("a failure must not log the user as reported")
			}
		})
	}
}

// doFunc is a signedTransport from a function.
type doFunc func(method, path string, body []byte) (*http.Response, error)

func (f doFunc) Do(method, path string, body []byte) (*http.Response, error) {
	return f(method, path, body)
}

func ptr(s string) *string { return &s }

func deref(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}
