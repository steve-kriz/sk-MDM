// E2E cucumber-style tests for TASK-061's self-update exit-to-restart (AC7,
// AC8, AC9, AC13). Nothing here opens a real process, network connection,
// sc.exe/launchctl or database: FS, the command runner and the HTTP doer are
// all fakes, and dispatch/managed/newRunner/executablePath are swapped for the
// duration of each test.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/service"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

// runSeams is what one test overrides the package-level wiring seams with.
type runSeams struct {
	runner   platform.CommandRunner
	clock    platform.Clock
	doer     platform.HTTPDoer
	hostname string
	exePath  string
	exeErr   error
	managed  bool
	dispatch func(ctx context.Context, hooks service.Hooks) error
}

// swapRunSeams overrides newRunner, newClock, newDoer, hostName,
// executablePath, managed, dispatch and signalContext for the duration of the
// test, restoring every one of them on cleanup.
func swapRunSeams(t *testing.T, s runSeams) {
	t.Helper()
	origRunner, origClock, origDoer := newRunner, newClock, newDoer
	origHost, origExe, origManaged, origDispatch, origSignal := hostName, executablePath, managed, dispatch, signalContext

	newRunner = func() platform.CommandRunner { return s.runner }
	newClock = func() platform.Clock { return s.clock }
	newDoer = func() platform.HTTPDoer { return s.doer }
	hostName = func() (string, error) { return s.hostname, nil }
	executablePath = func() (string, error) { return s.exePath, s.exeErr }
	managed = func() bool { return s.managed }
	if s.dispatch != nil {
		dispatch = s.dispatch
	}
	// Never register a real OS signal handler in a test.
	signalContext = func(parent context.Context) (context.Context, context.CancelFunc) {
		return context.WithCancel(parent)
	}

	t.Cleanup(func() {
		newRunner, newClock, newDoer = origRunner, origClock, origDoer
		hostName, executablePath, managed, dispatch, signalContext = origHost, origExe, origManaged, origDispatch, origSignal
	})
}

// seedRestartConfig seeds a minimal valid config at goos's config path.
func seedRestartConfig(t *testing.T, fsys *fake.FS, goos string) {
	t.Helper()
	data, err := json.Marshal(config.Config{CollectionURL: "https://collect.example.com"})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	fsys.Seed(config.Path(goos), data)
}

// seedPendingRollback arranges a pending update that settleUpdate rolls back:
// the marker names a version other than the one the test binary reports
// (version.Version, "0.0.0-dev"), and the replaced binary is still at
// "<binary>.old", so RollbackIfUnhealthy's Restart hook -- service.Restart --
// returns the sentinel immediately, with no probe, no HTTP request and no
// sc.exe/launchctl call.
func seedPendingRollback(fsys *fake.FS, binary string) {
	fsys.Seed(binary+".old", []byte("old binary"))
	fsys.Seed(binary+".update-pending", []byte("9.9.9"))
}

// ----------------------------------------------------------------------------
// AC7: a foreground agent exits with code 3 to be restarted.
// ----------------------------------------------------------------------------

func TestScenario_AC7_ForegroundAgentExitsWithCodeThreeToBeRestarted(t *testing.T) {
	fsys := fake.NewFS()
	binary := `C:\mdmagent.exe`
	seedRestartConfig(t, fsys, "windows")
	seedPendingRollback(fsys, binary)

	// Given managed() returns false
	// And the agent's scheduler run ends with service.ErrRestartRequired
	// (here, via the rollback settleUpdate performs before the scheduler ever
	// starts -- the end result service.Run sees is the same sentinel)
	swapRunSeams(t, runSeams{
		runner:   fake.NewCommandRunner(),
		clock:    fake.NewClock(time.Now()),
		doer:     fake.NewHTTPDoer(),
		hostname: "host",
		exePath:  binary,
		managed:  false,
	})

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}

	// When runAgent runs
	code := runAgent(fsys, "windows", nil, stdout, stderr)

	// Then the exit code is 3
	if code != exitRestart {
		t.Fatalf("exit code = %d, want %d (stderr=%s)", code, exitRestart, stderr.String())
	}
	// And stdout contains "mdmagent restarting to apply an update"
	if !strings.Contains(stdout.String(), "mdmagent restarting to apply an update") {
		t.Errorf("stdout = %q", stdout.String())
	}
	// And stderr is empty
	if stderr.String() != "" {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

// ----------------------------------------------------------------------------
// AC8: a rollback at start-up hands the restart to the service manager.
// ----------------------------------------------------------------------------

func TestScenario_AC8_RollbackHandsRestartToServiceManager(t *testing.T) {
	fsys := fake.NewFS()
	doer := fake.NewHTTPDoer()
	binary := `C:\mdmagent.exe`
	seedRestartConfig(t, fsys, "windows")
	// Given "<path>.update-pending" contains "9.9.9" while the running
	// version is the test binary's, and "<path>.old" exists
	seedPendingRollback(fsys, binary)

	a, err := newAgent(agentEnv{
		FS:         fsys,
		Runner:     fake.NewCommandRunner(),
		Clock:      fake.NewClock(time.Now()),
		Doer:       doer,
		GOOS:       "windows",
		ConfigPath: config.Path("windows"),
		StatePath:  state.StatePath("windows"),
		BinaryPath: binary,
	})
	if err != nil {
		t.Fatalf("newAgent: %v", err)
	}

	// When the agent settles the update and its Start hook is called
	a.settleUpdate()
	startErr := a.hooks().Start(context.Background())

	// Then "<path>.old" has been renamed back to "<path>"
	content, ok := fsys.Content(binary)
	if !ok || string(content) != "old binary" {
		t.Errorf("binary = %q (exists=%v), want the old bytes restored", content, ok)
	}
	// And no "update could not be settled" line is logged
	logged, _ := fsys.Content(agentLogPath("windows"))
	if strings.Contains(string(logged), "update could not be settled") {
		t.Errorf("log should not contain 'update could not be settled':\n%s", logged)
	}
	// And Start returns an error matching service.ErrRestartRequired without
	// calling scheduler.Run, starting the sign-in broker or the heartbeat
	if !errors.Is(startErr, service.ErrRestartRequired) {
		t.Errorf("Start returned %v, want ErrRestartRequired", startErr)
	}
	// And the fake HTTP doer recorded 0 requests
	if n := len(doer.Requests()); n != 0 {
		t.Errorf("doer recorded %d requests, want 0", n)
	}
}

// ----------------------------------------------------------------------------
// AC9: a rollback that cannot rename still lets the agent run.
// ----------------------------------------------------------------------------

func TestScenario_AC9_RollbackRenameFailureStillRuns(t *testing.T) {
	fsys := fake.NewFS()
	binary := `C:\mdmagent.exe`
	seedRestartConfig(t, fsys, "windows")
	// Given a pending marker naming another version and no "<path>.old" file
	fsys.Seed(binary+".update-pending", []byte("9.9.9"))

	a, err := newAgent(agentEnv{
		FS:         fsys,
		Runner:     fake.NewCommandRunner(),
		Clock:      fake.NewClock(time.Now()),
		Doer:       fake.NewHTTPDoer(),
		GOOS:       "windows",
		ConfigPath: config.Path("windows"),
		StatePath:  state.StatePath("windows"),
		BinaryPath: binary,
	})
	if err != nil {
		t.Fatalf("newAgent: %v", err)
	}

	// When the agent settles the update
	a.settleUpdate()

	// Then exactly one line starting "update could not be settled:" is logged
	logged, _ := fsys.Content(agentLogPath("windows"))
	if n := strings.Count(string(logged), `"msg":"update could not be settled:`); n != 1 {
		t.Fatalf("got %d 'update could not be settled:' lines, want 1:\n%s", n, logged)
	}

	// And the Start hook runs the scheduler loop: with an already-cancelled
	// context, Start reaches scheduler.Run (which returns ctx.Err() at once)
	// rather than short-circuiting with the restart sentinel the way AC8 does.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	startErr := a.hooks().Start(ctx)
	if !errors.Is(startErr, context.Canceled) {
		t.Errorf("Start returned %v, want context.Canceled (proof it reached scheduler.Run)", startErr)
	}
}

// ----------------------------------------------------------------------------
// AC13: a managed Windows start reapplies recovery before dispatch.
// ----------------------------------------------------------------------------

func TestScenario_AC13_ManagedWindowsStartReappliesRecoveryBeforeDispatch(t *testing.T) {
	fsys := fake.NewFS()
	seedRestartConfig(t, fsys, "windows")
	runner := fake.NewCommandRunner()

	var dispatchCalls int
	var recoveryCallsWhenDispatched int

	// Given goos "windows" and managed() returns true
	swapRunSeams(t, runSeams{
		runner:   runner,
		clock:    fake.NewClock(time.Now()),
		doer:     fake.NewHTTPDoer(),
		hostname: "host",
		exeErr:   errors.New("no executable path in this test"),
		managed:  true,
		dispatch: func(ctx context.Context, hooks service.Hooks) error {
			dispatchCalls++
			recoveryCallsWhenDispatched = len(runner.Calls())
			return nil
		},
	})

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}

	// When runAgent runs
	code := runAgent(fsys, "windows", nil, stdout, stderr)

	if code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr=%s)", code, exitOK, stderr.String())
	}
	// Then the "sc.exe failure" and "sc.exe failureflag" calls are recorded
	// before dispatch is invoked
	calls := runner.Calls()
	if len(calls) != 2 || calls[0].Args[0] != "failure" || calls[1].Args[0] != "failureflag" {
		t.Fatalf("runner calls = %v, want sc.exe failure then failureflag", calls)
	}
	if recoveryCallsWhenDispatched != 2 {
		t.Errorf("recovery calls recorded by the time dispatch ran = %d, want 2", recoveryCallsWhenDispatched)
	}
	// And dispatch is invoked once
	if dispatchCalls != 1 {
		t.Errorf("dispatch called %d times, want 1", dispatchCalls)
	}
}

// AC13 failure: a recovery configuration failure does not stop the service
// starting.
func TestScenario_AC13_RecoveryFailureDoesNotStopServiceStarting(t *testing.T) {
	fsys := fake.NewFS()
	seedRestartConfig(t, fsys, "windows")
	runner := fake.NewCommandRunner()
	// Given goos "windows", managed() returns true and "sc.exe failure" exits 5
	runner.Results[`sc.exe failure OfficeHQMDMAgent reset= 86400 actions= restart/5000/restart/5000/restart/5000`] =
		platform.CommandResult{ExitCode: 5}

	var dispatchCalls int
	swapRunSeams(t, runSeams{
		runner:   runner,
		clock:    fake.NewClock(time.Now()),
		doer:     fake.NewHTTPDoer(),
		hostname: "host",
		exeErr:   errors.New("no executable path in this test"),
		managed:  true,
		dispatch: func(ctx context.Context, hooks service.Hooks) error {
			dispatchCalls++
			return nil
		},
	})

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}

	// When runAgent runs
	code := runAgent(fsys, "windows", nil, stdout, stderr)

	if code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr=%s)", code, exitOK, stderr.String())
	}
	// And dispatch is invoked once (the service still starts)
	if dispatchCalls != 1 {
		t.Fatalf("dispatch called %d times, want 1", dispatchCalls)
	}
	// Then exactly one warn line "service recovery could not be configured"
	// with an error field is logged
	logged, _ := fsys.Content(agentLogPath("windows"))
	count := 0
	for _, raw := range strings.Split(strings.TrimSpace(string(logged)), "\n") {
		if raw == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			continue
		}
		if m["msg"] != "service recovery could not be configured" {
			continue
		}
		count++
		if m["level"] != "warn" {
			t.Errorf("level = %v, want warn", m["level"])
		}
		if _, ok := m["error"]; !ok {
			t.Errorf("warn line missing an error field: %v", m)
		}
	}
	if count != 1 {
		t.Fatalf("got %d 'service recovery could not be configured' lines, want 1:\n%s", count, logged)
	}
}

// AC13 edge: no recovery calls outside the SCM or on macOS.
func TestScenario_AC13_NoRecoveryCallsOutsideSCMOrOnMacOS(t *testing.T) {
	cases := []struct {
		goos       string
		managedVal bool
	}{
		{"windows", false},
		{"darwin", false},
	}
	for _, tc := range cases {
		t.Run(tc.goos, func(t *testing.T) {
			fsys := fake.NewFS()
			seedRestartConfig(t, fsys, tc.goos)
			binary := `C:\mdmagent.exe`
			// The sentinel is reached via the same rollback trick as AC7, so
			// runAgent's foreground path returns promptly either way.
			seedPendingRollback(fsys, binary)

			runner := fake.NewCommandRunner()
			swapRunSeams(t, runSeams{
				runner:   runner,
				clock:    fake.NewClock(time.Now()),
				doer:     fake.NewHTTPDoer(),
				hostname: "host",
				exePath:  binary,
				managed:  tc.managedVal,
			})

			stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}

			// Given goos "<goos>" and managed() returns <managed>
			// When runAgent runs
			code := runAgent(fsys, tc.goos, nil, stdout, stderr)

			if code != exitRestart {
				t.Fatalf("exit code = %d, want %d (stderr=%s)", code, exitRestart, stderr.String())
			}
			// Then no "sc.exe failure" or "sc.exe failureflag" call was recorded
			for _, call := range runner.Calls() {
				if call.Name == "sc.exe" && len(call.Args) > 0 && (call.Args[0] == "failure" || call.Args[0] == "failureflag") {
					t.Errorf("unexpected recovery call: %v", call)
				}
			}
		})
	}
}
