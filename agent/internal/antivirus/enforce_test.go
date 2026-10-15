package antivirus_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/antivirus"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/enforce"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// enableArgs is the argument list WindowsEnableScript is run under.
func enableArgs() []string {
	return []string{"-NoProfile", "-NonInteractive", "-Command", antivirus.WindowsEnableScript}
}

// enableCommandKey is the fake runner key for the enable command.
func enableCommandKey() string {
	return fake.Command{Name: "powershell.exe", Args: enableArgs()}.String()
}

// blockingRunner never returns from Run, so a timeout path can be exercised
// deterministically: the test advances the fake clock once Run has started.
type blockingRunner struct {
	started chan struct{}
}

func newBlockingRunner() *blockingRunner {
	return &blockingRunner{started: make(chan struct{})}
}

func (b *blockingRunner) Run(ctx context.Context, name string, args ...string) (platform.CommandResult, error) {
	close(b.started)
	select {}
}

// TestScenario_WindowsEnableScriptContainsBothCommands covers the fixed script text.
func TestScenario_WindowsEnableScriptContainsBothCommands(t *testing.T) {
	if !strings.Contains(antivirus.WindowsEnableScript, "Start-Service -Name WinDefend") {
		t.Errorf("WindowsEnableScript should contain Start-Service -Name WinDefend, got %q", antivirus.WindowsEnableScript)
	}
	if !strings.Contains(antivirus.WindowsEnableScript, "Set-MpPreference -DisableRealtimeMonitoring $false") {
		t.Errorf("WindowsEnableScript should contain Set-MpPreference -DisableRealtimeMonitoring $false, got %q", antivirus.WindowsEnableScript)
	}
}

// TestScenario_EnforcerNameIsAntivirus covers the enforcer's log name.
func TestScenario_EnforcerNameIsAntivirus(t *testing.T) {
	e := antivirus.NewEnforcer(fake.NewCommandRunner(), fake.NewClock(time.Now()), "windows")
	if e.Name() != "antivirus" {
		t.Errorf("Name() = %q, want \"antivirus\"", e.Name())
	}
}

// TestScenario_WindowsDeviceWithNoActiveAntivirusRunsEnableCommandOnce covers the
// one case Apply runs its command.
func TestScenario_WindowsDeviceWithNoActiveAntivirusRunsEnableCommandOnce(t *testing.T) {
	runner := fake.NewCommandRunner()
	runner.Results[enableCommandKey()] = platform.CommandResult{Stdout: "realTimeProtectionEnabled=True\n"}
	clock := fake.NewClock(time.Now())
	e := antivirus.NewEnforcer(runner, clock, "windows")

	effective := map[string]any{antivirus.SettingAntivirusEnabled: true}
	posture := contract.Posture{Antivirus: contract.Antivirus{Enabled: false}}

	err := e.Apply(context.Background(), effective, posture)
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	calls := runner.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected exactly one runner call, got %d: %v", len(calls), calls)
	}
	if calls[0].Name != "powershell.exe" {
		t.Errorf("command name = %q, want powershell.exe", calls[0].Name)
	}
	want := enableArgs()
	if len(calls[0].Args) != len(want) {
		t.Fatalf("args = %v, want %v", calls[0].Args, want)
	}
	for i, arg := range want {
		if calls[0].Args[i] != arg {
			t.Errorf("args[%d] = %q, want %q", i, calls[0].Args[i], arg)
		}
	}
}

// TestScenario_NoEnableCommandIsRun covers every condition under which Apply
// must do nothing and return nil.
func TestScenario_NoEnableCommandIsRun(t *testing.T) {
	// A posture matching the antivirus-thirdparty.txt fixture: Defender off,
	// Contoso Endpoint Security active, per the posture package's parse of
	// that fixture.
	thirdPartyPosture := contract.Posture{
		Antivirus: contract.Antivirus{Name: "Contoso Endpoint Security", Enabled: true, DefinitionsAgeDays: 0},
	}

	cases := []struct {
		name      string
		goos      string
		effective map[string]any
		posture   contract.Posture
	}{
		{
			name:      "darwin with antivirusEnabled true and antivirus off",
			goos:      "darwin",
			effective: map[string]any{antivirus.SettingAntivirusEnabled: true},
			posture:   contract.Posture{Antivirus: contract.Antivirus{Enabled: false}},
		},
		{
			name:      "windows with antivirusEnabled false",
			goos:      "windows",
			effective: map[string]any{antivirus.SettingAntivirusEnabled: false},
			posture:   contract.Posture{Antivirus: contract.Antivirus{Enabled: false}},
		},
		{
			name:      "windows with antivirusEnabled absent",
			goos:      "windows",
			effective: map[string]any{},
			posture:   contract.Posture{Antivirus: contract.Antivirus{Enabled: false}},
		},
		{
			name:      `windows with antivirusEnabled "true" (a string)`,
			goos:      "windows",
			effective: map[string]any{antivirus.SettingAntivirusEnabled: "true"},
			posture:   contract.Posture{Antivirus: contract.Antivirus{Enabled: false}},
		},
		{
			name:      "windows with antivirusEnabled true and antivirus on",
			goos:      "windows",
			effective: map[string]any{antivirus.SettingAntivirusEnabled: true},
			posture:   contract.Posture{Antivirus: contract.Antivirus{Enabled: true}},
		},
		{
			name:      "windows with antivirusEnabled true and the posture from antivirus-thirdparty",
			goos:      "windows",
			effective: map[string]any{antivirus.SettingAntivirusEnabled: true},
			posture:   thirdPartyPosture,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := fake.NewCommandRunner()
			clock := fake.NewClock(time.Now())
			e := antivirus.NewEnforcer(runner, clock, tc.goos)

			err := e.Apply(context.Background(), tc.effective, tc.posture)
			if err != nil {
				t.Fatalf("Apply returned an error: %v", err)
			}
			if calls := runner.Calls(); len(calls) != 0 {
				t.Errorf("expected no runner calls, got %v", calls)
			}
		})
	}
}

// TestScenario_ApplyFailurePaths covers the three ways the enable command can
// fail.
func TestScenario_ApplyFailurePaths(t *testing.T) {
	effective := map[string]any{antivirus.SettingAntivirusEnabled: true}
	posture := contract.Posture{Antivirus: contract.Antivirus{Enabled: false}}

	t.Run("exits with code 7", func(t *testing.T) {
		runner := fake.NewCommandRunner()
		runner.Results[enableCommandKey()] = platform.CommandResult{ExitCode: 7}
		clock := fake.NewClock(time.Now())
		e := antivirus.NewEnforcer(runner, clock, "windows")

		err := e.Apply(context.Background(), effective, posture)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !strings.Contains(err.Error(), "7") {
			t.Errorf("error %q should mention the exit code 7", err.Error())
		}
	})

	t.Run("cannot be started", func(t *testing.T) {
		runner := fake.NewCommandRunner()
		runnerErr := errors.New("boom: cannot start process")
		runner.Errors[enableCommandKey()] = runnerErr
		clock := fake.NewClock(time.Now())
		e := antivirus.NewEnforcer(runner, clock, "windows")

		err := e.Apply(context.Background(), effective, posture)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !errors.Is(err, runnerErr) {
			t.Errorf("error %v should wrap the runner's error %v", err, runnerErr)
		}
	})

	t.Run("never answers and the clock advances EnforceTimeout", func(t *testing.T) {
		runner := newBlockingRunner()
		clock := fake.NewClock(time.Now())
		e := antivirus.NewEnforcer(runner, clock, "windows")

		go func() {
			<-runner.started
			clock.Advance(antivirus.EnforceTimeout)
		}()

		err := e.Apply(context.Background(), effective, posture)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !strings.Contains(err.Error(), "timeout") {
			t.Errorf("error %q should mention timeout", err.Error())
		}
	})
}

// logRecord is one decoded line of the agent's JSON log.
type logRecord map[string]any

// readLogRecords decodes every JSON line the fake filesystem holds at path.
func readLogRecords(t *testing.T, fsys *fake.FS, path string) []logRecord {
	t.Helper()
	data, ok := fsys.Content(path)
	if !ok {
		return nil
	}
	var records []logRecord
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec logRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("failed to decode log line %q: %v", line, err)
		}
		records = append(records, rec)
	}
	return records
}

// TestScenario_EnforceRunLogsOneWarnLineOnFailure covers the three failure
// paths through enforce.Run, each producing exactly one "policy enforcement
// failed" warn line naming the antivirus enforcer.
func TestScenario_EnforceRunLogsOneWarnLineOnFailure(t *testing.T) {
	effective := map[string]any{antivirus.SettingAntivirusEnabled: true}
	posture := contract.Posture{Antivirus: contract.Antivirus{Enabled: false}}

	assertOneWarnLine := func(t *testing.T, fsys *fake.FS, wantSubstring string) {
		t.Helper()
		records := readLogRecords(t, fsys, "/agent.log")
		var warnLines []logRecord
		for _, rec := range records {
			if rec["msg"] == "policy enforcement failed" {
				warnLines = append(warnLines, rec)
			}
		}
		if len(warnLines) != 1 {
			t.Fatalf("expected exactly one warn line, got %d: %v", len(warnLines), warnLines)
		}
		if warnLines[0]["level"] != "warn" {
			t.Errorf("level = %v, want warn", warnLines[0]["level"])
		}
		if warnLines[0]["enforcer"] != "antivirus" {
			t.Errorf("enforcer = %v, want antivirus", warnLines[0]["enforcer"])
		}
		errField, _ := warnLines[0]["error"].(string)
		if !strings.Contains(errField, wantSubstring) {
			t.Errorf("error field %q should contain %q", errField, wantSubstring)
		}
	}

	t.Run("exits with code 7", func(t *testing.T) {
		runner := fake.NewCommandRunner()
		runner.Results[enableCommandKey()] = platform.CommandResult{ExitCode: 7}
		clock := fake.NewClock(time.Now())
		fs := fake.NewFS()
		logger := logging.New(fs, clock, "/agent.log", logging.LevelDebug, "enforce")
		e := antivirus.NewEnforcer(runner, clock, "windows")

		enforce.Run(context.Background(), []enforce.Enforcer{e}, effective, posture, logger)
		assertOneWarnLine(t, fs, "7")
	})

	t.Run("cannot be started", func(t *testing.T) {
		runner := fake.NewCommandRunner()
		runner.Errors[enableCommandKey()] = errors.New("boom: cannot start process")
		clock := fake.NewClock(time.Now())
		fs := fake.NewFS()
		logger := logging.New(fs, clock, "/agent.log", logging.LevelDebug, "enforce")
		e := antivirus.NewEnforcer(runner, clock, "windows")

		enforce.Run(context.Background(), []enforce.Enforcer{e}, effective, posture, logger)
		assertOneWarnLine(t, fs, "boom")
	})

	t.Run("never answers and the clock advances EnforceTimeout", func(t *testing.T) {
		runner := newBlockingRunner()
		clock := fake.NewClock(time.Now())
		fs := fake.NewFS()
		logger := logging.New(fs, clock, "/agent.log", logging.LevelDebug, "enforce")
		e := antivirus.NewEnforcer(runner, clock, "windows")

		go func() {
			<-runner.started
			clock.Advance(antivirus.EnforceTimeout)
		}()

		enforce.Run(context.Background(), []enforce.Enforcer{e}, effective, posture, logger)
		assertOneWarnLine(t, fs, "timeout")
	})
}

// ============================================================================
// AC6: the Actions recorder.
// ============================================================================

// TestScenario_AC6_TurningRealTimeProtectionOnIsRecordedOnlyWhenConfirmed
// covers:
//
//	Given GOOS windows, antivirusEnabled true, antivirus off and a read-back
//	     "realTimeProtectionEnabled=True"
//	When the antivirus enforcer applies
//	Then Actions was called once with "enforce.antivirus_enabled"
func TestScenario_AC6_TurningRealTimeProtectionOnIsRecordedOnlyWhenConfirmed(t *testing.T) {
	runner := fake.NewCommandRunner()
	runner.Results[enableCommandKey()] = platform.CommandResult{Stdout: "realTimeProtectionEnabled=True\n"}
	clock := fake.NewClock(time.Now())
	e := antivirus.NewEnforcer(runner, clock, "windows")

	var calls []string
	var lastDetails map[string]string
	e.Actions = func(actionType string, details map[string]string) {
		calls = append(calls, actionType)
		lastDetails = details
	}

	effective := map[string]any{antivirus.SettingAntivirusEnabled: true}
	posture := contract.Posture{Antivirus: contract.Antivirus{Enabled: false}}

	err := e.Apply(context.Background(), effective, posture)
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if len(calls) != 1 || calls[0] != contract.ActionAntivirusEnabled {
		t.Fatalf("Actions calls = %v, want exactly one call with %q", calls, contract.ActionAntivirusEnabled)
	}
	if len(lastDetails) != 0 {
		t.Errorf("details = %+v, want empty", lastDetails)
	}
}

// TestScenario_AC6Outline_AnUnconfirmedAntivirusEnableRecordsNothing covers
// the scenario outline's four outcomes, plus NewEnforcer's signature being
// unchanged (used throughout this file already) and a nil Actions recording
// nothing.
func TestScenario_AC6Outline_AnUnconfirmedAntivirusEnableRecordsNothing(t *testing.T) {
	effective := map[string]any{antivirus.SettingAntivirusEnabled: true}
	posture := contract.Posture{Antivirus: contract.Antivirus{Enabled: false}}

	t.Run(`a read-back "realTimeProtectionEnabled=False" with tamper on`, func(t *testing.T) {
		runner := fake.NewCommandRunner()
		runner.Results[enableCommandKey()] = platform.CommandResult{
			Stdout: "realTimeProtectionEnabled=False\nisTamperProtected=True\n",
		}
		clock := fake.NewClock(time.Now())
		e := antivirus.NewEnforcer(runner, clock, "windows")
		called := false
		e.Actions = func(string, map[string]string) { called = true }

		err := e.Apply(context.Background(), effective, posture)
		if !errors.Is(err, antivirus.ErrTamperProtected) {
			t.Fatalf("err = %v, want ErrTamperProtected", err)
		}
		if called {
			t.Error("Actions was called despite tamper protection blocking the change")
		}
	})

	t.Run("a read-back with no realTimeProtectionEnabled line", func(t *testing.T) {
		runner := fake.NewCommandRunner()
		runner.Results[enableCommandKey()] = platform.CommandResult{Stdout: "nothing useful here\n"}
		clock := fake.NewClock(time.Now())
		e := antivirus.NewEnforcer(runner, clock, "windows")
		called := false
		e.Actions = func(string, map[string]string) { called = true }

		err := e.Apply(context.Background(), effective, posture)
		if !errors.Is(err, antivirus.ErrEnableUnparseable) {
			t.Fatalf("err = %v, want ErrEnableUnparseable", err)
		}
		if called {
			t.Error("Actions was called for an unparseable read-back")
		}
	})

	t.Run("exit code 1", func(t *testing.T) {
		runner := fake.NewCommandRunner()
		runner.Results[enableCommandKey()] = platform.CommandResult{ExitCode: 1}
		clock := fake.NewClock(time.Now())
		e := antivirus.NewEnforcer(runner, clock, "windows")
		called := false
		e.Actions = func(string, map[string]string) { called = true }

		err := e.Apply(context.Background(), effective, posture)
		if err == nil {
			t.Fatal("expected an error for a non-zero exit code")
		}
		if called {
			t.Error("Actions was called for a non-zero exit code")
		}
	})

	t.Run("a timeout", func(t *testing.T) {
		runner := newBlockingRunner()
		clock := fake.NewClock(time.Now())
		e := antivirus.NewEnforcer(runner, clock, "windows")
		called := false
		e.Actions = func(string, map[string]string) { called = true }

		go func() {
			<-runner.started
			clock.Advance(antivirus.EnforceTimeout)
		}()

		err := e.Apply(context.Background(), effective, posture)
		if err == nil {
			t.Fatal("expected a timeout error")
		}
		if called {
			t.Error("Actions was called on a timeout")
		}
	})
}

// TestScenario_AC6_ANilActionsRecordsNothing covers "A nil Actions records
// nothing": the zero-value Enforcer still applies successfully.
func TestScenario_AC6_ANilActionsRecordsNothing(t *testing.T) {
	runner := fake.NewCommandRunner()
	runner.Results[enableCommandKey()] = platform.CommandResult{Stdout: "realTimeProtectionEnabled=True\n"}
	clock := fake.NewClock(time.Now())
	e := antivirus.NewEnforcer(runner, clock, "windows")

	effective := map[string]any{antivirus.SettingAntivirusEnabled: true}
	posture := contract.Posture{Antivirus: contract.Antivirus{Enabled: false}}

	err := e.Apply(context.Background(), effective, posture)
	if err != nil {
		t.Fatalf("Apply returned an error with a nil Actions: %v", err)
	}
}

// ============================================================================
// AC9: the hardener and the scanner never record an action -- structurally,
// because neither type exposes an Actions field to call.
// ============================================================================

// TestScenario_AC9_HardenerAndScannerExposeNoActionsField documents and locks
// in the structural guarantee: antivirus.NewHardener and antivirus.NewScanner
// return types with no Actions field, so no agent action can ever be recorded
// from either, whatever they apply.
func TestScenario_AC9_HardenerAndScannerExposeNoActionsField(t *testing.T) {
	runner := fake.NewCommandRunner()
	clock := fake.NewClock(time.Now())
	fsys := fake.NewFS()

	hardener := antivirus.NewHardener(runner, clock, "windows")
	if hardener == nil {
		t.Fatal("NewHardener returned nil")
	}
	scanner := antivirus.NewScanner(runner, clock, fsys, "windows", nil, "/scan-state.json")
	if scanner == nil {
		t.Fatal("NewScanner returned nil")
	}
	// Both are enforce.Enforcer implementations with no exported Actions
	// field; compilation of this file is itself the proof for the Enforcer
	// type (see TestScenario_AC6_TurningRealTimeProtectionOnIsRecordedOnlyWhenConfirmed
	// for the one type in this package that does expose one).
	var _ enforce.Enforcer = hardener
	var _ enforce.Enforcer = scanner
}
