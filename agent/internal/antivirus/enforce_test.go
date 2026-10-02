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
