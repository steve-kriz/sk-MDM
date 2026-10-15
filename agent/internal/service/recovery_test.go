// E2E cucumber-style tests for TASK-061's Windows service recovery actions
// (AC10, AC11, AC12): the agent never restarts itself, so the service control
// manager's failure actions are what restart it after a self-update. Every
// sc.exe call goes through agent/internal/platform/fake's CommandRunner, so
// nothing here shells out to a real sc.exe, and no database is touched.
package service

import (
	"context"
	"strings"
	"testing"

	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// AC10: Installing the Windows service configures recovery actions.
func TestScenario_AC10_InstallConfiguresRecoveryActions(t *testing.T) {
	// Given a Windows install config for binary "C:\Program Files\OfficeHQ\MDM\mdmagent.exe"
	runner := fake.NewCommandRunner()
	binary := `C:\Program Files\OfficeHQ\MDM\mdmagent.exe`
	cfg := Config{Runner: runner, GOOS: "windows", BinaryPath: binary}

	// When service.Install is called
	err := Install(context.Background(), cfg)

	// Then the runner recorded exactly 3 calls in order
	calls := runner.Calls()
	if len(calls) != 3 {
		t.Fatalf("got %d calls, want 3: %v", len(calls), calls)
	}
	want := []string{
		`sc.exe create OfficeHQMDMAgent binPath= "C:\Program Files\OfficeHQ\MDM\mdmagent.exe" run start= auto DisplayName= OfficeHQ MDM Agent`,
		`sc.exe failure OfficeHQMDMAgent reset= 86400 actions= restart/5000/restart/5000/restart/5000`,
		`sc.exe failureflag OfficeHQMDMAgent 1`,
	}
	for i, w := range want {
		got := calls[i].String()
		if got != w {
			t.Errorf("call[%d] = %q, want %q", i, got, w)
		}
	}
	// And Install returns nil
	if err != nil {
		t.Errorf("Install returned %v, want nil", err)
	}
}

// AC11 failure: a failed create configures nothing else.
func TestScenario_AC11_FailedCreateConfiguresNothingElse(t *testing.T) {
	// Given "sc.exe create" exits 1073
	runner := fake.NewCommandRunner()
	binary := `C:\Program Files\OfficeHQ\MDM\mdmagent.exe`
	runner.Results[`sc.exe create OfficeHQMDMAgent binPath= "`+binary+`" run start= auto DisplayName= OfficeHQ MDM Agent`] =
		platform.CommandResult{ExitCode: 1073}

	cfg := Config{Runner: runner, GOOS: "windows", BinaryPath: binary}

	// When service.Install is called for Windows
	err := Install(context.Background(), cfg)

	// Then Install returns an error
	if err == nil {
		t.Fatal("Install should return an error")
	}
	// And no "sc.exe failure" or "sc.exe failureflag" call was recorded
	for _, call := range runner.Calls() {
		if call.Name == "sc.exe" && len(call.Args) > 0 && (call.Args[0] == "failure" || call.Args[0] == "failureflag") {
			t.Errorf("unexpected call recorded: %v", call)
		}
	}
}

// AC11 failure: a failed failure-action call stops the install.
func TestScenario_AC11_FailedFailureActionStopsInstall(t *testing.T) {
	// Given "sc.exe failure" exits 5
	runner := fake.NewCommandRunner()
	binary := `C:\Program Files\OfficeHQ\MDM\mdmagent.exe`
	runner.Results[`sc.exe failure OfficeHQMDMAgent reset= 86400 actions= restart/5000/restart/5000/restart/5000`] =
		platform.CommandResult{ExitCode: 5}

	cfg := Config{Runner: runner, GOOS: "windows", BinaryPath: binary}

	// When service.Install is called for Windows
	err := Install(context.Background(), cfg)

	// Then the error text contains "sc.exe failure" and "5"
	if err == nil {
		t.Fatal("Install should return an error")
	}
	if !strings.Contains(err.Error(), "sc.exe failure") || !strings.Contains(err.Error(), "5") {
		t.Errorf("error = %q, want it to name sc.exe failure and exit code 5", err.Error())
	}
	// And no "sc.exe failureflag" call was recorded
	for _, call := range runner.Calls() {
		if call.Name == "sc.exe" && len(call.Args) > 0 && call.Args[0] == "failureflag" {
			t.Error("failureflag should not have been called")
		}
	}
}

// AC12: EnsureRecovery reapplies the recovery actions on Windows.
func TestScenario_AC12_EnsureRecoveryReappliesOnWindows(t *testing.T) {
	// When service.EnsureRecovery is called with GOOS "windows"
	runner := fake.NewCommandRunner()
	cfg := Config{Runner: runner, GOOS: "windows"}

	err := EnsureRecovery(context.Background(), cfg)

	// Then the runner recorded exactly the "sc.exe failure" call and then the
	// "sc.exe failureflag" call
	calls := runner.Calls()
	if len(calls) != 2 {
		t.Fatalf("got %d calls, want 2: %v", len(calls), calls)
	}
	if calls[0].Name != "sc.exe" || calls[0].Args[0] != "failure" {
		t.Errorf("call[0] = %v, want sc.exe failure ...", calls[0])
	}
	if calls[1].Name != "sc.exe" || calls[1].Args[0] != "failureflag" {
		t.Errorf("call[1] = %v, want sc.exe failureflag ...", calls[1])
	}
	// And it returns nil
	if err != nil {
		t.Errorf("EnsureRecovery returned %v, want nil", err)
	}
}

// AC12 failure: EnsureRecovery reports the first failing command.
func TestScenario_AC12_EnsureRecoveryReportsFirstFailingCommand(t *testing.T) {
	// Given "sc.exe failure" exits 1060
	runner := fake.NewCommandRunner()
	runner.Results[`sc.exe failure OfficeHQMDMAgent reset= 86400 actions= restart/5000/restart/5000/restart/5000`] =
		platform.CommandResult{ExitCode: 1060}
	cfg := Config{Runner: runner, GOOS: "windows"}

	// When service.EnsureRecovery is called with GOOS "windows"
	err := EnsureRecovery(context.Background(), cfg)

	// Then the error names "sc.exe failure" and exit code 1060
	if err == nil || !strings.Contains(err.Error(), "sc.exe failure") || !strings.Contains(err.Error(), "1060") {
		t.Errorf("error = %v, want it to name sc.exe failure and 1060", err)
	}
	// And no "sc.exe failureflag" call was recorded
	for _, call := range runner.Calls() {
		if call.Args[0] == "failureflag" {
			t.Error("failureflag should not have been called")
		}
	}
}

// AC12 edge: EnsureRecovery does nothing on macOS.
func TestScenario_AC12_EnsureRecoveryNoopOnDarwin(t *testing.T) {
	// When service.EnsureRecovery is called with GOOS "darwin"
	runner := fake.NewCommandRunner()
	cfg := Config{Runner: runner, GOOS: "darwin"}

	err := EnsureRecovery(context.Background(), cfg)

	// Then the runner recorded 0 calls
	if calls := runner.Calls(); len(calls) != 0 {
		t.Errorf("got %d calls, want 0: %v", len(calls), calls)
	}
	// And it returns nil
	if err != nil {
		t.Errorf("EnsureRecovery returned %v, want nil", err)
	}
}
