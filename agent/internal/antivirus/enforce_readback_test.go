package antivirus_test

// E2E/cucumber-style tests for TASK-055 Part A: the enable command's
// read-back of RealTimeProtectionEnabled and IsTamperProtected.
// Mocks all commands through agent/internal/platform/fake -- no real
// PowerShell or Defender is ever invoked.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/antivirus"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// TestScenario_AC2_WindowsEnableScriptIsExact covers the exact text AC2
// requires, and that Apply runs it exactly once through powershell.exe.
func TestScenario_AC2_WindowsEnableScriptIsExact(t *testing.T) {
	want := `Start-Service -Name WinDefend -ErrorAction Stop; ` +
		`Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop; ` +
		`$s = Get-MpComputerStatus -ErrorAction Stop; ` +
		`"realTimeProtectionEnabled=$([bool]$s.RealTimeProtectionEnabled)"; ` +
		`"isTamperProtected=$([bool]$s.IsTamperProtected)"`
	if antivirus.WindowsEnableScript != want {
		t.Fatalf("WindowsEnableScript =\n%q\nwant\n%q", antivirus.WindowsEnableScript, want)
	}

	// Given goos "windows" and effective settings {"antivirusEnabled": true},
	// with posture.antivirus.enabled false
	runner := fake.NewCommandRunner()
	runner.Results[enableCommandKey()] = platform.CommandResult{Stdout: "realTimeProtectionEnabled=True\nisTamperProtected=False\n"}
	clock := fake.NewClock(time.Now())
	e := antivirus.NewEnforcer(runner, clock, "windows")

	// When Apply is called once
	err := e.Apply(context.Background(), map[string]any{antivirus.SettingAntivirusEnabled: true},
		contract.Posture{Antivirus: contract.Antivirus{Enabled: false}})
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	// Then the runner received exactly one command running WindowsEnableScript
	calls := runner.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected exactly 1 runner call, got %d: %v", len(calls), calls)
	}
	if calls[0].Name != "powershell.exe" {
		t.Errorf("command name = %q, want powershell.exe", calls[0].Name)
	}
	if len(calls[0].Args) == 0 || calls[0].Args[len(calls[0].Args)-1] != want {
		t.Errorf("command script = %v, want it to end with the exact WindowsEnableScript text", calls[0].Args)
	}
}

// TestScenario_AC3_RealTimeConfirmedOnReturnsNil covers a clean enable.
func TestScenario_AC3_RealTimeConfirmedOnReturnsNil(t *testing.T) {
	runner := fake.NewCommandRunner()
	runner.Results[enableCommandKey()] = platform.CommandResult{Stdout: "realTimeProtectionEnabled=True\nisTamperProtected=True\n"}
	clock := fake.NewClock(time.Now())
	e := antivirus.NewEnforcer(runner, clock, "windows")

	err := e.Apply(context.Background(), map[string]any{antivirus.SettingAntivirusEnabled: true},
		contract.Posture{Antivirus: contract.Antivirus{Enabled: false}})
	if err != nil {
		t.Fatalf("expected Apply to return nil, got %v", err)
	}
}

// TestScenario_AC4_TamperProtectionBlocksEnabling covers the distinct
// ErrTamperProtected error and its wording.
func TestScenario_AC4_TamperProtectionBlocksEnabling(t *testing.T) {
	runner := fake.NewCommandRunner()
	runner.Results[enableCommandKey()] = platform.CommandResult{Stdout: "realTimeProtectionEnabled=False\nisTamperProtected=True\n"}
	clock := fake.NewClock(time.Now())
	e := antivirus.NewEnforcer(runner, clock, "windows")

	err := e.Apply(context.Background(), map[string]any{antivirus.SettingAntivirusEnabled: true},
		contract.Posture{Antivirus: contract.Antivirus{Enabled: false}})

	if !errors.Is(err, antivirus.ErrTamperProtected) {
		t.Fatalf("expected errors.Is(err, ErrTamperProtected), got %v", err)
	}
	if !strings.Contains(err.Error(), "Tamper Protection") {
		t.Errorf("error %q should contain %q", err.Error(), "Tamper Protection")
	}
	if calls := runner.Calls(); len(calls) != 1 {
		t.Errorf("expected exactly one runner call, got %d: %v", len(calls), calls)
	}
}

// TestScenario_AC5_RealTimeStillOffWithoutTamperProtection covers the
// Group-Policy style failure, distinct from ErrTamperProtected.
func TestScenario_AC5_RealTimeStillOffWithoutTamperProtection(t *testing.T) {
	runner := fake.NewCommandRunner()
	runner.Results[enableCommandKey()] = platform.CommandResult{Stdout: "realTimeProtectionEnabled=False\nisTamperProtected=False\n"}
	clock := fake.NewClock(time.Now())
	e := antivirus.NewEnforcer(runner, clock, "windows")

	err := e.Apply(context.Background(), map[string]any{antivirus.SettingAntivirusEnabled: true},
		contract.Posture{Antivirus: contract.Antivirus{Enabled: false}})

	if !errors.Is(err, antivirus.ErrRealTimeStillOff) {
		t.Fatalf("expected errors.Is(err, ErrRealTimeStillOff), got %v", err)
	}
	if errors.Is(err, antivirus.ErrTamperProtected) {
		t.Errorf("error %v should not also be ErrTamperProtected", err)
	}
}

// TestScenario_AC6_UnparseableEnableOutput covers empty stdout and other
// stdout carrying no realTimeProtectionEnabled= line.
func TestScenario_AC6_UnparseableEnableOutput(t *testing.T) {
	cases := []string{"", "garbage\nmore garbage\n", "realTimeProtectionEnabled=Maybe\n"}
	for _, stdout := range cases {
		t.Run(stdout, func(t *testing.T) {
			runner := fake.NewCommandRunner()
			runner.Results[enableCommandKey()] = platform.CommandResult{Stdout: stdout}
			clock := fake.NewClock(time.Now())
			e := antivirus.NewEnforcer(runner, clock, "windows")

			err := e.Apply(context.Background(), map[string]any{antivirus.SettingAntivirusEnabled: true},
				contract.Posture{Antivirus: contract.Antivirus{Enabled: false}})

			if !errors.Is(err, antivirus.ErrEnableUnparseable) {
				t.Fatalf("expected errors.Is(err, ErrEnableUnparseable), got %v", err)
			}
		})
	}
}

// TestScenario_AC7_ExistingFailuresAreUnchanged covers exit-code, timeout and
// runner-error wrapping, each with the exact "antivirus enable command: ..."
// text TASK-030 already specified.
func TestScenario_AC7_ExistingFailuresAreUnchanged(t *testing.T) {
	effective := map[string]any{antivirus.SettingAntivirusEnabled: true}
	posture := contract.Posture{Antivirus: contract.Antivirus{Enabled: false}}

	t.Run("exits with code 1", func(t *testing.T) {
		runner := fake.NewCommandRunner()
		runner.Results[enableCommandKey()] = platform.CommandResult{ExitCode: 1}
		clock := fake.NewClock(time.Now())
		e := antivirus.NewEnforcer(runner, clock, "windows")

		err := e.Apply(context.Background(), effective, posture)
		if err == nil || err.Error() != "antivirus enable command: exit code 1" {
			t.Fatalf("error = %v, want %q", err, "antivirus enable command: exit code 1")
		}
	})

	t.Run("does not answer before 60s on the clock", func(t *testing.T) {
		runner := newBlockingRunner()
		clock := fake.NewClock(time.Now())
		e := antivirus.NewEnforcer(runner, clock, "windows")

		go func() {
			<-runner.started
			clock.Advance(antivirus.EnforceTimeout)
		}()

		err := e.Apply(context.Background(), effective, posture)
		if err == nil || err.Error() != "antivirus enable command: timeout after 1m0s" {
			t.Fatalf("error = %v, want %q", err, "antivirus enable command: timeout after 1m0s")
		}
	})

	t.Run("a runner error is wrapped", func(t *testing.T) {
		runner := fake.NewCommandRunner()
		runner.Errors[enableCommandKey()] = errors.New("boom")
		clock := fake.NewClock(time.Now())
		e := antivirus.NewEnforcer(runner, clock, "windows")

		err := e.Apply(context.Background(), effective, posture)
		if err == nil || err.Error() != "antivirus enable command: boom" {
			t.Fatalf("error = %v, want %q", err, "antivirus enable command: boom")
		}
	})
}
