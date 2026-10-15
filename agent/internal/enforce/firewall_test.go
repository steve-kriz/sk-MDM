package enforce

import (
	"context"
	"errors"
	"testing"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// TestUnit_FirewallNameIsFirewall verifies that the firewall enforcer's name is "firewall".
func TestUnit_FirewallNameIsFirewall(t *testing.T) {
	// Given: a firewall enforcer
	fw := &Firewall{}

	// When: Name is called
	name := fw.Name()

	// Then: it returns "firewall"
	if name != "firewall" {
		t.Errorf("Expected name 'firewall', got %q", name)
	}
}

// TestUnit_FirewallRunsOnWindowsWhenRequired verifies that the firewall enforcer
// runs the Windows firewall command when required.
func TestUnit_FirewallRunsOnWindowsWhenRequired(t *testing.T) {
	// Given: a firewall enforcer on windows, firewallEnabled=true, and firewall off
	runner := fake.NewCommandRunner()
	fw := &Firewall{Runner: runner, GOOS: "windows"}
	effective := map[string]any{SettingFirewallEnabled: true}
	posture := contract.Posture{Firewall: contract.Firewall{Enabled: false}}

	// When: Apply is called
	ctx := context.Background()
	err := fw.Apply(ctx, effective, posture)

	// Then: no error, and the correct command was run
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	calls := runner.Calls()
	if len(calls) != 1 {
		t.Errorf("Expected 1 call, got %d", len(calls))
	}
	if len(calls) > 0 {
		if calls[0].Name != "powershell.exe" {
			t.Errorf("Expected command 'powershell.exe', got %q", calls[0].Name)
		}
		expectedArgs := []string{"-NoProfile", "-NonInteractive", "-Command", "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"}
		if len(calls[0].Args) != len(expectedArgs) {
			t.Errorf("Expected %d args, got %d", len(expectedArgs), len(calls[0].Args))
		}
		for i, arg := range expectedArgs {
			if i < len(calls[0].Args) && calls[0].Args[i] != arg {
				t.Errorf("Arg %d: expected %q, got %q", i, arg, calls[0].Args[i])
			}
		}
	}
}

// TestUnit_FirewallRunsOnDarwinWhenRequired verifies that the firewall enforcer
// runs the macOS firewall command when required.
func TestUnit_FirewallRunsOnDarwinWhenRequired(t *testing.T) {
	// Given: a firewall enforcer on darwin, firewallEnabled=true, and firewall off
	runner := fake.NewCommandRunner()
	fw := &Firewall{Runner: runner, GOOS: "darwin"}
	effective := map[string]any{SettingFirewallEnabled: true}
	posture := contract.Posture{Firewall: contract.Firewall{Enabled: false}}

	// When: Apply is called
	ctx := context.Background()
	err := fw.Apply(ctx, effective, posture)

	// Then: no error, and the correct command was run
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	calls := runner.Calls()
	if len(calls) != 1 {
		t.Errorf("Expected 1 call, got %d", len(calls))
	}
	if len(calls) > 0 {
		if calls[0].Name != "/usr/libexec/ApplicationFirewall/socketfilterfw" {
			t.Errorf("Expected command '/usr/libexec/ApplicationFirewall/socketfilterfw', got %q", calls[0].Name)
		}
		expectedArgs := []string{"--setglobalstate", "on"}
		if len(calls[0].Args) != len(expectedArgs) {
			t.Errorf("Expected %d args, got %d", len(expectedArgs), len(calls[0].Args))
		}
		for i, arg := range expectedArgs {
			if i < len(calls[0].Args) && calls[0].Args[i] != arg {
				t.Errorf("Arg %d: expected %q, got %q", i, arg, calls[0].Args[i])
			}
		}
	}
}

// TestUnit_FirewallDoesNotRunWhenFirewallEnabled is false
func TestUnit_FirewallDoesNotRunWhenFirewallEnabledIsFalse(t *testing.T) {
	// Given: a firewall enforcer with firewallEnabled=false
	runner := fake.NewCommandRunner()
	fw := &Firewall{Runner: runner, GOOS: "windows"}
	effective := map[string]any{SettingFirewallEnabled: false}
	posture := contract.Posture{Firewall: contract.Firewall{Enabled: false}}

	// When: Apply is called
	ctx := context.Background()
	err := fw.Apply(ctx, effective, posture)

	// Then: no error and no command was run
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(runner.Calls()) != 0 {
		t.Errorf("Expected 0 calls, got %d", len(runner.Calls()))
	}
}

// TestUnit_FirewallDoesNotRunWhenFirewallEnabledIsAbsent verifies that no
// command runs when firewallEnabled is not set.
func TestUnit_FirewallDoesNotRunWhenFirewallEnabledIsAbsent(t *testing.T) {
	// Given: a firewall enforcer without firewallEnabled
	runner := fake.NewCommandRunner()
	fw := &Firewall{Runner: runner, GOOS: "windows"}
	effective := map[string]any{}
	posture := contract.Posture{Firewall: contract.Firewall{Enabled: false}}

	// When: Apply is called
	ctx := context.Background()
	err := fw.Apply(ctx, effective, posture)

	// Then: no error and no command was run
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(runner.Calls()) != 0 {
		t.Errorf("Expected 0 calls, got %d", len(runner.Calls()))
	}
}

// TestUnit_FirewallDoesNotRunWhenFirewallEnabledIsNotBoolean verifies that no
// command runs when firewallEnabled is not a boolean.
func TestUnit_FirewallDoesNotRunWhenFirewallEnabledIsNotBoolean(t *testing.T) {
	// Given: a firewall enforcer with firewallEnabled="true" (string, not boolean)
	runner := fake.NewCommandRunner()
	fw := &Firewall{Runner: runner, GOOS: "windows"}
	effective := map[string]any{SettingFirewallEnabled: "true"}
	posture := contract.Posture{Firewall: contract.Firewall{Enabled: false}}

	// When: Apply is called
	ctx := context.Background()
	err := fw.Apply(ctx, effective, posture)

	// Then: no error and no command was run
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(runner.Calls()) != 0 {
		t.Errorf("Expected 0 calls, got %d", len(runner.Calls()))
	}
}

// TestUnit_FirewallDoesNotRunWhenAlreadyEnabled verifies that no command runs
// when the firewall is already enabled.
func TestUnit_FirewallDoesNotRunWhenAlreadyEnabled(t *testing.T) {
	// Given: a firewall enforcer with firewall already enabled
	runner := fake.NewCommandRunner()
	fw := &Firewall{Runner: runner, GOOS: "windows"}
	effective := map[string]any{SettingFirewallEnabled: true}
	posture := contract.Posture{Firewall: contract.Firewall{Enabled: true}}

	// When: Apply is called
	ctx := context.Background()
	err := fw.Apply(ctx, effective, posture)

	// Then: no error and no command was run
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(runner.Calls()) != 0 {
		t.Errorf("Expected 0 calls, got %d", len(runner.Calls()))
	}
}

// TestUnit_FirewallReturnsErrorWhenCommandExitsNonZero verifies that an error
// is returned when the command exits with non-zero code.
func TestUnit_FirewallReturnsErrorWhenCommandExitsNonZero(t *testing.T) {
	// Given: a firewall enforcer with a command that exits with code 5
	runner := fake.NewCommandRunner()
	runner.Results["powershell.exe -NoProfile -NonInteractive -Command Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"] = platform.CommandResult{
		ExitCode: 5,
		Stderr:   "error message",
	}
	fw := &Firewall{Runner: runner, GOOS: "windows"}
	effective := map[string]any{SettingFirewallEnabled: true}
	posture := contract.Posture{Firewall: contract.Firewall{Enabled: false}}

	// When: Apply is called
	ctx := context.Background()
	err := fw.Apply(ctx, effective, posture)

	// Then: an error is returned containing "5"
	if err == nil {
		t.Errorf("Expected an error, got nil")
	}
	if err != nil && !contains(err.Error(), "5") {
		t.Errorf("Expected error message to contain '5', got %q", err.Error())
	}
}

// TestUnit_FirewallReturnsErrorWhenCommandCannotStart verifies that an error
// is returned when the command cannot start.
func TestUnit_FirewallReturnsErrorWhenCommandCannotStart(t *testing.T) {
	// Given: a firewall enforcer with a runner that returns an error
	runner := fake.NewCommandRunner()
	runner.Errors["powershell.exe -NoProfile -NonInteractive -Command Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"] = errors.New("cannot start")
	fw := &Firewall{Runner: runner, GOOS: "windows"}
	effective := map[string]any{SettingFirewallEnabled: true}
	posture := contract.Posture{Firewall: contract.Firewall{Enabled: false}}

	// When: Apply is called
	ctx := context.Background()
	err := fw.Apply(ctx, effective, posture)

	// Then: an error is returned that wraps the runner's error
	if err == nil {
		t.Errorf("Expected an error, got nil")
	}
	if err != nil && !contains(err.Error(), "cannot start") {
		t.Errorf("Expected error message to mention startup, got %q", err.Error())
	}
}

// TestUnit_FirewallDoesNotRunOnUnknownGoos verifies that no command runs on
// unknown GOOS.
func TestUnit_FirewallDoesNotRunOnUnknownGoos(t *testing.T) {
	// Given: a firewall enforcer on an unknown GOOS
	runner := fake.NewCommandRunner()
	fw := &Firewall{Runner: runner, GOOS: "linux"}
	effective := map[string]any{SettingFirewallEnabled: true}
	posture := contract.Posture{Firewall: contract.Firewall{Enabled: false}}

	// When: Apply is called
	ctx := context.Background()
	err := fw.Apply(ctx, effective, posture)

	// Then: no error and no command was run
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(runner.Calls()) != 0 {
		t.Errorf("Expected 0 calls, got %d", len(runner.Calls()))
	}
}

// contains is a helper to check if a string contains a substring.
func contains(s, substr string) bool {
	for i := 0; i < len(s)-len(substr)+1; i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ============================================================================
// AC5: the Actions recorder.
// ============================================================================

// TestScenario_AC5_TurningTheFirewallOnIsRecorded covers:
//
//	Given firewallEnabled true, a posture with the firewall off and a runner
//	     answering exit 0
//	When the firewall enforcer applies
//	Then Actions was called once with "enforce.firewall_enabled" and empty details
func TestScenario_AC5_TurningTheFirewallOnIsRecorded(t *testing.T) {
	runner := fake.NewCommandRunner()
	var calls []string
	var lastDetails map[string]string
	fw := &Firewall{Runner: runner, GOOS: "windows", Actions: func(actionType string, details map[string]string) {
		calls = append(calls, actionType)
		lastDetails = details
	}}
	effective := map[string]any{SettingFirewallEnabled: true}
	posture := contract.Posture{Firewall: contract.Firewall{Enabled: false}}

	err := fw.Apply(context.Background(), effective, posture)
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if len(calls) != 1 || calls[0] != contract.ActionFirewallEnabled {
		t.Fatalf("Actions calls = %v, want exactly one call with %q", calls, contract.ActionFirewallEnabled)
	}
	if len(lastDetails) != 0 {
		t.Errorf("details = %+v, want empty", lastDetails)
	}
}

// TestScenario_AC5_ANilActionsRecordsNothingAndBehavesAsBefore covers: "A nil
// Actions records nothing and Apply behaves as before" -- no panic and the
// firewall command still runs.
func TestScenario_AC5_ANilActionsRecordsNothingAndBehavesAsBefore(t *testing.T) {
	runner := fake.NewCommandRunner()
	fw := &Firewall{Runner: runner, GOOS: "windows"}
	effective := map[string]any{SettingFirewallEnabled: true}
	posture := contract.Posture{Firewall: contract.Firewall{Enabled: false}}

	err := fw.Apply(context.Background(), effective, posture)
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if len(runner.Calls()) != 1 {
		t.Fatalf("expected the firewall-on command to still run, got %d calls", len(runner.Calls()))
	}
}

// TestScenario_AC5Outline_AFirewallThatWasNotTurnedOnRecordsNothing covers the
// scenario outline: firewallEnabled absent, the firewall already on, the
// runner answering exit code 1, the runner returning an error, and GOOS
// "linux".
func TestScenario_AC5Outline_AFirewallThatWasNotTurnedOnRecordsNothing(t *testing.T) {
	cases := []struct {
		name      string
		goos      string
		effective map[string]any
		posture   contract.Posture
		configure func(runner *fake.CommandRunner)
	}{
		{
			name:      "firewallEnabled absent",
			goos:      "windows",
			effective: map[string]any{},
			posture:   contract.Posture{Firewall: contract.Firewall{Enabled: false}},
		},
		{
			name:      "the firewall already on",
			goos:      "windows",
			effective: map[string]any{SettingFirewallEnabled: true},
			posture:   contract.Posture{Firewall: contract.Firewall{Enabled: true}},
		},
		{
			name:      "the runner answering exit code 1",
			goos:      "windows",
			effective: map[string]any{SettingFirewallEnabled: true},
			posture:   contract.Posture{Firewall: contract.Firewall{Enabled: false}},
			configure: func(runner *fake.CommandRunner) {
				runner.Results["powershell.exe -NoProfile -NonInteractive -Command Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"] = platform.CommandResult{ExitCode: 1}
			},
		},
		{
			name:      "the runner returning an error",
			goos:      "windows",
			effective: map[string]any{SettingFirewallEnabled: true},
			posture:   contract.Posture{Firewall: contract.Firewall{Enabled: false}},
			configure: func(runner *fake.CommandRunner) {
				runner.Errors["powershell.exe -NoProfile -NonInteractive -Command Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"] = errors.New("cannot start")
			},
		},
		{
			name:      `GOOS "linux"`,
			goos:      "linux",
			effective: map[string]any{SettingFirewallEnabled: true},
			posture:   contract.Posture{Firewall: contract.Firewall{Enabled: false}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := fake.NewCommandRunner()
			if tc.configure != nil {
				tc.configure(runner)
			}
			called := false
			fw := &Firewall{Runner: runner, GOOS: tc.goos, Actions: func(string, map[string]string) { called = true }}

			_ = fw.Apply(context.Background(), tc.effective, tc.posture)

			if called {
				t.Errorf("Actions was called for case %q, want no call", tc.name)
			}
		})
	}
}
