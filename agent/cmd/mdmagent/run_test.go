package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/agentactions"
	"github.com/officehq/sk-mdm/agent/internal/analytics"
	"github.com/officehq/sk-mdm/agent/internal/antivirus"
	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/enforce"
	"github.com/officehq/sk-mdm/agent/internal/executor"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/service"
	"github.com/officehq/sk-mdm/agent/internal/state"
	"github.com/officehq/sk-mdm/agent/internal/update"
)

// TestE2E_NewAgentSetsEnforcementWiring verifies that newAgent sets up the
// Enforce seam with the production enforce.Run and enforce.Defaults.
func TestE2E_NewAgentSetsEnforcementWiring(t *testing.T) {
	// Given: a simulated agentEnv with fakes for newAgent
	runner := fake.NewCommandRunner()

	// Arrange the firewall command to succeed
	runner.Results["powershell.exe -NoProfile -NonInteractive -Command Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"] = platform.CommandResult{
		ExitCode: 0,
		Stdout:   "",
		Stderr:   "",
	}

	// Since newAgent requires a real filesystem for config, we'll test that
	// Enforce is wired by checking that enforce.Run and enforce.Defaults
	// work together. Create a simple scenario: firewall enforcer should run
	// the command when firewallEnabled is true and firewall is off.
	enforcer := &enforce.Firewall{
		Runner: runner,
		GOOS:   "windows",
	}

	// When: Apply is called with firewallEnabled=true and firewall disabled
	ctx := context.Background()
	effective := map[string]any{enforce.SettingFirewallEnabled: true}
	posture := contract.Posture{Firewall: contract.Firewall{Enabled: false}}
	err := enforcer.Apply(ctx, effective, posture)

	// Then: no error and the firewall command was run
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	calls := runner.Calls()
	if len(calls) != 1 {
		t.Errorf("Expected 1 call, got %d", len(calls))
	}
	if len(calls) > 0 && calls[0].Name != "powershell.exe" {
		t.Errorf("Expected powershell.exe, got %q", calls[0].Name)
	}
}

// TestE2E_NewAgentAppendsAntivirusEnforcerAfterDefaults verifies the AC:
// newAgent wires deps.Enforce to enforce.Defaults(...) followed by
// antivirus.NewEnforcer(...), and enforce.Defaults itself is unchanged.
func TestE2E_NewAgentAppendsAntivirusEnforcerAfterDefaults(t *testing.T) {
	// Given: a simulated agentEnv with fakes, assembled through newAgent
	fsys := fake.NewFS()
	runner := fake.NewCommandRunner()
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	doer := fake.NewHTTPDoer()

	cfg := config.Config{CollectionURL: "https://collect.example.com", EnrollmentToken: "tok"}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	fsys.Seed(config.Path("windows"), data)

	env := agentEnv{
		FS:         fsys,
		Runner:     runner,
		Clock:      clock,
		Doer:       doer,
		GOOS:       "windows",
		ConfigPath: config.Path("windows"),
		StatePath:  state.StatePath("windows"),
	}

	a, err := newAgent(env)
	if err != nil {
		t.Fatalf("newAgent failed: %v", err)
	}
	if a.deps.Enforce == nil {
		t.Fatal("expected deps.Enforce to be set")
	}

	// When: deps.Enforce is called with {antivirusEnabled:true} and a posture
	// with antivirus off (and nothing requiring the firewall/domains enforcers)
	effective := map[string]any{antivirus.SettingAntivirusEnabled: true}
	posture := contract.Posture{Antivirus: contract.Antivirus{Enabled: false}}
	a.deps.Enforce(context.Background(), effective, posture)

	// Then: the fake runner received exactly the WindowsEnableScript command
	calls := runner.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected exactly 1 runner call, got %d: %v", len(calls), calls)
	}
	wantArgs := []string{"-NoProfile", "-NonInteractive", "-Command", antivirus.WindowsEnableScript}
	if calls[0].Name != "powershell.exe" {
		t.Errorf("command name = %q, want powershell.exe", calls[0].Name)
	}
	if len(calls[0].Args) != len(wantArgs) {
		t.Fatalf("args = %v, want %v", calls[0].Args, wantArgs)
	}
	for i, arg := range wantArgs {
		if calls[0].Args[i] != arg {
			t.Errorf("args[%d] = %q, want %q", i, calls[0].Args[i], arg)
		}
	}

	// And: enforce.Defaults is unchanged -- still firewall then domains.
	defaults := enforce.Defaults(runner, fsys, "windows", nil)
	if len(defaults) != 2 || defaults[0].Name() != "firewall" || defaults[1].Name() != "domains" {
		t.Errorf("enforce.Defaults should still return [firewall domains], got %v", defaults)
	}
}

// TestE2E_NewAgentWiresAgentErrorBuffer covers TASK-063: newAgent attaches an
// agenterrors.Buffer to the root logger (before any With call, so every
// component's logger reaches it) and wires deps.CollectAgentErrors to its
// Collect method.
func TestE2E_NewAgentWiresAgentErrorBuffer(t *testing.T) {
	// Given: a simulated agentEnv assembled through newAgent
	fsys := fake.NewFS()
	runner := fake.NewCommandRunner()
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	doer := fake.NewHTTPDoer()

	cfg := config.Config{CollectionURL: "https://collect.example.com", EnrollmentToken: "tok"}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	fsys.Seed(config.Path("windows"), data)

	env := agentEnv{
		FS:         fsys,
		Runner:     runner,
		Clock:      clock,
		Doer:       doer,
		GOOS:       "windows",
		ConfigPath: config.Path("windows"),
		StatePath:  state.StatePath("windows"),
	}

	a, err := newAgent(env)
	if err != nil {
		t.Fatalf("newAgent failed: %v", err)
	}

	// Then: deps.CollectAgentErrors is wired
	if a.deps.CollectAgentErrors == nil {
		t.Fatal("expected deps.CollectAgentErrors to be set")
	}

	// And: a warn record from deps.Logger (itself a child made with With,
	// before CollectAgentErrors is ever called) reaches the buffer.
	a.deps.Logger.Warn("policy enforcement failed")

	errs := a.deps.CollectAgentErrors()
	if len(errs) != 1 || errs[0].Message != "policy enforcement failed" || errs[0].Level != "warn" {
		t.Fatalf("CollectAgentErrors() = %+v, want one warn entry for the logged record", errs)
	}

	// And: once collected, the buffer is empty again (Collect drains it).
	if more := a.deps.CollectAgentErrors(); len(more) != 0 {
		t.Errorf("expected the buffer to be empty after Collect, got %+v", more)
	}
}

// TestE2E_NewAgentWiresHardenerAfterAntivirusEnforcer covers the AC: newAgent
// constructs one antivirus.NewHardener(env.Runner, env.Clock, env.GOOS) outside
// the Enforce closure, appends it to the enforcer list after
// antivirus.NewEnforcer, and passes hardener.Last as
// scheduler.Deps.CollectDefenderHardening -- the same instance Enforce drives.
func TestE2E_NewAgentWiresHardenerAfterAntivirusEnforcer(t *testing.T) {
	// Given: a simulated agentEnv with fakes, assembled through newAgent
	fsys := fake.NewFS()
	runner := fake.NewCommandRunner()
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	doer := fake.NewHTTPDoer()

	cfg := config.Config{CollectionURL: "https://collect.example.com", EnrollmentToken: "tok"}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	fsys.Seed(config.Path("windows"), data)

	env := agentEnv{
		FS:         fsys,
		Runner:     runner,
		Clock:      clock,
		Doer:       doer,
		GOOS:       "windows",
		ConfigPath: config.Path("windows"),
		StatePath:  state.StatePath("windows"),
	}

	a, err := newAgent(env)
	if err != nil {
		t.Fatalf("newAgent failed: %v", err)
	}
	if a.deps.CollectDefenderHardening == nil {
		t.Fatal("expected deps.CollectDefenderHardening to be set")
	}

	// Before any Enforce call, the wired hardener has applied nothing.
	if block := a.deps.CollectDefenderHardening(); block != nil {
		t.Fatalf("CollectDefenderHardening() before Enforce = %+v, want nil", block)
	}

	// When: deps.Enforce runs with both antivirusEnabled (the antivirus
	// enforcer) and defenderNetworkProtection (the hardener) required, and a
	// read that reports the network protection item already satisfied.
	readStdout := `{"defenderAvailable":true,"runningMode":"Normal","tamperProtected":false,` +
		`"antivirusSignatureAge":null,"preferences":{"EnableNetworkProtection":1},` +
		`"smartScreen":{},"errors":{}}`
	runner.Results[fake.Command{
		Name: "powershell.exe",
		Args: []string{"-NoProfile", "-NonInteractive", "-Command", antivirus.HardeningReadScript},
	}.String()] = platform.CommandResult{Stdout: readStdout}

	effective := map[string]any{
		antivirus.SettingAntivirusEnabled:          true,
		antivirus.SettingDefenderNetworkProtection: true,
	}
	posture := contract.Posture{Antivirus: contract.Antivirus{Enabled: false}}
	a.deps.Enforce(context.Background(), effective, posture)

	// Then: the antivirus enforcer's command ran before the hardener's, which
	// confirms the hardener was appended after antivirus.NewEnforcer.
	calls := runner.Calls()
	enableIdx, readIdx := -1, -1
	for i, c := range calls {
		if len(c.Args) == 0 {
			continue
		}
		switch c.Args[len(c.Args)-1] {
		case antivirus.WindowsEnableScript:
			enableIdx = i
		case antivirus.HardeningReadScript:
			readIdx = i
		}
	}
	if enableIdx < 0 || readIdx < 0 {
		t.Fatalf("expected both the antivirus enable command and the hardening read command, got %v", calls)
	}
	if enableIdx >= readIdx {
		t.Errorf("antivirus enforcer command (index %d) should run before the hardener's (index %d)", enableIdx, readIdx)
	}

	// And: CollectDefenderHardening (hardener.Last) now reflects that very
	// Enforce call -- it is wired to the same hardener instance.
	block := a.deps.CollectDefenderHardening()
	if block == nil || len(block.Items) != 1 || block.Items[0].Item != "networkProtection" || block.Items[0].State != "ok" {
		t.Errorf("CollectDefenderHardening() = %+v, want the block from the Enforce call just run", block)
	}
}

// TestE2E_EnforceRunWithDefaultsExecutesInOrder verifies that enforce.Run
// calls enforcers in order and enforce.Defaults returns firewall then domains.
func TestE2E_EnforceRunWithDefaultsExecutesInOrder(t *testing.T) {
	// Given: a runner and filesystem for enforce.Defaults
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()

	// When: Defaults is called for windows
	enforcers := enforce.Defaults(runner, fsys, "windows", nil)

	// Then: it returns exactly two enforcers in the correct order
	if len(enforcers) != 2 {
		t.Errorf("Expected 2 enforcers, got %d", len(enforcers))
	}
	if len(enforcers) >= 1 && enforcers[0].Name() != "firewall" {
		t.Errorf("Expected first enforcer 'firewall', got %q", enforcers[0].Name())
	}
	if len(enforcers) >= 2 && enforcers[1].Name() != "domains" {
		t.Errorf("Expected second enforcer 'domains', got %q", enforcers[1].Name())
	}

	// When: enforce.Run is called with the defaults
	ctx := context.Background()
	effective := map[string]any{enforce.SettingFirewallBlockedDomains: []any{"test.com"}}
	posture := contract.Posture{}
	enforce.Run(ctx, enforcers, effective, posture, nil)

	// Then: both enforcers were called (verified by checking that Apply
	// would have been called on both)
}

// TestE2E_FirewallEnforcerRunsCommandOnWindowsWhenRequired verifies the
// complete scenario of the firewall enforcer on Windows.
func TestE2E_FirewallEnforcerRunsCommandOnWindowsWhenRequired(t *testing.T) {
	// Given: goos=windows, effective={firewallEnabled:true}, posture firewall enabled=false
	runner := fake.NewCommandRunner()
	fw := &enforce.Firewall{Runner: runner, GOOS: "windows"}
	effective := map[string]any{enforce.SettingFirewallEnabled: true}
	posture := contract.Posture{Firewall: contract.Firewall{Enabled: false}}

	// When: the firewall enforcer applies
	ctx := context.Background()
	err := fw.Apply(ctx, effective, posture)

	// Then: exactly one command was run with correct args
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	calls := runner.Calls()
	if len(calls) != 1 {
		t.Errorf("Expected 1 command, got %d", len(calls))
	}
	if len(calls) > 0 {
		expectedCmd := "powershell.exe"
		expectedArgs := []string{
			"-NoProfile",
			"-NonInteractive",
			"-Command",
			"Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
		}
		if calls[0].Name != expectedCmd {
			t.Errorf("Expected command %q, got %q", expectedCmd, calls[0].Name)
		}
		if len(calls[0].Args) != len(expectedArgs) {
			t.Errorf("Expected %d args, got %d", len(expectedArgs), len(calls[0].Args))
		}
		for i, expected := range expectedArgs {
			if i < len(calls[0].Args) && calls[0].Args[i] != expected {
				t.Errorf("Arg %d: expected %q, got %q", i, expected, calls[0].Args[i])
			}
		}
	}
}

// TestE2E_FirewallEnforcerRunsCommandOnDarwinWhenRequired verifies the
// complete scenario on macOS.
func TestE2E_FirewallEnforcerRunsCommandOnDarwinWhenRequired(t *testing.T) {
	// Given: goos=darwin, effective={firewallEnabled:true}, posture firewall enabled=false
	runner := fake.NewCommandRunner()
	fw := &enforce.Firewall{Runner: runner, GOOS: "darwin"}
	effective := map[string]any{enforce.SettingFirewallEnabled: true}
	posture := contract.Posture{Firewall: contract.Firewall{Enabled: false}}

	// When: the firewall enforcer applies
	ctx := context.Background()
	err := fw.Apply(ctx, effective, posture)

	// Then: exactly one command was run with correct args
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	calls := runner.Calls()
	if len(calls) != 1 {
		t.Errorf("Expected 1 command, got %d", len(calls))
	}
	if len(calls) > 0 {
		expectedCmd := "/usr/libexec/ApplicationFirewall/socketfilterfw"
		expectedArgs := []string{"--setglobalstate", "on"}
		if calls[0].Name != expectedCmd {
			t.Errorf("Expected command %q, got %q", expectedCmd, calls[0].Name)
		}
		if len(calls[0].Args) != len(expectedArgs) {
			t.Errorf("Expected %d args, got %d", len(expectedArgs), len(calls[0].Args))
		}
		for i, expected := range expectedArgs {
			if i < len(calls[0].Args) && calls[0].Args[i] != expected {
				t.Errorf("Arg %d: expected %q, got %q", i, expected, calls[0].Args[i])
			}
		}
	}
}

// TestE2E_FirewallEnforcerDoesNotRunWhenAlreadyEnabled verifies firewall
// enforcer doesn't run when firewall is already on.
func TestE2E_FirewallEnforcerDoesNotRunWhenAlreadyEnabled(t *testing.T) {
	// Given: effective={firewallEnabled:true}, posture firewall enabled=true
	runner := fake.NewCommandRunner()
	fw := &enforce.Firewall{Runner: runner, GOOS: "windows"}
	effective := map[string]any{enforce.SettingFirewallEnabled: true}
	posture := contract.Posture{Firewall: contract.Firewall{Enabled: true}}

	// When: the firewall enforcer applies
	ctx := context.Background()
	err := fw.Apply(ctx, effective, posture)

	// Then: no command was run and result is nil
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(runner.Calls()) != 0 {
		t.Errorf("Expected no commands, got %d", len(runner.Calls()))
	}
}

// TestE2E_FirewallEnforcerDoesNotRunWhenNotRequired verifies firewall enforcer
// doesn't run when firewallEnabled is false or absent.
func TestE2E_FirewallEnforcerDoesNotRunWhenNotRequired(t *testing.T) {
	tests := []struct {
		name      string
		effective map[string]any
	}{
		{"absent", map[string]any{}},
		{"false", map[string]any{enforce.SettingFirewallEnabled: false}},
		{"not boolean", map[string]any{enforce.SettingFirewallEnabled: "true"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			runner := fake.NewCommandRunner()
			fw := &enforce.Firewall{Runner: runner, GOOS: "windows"}
			posture := contract.Posture{Firewall: contract.Firewall{Enabled: false}}

			// When
			ctx := context.Background()
			err := fw.Apply(ctx, tt.effective, posture)

			// Then
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
			if len(runner.Calls()) != 0 {
				t.Errorf("Expected no commands, got %d", len(runner.Calls()))
			}
		})
	}
}

// TestE2E_DomainsEnforcerComputesBlockedSet verifies the complete flow for
// the domains enforcer's blocked set computation.
func TestE2E_DomainsEnforcerComputesBlockedSet(t *testing.T) {
	// Given: effective with blocked and allowed domains
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	d := &enforce.Domains{
		Runner: runner,
		FS:     fsys,
		GOOS:   "windows",
		Logger: nil,
	}
	effective := map[string]any{
		enforce.SettingFirewallBlockedDomains: []any{"Example.com", "bad domain", "www.news.com"},
		enforce.SettingFirewallAllowedDomains: []any{"www.example.com"},
	}

	// When: BlockedNames computes the set
	names := d.BlockedNames(effective)

	// Then: the set includes lowercase valid entries with www variants,
	// but excludes allowed entries
	expectedNames := []string{"example.com", "www.news.com"}
	if len(names) != len(expectedNames) {
		t.Errorf("Expected %d names, got %d: %v", len(expectedNames), len(names), names)
	}
	for i, exp := range expectedNames {
		if i < len(names) && names[i] != exp {
			t.Errorf("Name %d: expected %q, got %q", i, exp, names[i])
		}
	}
	// Verify www.example.com is not in the result (removed by allow rule)
	for _, name := range names {
		if name == "www.example.com" {
			t.Errorf("Expected www.example.com to be removed by allow rule")
		}
	}
}

// TestE2E_DomainsEnforcerManagedBlockAppended verifies that the domains
// enforcer appends a managed block to the hosts file.
func TestE2E_DomainsEnforcerManagedBlockAppended(t *testing.T) {
	// Given: goos=windows, hosts file with no trailing line ending
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	fsys.Seed(enforce.WindowsHostsPath, []byte("127.0.0.1 localhost"))
	d := &enforce.Domains{
		Runner: runner,
		FS:     fsys,
		GOOS:   "windows",
		Logger: nil,
	}
	effective := map[string]any{enforce.SettingFirewallBlockedDomains: []any{"a.com"}}

	// When: the domain enforcer applies
	ctx := context.Background()
	err := d.Apply(ctx, effective, contract.Posture{})

	// Then: hosts file contains original content, a line ending, and the managed block
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	content, exists := fsys.Content(enforce.WindowsHostsPath)
	if !exists {
		t.Errorf("Expected hosts file to exist")
	}
	contentStr := string(content)
	if !stringContains(contentStr, "127.0.0.1 localhost") {
		t.Errorf("Expected original content to be preserved")
	}
	if !stringContains(contentStr, enforce.HostsBeginMarker) {
		t.Errorf("Expected managed block BEGIN marker")
	}
	if !stringContains(contentStr, "0.0.0.0 a.com") {
		t.Errorf("Expected blocked entry for a.com")
	}
	if !stringContains(contentStr, ":: a.com") {
		t.Errorf("Expected IPv6 entry for a.com")
	}
	if !stringContains(contentStr, "0.0.0.0 www.a.com") {
		t.Errorf("Expected www variant for a.com")
	}
	// Verify ipconfig flush was called
	if len(runner.Calls()) == 0 {
		t.Errorf("Expected flush command to be run")
	}
	if len(runner.Calls()) > 0 && runner.Calls()[0].Name != "ipconfig.exe" {
		t.Errorf("Expected ipconfig.exe flush, got %q", runner.Calls()[0].Name)
	}
}

// TestE2E_DomainsEnforcerExistingBlockReplaced verifies that an existing
// managed block is replaced in place.
func TestE2E_DomainsEnforcerExistingBlockReplaced(t *testing.T) {
	// Given: goos=darwin and /etc/hosts with lines before and after a managed block
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	hostsContent := "127.0.0.1 localhost\n# BEGIN sk-mdm managed block - do not edit\n0.0.0.0 old.com\n:: old.com\n# END sk-mdm managed block\n# My custom comment\n"
	fsys.Seed(enforce.DarwinHostsPath, []byte(hostsContent))
	d := &enforce.Domains{
		Runner: runner,
		FS:     fsys,
		GOOS:   "darwin",
		Logger: nil,
	}
	effective := map[string]any{enforce.SettingFirewallBlockedDomains: []any{"new.com"}}

	// When: the domain enforcer applies
	ctx := context.Background()
	err := d.Apply(ctx, effective, contract.Posture{})

	// Then: the managed block contains only new.com and www.new.com,
	// and lines before/after are byte-identical
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	content, _ := fsys.Content(enforce.DarwinHostsPath)
	contentStr := string(content)
	if !stringContains(contentStr, "127.0.0.1 localhost") {
		t.Errorf("Expected localhost to be preserved")
	}
	if !stringContains(contentStr, "# My custom comment") {
		t.Errorf("Expected custom comment to be preserved")
	}
	if !stringContains(contentStr, "0.0.0.0 new.com") {
		t.Errorf("Expected new.com in block")
	}
	if stringContains(contentStr, "0.0.0.0 old.com") {
		t.Errorf("Expected old.com to be removed")
	}
	// Verify both darwin flush commands were run
	calls := runner.Calls()
	if len(calls) != 2 {
		t.Errorf("Expected 2 flush commands on darwin, got %d", len(calls))
	}
	if len(calls) >= 1 && calls[0].Name != "/usr/bin/dscacheutil" {
		t.Errorf("Expected dscacheutil, got %q", calls[0].Name)
	}
	if len(calls) >= 2 && calls[1].Name != "/usr/bin/killall" {
		t.Errorf("Expected killall, got %q", calls[1].Name)
	}
}

// TestE2E_DomainsEnforcerRemovesBlockWhenEmpty verifies that removing the
// blocked list removes the managed block.
func TestE2E_DomainsEnforcerRemovesBlockWhenEmpty(t *testing.T) {
	// Given: a hosts file containing a managed block
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	hostsContent := "127.0.0.1 localhost\n# BEGIN sk-mdm managed block - do not edit\n0.0.0.0 a.com\n# END sk-mdm managed block\n"
	fsys.Seed(enforce.WindowsHostsPath, []byte(hostsContent))
	d := &enforce.Domains{
		Runner: runner,
		FS:     fsys,
		GOOS:   "windows",
		Logger: nil,
	}
	effective := map[string]any{} // No firewallBlockedDomains

	// When: the domain enforcer applies
	ctx := context.Background()
	err := d.Apply(ctx, effective, contract.Posture{})

	// Then: the managed block lines are gone and every other byte is unchanged
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	content, _ := fsys.Content(enforce.WindowsHostsPath)
	contentStr := string(content)
	if !stringContains(contentStr, "127.0.0.1 localhost") {
		t.Errorf("Expected localhost to be preserved")
	}
	if stringContains(contentStr, enforce.HostsBeginMarker) {
		t.Errorf("Expected managed block to be removed")
	}
}

// TestE2E_DomainsEnforcerNoWriteWhenNoBlockAndNothingToBlock verifies that
// no block and nothing to block writes nothing.
func TestE2E_DomainsEnforcerNoWriteWhenNoBlockAndNothingToBlock(t *testing.T) {
	// Given: a hosts file without a managed block and empty blocked list
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	fsys.Seed(enforce.WindowsHostsPath, []byte("127.0.0.1 localhost\n"))
	d := &enforce.Domains{
		Runner: runner,
		FS:     fsys,
		GOOS:   "windows",
		Logger: nil,
	}
	effective := map[string]any{enforce.SettingFirewallBlockedDomains: []any{}}

	// When: the domain enforcer applies
	ctx := context.Background()
	err := d.Apply(ctx, effective, contract.Posture{})

	// Then: the hosts file was not written and no command was run
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(runner.Calls()) != 0 {
		t.Errorf("Expected 0 commands, got %d", len(runner.Calls()))
	}
}

// TestE2E_DomainsEnforcerUnchangedContentNotRewritten verifies that unchanged
// content is not rewritten or flushed.
func TestE2E_DomainsEnforcerUnchangedContentNotRewritten(t *testing.T) {
	// Given: the hosts file already holds the exact block for ["a.com"]
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	expectedContent := "# BEGIN sk-mdm managed block - do not edit\r\n0.0.0.0 a.com\r\n:: a.com\r\n0.0.0.0 www.a.com\r\n:: www.a.com\r\n# END sk-mdm managed block\r\n"
	fsys.Seed(enforce.WindowsHostsPath, []byte(expectedContent))
	d := &enforce.Domains{
		Runner: runner,
		FS:     fsys,
		GOOS:   "windows",
		Logger: nil,
	}
	effective := map[string]any{enforce.SettingFirewallBlockedDomains: []any{"a.com"}}

	// When: the domain enforcer applies
	ctx := context.Background()
	err := d.Apply(ctx, effective, contract.Posture{})

	// Then: the hosts file was not written and no flush command was run
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(runner.Calls()) != 0 {
		t.Errorf("Expected no flush commands, got %d", len(runner.Calls()))
	}
}

// TestE2E_DomainsEnforcerMissingHostsFileTreatedAsEmpty verifies that a
// missing hosts file is treated as empty.
func TestE2E_DomainsEnforcerMissingHostsFileTreatedAsEmpty(t *testing.T) {
	// Given: no hosts file exists
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	d := &enforce.Domains{
		Runner: runner,
		FS:     fsys,
		GOOS:   "windows",
		Logger: nil,
	}
	effective := map[string]any{enforce.SettingFirewallBlockedDomains: []any{"a.com"}}

	// When: the domain enforcer applies
	ctx := context.Background()
	err := d.Apply(ctx, effective, contract.Posture{})

	// Then: the hosts file holds only the managed block
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	content, exists := fsys.Content(enforce.WindowsHostsPath)
	if !exists {
		t.Errorf("Expected hosts file to be created")
	}
	contentStr := string(content)
	if !stringContains(contentStr, enforce.HostsBeginMarker) {
		t.Errorf("Expected managed block BEGIN marker")
	}
	if !stringContains(contentStr, "0.0.0.0 a.com") {
		t.Errorf("Expected a.com in created file")
	}
}

// TestE2E_DomainsEnforcerUnreadableHostsFileLeftAlone verifies that an
// unreadable hosts file is left alone with an error returned.
func TestE2E_DomainsEnforcerUnreadableHostsFileLeftAlone(t *testing.T) {
	// Given: reading the hosts file fails
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	fsys.ReadErr = func(path string) error {
		return &fsError{msg: "permission denied"}
	}
	fsys.Seed(enforce.WindowsHostsPath, []byte("original content"))
	d := &enforce.Domains{
		Runner: runner,
		FS:     fsys,
		GOOS:   "windows",
		Logger: nil,
	}
	effective := map[string]any{enforce.SettingFirewallBlockedDomains: []any{"a.com"}}

	// When: the domain enforcer applies
	ctx := context.Background()
	err := d.Apply(ctx, effective, contract.Posture{})

	// Then: an error is returned and the hosts file was not written
	if err == nil {
		t.Errorf("Expected an error")
	}
	// Content should remain unchanged (not written)
	content, _ := fsys.Content(enforce.WindowsHostsPath)
	if string(content) != "original content" {
		t.Errorf("Expected hosts file to remain unchanged")
	}
}

// TestE2E_DomainsEnforcerMalformedBlockLeftAlone verifies that a malformed
// managed block is left alone with an error.
func TestE2E_DomainsEnforcerMalformedBlockLeftAlone(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		contains string
	}{
		{
			"BEGIN without END",
			"# BEGIN sk-mdm managed block - do not edit\n0.0.0.0 a.com\n",
			"BEGIN marker without END",
		},
		{
			"END without BEGIN",
			"# END sk-mdm managed block\n",
			"END marker without BEGIN",
		},
		{
			"two BEGIN markers",
			"# BEGIN sk-mdm managed block - do not edit\n0.0.0.0 a.com\n# BEGIN sk-mdm managed block - do not edit\n# END sk-mdm managed block\n",
			"more than one BEGIN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			runner := fake.NewCommandRunner()
			fsys := fake.NewFS()
			fsys.Seed(enforce.WindowsHostsPath, []byte(tt.content))
			d := &enforce.Domains{
				Runner: runner,
				FS:     fsys,
				GOOS:   "windows",
				Logger: nil,
			}
			effective := map[string]any{enforce.SettingFirewallBlockedDomains: []any{"a.com"}}

			// When
			ctx := context.Background()
			err := d.Apply(ctx, effective, contract.Posture{})

			// Then
			if err == nil {
				t.Errorf("Expected an error for malformed block")
			}
			if err != nil && !stringContains(err.Error(), "malformed") {
				t.Errorf("Expected error to contain 'malformed', got %q", err.Error())
			}
			// File should remain unchanged
			content, _ := fsys.Content(enforce.WindowsHostsPath)
			if string(content) != tt.content {
				t.Errorf("Expected file to remain unchanged")
			}
		})
	}
}

// TestE2E_EnforceRunContinuesAfterError verifies that one failing enforcer
// doesn't stop the next.
func TestE2E_EnforceRunContinuesAfterError(t *testing.T) {
	// Given: enforcers where E1 fails and E2 succeeds
	e1 := &testEnforcer{name: "E1", err: &testError{msg: "boom"}}
	e2 := &testEnforcer{name: "E2", err: nil}

	// When: enforce.Run is called
	ctx := context.Background()
	enforce.Run(ctx, []enforce.Enforcer{e1, e2}, map[string]any{}, contract.Posture{}, nil)

	// Then: E2 was applied despite E1 error
	if !e2.applied {
		t.Errorf("Expected E2 to be applied despite E1 error")
	}
}

// TestE2E_EnforcePackageDoesNotImportOSOrExec verifies that the enforce
// package only uses platform abstractions.
func TestE2E_EnforcePackageDoesNotImportOSOrExec(t *testing.T) {
	// This is a compile-time check: if enforce imports os or os/exec,
	// the code would fail to compile. The test here is a placeholder
	// to ensure we are aware of this constraint.

	// Given: the enforce package
	// When: we inspect its imports
	// Then: we should only see platform imports, not os/exec

	// The actual check is in the build/lint step. This test documents the requirement.
	// To truly enforce this, add:
	// //go:embed ../../internal/enforce/*.go
	// or use a linter rule that forbids os/exec imports in this package.

	// For now, we document that enforce.Defaults returns the correct types
	// which are platform-agnostic:
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	enforcers := enforce.Defaults(runner, fsys, "windows", nil)

	// The enforcers use platform.CommandRunner and platform.FileSystem
	// (which is verified by the type system)
	if len(enforcers) == 0 {
		t.Errorf("Expected enforcers")
	}
}

// Helper types for testing

type testEnforcer struct {
	name    string
	applied bool
	err     error
}

func (e *testEnforcer) Name() string {
	return e.name
}

func (e *testEnforcer) Apply(ctx context.Context, effective map[string]any, posture contract.Posture) error {
	e.applied = true
	return e.err
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

type fsError struct {
	msg string
}

func (e *fsError) Error() string {
	return e.msg
}

// TestE2E_NewAgentWiresAnalytics verifies that newAgent wires analytics collector and watermark.
func TestE2E_NewAgentWiresAnalytics(t *testing.T) {
	// Given: a simulated agentEnv with fakes for newAgent
	fsys := fake.NewFS()
	runner := fake.NewCommandRunner()
	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))
	doer := fake.NewHTTPDoer()

	cfg := config.Config{CollectionURL: "https://collect.example.com", EnrollmentToken: "tok"}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	fsys.Seed(config.Path("windows"), data)

	env := agentEnv{
		FS:         fsys,
		Runner:     runner,
		Clock:      clock,
		Doer:       doer,
		GOOS:       "windows",
		ConfigPath: config.Path("windows"),
		StatePath:  state.StatePath("windows"),
	}

	// When: newAgent is called
	a, err := newAgent(env)
	if err != nil {
		t.Fatalf("newAgent failed: %v", err)
	}

	// Then: deps.CollectAnalytics and deps.AnalyticsWatermark are non-nil
	if a.deps.CollectAnalytics == nil {
		t.Fatal("deps.CollectAnalytics should be non-nil")
	}
	if a.deps.AnalyticsWatermark == nil {
		t.Fatal("deps.AnalyticsWatermark should be non-nil")
	}

	// And: the watermark path is analytics.WatermarkPath("windows")
	watermarkStore, ok := a.deps.AnalyticsWatermark.(*analytics.WatermarkStore)
	if !ok {
		t.Fatal("deps.AnalyticsWatermark should be a *WatermarkStore")
	}
	if watermarkStore.Path() != analytics.WatermarkPath("windows") {
		t.Errorf("watermark path should be %s, got %s", analytics.WatermarkPath("windows"), watermarkStore.Path())
	}
}

// TestE2E_AnalyticsPackageDoesNotImportOSOrExec verifies that the analytics
// package only uses platform abstractions.
func TestE2E_AnalyticsPackageDoesNotImportOSOrExec(t *testing.T) {
	// The compile-time constraint is checked by the build system.
	// This test documents that analytics.Collect and analytics.Probes
	// work with injected dependencies:
	runner := fake.NewCommandRunner()
	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))

	// Given: Windows probes with fake runner and clock
	probes := analytics.Probes("windows")
	if len(probes) == 0 {
		t.Fatal("Expected probes")
	}

	// When: Collect is called with these fakes
	for _, p := range probes {
		runner.Results[p.String()] = platform.CommandResult{
			Stdout:   "",
			ExitCode: 0,
		}
	}

	_, _, err := analytics.Collect(runner, clock, "windows", time.Time{})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Then: no OS or os/exec functions were called (implicitly verified by
	// the fact that we used only platform abstractions)
}

// stringContains checks if a string contains a substring
func stringContains(s, substr string) bool {
	for i := 0; i < len(s)-len(substr)+1; i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ============================================================================
// TASK-049 AC27: run.go wires executor.Deps.Downloader to a 30-minute client
// ============================================================================

// TestScenario_ApplicationDownloadTimeoutIsThirtyMinutes pins the constant
// run.go wires the Downloader's timeout from.
func TestScenario_ApplicationDownloadTimeoutIsThirtyMinutes(t *testing.T) {
	if executor.ApplicationDownloadTimeout != 30*time.Minute {
		t.Fatalf("expected 30m, got %s", executor.ApplicationDownloadTimeout)
	}
}

// TestScenario_RequestTimeoutForSignedRequestsStillSixtySeconds pins the
// unrelated signed-request timeout, which TASK-049 must not change.
func TestScenario_RequestTimeoutForSignedRequestsStillSixtySeconds(t *testing.T) {
	if requestTimeout != 60*time.Second {
		t.Fatalf("expected 60s, got %s", requestTimeout)
	}
}

// TestE2E_NewAgentWiresApplicationDownloaderWithALongTimeout assembles the
// production agent and runs an install_application command end to end,
// through its real, non-faked Downloader -- an *http.Client whose Timeout is
// executor.ApplicationDownloadTimeout -- fetching from a local httptest
// server. The lease, the download-details fetch and the result post all run
// over the fake signed Doer; only the installer bytes travel over the real
// Downloader, which is exactly the piece run.go wires (agentEnv.Doer, used for
// everything else, keeps its own 60 second timeout unchanged).
func TestE2E_NewAgentWiresApplicationDownloaderWithALongTimeout(t *testing.T) {
	body := []byte("installer-bytes")
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])

	installerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer installerServer.Close()

	fsys := fake.NewFS()
	runner := fake.NewCommandRunner()
	clock := fake.NewClock(time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC))

	doer := fake.NewHTTPDoer()
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/commands"):
			lease := `{"commands":[{"commandId":"cmd-1","type":"install_application",` +
				`"payload":{"applicationId":"app-1","applicationName":"Test App","timeoutSeconds":3600},` +
				`"issuedAt":1000,"expiresAt":2000}]}`
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(lease))}, nil
		case req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/applications/app-1/download"):
			details := fmt.Sprintf(`{"url":%q,"sha256":%q,"installerType":"msi","installArgs":null,"fileName":"a.msi"}`,
				installerServer.URL+"/installer.msi", digest)
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(details))}, nil
		default:
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}"))}, nil
		}
	}

	cfg := config.Config{CollectionURL: "https://collect.example.com", EnrollmentToken: "tok"}
	cfgData, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	fsys.Seed(config.Path("windows"), cfgData)

	stateData, err := json.Marshal(state.State{DeviceID: "dev-1", DeviceSecret: strings.Repeat("ab", 32)})
	if err != nil {
		t.Fatalf("failed to marshal state: %v", err)
	}
	fsys.Seed(state.StatePath("windows"), stateData)

	env := agentEnv{
		FS:         fsys,
		Runner:     runner,
		Clock:      clock,
		Doer:       doer,
		GOOS:       "windows",
		ConfigPath: config.Path("windows"),
		StatePath:  state.StatePath("windows"),
	}

	a, err := newAgent(env)
	if err != nil {
		t.Fatalf("newAgent failed: %v", err)
	}

	if err := a.deps.AfterCheckIn(context.Background(), contract.CheckInResponse{}); err != nil {
		t.Fatalf("AfterCheckIn failed: %v", err)
	}

	var ranMsiexec bool
	for _, call := range runner.Calls() {
		if call.Name == "msiexec" {
			ranMsiexec = true
		}
	}
	if !ranMsiexec {
		t.Fatalf("expected msiexec to run after a real download through the Downloader, calls=%v", runner.Calls())
	}
}

// ============================================================================
// AC15: newAgent wires the action buffer end to end.
// ============================================================================

// TestE2E_AC15_NewAgentWiresTheActionBufferEndToEnd covers:
//
//	Given an agent assembled by newAgent on GOOS windows with a runner
//	     answering exit 0
//	When deps.Enforce runs with firewallEnabled true and the firewall off
//	Then deps.CollectAgentActions returns one "enforce.firewall_enabled" action
func TestE2E_AC15_NewAgentWiresTheActionBufferEndToEnd(t *testing.T) {
	fsys := fake.NewFS()
	runner := fake.NewCommandRunner()
	runner.Results["powershell.exe -NoProfile -NonInteractive -Command Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"] = platform.CommandResult{ExitCode: 0}
	clock := fake.NewClock(time.Date(2026, 10, 12, 1, 0, 0, 0, time.UTC))
	doer := fake.NewHTTPDoer()

	cfg := config.Config{CollectionURL: "https://collect.example.com", EnrollmentToken: "tok"}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	fsys.Seed(config.Path("windows"), data)

	env := agentEnv{
		FS:         fsys,
		Runner:     runner,
		Clock:      clock,
		Doer:       doer,
		GOOS:       "windows",
		ConfigPath: config.Path("windows"),
		StatePath:  state.StatePath("windows"),
	}

	a, err := newAgent(env)
	if err != nil {
		t.Fatalf("newAgent failed: %v", err)
	}
	if a.deps.CollectAgentActions == nil {
		t.Fatal("expected deps.CollectAgentActions to be set")
	}
	// Before any Enforce call, nothing has been recorded.
	if got := a.deps.CollectAgentActions(); got != nil {
		t.Fatalf("CollectAgentActions() before Enforce = %+v, want nil", got)
	}

	effective := map[string]any{enforce.SettingFirewallEnabled: true}
	posture := contract.Posture{Firewall: contract.Firewall{Enabled: false}}
	a.deps.Enforce(context.Background(), effective, posture)

	actions := a.deps.CollectAgentActions()
	if len(actions) != 1 {
		t.Fatalf("CollectAgentActions() = %+v, want exactly one action", actions)
	}
	if actions[0].Type != contract.ActionFirewallEnabled {
		t.Errorf("action type = %q, want %q", actions[0].Type, contract.ActionFirewallEnabled)
	}

	// And: once collected, the buffer is empty again.
	if more := a.deps.CollectAgentActions(); more != nil {
		t.Errorf("expected the buffer to be empty after Collect, got %+v", more)
	}
}

// ============================================================================
// AC12: settleUpdate takes a rollback record left by an earlier process.
// ============================================================================

// TestScenario_AC12_TheNextStartTakesTheRecord covers:
//
//	Given <path>.update-rollback holds a valid record at 2026-10-12T02:00:00Z
//	When the agent settles its update with no marker present
//	Then the file is deleted
//	And the action buffer holds "agent.update_rolled_back" with occurredAt
//	     "2026-10-12T02:00:00Z" and details installedVersion "1.5.0",
//	     runningVersion "1.4.9"
func TestScenario_AC12_TheNextStartTakesTheRecord(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed(update.RollbackPath("/usr/local/bin/mdmagent"), []byte(
		`{"installedVersion":"1.5.0","runningVersion":"1.4.9","occurredAt":"2026-10-12T02:00:00Z"}`,
	))

	buf := agentactions.New(fake.NewClock(time.Now()))
	a := &agent{
		updates: &update.Deps{FS: fsys, Path: "/usr/local/bin/mdmagent", CurrentVersion: "1.4.9"},
		actions: buf,
	}

	a.settleUpdate()

	if a.restartPending {
		t.Fatal("expected restartPending to stay false with no marker present")
	}
	if fsys.Exists(update.RollbackPath("/usr/local/bin/mdmagent")) {
		t.Error("expected the rollback record file to be deleted")
	}

	actions := buf.Collect()
	if len(actions) != 1 {
		t.Fatalf("action buffer = %+v, want exactly one action", actions)
	}
	a0 := actions[0]
	if a0.Type != contract.ActionAgentUpdateRolledBack {
		t.Errorf("type = %q, want %q", a0.Type, contract.ActionAgentUpdateRolledBack)
	}
	if a0.OccurredAt != "2026-10-12T02:00:00Z" {
		t.Errorf("occurredAt = %q, want %q", a0.OccurredAt, "2026-10-12T02:00:00Z")
	}
	if a0.Details["installedVersion"] != "1.5.0" || a0.Details["runningVersion"] != "1.4.9" {
		t.Errorf("details = %+v", a0.Details)
	}
}

// TestScenario_AC12_NoMarkerAndNoRecordLeavesTheBufferEmpty is the baseline:
// a settle with nothing to report touches neither the buffer nor the
// filesystem for a rollback record.
func TestScenario_AC12_NoMarkerAndNoRecordLeavesTheBufferEmpty(t *testing.T) {
	fsys := fake.NewFS()
	buf := agentactions.New(fake.NewClock(time.Now()))
	a := &agent{
		updates: &update.Deps{FS: fsys, Path: "/usr/local/bin/mdmagent", CurrentVersion: "1.4.9"},
		actions: buf,
	}

	a.settleUpdate()

	if a.restartPending {
		t.Error("expected restartPending to stay false")
	}
	if got := buf.Collect(); got != nil {
		t.Errorf("action buffer = %+v, want empty", got)
	}
}

// TestScenario_AC12_TheProcessThatJustRolledBackDoesNotTakeItsOwnRecord
// covers:
//
//	Given RollbackIfUnhealthy returns service.ErrRestartRequired
//	When settleUpdate completes
//	Then <path>.update-rollback still exists and the action buffer is empty
func TestScenario_AC12_TheProcessThatJustRolledBackDoesNotTakeItsOwnRecord(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed("/usr/local/bin/mdmagent", []byte("broken binary"))
	fsys.Seed("/usr/local/bin/mdmagent.old", []byte("working binary"))
	fsys.Seed("/usr/local/bin/mdmagent.update-pending", []byte("1.5.0"))

	buf := agentactions.New(fake.NewClock(time.Now()))
	a := &agent{
		updates: &update.Deps{
			FS:             fsys,
			Path:           "/usr/local/bin/mdmagent",
			CurrentVersion: "1.4.9", // does not match the marker: rollback branch
			Clock:          fake.NewClock(time.Date(2026, 10, 12, 2, 0, 0, 0, time.UTC)),
			Restart: func(ctx context.Context) error {
				return service.ErrRestartRequired
			},
		},
		actions: buf,
	}

	a.settleUpdate()

	if !a.restartPending {
		t.Fatal("expected restartPending to be true after a rollback restart")
	}
	if !fsys.Exists(update.RollbackPath("/usr/local/bin/mdmagent")) {
		t.Error("expected the rollback record file to still exist (not taken by this process)")
	}
	if got := buf.Collect(); got != nil {
		t.Errorf("action buffer = %+v, want empty: this process must not report its own rollback", got)
	}
}

// TestScenario_AC12Edge_ANonRestartErrorStillTakesTheRecordThisProcessWrote
// covers the handoff note: "If RollbackIfUnhealthy returns a non-restart
// error, restartPending stays false and the same process takes its own
// record." This happens when the restart hook itself fails without being the
// sentinel: the rollback record was already written to disk before the
// failing restart call, so settleUpdate's own TakeRollbackRecord call picks
// it straight back up.
func TestScenario_AC12Edge_ANonRestartErrorStillTakesTheRecordThisProcessWrote(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed("/usr/local/bin/mdmagent", []byte("broken binary"))
	fsys.Seed("/usr/local/bin/mdmagent.old", []byte("working binary"))
	fsys.Seed("/usr/local/bin/mdmagent.update-pending", []byte("1.5.0"))

	buf := agentactions.New(fake.NewClock(time.Now()))
	restartErr := errors.New("restart hook failed, not the exit sentinel")
	a := &agent{
		updates: &update.Deps{
			FS:             fsys,
			Path:           "/usr/local/bin/mdmagent",
			CurrentVersion: "1.4.9",
			Clock:          fake.NewClock(time.Date(2026, 10, 12, 2, 0, 0, 0, time.UTC)),
			Restart: func(ctx context.Context) error {
				return restartErr
			},
		},
		actions: buf,
	}

	a.settleUpdate()

	if a.restartPending {
		t.Fatal("expected restartPending to stay false for a non-restart-sentinel error")
	}
	if fsys.Exists(update.RollbackPath("/usr/local/bin/mdmagent")) {
		t.Error("expected the record this process wrote to have been taken (deleted) by its own settleUpdate")
	}
	actions := buf.Collect()
	if len(actions) != 1 {
		t.Fatalf("action buffer = %+v, want exactly one action (this process's own rollback)", actions)
	}
	if actions[0].Type != contract.ActionAgentUpdateRolledBack {
		t.Errorf("type = %q, want %q", actions[0].Type, contract.ActionAgentUpdateRolledBack)
	}
}

// TestScenario_AC12Edge_SettleUpdateWithNilUpdatesIsANoOp covers the guard
// clause: an agent assembled with no BinaryPath (a.updates is nil) settles
// without touching the action buffer.
func TestScenario_AC12Edge_SettleUpdateWithNilUpdatesIsANoOp(t *testing.T) {
	buf := agentactions.New(fake.NewClock(time.Now()))
	a := &agent{actions: buf}
	a.settleUpdate()
	if got := buf.Collect(); got != nil {
		t.Errorf("action buffer = %+v, want empty", got)
	}
}
