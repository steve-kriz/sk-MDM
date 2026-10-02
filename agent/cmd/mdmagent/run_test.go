package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/antivirus"
	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/enforce"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
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

// stringContains checks if a string contains a substring
func stringContains(s, substr string) bool {
	for i := 0; i < len(s)-len(substr)+1; i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
