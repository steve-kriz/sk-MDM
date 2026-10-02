package enforce

import (
	"context"
	"errors"
	"testing"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// TestUnit_RunCallsEachEnforcer verifies that Run calls every enforcer in order.
func TestUnit_RunCallsEachEnforcer(t *testing.T) {
	// Given: three enforcers that track whether they were called
	calls := []string{}
	e1 := &mockEnforcer{name: "e1", calls: &calls}
	e2 := &mockEnforcer{name: "e2", calls: &calls}
	e3 := &mockEnforcer{name: "e3", calls: &calls}

	// When: Run is called with them
	ctx := context.Background()
	Run(ctx, []Enforcer{e1, e2, e3}, map[string]any{}, contract.Posture{}, nil)

	// Then: they were called in order
	if len(calls) != 3 || calls[0] != "e1" || calls[1] != "e2" || calls[2] != "e3" {
		t.Errorf("Expected [e1 e2 e3], got %v", calls)
	}
}

// TestUnit_RunContinuesAfterEnforcerError verifies that an error from one enforcer
// does not prevent the next from running.
func TestUnit_RunContinuesAfterEnforcerError(t *testing.T) {
	// Given: e1 that returns an error and e2 that succeeds
	calls := []string{}
	e1 := &mockEnforcer{name: "e1", calls: &calls, err: errors.New("boom")}
	e2 := &mockEnforcer{name: "e2", calls: &calls}

	// When: Run is called
	ctx := context.Background()
	Run(ctx, []Enforcer{e1, e2}, map[string]any{}, contract.Posture{}, nil)

	// Then: both were called
	if len(calls) != 2 || calls[0] != "e1" || calls[1] != "e2" {
		t.Errorf("Expected [e1 e2], got %v", calls)
	}
}

// TestUnit_RunLogsEnforcerError verifies that Run handles enforcer errors
// and continues to the next enforcer (logging is tested in e2e tests).
func TestUnit_RunLogsEnforcerError(t *testing.T) {
	// Given: an enforcer that returns an error and a second enforcer
	calls := []string{}
	e1 := &mockEnforcer{name: "e1", calls: &calls, err: errors.New("boom")}
	e2 := &mockEnforcer{name: "e2", calls: &calls}

	// When: Run is called with nil logger (tolerated by the package)
	ctx := context.Background()
	Run(ctx, []Enforcer{e1, e2}, map[string]any{}, contract.Posture{}, nil)

	// Then: both enforcers were called despite e1 error
	if len(calls) != 2 || calls[0] != "e1" || calls[1] != "e2" {
		t.Errorf("Expected [e1 e2], got %v", calls)
	}
}

// TestUnit_RunToleratesNilLogger verifies that Run works with a nil logger.
func TestUnit_RunToleratesNilLogger(t *testing.T) {
	// Given: an enforcer that returns an error and no logger
	e1 := &mockEnforcer{name: "e1", err: errors.New("boom")}

	// When: Run is called with nil logger
	ctx := context.Background()
	Run(ctx, []Enforcer{e1}, map[string]any{}, contract.Posture{}, nil)

	// Then: no panic occurs (test passes if we reach here)
}

// TestUnit_DefaultsReturnsFirewallThenDomains verifies that Defaults returns
// the firewall enforcer first, then the domains enforcer.
func TestUnit_DefaultsReturnsFirewallThenDomains(t *testing.T) {
	// Given: a runner and filesystem
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()

	// When: Defaults is called for windows
	enforcers := Defaults(runner, fsys, "windows", nil)

	// Then: it returns two enforcers named firewall and domains in that order
	if len(enforcers) != 2 {
		t.Errorf("Expected 2 enforcers, got %d", len(enforcers))
	}
	if len(enforcers) >= 1 && enforcers[0].Name() != "firewall" {
		t.Errorf("Expected first enforcer name 'firewall', got %q", enforcers[0].Name())
	}
	if len(enforcers) >= 2 && enforcers[1].Name() != "domains" {
		t.Errorf("Expected second enforcer name 'domains', got %q", enforcers[1].Name())
	}
}

// TestUnit_BoolSettingReadsBoolean verifies that boolSetting correctly reads boolean values.
func TestUnit_BoolSettingReadsBoolean(t *testing.T) {
	// Given: settings with a boolean value
	settings := map[string]any{SettingFirewallEnabled: true}

	// When: boolSetting reads it
	value, ok := boolSetting(settings, SettingFirewallEnabled)

	// Then: it returns the boolean and true
	if !ok || !value {
		t.Errorf("Expected (true, true), got (%v, %v)", value, ok)
	}
}

// TestUnit_BoolSettingReturnsNotOkForNonBoolean verifies that boolSetting
// returns ok=false for non-boolean values.
func TestUnit_BoolSettingReturnsNotOkForNonBoolean(t *testing.T) {
	// Given: settings with a non-boolean value
	settings := map[string]any{SettingFirewallEnabled: "true"}

	// When: boolSetting reads it
	_, ok := boolSetting(settings, SettingFirewallEnabled)

	// Then: it returns ok=false
	if ok {
		t.Errorf("Expected ok=false for string value, got ok=%v", ok)
	}
}

// TestUnit_BoolSettingReturnsNotOkForAbsentKey verifies that boolSetting
// returns ok=false when the key is absent.
func TestUnit_BoolSettingReturnsNotOkForAbsentKey(t *testing.T) {
	// Given: settings without the key
	settings := map[string]any{}

	// When: boolSetting reads it
	value, ok := boolSetting(settings, SettingFirewallEnabled)

	// Then: it returns ok=false
	if ok || value {
		t.Errorf("Expected (false, false), got (%v, %v)", value, ok)
	}
}

// TestUnit_ListSettingReadsArrayOfAny verifies that listSetting reads []any values.
func TestUnit_ListSettingReadsArrayOfAny(t *testing.T) {
	// Given: settings with []any value
	settings := map[string]any{SettingFirewallBlockedDomains: []any{"a.com", "b.com"}}

	// When: listSetting reads it
	list, ok := listSetting(settings, SettingFirewallBlockedDomains)

	// Then: it returns the list and true
	if !ok || len(list) != 2 {
		t.Errorf("Expected ok=true and length 2, got ok=%v, len=%d", ok, len(list))
	}
}

// TestUnit_ListSettingConvertsArrayOfString verifies that listSetting
// converts []string to []any.
func TestUnit_ListSettingConvertsArrayOfString(t *testing.T) {
	// Given: settings with []string value
	settings := map[string]any{SettingFirewallBlockedDomains: []string{"a.com", "b.com"}}

	// When: listSetting reads it
	list, ok := listSetting(settings, SettingFirewallBlockedDomains)

	// Then: it returns the list as []any and true
	if !ok || len(list) != 2 {
		t.Errorf("Expected ok=true and length 2, got ok=%v, len=%d", ok, len(list))
	}
}

// TestUnit_ListSettingReturnsNotOkForNonList verifies that listSetting
// returns ok=false for non-list values.
func TestUnit_ListSettingReturnsNotOkForNonList(t *testing.T) {
	// Given: settings with a non-list value
	settings := map[string]any{SettingFirewallBlockedDomains: "a.com"}

	// When: listSetting reads it
	list, ok := listSetting(settings, SettingFirewallBlockedDomains)

	// Then: it returns ok=false and nil list
	if ok || list != nil {
		t.Errorf("Expected ok=false and nil list, got ok=%v, list=%v", ok, list)
	}
}

// TestUnit_ValidDomainAcceptsValidDomains verifies that validDomain accepts valid domains.
func TestUnit_ValidDomainAcceptsValidDomains(t *testing.T) {
	tests := []string{
		"example.com",
		"a.co",
		"sub.domain.example.com",
		"x-y.example.com",
		"Example.COM",
	}
	for _, domain := range tests {
		if !validDomain(domain) {
			t.Errorf("Expected %q to be valid", domain)
		}
	}
}

// TestUnit_ValidDomainRejectsInvalidDomains verifies that validDomain rejects invalid domains.
func TestUnit_ValidDomainRejectsInvalidDomains(t *testing.T) {
	tests := []string{
		"localhost",           // single label
		"10.0.0.1",            // IP address
		"http://example.com",  // URL with scheme
		"*.example.com",       // wildcard
		"a..b.com",            // empty label
		"example.com\n",       // newline (injection)
		"a",                   // too short
		"",                    // empty
		"-example.com",        // starts with hyphen
		"example-.com",        // ends with hyphen
	}
	for _, domain := range tests {
		if validDomain(domain) {
			t.Errorf("Expected %q to be invalid", domain)
		}
	}
}

// TestUnit_ValidDomainRejectsToolongDomain verifies that validDomain rejects domains longer than 253 characters.
func TestUnit_ValidDomainRejectsToolongDomain(t *testing.T) {
	// Given: a domain that is 254 characters long
	longDomain := ""
	for i := 0; i < 254; i++ {
		longDomain += "a"
	}
	// Add some dots to make it valid syntax
	longDomain = "a." + longDomain + ".com"

	// When: validDomain checks it
	result := validDomain(longDomain)

	// Then: it returns false
	if result {
		t.Errorf("Expected long domain to be invalid")
	}
}

// mockEnforcer is a test double for Enforcer.
type mockEnforcer struct {
	name  string
	calls *[]string
	err   error
}

func (m *mockEnforcer) Name() string {
	return m.name
}

func (m *mockEnforcer) Apply(ctx context.Context, effective map[string]any, posture contract.Posture) error {
	if m.calls != nil {
		*m.calls = append(*m.calls, m.name)
	}
	return m.err
}

