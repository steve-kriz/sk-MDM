// Package enforce makes the device's effective policy settings true on the
// machine, once per cycle, after the bundle has been evaluated.
//
// Each setting family has its own Enforcer. The scheduler hands every one of
// them the bundle's effectiveSettings and the posture the cycle collected;
// an enforcer that has nothing to do returns nil without touching the system,
// and one that fails costs a single warning line and never stops the next
// enforcer or the check-in.
//
// Enforcement only ever moves a device towards a setting. A setting that is
// false or absent means "not required", never "turn it off": no code path in
// this package disables a firewall.
//
// Like the rest of agent/internal, this package touches the operating system
// only through agent/internal/platform: commands through CommandRunner and
// files through FileSystem, so the whole suite runs against the fakes in
// agent/internal/platform/fake.
package enforce

import (
	"context"
	"regexp"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// The policy setting keys this package enforces. They are the keys the backend
// validates in backend/src/admin/policies.ts; renaming one means changing it
// there too.
const (
	// SettingFirewallEnabled requires the host firewall to be on.
	SettingFirewallEnabled = "firewallEnabled"
	// SettingFirewallBlockedDomains lists the domains the device must not reach.
	SettingFirewallBlockedDomains = "firewallBlockedDomains"
	// SettingFirewallAllowedDomains lists exceptions removed from the blocked set.
	SettingFirewallAllowedDomains = "firewallAllowedDomains"
)

// Domain entry limits, the same rule the backend applies before it stores a
// list. An entry that reaches the agent without meeting it is skipped.
const (
	// DomainMaxLength is the longest accepted domain name, in characters.
	DomainMaxLength = 253
)

// domainPattern is what one domain entry must look like: two or more labels,
// alphanumeric with inner hyphens, ending in an alphabetic top-level label.
// Without the multi-line flag `$` matches only at the end of the text, so an
// entry carrying a newline never matches.
var domainPattern = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$`)

// Enforcer applies one family of settings to the machine.
type Enforcer interface {
	// Name identifies the enforcer in the log.
	Name() string

	// Apply makes the settings it owns true on the machine. A nil return
	// means the machine now holds them, or that nothing was required.
	Apply(ctx context.Context, effective map[string]any, posture contract.Posture) error
}

// Run applies every enforcer in slice order. An enforcer's error is logged as
// one warning and the next enforcer still runs. A nil logger is allowed.
func Run(ctx context.Context, enforcers []Enforcer, effective map[string]any, posture contract.Posture, logger *logging.Logger) {
	for _, enforcer := range enforcers {
		if err := enforcer.Apply(ctx, effective, posture); err != nil {
			warn(logger, "policy enforcement failed",
				logging.F("enforcer", enforcer.Name()),
				logging.F("error", err.Error()))
		}
	}
}

// Defaults is the production enforcer list: the firewall, then the domains.
func Defaults(runner platform.CommandRunner, fsys platform.FileSystem, goos string, logger *logging.Logger) []Enforcer {
	return []Enforcer{
		&Firewall{Runner: runner, GOOS: goos},
		&Domains{Runner: runner, FS: fsys, GOOS: goos, Logger: logger},
	}
}

// warn writes one warning, or nothing when there is no logger.
func warn(logger *logging.Logger, msg string, fields ...logging.Field) {
	if logger == nil {
		return
	}
	_ = logger.Log(logging.LevelWarn, msg, fields...)
}

// boolSetting reads key as a boolean. A value of any other type is reported as
// not set, exactly as agent/internal/policy reads it.
func boolSetting(settings map[string]any, key string) (bool, bool) {
	value, ok := settings[key]
	if !ok {
		return false, false
	}
	b, ok := value.(bool)
	return b, ok
}

// listSetting reads key as a list. A bundle decoded from JSON holds []any; a
// bundle built in Go may hold []string. Any other value is reported as not set.
// Entries are returned as they are, so the caller can name the ones it skips.
func listSetting(settings map[string]any, key string) ([]any, bool) {
	value, ok := settings[key]
	if !ok {
		return nil, false
	}

	switch v := value.(type) {
	case []string:
		list := make([]any, 0, len(v))
		for _, item := range v {
			list = append(list, item)
		}
		return list, true
	case []any:
		return v, true
	default:
		return nil, false
	}
}

// validDomain reports whether entry meets the backend's domain rule.
func validDomain(entry string) bool {
	return len(entry) <= DomainMaxLength && domainPattern.MatchString(entry)
}
