// Package policy evaluates the device's policy bundle against the posture the
// agent just collected and reports the result on the next check-in.
//
// v1 reports, it does not enforce: a violation found here travels to the
// backend as one entry of CheckInRequest.policyCompliance, and whatever has to
// change on the device is done by a command the backend issues afterwards.
//
// Each entry of the bundle is judged on its own settings rather than on the
// bundle's effectiveSettings, because a result is reported per policyId and
// version: a policy that lost a contested setting still has to say whether the
// device met what that policy itself asked for.
//
// A setting this package does not understand is treated as met. The backend
// (backend/src/admin/policies.ts) also stores screenLockTimeoutSeconds, which
// no posture probe reports, so a policy that sets only that is compliant here
// and is enforced by command instead. The same holds for firewallBlockedDomains
// and firewallAllowedDomains: agent/internal/enforce writes them into the hosts
// file, and they are not judged here, so a policy that sets only those is
// compliant.
package policy

import (
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
)

// The policy setting keys this package understands. They are the keys the
// backend validates in backend/src/admin/policies.ts; renaming one means
// changing it there too.
const (
	// SettingFirewallEnabled requires the host firewall to be on.
	SettingFirewallEnabled = "firewallEnabled"
	// SettingDiskEncryptionRequired requires full-disk encryption.
	SettingDiskEncryptionRequired = "diskEncryptionRequired"
	// SettingOSUpdateMaxAgeDays is how old the last OS update check may be.
	SettingOSUpdateMaxAgeDays = "osUpdateMaxAgeDays"
	// SettingLocalAdminAllowlist names the accounts allowed to be local
	// administrators; any other local administrator is a violation.
	SettingLocalAdminAllowlist = "localAdminAllowlist"
)

// The violation codes reported on the wire. ViolationLocalAdminPrefix is a
// prefix: the offending account name is appended to it verbatim, one entry per
// account.
const (
	ViolationFirewallDisabled      = "firewall_disabled"
	ViolationDiskEncryptionMissing = "disk_encryption_missing"
	ViolationOSUpdateOverdue       = "os_update_overdue"
	ViolationLocalAdminPrefix      = "unauthorized_local_admin:"
)

// day is the unit the OS update age is measured in.
const day = 24 * time.Hour

// Result is one evaluated policy, as it travels inside
// contract.CheckInRequest.PolicyCompliance.
//
// Violations is always present and never nil: a compliant policy marshals
// "violations": [] rather than "violations": null, so the backend never has to
// tell absent from empty.
type Result struct {
	PolicyId   string   `json:"policyId"`
	Version    int      `json:"version"`
	Compliant  bool     `json:"compliant"`
	Violations []string `json:"violations"`
}

// Entry is Result as the frozen wire type in agent/internal/contract spells
// it. The two carry the same four json fields; this is the conversion the
// check-in body is built from.
func (r Result) Entry() contract.PolicyComplianceEntry {
	violations := r.Violations
	if violations == nil {
		violations = []string{}
	}
	return contract.PolicyComplianceEntry{
		PolicyID:   r.PolicyId,
		Version:    r.Version,
		Compliant:  r.Compliant,
		Violations: violations,
	}
}

// Entries converts a slice of results to the wire type, preserving order.
func Entries(results []Result) []contract.PolicyComplianceEntry {
	entries := make([]contract.PolicyComplianceEntry, 0, len(results))
	for _, r := range results {
		entries = append(entries, r.Entry())
	}
	return entries
}

// Evaluate judges every policy in the bundle against posture and returns one
// Result per entry of bundle.Policies, in the order those entries appear.
//
// now is the injected clock's time: the OS update age is measured against it,
// never against the wall clock.
func Evaluate(bundle contract.PolicyBundleResponse, posture contract.Posture, now time.Time) []Result {
	results := make([]Result, 0, len(bundle.Policies))
	for _, p := range bundle.Policies {
		results = append(results, evaluatePolicy(p, posture, now))
	}
	return results
}

// evaluatePolicy judges one policy. Violations are collected in a fixed order
// — firewall, disk encryption, OS update, then the local administrators sorted
// by account name — so two runs over the same facts produce the same bytes.
func evaluatePolicy(p contract.Policy, posture contract.Posture, now time.Time) Result {
	violations := []string{}

	if required, ok := boolSetting(p.Settings, SettingFirewallEnabled); ok && required && !posture.Firewall.Enabled {
		violations = append(violations, ViolationFirewallDisabled)
	}

	if required, ok := boolSetting(p.Settings, SettingDiskEncryptionRequired); ok && required && !posture.DiskEncryption.Enabled {
		violations = append(violations, ViolationDiskEncryptionMissing)
	}

	if maxAgeDays, ok := intSetting(p.Settings, SettingOSUpdateMaxAgeDays); ok {
		// A timestamp that is missing or unreadable is reported overdue
		// rather than skipped: the device cannot show it is up to date.
		age, known := UpdateAgeDays(posture.OSUpdate.LastCheckedAt, now)
		if !known || age > maxAgeDays {
			violations = append(violations, ViolationOSUpdateOverdue)
		}
	}

	if allowlist, ok := stringsSetting(p.Settings, SettingLocalAdminAllowlist); ok {
		violations = append(violations, unauthorizedAdmins(posture.LocalAdmins, allowlist)...)
	}

	return Result{
		PolicyId:   p.PolicyID,
		Version:    p.Version,
		Compliant:  len(violations) == 0,
		Violations: violations,
	}
}

// UpdateAgeDays is how many whole days ago lastCheckedAt was, floored, with
// lastCheckedAt parsed as RFC3339. The second return is false when the
// timestamp is empty or does not parse, which no caller may treat as age zero.
func UpdateAgeDays(lastCheckedAt string, now time.Time) (int, bool) {
	checked, err := time.Parse(time.RFC3339, lastCheckedAt)
	if err != nil {
		return 0, false
	}

	elapsed := now.Sub(checked)
	days := elapsed / day
	// Integer division truncates toward zero; a clock behind the recorded
	// check has to floor downwards to stay a floor.
	if elapsed < 0 && elapsed%day != 0 {
		days--
	}
	return int(days), true
}

// unauthorizedAdmins names every local administrator that the allowlist does
// not carry, sorted ascending by account name. Account names are compared and
// reported exactly as both sides spell them.
func unauthorizedAdmins(localAdmins, allowlist []string) []string {
	allowed := make(map[string]bool, len(allowlist))
	for _, account := range allowlist {
		allowed[account] = true
	}

	offenders := make([]string, 0, len(localAdmins))
	for _, account := range localAdmins {
		if !allowed[account] {
			offenders = append(offenders, account)
		}
	}
	sort.Strings(offenders)

	violations := make([]string, 0, len(offenders))
	for _, account := range offenders {
		violations = append(violations, ViolationLocalAdminPrefix+account)
	}
	return violations
}

// boolSetting reads key as a boolean. A key that is absent, or holds anything
// but a boolean, is reported as unset and so is treated as met.
func boolSetting(settings map[string]any, key string) (bool, bool) {
	value, ok := settings[key]
	if !ok {
		return false, false
	}
	b, ok := value.(bool)
	return b, ok
}

// intSetting reads key as a whole number. A bundle decoded from JSON holds
// float64 here; a bundle built in Go may hold any integer kind, so both are
// accepted.
func intSetting(settings map[string]any, key string) (int, bool) {
	value, ok := settings[key]
	if !ok {
		return 0, false
	}

	switch v := value.(type) {
	case int:
		return v, true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	case float32:
		return int(v), true
	case json.Number:
		n, err := strconv.ParseInt(v.String(), 10, 64)
		if err != nil {
			return 0, false
		}
		return int(n), true
	default:
		return 0, false
	}
}

// stringsSetting reads key as a list of strings, accepting both the []any a
// JSON decode produces and a []string built in Go. A non-string element is
// dropped; a value that is not a list at all is reported as unset.
func stringsSetting(settings map[string]any, key string) ([]string, bool) {
	value, ok := settings[key]
	if !ok {
		return nil, false
	}

	switch v := value.(type) {
	case []string:
		return v, true
	case []any:
		list := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				list = append(list, s)
			}
		}
		return list, true
	default:
		return nil, false
	}
}
