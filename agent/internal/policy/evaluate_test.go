package policy

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
)

// TestScenario_ResultsMirrorBundleEntries tests that results match bundle order and structure.
func TestScenario_ResultsMirrorBundleEntries(t *testing.T) {
	// Given: a bundle with policies p1 version 2 and p2 version 5
	bundle := contract.PolicyBundleResponse{
		Policies: []contract.Policy{
			{PolicyID: "p1", Version: 2, Settings: map[string]any{}},
			{PolicyID: "p2", Version: 5, Settings: map[string]any{}},
		},
	}
	posture := contract.Posture{}
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

	// When: Evaluate runs
	results := Evaluate(bundle, posture, now)

	// Then: two Results are returned in that order with policyId/version p1/2 and p2/5
	if len(results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(results))
	}

	if results[0].PolicyId != "p1" || results[0].Version != 2 {
		t.Errorf("Expected first result p1/2, got %s/%d", results[0].PolicyId, results[0].Version)
	}

	if results[1].PolicyId != "p2" || results[1].Version != 5 {
		t.Errorf("Expected second result p2/5, got %s/%d", results[1].PolicyId, results[1].Version)
	}

	// And: marshalling them produces the keys policyId, version, compliant and violations
	data, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("Failed to marshal results: %v", err)
	}

	var obj []map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatalf("Failed to unmarshal results: %v", err)
	}

	if len(obj) < 1 {
		t.Fatal("No results in JSON")
	}

	expectedKeys := map[string]bool{"policyId": true, "version": true, "compliant": true, "violations": true}
	for key := range obj[0] {
		if !expectedKeys[key] {
			t.Errorf("Unexpected key in JSON: %s", key)
		}
	}
	for key := range expectedKeys {
		if _, ok := obj[0][key]; !ok {
			t.Errorf("Missing key in JSON: %s", key)
		}
	}
}

// TestScenario_FirewallViolationIsReported tests firewall check.
func TestScenario_FirewallViolationIsReported(t *testing.T) {
	// Given: a policy with firewallEnabled true and posture firewall enabled false
	bundle := contract.PolicyBundleResponse{
		Policies: []contract.Policy{
			{
				PolicyID: "fw-policy",
				Version:  1,
				Settings: map[string]any{SettingFirewallEnabled: true},
			},
		},
	}
	posture := contract.Posture{
		Firewall: contract.Firewall{Enabled: false},
	}
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

	// When: Evaluate runs
	results := Evaluate(bundle, posture, now)

	// Then: the result is compliant false with violation firewall_disabled
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	if results[0].Compliant {
		t.Error("Expected compliant false")
	}

	if len(results[0].Violations) == 0 {
		t.Fatal("Expected violations")
	}

	found := false
	for _, v := range results[0].Violations {
		if v == ViolationFirewallDisabled {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected violation %s, got %v", ViolationFirewallDisabled, results[0].Violations)
	}
}

// TestScenario_DiskEncryptionViolationIsReported tests disk encryption check.
func TestScenario_DiskEncryptionViolationIsReported(t *testing.T) {
	// Given: a policy with diskEncryptionRequired true and posture diskEncryption enabled false
	bundle := contract.PolicyBundleResponse{
		Policies: []contract.Policy{
			{
				PolicyID: "de-policy",
				Version:  1,
				Settings: map[string]any{SettingDiskEncryptionRequired: true},
			},
		},
	}
	posture := contract.Posture{
		DiskEncryption: contract.DiskEncryption{Enabled: false},
	}
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

	// When: Evaluate runs
	results := Evaluate(bundle, posture, now)

	// Then: the result is compliant false with violation disk_encryption_missing
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	if results[0].Compliant {
		t.Error("Expected compliant false")
	}

	found := false
	for _, v := range results[0].Violations {
		if v == ViolationDiskEncryptionMissing {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected violation %s, got %v", ViolationDiskEncryptionMissing, results[0].Violations)
	}
}

// TestScenario_OSUpdateAgeIsFloored tests OS update age calculation.
func TestScenario_OSUpdateAgeIsFloored(t *testing.T) {
	// Given: osUpdateMaxAgeDays 7, now 2026-10-02T00:00:00Z and lastCheckedAt 2026-09-24T12:00:00Z
	bundle := contract.PolicyBundleResponse{
		Policies: []contract.Policy{
			{
				PolicyID: "update-policy",
				Version:  1,
				Settings: map[string]any{SettingOSUpdateMaxAgeDays: 7},
			},
		},
	}

	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	lastCheckedAt := "2026-09-24T12:00:00Z"

	posture := contract.Posture{
		OSUpdate: contract.OSUpdate{LastCheckedAt: lastCheckedAt},
	}

	// When: Evaluate runs
	results := Evaluate(bundle, posture, now)

	// Then: the computed age is 7 days and no os_update_overdue violation is produced
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	if !results[0].Compliant {
		t.Errorf("Expected compliant true for age 7 <= 7, got %v with violations: %v", results[0].Compliant, results[0].Violations)
	}

	for _, v := range results[0].Violations {
		if v == ViolationOSUpdateOverdue {
			t.Errorf("Did not expect os_update_overdue violation for age 7")
		}
	}

	// And: with lastCheckedAt 2026-09-24T00:00:00Z the age is 8 and os_update_overdue is produced
	posture.OSUpdate.LastCheckedAt = "2026-09-24T00:00:00Z"
	results = Evaluate(bundle, posture, now)

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	if results[0].Compliant {
		t.Errorf("Expected compliant false for age 8 > 7")
	}

	found := false
	for _, v := range results[0].Violations {
		if v == ViolationOSUpdateOverdue {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected os_update_overdue violation, got %v", results[0].Violations)
	}
}

// TestScenario_UnparseableUpdateTimestampIsOverdue tests handling of invalid timestamps.
func TestScenario_UnparseableUpdateTimestampIsOverdue(t *testing.T) {
	// Given: osUpdateMaxAgeDays 7 and lastCheckedAt ""
	bundle := contract.PolicyBundleResponse{
		Policies: []contract.Policy{
			{
				PolicyID: "update-policy",
				Version:  1,
				Settings: map[string]any{SettingOSUpdateMaxAgeDays: 7},
			},
		},
	}

	posture := contract.Posture{
		OSUpdate: contract.OSUpdate{LastCheckedAt: ""},
	}
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

	// When: Evaluate runs
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Evaluate panicked: %v", r)
		}
	}()

	results := Evaluate(bundle, posture, now)

	// Then: the result is compliant false with violation os_update_overdue and no panic occurs
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	if results[0].Compliant {
		t.Error("Expected compliant false for unparseable timestamp")
	}

	found := false
	for _, v := range results[0].Violations {
		if v == ViolationOSUpdateOverdue {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected os_update_overdue violation, got %v", results[0].Violations)
	}
}

// TestScenario_UnauthorizedAdminsAreSorted tests local admin allowlist check.
func TestScenario_UnauthorizedAdminsAreSorted(t *testing.T) {
	// Given: localAdminAllowlist ["Administrator"] and posture localAdmins ["zoe","Administrator","evil"]
	bundle := contract.PolicyBundleResponse{
		Policies: []contract.Policy{
			{
				PolicyID: "admin-policy",
				Version:  1,
				Settings: map[string]any{
					SettingLocalAdminAllowlist: []string{"Administrator"},
				},
			},
		},
	}

	posture := contract.Posture{
		LocalAdmins: []string{"zoe", "Administrator", "evil"},
	}
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

	// When: Evaluate runs
	results := Evaluate(bundle, posture, now)

	// Then: violations contains exactly "unauthorized_local_admin:evil" and "unauthorized_local_admin:zoe" in that order
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	if results[0].Compliant {
		t.Error("Expected compliant false")
	}

	unauthorizedAdmins := []string{}
	for _, v := range results[0].Violations {
		if v != ViolationFirewallDisabled && v != ViolationDiskEncryptionMissing && v != ViolationOSUpdateOverdue {
			unauthorizedAdmins = append(unauthorizedAdmins, v)
		}
	}

	if len(unauthorizedAdmins) != 2 {
		t.Fatalf("Expected 2 unauthorized admin violations, got %d: %v", len(unauthorizedAdmins), unauthorizedAdmins)
	}

	if unauthorizedAdmins[0] != ViolationLocalAdminPrefix+"evil" {
		t.Errorf("Expected first violation 'unauthorized_local_admin:evil', got %s", unauthorizedAdmins[0])
	}

	if unauthorizedAdmins[1] != ViolationLocalAdminPrefix+"zoe" {
		t.Errorf("Expected second violation 'unauthorized_local_admin:zoe', got %s", unauthorizedAdmins[1])
	}
}

// TestScenario_UnknownSettingsAreTreatedAsMet tests handling of unknown settings.
func TestScenario_UnknownSettingsAreTreatedAsMet(t *testing.T) {
	// Given: a policy whose settings hold only screenLockTimeoutSeconds
	bundle := contract.PolicyBundleResponse{
		Policies: []contract.Policy{
			{
				PolicyID: "unknown-policy",
				Version:  1,
				Settings: map[string]any{
					"screenLockTimeoutSeconds": 30,
				},
			},
		},
	}

	posture := contract.Posture{}
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

	// When: Evaluate runs
	results := Evaluate(bundle, posture, now)

	// Then: it is compliant true and violations marshals as [] rather than null
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	if !results[0].Compliant {
		t.Errorf("Expected compliant true, got false with violations %v", results[0].Violations)
	}

	// Marshal and check that violations is [] not null
	data, err := json.Marshal(results[0])
	if err != nil {
		t.Fatalf("Failed to marshal result: %v", err)
	}

	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	violationsJSON := string(data)
	if !strings.Contains(violationsJSON, `"violations":[]`) {
		t.Errorf("Expected violations marshaled as [], got: %s", violationsJSON)
	}
}

// TestScenario_EmptyViolationsArrayNotNull tests that violations is never nil.
func TestScenario_EmptyViolationsArrayNotNull(t *testing.T) {
	// Given: a policy with no violations
	bundle := contract.PolicyBundleResponse{
		Policies: []contract.Policy{
			{
				PolicyID: "clean-policy",
				Version:  1,
				Settings: map[string]any{},
			},
		},
	}

	posture := contract.Posture{
		Firewall:       contract.Firewall{Enabled: true},
		DiskEncryption: contract.DiskEncryption{Enabled: true},
		OSUpdate:       contract.OSUpdate{LastCheckedAt: "2026-10-02T00:00:00Z"},
	}
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

	// When: Evaluate runs
	results := Evaluate(bundle, posture, now)

	// Then: violations is an empty array, not nil
	if results[0].Violations == nil {
		t.Error("Expected empty violations array, got nil")
	}

	if len(results[0].Violations) != 0 {
		t.Errorf("Expected empty violations, got %v", results[0].Violations)
	}

	// Verify it marshals as []
	data, _ := json.Marshal(results[0])
	if !strings.Contains(string(data), `"violations":[]`) {
		t.Errorf("Expected violations to marshal as [], got: %s", string(data))
	}
}

// TestScenario_UpdateAgeDaysCalculation tests the UpdateAgeDays helper function.
func TestScenario_UpdateAgeDaysCalculation(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

	// Test case 1: exactly 7 days before
	checked := "2026-09-25T00:00:00Z"
	age, known := UpdateAgeDays(checked, now)
	if !known {
		t.Fatal("Expected known=true")
	}
	if age != 7 {
		t.Errorf("Expected age 7, got %d", age)
	}

	// Test case 2: 7 days 1 hour before (should be 7 due to floor)
	checked = "2026-09-24T23:00:00Z"
	age, known = UpdateAgeDays(checked, now)
	if !known {
		t.Fatal("Expected known=true")
	}
	if age != 7 {
		t.Errorf("Expected age 7, got %d", age)
	}

	// Test case 3: 8 days before
	checked = "2026-09-24T00:00:00Z"
	age, known = UpdateAgeDays(checked, now)
	if !known {
		t.Fatal("Expected known=true")
	}
	if age != 8 {
		t.Errorf("Expected age 8, got %d", age)
	}

	// Test case 4: invalid timestamp
	checked = "not a timestamp"
	age, known = UpdateAgeDays(checked, now)
	if known {
		t.Error("Expected known=false for invalid timestamp")
	}

	// Test case 5: empty timestamp
	checked = ""
	age, known = UpdateAgeDays(checked, now)
	if known {
		t.Error("Expected known=false for empty timestamp")
	}
}

// TestScenario_DomainOnlyPolicyIsCompliant tests that a policy whose settings
// hold only firewallBlockedDomains and/or firewallAllowedDomains evaluates
// compliant true with violations [], per AC18: these keys are enforced by
// agent/internal/enforce, not judged here.
func TestScenario_DomainOnlyPolicyIsCompliant(t *testing.T) {
	// Given: a policy whose settings are {firewallBlockedDomains:["a.com"], firewallAllowedDomains:["b.com"]}
	bundle := contract.PolicyBundleResponse{
		Policies: []contract.Policy{
			{
				PolicyID: "domain-policy",
				Version:  1,
				Settings: map[string]any{
					"firewallBlockedDomains": []string{"a.com"},
					"firewallAllowedDomains": []string{"b.com"},
				},
			},
		},
	}
	posture := contract.Posture{}
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

	// When: policy.Evaluate runs
	results := Evaluate(bundle, posture, now)

	// Then: the result is compliant true with violations []
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}
	if !results[0].Compliant {
		t.Errorf("Expected compliant true, got false with violations %v", results[0].Violations)
	}
	if len(results[0].Violations) != 0 {
		t.Errorf("Expected empty violations, got %v", results[0].Violations)
	}

	data, err := json.Marshal(results[0])
	if err != nil {
		t.Fatalf("Failed to marshal result: %v", err)
	}
	if !strings.Contains(string(data), `"violations":[]`) {
		t.Errorf("Expected violations marshaled as [], got: %s", string(data))
	}
}

// Helper for substring check in violations
func contains(violations []string, s string) bool {
	for _, v := range violations {
		if v == s {
			return true
		}
	}
	return false
}

// TestUnit_PolicyResultJSON tests the JSON marshaling of Result.
func TestUnit_PolicyResultJSON(t *testing.T) {
	result := Result{
		PolicyId:   "p1",
		Version:    2,
		Compliant:  false,
		Violations: []string{"firewall_disabled", "disk_encryption_missing"},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if obj["policyId"] != "p1" {
		t.Errorf("Expected policyId p1, got %v", obj["policyId"])
	}
	if obj["version"] != float64(2) {
		t.Errorf("Expected version 2, got %v", obj["version"])
	}
	if obj["compliant"] != false {
		t.Errorf("Expected compliant false, got %v", obj["compliant"])
	}
}

// TestUnit_EntryConverter tests the Entry() converter method.
func TestUnit_EntryConverter(t *testing.T) {
	result := Result{
		PolicyId:   "p1",
		Version:    1,
		Compliant:  false,
		Violations: []string{"firewall_disabled"},
	}

	entry := result.Entry()

	if entry.PolicyID != "p1" {
		t.Errorf("Expected PolicyID p1, got %s", entry.PolicyID)
	}
	if entry.Version != 1 {
		t.Errorf("Expected Version 1, got %d", entry.Version)
	}
	if entry.Compliant {
		t.Errorf("Expected Compliant false, got %v", entry.Compliant)
	}
	if len(entry.Violations) != 1 || entry.Violations[0] != "firewall_disabled" {
		t.Errorf("Expected violations [firewall_disabled], got %v", entry.Violations)
	}
}

// TestUnit_EntriesConverter tests the Entries() converter function.
func TestUnit_EntriesConverter(t *testing.T) {
	results := []Result{
		{PolicyId: "p1", Version: 1, Compliant: true, Violations: []string{}},
		{PolicyId: "p2", Version: 2, Compliant: false, Violations: []string{"firewall_disabled"}},
	}

	entries := Entries(results)

	if len(entries) != 2 {
		t.Fatalf("Expected 2 entries, got %d", len(entries))
	}

	if entries[0].PolicyID != "p1" {
		t.Errorf("Expected first PolicyID p1, got %s", entries[0].PolicyID)
	}
	if entries[1].PolicyID != "p2" {
		t.Errorf("Expected second PolicyID p2, got %s", entries[1].PolicyID)
	}
}

// TestUnit_EvaluatePolicyWithMultipleViolations tests a policy with multiple violations.
func TestUnit_EvaluatePolicyWithMultipleViolations(t *testing.T) {
	// A policy that requires firewall, disk encryption, and limits OS update age
	policy := contract.Policy{
		PolicyID: "strict",
		Version:  1,
		Settings: map[string]any{
			SettingFirewallEnabled:        true,
			SettingDiskEncryptionRequired: true,
			SettingOSUpdateMaxAgeDays:     5,
			SettingLocalAdminAllowlist:    []string{"Administrator"},
		},
	}

	// A posture that violates all of these
	posture := contract.Posture{
		Firewall:       contract.Firewall{Enabled: false},
		DiskEncryption: contract.DiskEncryption{Enabled: false},
		OSUpdate:       contract.OSUpdate{LastCheckedAt: "2026-09-20T00:00:00Z"}, // 12 days old
		LocalAdmins:    []string{"Administrator", "Bob", "Charlie"},
	}

	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

	// Evaluate just this policy
	bundle := contract.PolicyBundleResponse{Policies: []contract.Policy{policy}}
	results := Evaluate(bundle, posture, now)

	result := results[0]

	// Should have multiple violations in the correct order:
	// firewall, disk encryption, OS update, then unauthorized admins sorted
	expected := []string{
		ViolationFirewallDisabled,
		ViolationDiskEncryptionMissing,
		ViolationOSUpdateOverdue,
		ViolationLocalAdminPrefix + "Bob",
		ViolationLocalAdminPrefix + "Charlie",
	}

	// Verify the admin violations are sorted
	adminViolations := []string{}
	for _, v := range result.Violations {
		if strings.HasPrefix(v, ViolationLocalAdminPrefix) {
			adminViolations = append(adminViolations, v)
		}
	}
	if !sort.StringsAreSorted(adminViolations) {
		t.Errorf("Admin violations not sorted: %v", adminViolations)
	}

	if len(result.Violations) != len(expected) {
		t.Errorf("Expected %d violations, got %d: %v", len(expected), len(result.Violations), result.Violations)
	}

	for i, v := range expected {
		if i >= len(result.Violations) {
			t.Errorf("Missing expected violation: %s", v)
			continue
		}
		if result.Violations[i] != v {
			t.Errorf("Expected violation[%d]=%s, got %s", i, v, result.Violations[i])
		}
	}
}

// TestUnit_BoolSettingExtraction tests boolean setting parsing.
func TestUnit_BoolSettingExtraction(t *testing.T) {
	settings := map[string]any{
		"firewallEnabled": true,
		"invalidBool":     "not a bool",
	}

	val, ok := boolSetting(settings, "firewallEnabled")
	if !ok || !val {
		t.Errorf("Expected true for firewallEnabled, got %v, ok=%v", val, ok)
	}

	val, ok = boolSetting(settings, "invalidBool")
	if ok || val {
		t.Errorf("Expected false,ok=false for invalidBool, got %v, ok=%v", val, ok)
	}

	val, ok = boolSetting(settings, "missing")
	if ok {
		t.Errorf("Expected ok=false for missing key, got %v", ok)
	}
}

// TestUnit_IntSettingExtraction tests integer setting parsing.
func TestUnit_IntSettingExtraction(t *testing.T) {
	settings := map[string]any{
		"intValue":   42,
		"floatValue": 42.5,
		"int64Value": int64(42),
		"int32Value": int32(42),
	}

	val, ok := intSetting(settings, "intValue")
	if !ok || val != 42 {
		t.Errorf("Expected 42 for intValue, got %v, ok=%v", val, ok)
	}

	val, ok = intSetting(settings, "floatValue")
	if !ok || val != 42 {
		t.Errorf("Expected 42 for floatValue (truncated), got %v, ok=%v", val, ok)
	}

	val, ok = intSetting(settings, "missing")
	if ok {
		t.Errorf("Expected ok=false for missing key")
	}
}

// TestUnit_StringsSettingExtraction tests string list setting parsing.
func TestUnit_StringsSettingExtraction(t *testing.T) {
	settings := map[string]any{
		"stringList": []string{"a", "b", "c"},
		"anyList":    []any{"x", "y", "z"},
		"mixed":      []any{"a", 42, "b"},
	}

	val, ok := stringsSetting(settings, "stringList")
	if !ok || len(val) != 3 {
		t.Errorf("Expected 3 strings for stringList, got %v, ok=%v", val, ok)
	}

	val, ok = stringsSetting(settings, "anyList")
	if !ok || len(val) != 3 {
		t.Errorf("Expected 3 strings for anyList, got %v, ok=%v", val, ok)
	}

	val, ok = stringsSetting(settings, "mixed")
	if !ok || len(val) != 2 {
		t.Errorf("Expected 2 strings for mixed (non-strings dropped), got %v, ok=%v", val, ok)
	}

	val, ok = stringsSetting(settings, "missing")
	if ok {
		t.Errorf("Expected ok=false for missing key")
	}
}

// ============================================================================
// TASK-030: Antivirus Setting Tests
// ============================================================================

// TestScenario_AntivirusOffViolatesAnAntivirusPolicy covers the setting key,
// the violation key and both posture outcomes.
func TestScenario_AntivirusOffViolatesAnAntivirusPolicy(t *testing.T) {
	if SettingAntivirusEnabled != "antivirusEnabled" {
		t.Fatalf("SettingAntivirusEnabled = %q, want antivirusEnabled", SettingAntivirusEnabled)
	}
	if ViolationAntivirusDisabled != "antivirus_disabled" {
		t.Fatalf("ViolationAntivirusDisabled = %q, want antivirus_disabled", ViolationAntivirusDisabled)
	}

	bundle := contract.PolicyBundleResponse{
		Policies: []contract.Policy{
			{PolicyID: "av-policy", Version: 1, Settings: map[string]any{SettingAntivirusEnabled: true}},
		},
	}
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

	// Given: posture.antivirus.enabled false
	off := Evaluate(bundle, contract.Posture{Antivirus: contract.Antivirus{Enabled: false}}, now)
	if len(off) != 1 {
		t.Fatalf("expected 1 result, got %d", len(off))
	}
	if off[0].Compliant {
		t.Error("expected compliant false when antivirus is off")
	}
	found := false
	for _, v := range off[0].Violations {
		if v == ViolationAntivirusDisabled {
			found = true
		}
	}
	if !found {
		t.Errorf("expected violation %s, got %v", ViolationAntivirusDisabled, off[0].Violations)
	}

	// Given: posture.antivirus.enabled true
	on := Evaluate(bundle, contract.Posture{Antivirus: contract.Antivirus{Enabled: true}}, now)
	if len(on) != 1 {
		t.Fatalf("expected 1 result, got %d", len(on))
	}
	if !on[0].Compliant {
		t.Error("expected compliant true when antivirus is on")
	}
	if len(on[0].Violations) != 0 {
		t.Errorf("expected no violations, got %v", on[0].Violations)
	}
}

// TestScenario_PolicyNotRequiringAntivirusNeverReportsViolation covers false,
// absent and a non-boolean value, whatever posture reports.
func TestScenario_PolicyNotRequiringAntivirusNeverReportsViolation(t *testing.T) {
	cases := []struct {
		name     string
		settings map[string]any
	}{
		{"false", map[string]any{SettingAntivirusEnabled: false}},
		{"absent", map[string]any{}},
		{`"true" (a string)`, map[string]any{SettingAntivirusEnabled: "true"}},
	}
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bundle := contract.PolicyBundleResponse{
				Policies: []contract.Policy{{PolicyID: "p1", Version: 1, Settings: tc.settings}},
			}
			results := Evaluate(bundle, contract.Posture{Antivirus: contract.Antivirus{Enabled: false}}, now)
			for _, v := range results[0].Violations {
				if v == ViolationAntivirusDisabled {
					t.Errorf("violations should not contain %s, got %v", ViolationAntivirusDisabled, results[0].Violations)
				}
			}
		})
	}
}

// TestScenario_ViolationOrderIncludesAntivirusAfterDiskEncryption covers the
// exact, full violation order the contract promises.
func TestScenario_ViolationOrderIncludesAntivirusAfterDiskEncryption(t *testing.T) {
	policy := contract.Policy{
		PolicyID: "strict",
		Version:  1,
		Settings: map[string]any{
			SettingFirewallEnabled:        true,
			SettingDiskEncryptionRequired: true,
			SettingAntivirusEnabled:       true,
			SettingOSUpdateMaxAgeDays:     5,
			SettingLocalAdminAllowlist:    []string{},
		},
	}
	posture := contract.Posture{
		Firewall:       contract.Firewall{Enabled: false},
		DiskEncryption: contract.DiskEncryption{Enabled: false},
		Antivirus:      contract.Antivirus{Enabled: false},
		OSUpdate:       contract.OSUpdate{LastCheckedAt: "2026-09-20T00:00:00Z"}, // 12 days old
		LocalAdmins:    []string{"bob"},
	}
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

	bundle := contract.PolicyBundleResponse{Policies: []contract.Policy{policy}}
	results := Evaluate(bundle, posture, now)

	want := []string{
		ViolationFirewallDisabled,
		ViolationDiskEncryptionMissing,
		ViolationAntivirusDisabled,
		ViolationOSUpdateOverdue,
		ViolationLocalAdminPrefix + "bob",
	}
	if len(results[0].Violations) != len(want) {
		t.Fatalf("violations = %v, want %v", results[0].Violations, want)
	}
	for i, v := range want {
		if results[0].Violations[i] != v {
			t.Errorf("violations[%d] = %q, want %q", i, results[0].Violations[i], v)
		}
	}
}
