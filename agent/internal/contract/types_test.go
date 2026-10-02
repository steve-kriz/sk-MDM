package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func loadMessageFiles(t *testing.T) map[string][]byte {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("Could not determine test file location")
	}

	messagesDir := filepath.Join(filepath.Dir(thisFile), "../../../contract/testdata/messages")

	files := []string{
		"checkin-request.json",
		"checkin-request-no-warnings.json",
		"checkin-request-with-compliance.json",
		"checkin-request-with-agent-version.json",
		"checkin-request-with-antivirus-findings.json",
		"policy-bundle-response.json",
		"policy-bundle-response-no-conflicts.json",
		"enroll-request.json",
		"enroll-response.json",
		"command-lease-response.json",
		"command-result-request.json",
		"checkin-response.json",
		"checkin-response-with-release.json",
	}

	messages := make(map[string][]byte)
	for _, file := range files {
		path := filepath.Join(messagesDir, file)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("Failed to read message file %s: %v", file, err)
		}
		messages[file] = data
	}

	return messages
}

func TestCheckInRequestFields(t *testing.T) {
	// Test: Golden messages round-trip in both languages
	messages := loadMessageFiles(t)

	// Decode checkin-request.json with DisallowUnknownFields
	var req CheckInRequest
	decoder := json.NewDecoder(strings.NewReader(string(messages["checkin-request.json"])))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		t.Fatalf("Failed to decode checkin-request.json: %v", err)
	}

	// Verify all expected fields are present
	if req.CollectedAt == "" {
		t.Error("CollectedAt should not be empty")
	}

	if req.Inventory.Hardware.Manufacturer == "" {
		t.Error("Inventory hardware manufacturer should not be empty")
	}

	if req.Inventory.OS.Name == "" {
		t.Error("Inventory OS name should not be empty")
	}

	if len(req.Inventory.Software) == 0 {
		t.Error("Inventory should have at least one software entry")
	}

	if len(req.Inventory.Warnings) == 0 {
		t.Error("Inventory in checkin-request.json should have warnings")
	}

	if req.Posture.Firewall.Enabled != true {
		t.Error("Posture firewall should be enabled")
	}

	if len(req.Posture.LocalAdmins) == 0 {
		t.Error("Posture should have local admins")
	}

	if len(req.Posture.Warnings) == 0 {
		t.Error("Posture in checkin-request.json should have warnings")
	}
}

func TestCheckInRequestNoWarnings(t *testing.T) {
	// Test: Warnings omitted when empty
	messages := loadMessageFiles(t)

	var req CheckInRequest
	decoder := json.NewDecoder(strings.NewReader(string(messages["checkin-request-no-warnings.json"])))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		t.Fatalf("Failed to decode checkin-request-no-warnings.json: %v", err)
	}

	// Warnings should be nil (omitted)
	if req.Inventory.Warnings != nil {
		t.Error("Inventory warnings should be nil when omitted")
	}

	if req.Posture.Warnings != nil {
		t.Error("Posture warnings should be nil when omitted")
	}

	// Re-marshal and verify no "warnings" key is present
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	if strings.Contains(string(data), "\"warnings\"") {
		t.Error("Marshalled JSON should not contain warnings key when nil")
	}
}

func TestCheckInRequestWithCompliance(t *testing.T) {
	// Test: Absent compliance is omitted from the wire
	messages := loadMessageFiles(t)

	var req CheckInRequest
	decoder := json.NewDecoder(strings.NewReader(string(messages["checkin-request-with-compliance.json"])))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		t.Fatalf("Failed to decode checkin-request-with-compliance.json: %v", err)
	}

	// Should have compliance entries
	if len(req.PolicyCompliance) != 2 {
		t.Errorf("Expected 2 compliance entries, got %d", len(req.PolicyCompliance))
	}

	// Find compliant and non-compliant entries
	var compliant, nonCompliant *PolicyComplianceEntry
	for i := range req.PolicyCompliance {
		if req.PolicyCompliance[i].Compliant {
			compliant = &req.PolicyCompliance[i]
		} else {
			nonCompliant = &req.PolicyCompliance[i]
		}
	}

	if compliant == nil {
		t.Fatal("Should have a compliant entry")
	}

	if nonCompliant == nil {
		t.Fatal("Should have a non-compliant entry")
	}

	// Compliant entry should have empty violations
	if len(compliant.Violations) != 0 {
		t.Errorf("Compliant entry should have empty violations, got %v", compliant.Violations)
	}

	// Non-compliant entry should have violations
	if len(nonCompliant.Violations) == 0 {
		t.Error("Non-compliant entry should have violations")
	}

	if !contains(nonCompliant.Violations, "firewall_disabled") {
		t.Error("Non-compliant entry should have firewall_disabled violation")
	}
}

func TestCheckInRequestNoCompliance(t *testing.T) {
	// Test: Absent compliance is omitted from the wire
	messages := loadMessageFiles(t)

	var req CheckInRequest
	decoder := json.NewDecoder(strings.NewReader(string(messages["checkin-request.json"])))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		t.Fatalf("Failed to decode checkin-request.json: %v", err)
	}

	// Should not have compliance entries
	if len(req.PolicyCompliance) != 0 {
		t.Errorf("checkin-request.json should not have compliance entries, got %d", len(req.PolicyCompliance))
	}

	// Re-marshal and verify no "policyCompliance" key
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	if strings.Contains(string(data), "\"policyCompliance\"") {
		t.Error("Marshalled JSON should not contain policyCompliance key when empty")
	}
}

func TestPolicyBundleResponseWithConflicts(t *testing.T) {
	// Test: Policy bundle shape is pinned
	messages := loadMessageFiles(t)

	var bundle PolicyBundleResponse
	decoder := json.NewDecoder(strings.NewReader(string(messages["policy-bundle-response.json"])))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&bundle); err != nil {
		t.Fatalf("Failed to decode policy-bundle-response.json: %v", err)
	}

	// Verify all top-level fields
	if bundle.DeviceID == "" {
		t.Error("DeviceID should not be empty")
	}

	if bundle.GeneratedAt == "" {
		t.Error("GeneratedAt should not be empty")
	}

	if len(bundle.Policies) == 0 {
		t.Error("Should have at least one policy")
	}

	if bundle.EffectiveSettings == nil {
		t.Error("EffectiveSettings should not be nil")
	}

	if bundle.Conflicts == nil {
		t.Error("Conflicts should not be nil")
	}

	if len(bundle.Conflicts) == 0 {
		t.Error("policy-bundle-response.json should have conflicts")
	}

	// Verify conflict structure
	conflict := bundle.Conflicts[0]
	if conflict.Key == "" {
		t.Error("Conflict key should not be empty")
	}

	if conflict.WinningPolicyID == "" {
		t.Error("WinningPolicyID should not be empty")
	}

	if len(conflict.Losers) == 0 {
		t.Error("Conflict should have at least one loser")
	}
}

func TestPolicyBundleResponseNoConflicts(t *testing.T) {
	// Test: Uncontested policy bundle still emits "conflicts": []
	messages := loadMessageFiles(t)

	var bundle PolicyBundleResponse
	decoder := json.NewDecoder(strings.NewReader(string(messages["policy-bundle-response-no-conflicts.json"])))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&bundle); err != nil {
		t.Fatalf("Failed to decode policy-bundle-response-no-conflicts.json: %v", err)
	}

	// Conflicts should be present and empty
	if bundle.Conflicts == nil {
		t.Error("Conflicts should not be nil")
	}

	if len(bundle.Conflicts) != 0 {
		t.Errorf("Conflicts should be empty, got %d entries", len(bundle.Conflicts))
	}

	// Re-marshal and verify "conflicts" is present and equals []
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	if !strings.Contains(string(data), "\"conflicts\":[]") {
		// Also check for conflicts with spaces
		if !strings.Contains(string(data), "\"conflicts\": []") {
			t.Error("Marshalled JSON should contain \"conflicts\":[] or \"conflicts\": []")
		}
	}
}

func TestInventoryWarningsOmitEmpty(t *testing.T) {
	// Test: Warnings are omitted when empty
	inv := Inventory{
		Hardware: InventoryHardware{
			Manufacturer: "Test",
			Model:        "Test",
			SerialNumber: "Test",
			CPU:          "Test",
			RAMBytes:     1,
			DiskBytes:    1,
		},
		OS: InventoryOS{
			Name:         "Test",
			Version:      "Test",
			Build:        "Test",
			Architecture: "Test",
		},
		Software: []SoftwareEntry{},
		Warnings: nil,
	}

	data, err := json.Marshal(inv)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	if strings.Contains(string(data), "\"warnings\"") {
		t.Error("Marshalled Inventory with nil warnings should not contain warnings key")
	}

	// With warnings
	inv.Warnings = []string{"test warning"}
	data, err = json.Marshal(inv)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	if !strings.Contains(string(data), "\"warnings\"") {
		t.Error("Marshalled Inventory with warnings should contain warnings key")
	}
}

func TestPostureWarningsOmitEmpty(t *testing.T) {
	// Test: Warnings are omitted when empty
	posture := Posture{
		DiskEncryption: DiskEncryption{
			Enabled: true,
			Method:  "bitlocker",
		},
		Firewall: Firewall{
			Enabled: true,
		},
		Antivirus: Antivirus{
			Name:               "Test",
			Enabled:            true,
			DefinitionsAgeDays: 1,
		},
		OSUpdate: OSUpdate{
			LastCheckedAt:  "2026-10-02T07:15:00Z",
			PendingCount:   0,
			RebootRequired: false,
		},
		LocalAdmins: []string{},
		Warnings:    nil,
	}

	data, err := json.Marshal(posture)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	if strings.Contains(string(data), "\"warnings\"") {
		t.Error("Marshalled Posture with nil warnings should not contain warnings key")
	}

	// With warnings
	posture.Warnings = []string{"test warning"}
	data, err = json.Marshal(posture)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	if !strings.Contains(string(data), "\"warnings\"") {
		t.Error("Marshalled Posture with warnings should contain warnings key")
	}
}

func TestCheckInRequestComplianceOmitEmpty(t *testing.T) {
	// Test: Absent compliance is omitted from the wire
	req := CheckInRequest{
		CollectedAt: "2026-10-02T07:15:00Z",
		Inventory: Inventory{
			Hardware: InventoryHardware{
				Manufacturer: "Test",
				Model:        "Test",
				SerialNumber: "Test",
				CPU:          "Test",
				RAMBytes:     1,
				DiskBytes:    1,
			},
			OS: InventoryOS{
				Name:         "Test",
				Version:      "Test",
				Build:        "Test",
				Architecture: "Test",
			},
			Software: []SoftwareEntry{},
		},
		Posture: Posture{
			DiskEncryption: DiskEncryption{
				Enabled: true,
				Method:  "bitlocker",
			},
			Firewall: Firewall{
				Enabled: true,
			},
			Antivirus: Antivirus{
				Name:               "Test",
				Enabled:            true,
				DefinitionsAgeDays: 1,
			},
			OSUpdate: OSUpdate{
				LastCheckedAt:  "2026-10-02T07:15:00Z",
				PendingCount:   0,
				RebootRequired: false,
			},
			LocalAdmins: []string{},
		},
		PolicyCompliance: nil,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	if strings.Contains(string(data), "\"policyCompliance\"") {
		t.Error("Marshalled CheckInRequest with nil compliance should not contain policyCompliance key")
	}

	// With empty compliance
	req.PolicyCompliance = []PolicyComplianceEntry{}
	data, err = json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	if strings.Contains(string(data), "\"policyCompliance\"") {
		t.Error("Marshalled CheckInRequest with empty compliance should not contain policyCompliance key")
	}

	// With compliance entry
	req.PolicyCompliance = []PolicyComplianceEntry{
		{
			PolicyID:   "policy-1",
			Version:    1,
			Compliant:  true,
			Violations: []string{},
		},
	}
	data, err = json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	if !strings.Contains(string(data), "\"policyCompliance\"") {
		t.Error("Marshalled CheckInRequest with compliance should contain policyCompliance key")
	}
}

func TestUnknownFieldRejection(t *testing.T) {
	// Test: Unknown field is rejected by the Go decoder
	jsonWithExtra := `{
		"collectedAt": "2026-10-02T07:15:00Z",
		"inventory": {
			"hardware": {
				"manufacturer": "Test",
				"model": "Test",
				"serialNumber": "Test",
				"cpu": "Test",
				"ramBytes": 1,
				"diskBytes": 1
			},
			"os": {
				"name": "Test",
				"version": "Test",
				"build": "Test",
				"architecture": "Test"
			},
			"software": []
		},
		"posture": {
			"diskEncryption": {
				"enabled": true,
				"method": "bitlocker"
			},
			"firewall": {
				"enabled": true
			},
			"antivirus": {
				"name": "Test",
				"enabled": true,
				"definitionsAgeDays": 1
			},
			"osUpdate": {
				"lastCheckedAt": "2026-10-02T07:15:00Z",
				"pendingCount": 0,
				"rebootRequired": false
			},
			"localAdmins": []
		},
		"surprise": "extra field"
	}`

	var req CheckInRequest
	decoder := json.NewDecoder(strings.NewReader(jsonWithExtra))
	decoder.DisallowUnknownFields()

	err := decoder.Decode(&req)
	if err == nil {
		t.Error("Should return an error for unknown field \"surprise\"")
	}

	if !strings.Contains(err.Error(), "surprise") {
		t.Errorf("Error should mention the unknown field: %v", err)
	}
}

func TestAllMessageFilesRoundTrip(t *testing.T) {
	// Test: All message files can be decoded without errors
	messages := loadMessageFiles(t)

	// Test CheckInRequest variants
	var checkinReq CheckInRequest
	checkInFiles := []string{
		"checkin-request.json",
		"checkin-request-no-warnings.json",
		"checkin-request-with-compliance.json",
		"checkin-request-with-antivirus-findings.json",
	}

	for _, file := range checkInFiles {
		decoder := json.NewDecoder(strings.NewReader(string(messages[file])))
		decoder.DisallowUnknownFields()

		if err := decoder.Decode(&checkinReq); err != nil {
			t.Fatalf("Failed to decode %s: %v", file, err)
		}
	}

	// Test PolicyBundleResponse variants
	var bundleResp PolicyBundleResponse
	bundleFiles := []string{
		"policy-bundle-response.json",
		"policy-bundle-response-no-conflicts.json",
	}

	for _, file := range bundleFiles {
		decoder := json.NewDecoder(strings.NewReader(string(messages[file])))
		decoder.DisallowUnknownFields()

		if err := decoder.Decode(&bundleResp); err != nil {
			t.Fatalf("Failed to decode %s: %v", file, err)
		}
	}

	// Test other message types
	var enrollReq EnrollRequest
	decoder := json.NewDecoder(strings.NewReader(string(messages["enroll-request.json"])))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&enrollReq); err != nil {
		t.Fatalf("Failed to decode enroll-request.json: %v", err)
	}

	var enrollResp EnrollResponse
	decoder = json.NewDecoder(strings.NewReader(string(messages["enroll-response.json"])))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&enrollResp); err != nil {
		t.Fatalf("Failed to decode enroll-response.json: %v", err)
	}

	var cmdResp CommandLeaseResponse
	decoder = json.NewDecoder(strings.NewReader(string(messages["command-lease-response.json"])))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cmdResp); err != nil {
		t.Fatalf("Failed to decode command-lease-response.json: %v", err)
	}

	var cmdReqResp CommandResultRequest
	decoder = json.NewDecoder(strings.NewReader(string(messages["command-result-request.json"])))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cmdReqResp); err != nil {
		t.Fatalf("Failed to decode command-result-request.json: %v", err)
	}

	var checkinResp CheckInResponse
	decoder = json.NewDecoder(strings.NewReader(string(messages["checkin-response.json"])))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&checkinResp); err != nil {
		t.Fatalf("Failed to decode checkin-response.json: %v", err)
	}
}

func TestCheckInRequestWithAgentVersion(t *testing.T) {
	// Test: Check-in request with agent version round-trips
	messages := loadMessageFiles(t)

	var req CheckInRequest
	decoder := json.NewDecoder(strings.NewReader(string(messages["checkin-request-with-agent-version.json"])))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		t.Fatalf("Failed to decode checkin-request-with-agent-version.json: %v", err)
	}

	// Verify agentVersion field is populated
	if req.AgentVersion == "" {
		t.Error("AgentVersion should not be empty in checkin-request-with-agent-version.json")
	}

	// Verify it round-trips: re-marshal and check agentVersion is present
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	if !strings.Contains(string(data), "\"agentVersion\"") {
		t.Error("Marshalled JSON should contain agentVersion when set")
	}

	// Verify omitempty works: create a request with empty agentVersion
	emptyVersionReq := CheckInRequest{
		CollectedAt: "2026-10-02T07:15:00Z",
		Inventory: Inventory{
			Hardware: InventoryHardware{Manufacturer: "Test", Model: "Test", SerialNumber: "Test", CPU: "Test"},
			OS:       InventoryOS{Name: "Test", Version: "Test", Build: "Test", Architecture: "amd64"},
			Software: []SoftwareEntry{},
		},
		Posture: Posture{
			Firewall:   Firewall{Enabled: true},
			Antivirus:  Antivirus{Name: "Test", Enabled: true, DefinitionsAgeDays: 1},
			OSUpdate:   OSUpdate{LastCheckedAt: "2026-10-02T07:15:00Z", PendingCount: 0},
			LocalAdmins: []string{},
		},
		AgentVersion: "",
	}
	emptyData, err := json.Marshal(emptyVersionReq)
	if err != nil {
		t.Fatalf("Failed to marshal empty version: %v", err)
	}

	if strings.Contains(string(emptyData), "\"agentVersion\"") {
		t.Error("Marshalled JSON should omit agentVersion when empty (omitempty)")
	}
}

func TestCheckInResponseWithRelease(t *testing.T) {
	// Test: Check-in response with agent release round-trips
	messages := loadMessageFiles(t)

	var resp CheckInResponse
	decoder := json.NewDecoder(strings.NewReader(string(messages["checkin-response-with-release.json"])))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&resp); err != nil {
		t.Fatalf("Failed to decode checkin-response-with-release.json: %v", err)
	}

	// Verify required fields
	if resp.CheckInIntervalSeconds == 0 {
		t.Error("CheckInIntervalSeconds should be set")
	}

	// Verify agentRelease is populated
	if resp.AgentRelease == nil {
		t.Fatal("AgentRelease should not be nil in checkin-response-with-release.json")
	}

	if resp.AgentRelease.Version == "" {
		t.Error("AgentRelease.Version should not be empty")
	}
	if resp.AgentRelease.URL == "" {
		t.Error("AgentRelease.URL should not be empty")
	}
	if resp.AgentRelease.SHA256 == "" {
		t.Error("AgentRelease.SHA256 should not be empty")
	}

	// Verify it round-trips
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	if !strings.Contains(string(data), "\"agentRelease\"") {
		t.Error("Marshalled JSON should contain agentRelease when set")
	}

	// Verify omitempty works: create a response with nil agentRelease
	emptyReleaseResp := CheckInResponse{
		CheckInIntervalSeconds: 900,
		PendingCommandCount:    0,
		AgentRelease:           nil,
	}
	emptyData, err := json.Marshal(emptyReleaseResp)
	if err != nil {
		t.Fatalf("Failed to marshal empty release: %v", err)
	}

	if strings.Contains(string(emptyData), "\"agentRelease\"") {
		t.Error("Marshalled JSON should omit agentRelease when nil")
	}
}

// Helper function
func contains(arr []string, item string) bool {
	for _, a := range arr {
		if a == item {
			return true
		}
	}
	return false
}
