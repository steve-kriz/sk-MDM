package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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
		"checkin-request-with-analytics.json",
		"checkin-request-with-analytics-nulls.json",
		"checkin-request-with-antivirus-scan.json",
		"checkin-request-with-antivirus-status.json",
		"checkin-request-with-antivirus-status-darwin.json",
		"checkin-request-with-device-details.json",
		"checkin-request-with-defender-hardening.json",
		"checkin-request-with-agent-errors.json",
		"checkin-request-with-agent-actions.json",
		"policy-bundle-response.json",
		"policy-bundle-response-no-conflicts.json",
		"enroll-request.json",
		"enroll-response.json",
		"command-lease-response.json",
		"command-result-request.json",
		"checkin-response.json",
		"checkin-response-with-release.json",
		"checkin-response-analytics-disabled.json",
		"checkin-response-heartbeat-enabled.json",
		"heartbeat-request.json",
		"heartbeat-request-with-network.json",
		"heartbeat-response.json",
		"heartbeat-response-disabled.json",
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
		"checkin-request-with-analytics.json",
		"checkin-request-with-analytics-nulls.json",
		"checkin-request-with-antivirus-scan.json",
		"checkin-request-with-antivirus-status.json",
		"checkin-request-with-antivirus-status-darwin.json",
		"checkin-request-with-device-details.json",
		"checkin-request-with-defender-hardening.json",
		"checkin-request-with-agent-errors.json",
		"checkin-request-with-agent-actions.json",
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

	var disabledResp CheckInResponse
	decoder = json.NewDecoder(strings.NewReader(string(messages["checkin-response-analytics-disabled.json"])))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&disabledResp); err != nil {
		t.Fatalf("Failed to decode checkin-response-analytics-disabled.json: %v", err)
	}

	// TASK-044: the heartbeat messages.
	var heartbeatCheckin CheckInResponse
	decoder = json.NewDecoder(strings.NewReader(string(messages["checkin-response-heartbeat-enabled.json"])))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&heartbeatCheckin); err != nil {
		t.Fatalf("Failed to decode checkin-response-heartbeat-enabled.json: %v", err)
	}

	var heartbeatReq HeartbeatRequest
	decoder = json.NewDecoder(strings.NewReader(string(messages["heartbeat-request.json"])))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&heartbeatReq); err != nil {
		t.Fatalf("Failed to decode heartbeat-request.json: %v", err)
	}
	if heartbeatReq.Network != nil {
		t.Errorf("heartbeat-request.json Network = %+v, want nil (no network key)", heartbeatReq.Network)
	}

	var networkReq HeartbeatRequest
	decoder = json.NewDecoder(strings.NewReader(string(messages["heartbeat-request-with-network.json"])))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&networkReq); err != nil {
		t.Fatalf("Failed to decode heartbeat-request-with-network.json: %v", err)
	}
	if len(networkReq.Network) != 2 || networkReq.Network[1].LinkSpeedBitsPerSecond != nil ||
		networkReq.Network[0].UtilizationPercent == nil || *networkReq.Network[0].UtilizationPercent != 20 {
		t.Errorf("heartbeat-request-with-network.json Network = %+v", networkReq.Network)
	}

	for _, file := range []string{"heartbeat-response.json", "heartbeat-response-disabled.json"} {
		var heartbeatResp HeartbeatResponse
		decoder = json.NewDecoder(strings.NewReader(string(messages[file])))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&heartbeatResp); err != nil {
			t.Fatalf("Failed to decode %s: %v", file, err)
		}
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
			Firewall:    Firewall{Enabled: true},
			Antivirus:   Antivirus{Name: "Test", Enabled: true, DefinitionsAgeDays: 1},
			OSUpdate:    OSUpdate{LastCheckedAt: "2026-10-02T07:15:00Z", PendingCount: 0},
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

func TestCheckInRequestAnalyticsOmitEmpty(t *testing.T) {
	// Test: TASK-034 - Marshalling a Go CheckInRequest with Analytics == nil produces JSON without an "analytics" key
	messages := loadMessageFiles(t)

	// Load the base checkin-request to get valid inventory and posture
	var baseReq CheckInRequest
	decoder := json.NewDecoder(strings.NewReader(string(messages["checkin-request.json"])))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&baseReq); err != nil {
		t.Fatalf("Failed to decode base checkin-request.json: %v", err)
	}

	// Create a CheckInRequest with nil Analytics (default)
	nilAnalyticsReq := CheckInRequest{
		CollectedAt: baseReq.CollectedAt,
		Inventory:   baseReq.Inventory,
		Posture:     baseReq.Posture,
		Analytics:   nil, // Explicitly nil
	}

	// Marshal the request
	data, err := json.Marshal(nilAnalyticsReq)
	if err != nil {
		t.Fatalf("Failed to marshal CheckInRequest with nil Analytics: %v", err)
	}

	// Verify that "analytics" key is not present
	if strings.Contains(string(data), "\"analytics\"") {
		t.Error("Marshalled CheckInRequest with nil Analytics should not contain analytics key")
	}
}

func TestCheckInRequestAnalyticsWithNullBootDurationSeconds(t *testing.T) {
	// Test: TASK-034 - Marshalling CheckInRequest whose AnalyticsBoot.BootDurationSeconds is nil produces "bootDurationSeconds":null
	messages := loadMessageFiles(t)

	// Load the base checkin-request to get valid inventory and posture
	var baseReq CheckInRequest
	decoder := json.NewDecoder(strings.NewReader(string(messages["checkin-request.json"])))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&baseReq); err != nil {
		t.Fatalf("Failed to decode base checkin-request.json: %v", err)
	}

	// Create Analytics with nil BootDurationSeconds
	var zero int64 = 0
	nilDurationAnalytics := &Analytics{
		Boot: AnalyticsBoot{
			LastBootAt:          stringPtr("2026-10-02T06:41:09Z"),
			BootDurationSeconds: nil, // nil value
			UptimeSeconds:       &zero,
		},
		Performance: AnalyticsPerformance{
			CPUPercent:           float64Ptr(12.5),
			MemoryUsedBytes:      int64Ptr(9663676416),
			MemoryTotalBytes:     int64Ptr(34359738368),
			SystemDiskFreeBytes:  int64Ptr(210453397504),
			SystemDiskTotalBytes: int64Ptr(1023741952000),
		},
		Crashes:  []AppCrash{},
		Warnings: nil,
	}

	analyticsReq := CheckInRequest{
		CollectedAt: baseReq.CollectedAt,
		Inventory:   baseReq.Inventory,
		Posture:     baseReq.Posture,
		Analytics:   nilDurationAnalytics,
	}

	// Marshal the request
	data, err := json.Marshal(analyticsReq)
	if err != nil {
		t.Fatalf("Failed to marshal CheckInRequest with Analytics: %v", err)
	}

	dataStr := string(data)

	// Verify that "analytics" key is present
	if !strings.Contains(dataStr, "\"analytics\"") {
		t.Error("Marshalled CheckInRequest with Analytics should contain analytics key")
	}

	// Verify that "bootDurationSeconds":null is present
	if !strings.Contains(dataStr, "\"bootDurationSeconds\":null") {
		t.Error("Marshalled Analytics with nil BootDurationSeconds should contain \"bootDurationSeconds\":null")
	}
}

// TASK-040: TestCheckInResponseAnalyticsEnabledNilMarshalling tests that AnalyticsEnabled omitempty works
func TestCheckInResponseAnalyticsEnabledNilMarshalling(t *testing.T) {
	// Given a CheckInResponse with AnalyticsEnabled == nil
	resp := CheckInResponse{
		CheckInIntervalSeconds: 900,
		PendingCommandCount:    0,
		AnalyticsEnabled:       nil, // Explicitly nil
	}

	// When marshalling to JSON
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal CheckInResponse: %v", err)
	}

	dataStr := string(data)

	// Then the JSON should NOT contain an "analyticsEnabled" key
	if strings.Contains(dataStr, "\"analyticsEnabled\"") {
		t.Error("Marshalled CheckInResponse with nil AnalyticsEnabled should NOT contain analyticsEnabled key (omitempty)")
	}

	// And when marshalling with AnalyticsEnabled set to false pointer
	falseVal := false
	respWithFalse := CheckInResponse{
		CheckInIntervalSeconds: 900,
		PendingCommandCount:    0,
		AnalyticsEnabled:       &falseVal,
	}

	dataFalse, err := json.Marshal(respWithFalse)
	if err != nil {
		t.Fatalf("Failed to marshal CheckInResponse with false: %v", err)
	}

	dataFalseStr := string(dataFalse)

	// Then the JSON should contain "analyticsEnabled":false
	if !strings.Contains(dataFalseStr, "\"analyticsEnabled\":false") {
		t.Error("Marshalled CheckInResponse with AnalyticsEnabled=false should contain \"analyticsEnabled\":false")
	}
}

// TestScenario_AC24_AntivirusScanFixtureRoundTrips covers decoding the
// checkin-request-with-antivirus-scan.json fixture into CheckInRequest and
// re-encoding it with the same antivirusScan fields.
func TestScenario_AC24_AntivirusScanFixtureRoundTrips(t *testing.T) {
	messages := loadMessageFiles(t)
	data, ok := messages["checkin-request-with-antivirus-scan.json"]
	if !ok {
		t.Fatal("fixture checkin-request-with-antivirus-scan.json not loaded")
	}

	var req CheckInRequest
	if err := json.Unmarshal(data, &req); err != nil {
		t.Fatalf("failed to decode fixture: %v", err)
	}
	if req.AntivirusScan == nil {
		t.Fatal("expected AntivirusScan to be set")
	}
	if req.AntivirusScan.ScanType != "quick" {
		t.Errorf("scanType = %q, want quick", req.AntivirusScan.ScanType)
	}
	if req.AntivirusScan.Result != "threats_found" {
		t.Errorf("result = %q, want threats_found", req.AntivirusScan.Result)
	}
	if req.AntivirusScan.StartedAt == nil || *req.AntivirusScan.StartedAt != "2026-10-02T06:00:00Z" {
		t.Errorf("startedAt = %v, want 2026-10-02T06:00:00Z", req.AntivirusScan.StartedAt)
	}
	if req.AntivirusScan.CompletedAt == nil || *req.AntivirusScan.CompletedAt != "2026-10-02T06:07:42Z" {
		t.Errorf("completedAt = %v, want 2026-10-02T06:07:42Z", req.AntivirusScan.CompletedAt)
	}
	if req.AntivirusScan.ThreatsFound != 2 {
		t.Errorf("threatsFound = %d, want 2", req.AntivirusScan.ThreatsFound)
	}
	if req.AntivirusScan.Detail != "" {
		t.Errorf("detail = %q, want empty (omitted in the fixture)", req.AntivirusScan.Detail)
	}

	// Re-encode and decode again: the antivirusScan fields must survive
	// unchanged.
	reEncoded, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to re-encode: %v", err)
	}
	var roundTripped CheckInRequest
	if err := json.Unmarshal(reEncoded, &roundTripped); err != nil {
		t.Fatalf("failed to decode re-encoded message: %v", err)
	}
	if roundTripped.AntivirusScan == nil {
		t.Fatal("round-tripped AntivirusScan is nil")
	}
	rt, orig := roundTripped.AntivirusScan, req.AntivirusScan
	if rt.ScanType != orig.ScanType || rt.Result != orig.Result || rt.ThreatsFound != orig.ThreatsFound || rt.Detail != orig.Detail {
		t.Errorf("round-tripped AntivirusScan = %+v, want %+v", rt, orig)
	}
	if rt.StartedAt == nil || orig.StartedAt == nil || *rt.StartedAt != *orig.StartedAt {
		t.Errorf("round-tripped startedAt = %v, want %v", rt.StartedAt, orig.StartedAt)
	}
	if rt.CompletedAt == nil || orig.CompletedAt == nil || *rt.CompletedAt != *orig.CompletedAt {
		t.Errorf("round-tripped completedAt = %v, want %v", rt.CompletedAt, orig.CompletedAt)
	}
	// The detail key must be absent from the wire when empty (omitempty).
	if strings.Contains(string(reEncoded), `"detail"`) {
		t.Error("re-encoded antivirusScan should omit detail when empty")
	}
}

// TestScenario_AC24_CheckInRequestOmitsAntivirusScanWhenNil covers the
// omitempty behaviour of CheckInRequest.AntivirusScan.
func TestScenario_AC24_CheckInRequestOmitsAntivirusScanWhenNil(t *testing.T) {
	req := CheckInRequest{CollectedAt: "2026-10-02T07:15:00Z"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	if strings.Contains(string(data), `"antivirusScan"`) {
		t.Error("CheckInRequest with no AntivirusScan should carry no antivirusScan key")
	}
}

// TestScenario_AC14_DeviceDetailsFixtureRoundTrips implements the TASK-059
// AC14 Gherkin scenario: the golden device-details fixture decodes into
// CheckInRequest with DisallowUnknownFields and re-marshals to semantically
// equal JSON.
func TestScenario_AC14_DeviceDetailsFixtureRoundTrips(t *testing.T) {
	// Given contract/testdata/messages/checkin-request-with-device-details.json
	messages := loadMessageFiles(t)
	data, ok := messages["checkin-request-with-device-details.json"]
	if !ok {
		t.Fatal("fixture checkin-request-with-device-details.json not loaded")
	}

	// When it is decoded into CheckInRequest with DisallowUnknownFields and re-marshalled
	var req CheckInRequest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		t.Fatalf("failed to decode fixture with DisallowUnknownFields: %v", err)
	}

	// Sanity: every new device-detail block actually decoded.
	inv := req.Inventory
	if inv.OS.Edition != "Enterprise" || inv.OS.DisplayVersion != "23H2" || inv.OS.UBR == nil || *inv.OS.UBR != 4317 {
		t.Errorf("os device-detail fields not decoded as expected: %+v", inv.OS)
	}
	if inv.Hardware.SystemFamily == "" || inv.Hardware.CPUCores == 0 {
		t.Errorf("hardware device-detail fields not decoded as expected: %+v", inv.Hardware)
	}
	if inv.Firmware == nil || inv.Firmware.Type != "uefi" {
		t.Errorf("firmware not decoded as expected: %+v", inv.Firmware)
	}
	if len(inv.Disks) == 0 || len(inv.PhysicalDisks) == 0 || len(inv.Network) == 0 {
		t.Errorf("disks/physicalDisks/network not decoded as expected: disks=%+v physicalDisks=%+v network=%+v",
			inv.Disks, inv.PhysicalDisks, inv.Network)
	}
	if inv.Join == nil || inv.Join.AzureADJoined == nil || !*inv.Join.AzureADJoined || inv.Join.Domain != "contoso.local" {
		t.Errorf("join not decoded as expected: %+v", inv.Join)
	}

	reEncoded, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to re-encode: %v", err)
	}

	// Then the result is semantically equal to the fixture: parse both sides
	// as generic JSON and compare, so field order and formatting differences
	// do not matter.
	var original, roundTripped interface{}
	if err := json.Unmarshal(data, &original); err != nil {
		t.Fatalf("failed to parse original fixture as generic JSON: %v", err)
	}
	if err := json.Unmarshal(reEncoded, &roundTripped); err != nil {
		t.Fatalf("failed to parse re-encoded fixture as generic JSON: %v", err)
	}
	if !reflect.DeepEqual(original, roundTripped) {
		t.Errorf("re-marshalled fixture is not semantically equal to the original.\noriginal:     %s\nre-marshalled: %s", data, reEncoded)
	}
}

// TestScenario_AC11_AgentErrorsFixtureRoundTrips covers the TASK-063 Gherkin
// scenario "Contract fixture round-trips (AC11)": the fixture unmarshals into
// CheckInRequest and marshals back to the same JSON.
func TestScenario_AC11_AgentErrorsFixtureRoundTrips(t *testing.T) {
	// Given contract/testdata/messages/checkin-request-with-agent-errors.json
	messages := loadMessageFiles(t)
	data, ok := messages["checkin-request-with-agent-errors.json"]
	if !ok {
		t.Fatal("fixture checkin-request-with-agent-errors.json not loaded")
	}

	// When it unmarshals into contract.CheckInRequest with DisallowUnknownFields
	var req CheckInRequest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		t.Fatalf("failed to decode fixture with DisallowUnknownFields: %v", err)
	}

	if len(req.AgentErrors) != 2 {
		t.Fatalf("expected 2 agentErrors entries, got %d: %+v", len(req.AgentErrors), req.AgentErrors)
	}
	first := req.AgentErrors[0]
	if first.Level != "warn" || first.Component != "enforce" || first.Message != "policy enforcement failed" {
		t.Errorf("first entry = %+v, want level=warn component=enforce message=%q", first, "policy enforcement failed")
	}
	if first.Count != 3 || first.FirstAt != "2026-10-11T09:00:00.000Z" || first.LastAt != "2026-10-11T09:30:00.000Z" {
		t.Errorf("first entry count/firstAt/lastAt = %+v", first)
	}
	if first.Fields["error"] != "exit status 1" || first.Fields["status"] != "503" {
		t.Errorf("first entry fields = %+v", first.Fields)
	}
	second := req.AgentErrors[1]
	if second.Level != "error" || second.Component != "update" || second.Message != "agent update failed" {
		t.Errorf("second entry = %+v, want level=error component=update message=%q", second, "agent update failed")
	}
	if second.Fields == nil || len(second.Fields) != 0 {
		t.Errorf("second entry fields = %+v, want an empty (never nil-on-the-wire) object", second.Fields)
	}

	// And it marshals back to the same JSON (semantically: field order and
	// formatting differences do not matter).
	reEncoded, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to re-encode: %v", err)
	}
	var original, roundTripped interface{}
	if err := json.Unmarshal(data, &original); err != nil {
		t.Fatalf("failed to parse original fixture as generic JSON: %v", err)
	}
	if err := json.Unmarshal(reEncoded, &roundTripped); err != nil {
		t.Fatalf("failed to parse re-encoded fixture as generic JSON: %v", err)
	}
	if !reflect.DeepEqual(original, roundTripped) {
		t.Errorf("re-marshalled fixture is not semantically equal to the original.\noriginal:     %s\nre-marshalled: %s", data, reEncoded)
	}
}

// TestScenario_AC7_CheckInRequestOmitsAgentErrorsWhenNil covers the omitempty
// behaviour of CheckInRequest.AgentErrors: a cycle with nothing buffered must
// send no "agentErrors" key at all (AC7's second scenario, exercised directly
// against the contract type here).
func TestScenario_AC7_CheckInRequestOmitsAgentErrorsWhenNil(t *testing.T) {
	req := CheckInRequest{CollectedAt: "2026-10-11T09:00:00Z"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	if strings.Contains(string(data), `"agentErrors"`) {
		t.Errorf("marshalled JSON should omit agentErrors when nil, got %s", data)
	}
}

// TestScenario_AC11_AgentErrorFieldsAlwaysSerialised covers: Fields is always
// serialised (never an omitted key), matching the wire shape documented for
// AgentError -- an entry with no fields is still `"fields":{}`, not absent.
func TestScenario_AC11_AgentErrorFieldsAlwaysSerialised(t *testing.T) {
	e := AgentError{
		Level:     "warn",
		Component: "enforce",
		Message:   "policy enforcement failed",
		Fields:    map[string]string{},
		Count:     1,
		FirstAt:   "2026-10-11T09:00:00.000Z",
		LastAt:    "2026-10-11T09:00:00.000Z",
	}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	if !strings.Contains(string(data), `"fields":{}`) {
		t.Errorf("expected fields to always serialise as an object, got %s", data)
	}
}

// TestScenario_AC16_WindowsAntivirusStatusFixtureRoundTrips covers decoding
// checkin-request-with-antivirus-status.json into CheckInRequest with
// DisallowUnknownFields and re-encoding it with the same antivirusStatus
// content, including the one finding carrying all eight new fields.
func TestScenario_AC16_WindowsAntivirusStatusFixtureRoundTrips(t *testing.T) {
	messages := loadMessageFiles(t)
	data, ok := messages["checkin-request-with-antivirus-status.json"]
	if !ok {
		t.Fatal("fixture checkin-request-with-antivirus-status.json not loaded")
	}

	var req CheckInRequest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		t.Fatalf("failed to decode fixture: %v", err)
	}
	if req.AntivirusStatus == nil {
		t.Fatal("expected AntivirusStatus to be set")
	}
	status := req.AntivirusStatus
	if status.Product != "Microsoft Defender" || !status.DefenderAvailable {
		t.Errorf("product/defenderAvailable = %q/%v, want Microsoft Defender/true", status.Product, status.DefenderAvailable)
	}
	if status.RunningMode == nil || *status.RunningMode != "Normal" {
		t.Errorf("runningMode = %v, want Normal", status.RunningMode)
	}
	if status.Protection.RealTimeProtectionEnabled == nil || !*status.Protection.RealTimeProtectionEnabled {
		t.Error("protection.realTimeProtectionEnabled should be true")
	}
	if len(status.SecurityCenterProducts) != 1 || status.SecurityCenterProducts[0].Name != "Windows Defender" {
		t.Errorf("securityCenterProducts = %+v", status.SecurityCenterProducts)
	}

	if len(req.AntivirusFindings) != 1 {
		t.Fatalf("expected 1 antivirus finding, got %d", len(req.AntivirusFindings))
	}
	finding := req.AntivirusFindings[0]
	if finding.Category != "Trojan" || finding.Status != "quarantined" || finding.Action != "quarantine" {
		t.Errorf("finding status/action/category = %q/%q/%q", finding.Status, finding.Action, finding.Category)
	}
	if finding.Active == nil || *finding.Active {
		t.Errorf("finding.active = %v, want false", finding.Active)
	}
	if finding.LastStatusChangeAt == "" || finding.RemediatedAt == "" || finding.ProcessName == "" || finding.User == "" {
		t.Errorf("expected all eight new finding fields to be set, got %+v", finding)
	}

	reEncoded, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to re-encode: %v", err)
	}
	var original, roundTripped map[string]interface{}
	if err := json.Unmarshal(data, &original); err != nil {
		t.Fatalf("failed to parse original fixture: %v", err)
	}
	if err := json.Unmarshal(reEncoded, &roundTripped); err != nil {
		t.Fatalf("failed to parse re-encoded fixture: %v", err)
	}
	if !reflect.DeepEqual(original["antivirusStatus"], roundTripped["antivirusStatus"]) {
		t.Errorf("antivirusStatus did not round-trip.\noriginal:      %v\nre-marshalled: %v", original["antivirusStatus"], roundTripped["antivirusStatus"])
	}
}

// TestScenario_AC16_DarwinAntivirusStatusFixtureRoundTrips covers the darwin
// fixture: an all-null Defender block with only the XProtect fields set.
func TestScenario_AC16_DarwinAntivirusStatusFixtureRoundTrips(t *testing.T) {
	messages := loadMessageFiles(t)
	data, ok := messages["checkin-request-with-antivirus-status-darwin.json"]
	if !ok {
		t.Fatal("fixture checkin-request-with-antivirus-status-darwin.json not loaded")
	}

	var req CheckInRequest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		t.Fatalf("failed to decode fixture: %v", err)
	}
	if req.AntivirusStatus == nil {
		t.Fatal("expected AntivirusStatus to be set")
	}
	status := req.AntivirusStatus
	if status.Product != "XProtect" || status.DefenderAvailable {
		t.Errorf("product/defenderAvailable = %q/%v, want XProtect/false", status.Product, status.DefenderAvailable)
	}
	if status.RunningMode != nil {
		t.Errorf("runningMode = %v, want nil", status.RunningMode)
	}
	if status.Versions.XProtectDefinitions == nil || *status.Versions.XProtectDefinitions != "5272" {
		t.Errorf("versions.xprotectDefinitions = %v, want 5272", status.Versions.XProtectDefinitions)
	}
	if status.Signatures.AntivirusAgeDays == nil || *status.Signatures.AntivirusAgeDays != 2 {
		t.Errorf("signatures.antivirusAgeDays = %v, want 2", status.Signatures.AntivirusAgeDays)
	}
	if len(status.SecurityCenterProducts) != 0 {
		t.Errorf("securityCenterProducts = %+v, want []", status.SecurityCenterProducts)
	}

	reEncoded, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to re-encode: %v", err)
	}
	var original, roundTripped map[string]interface{}
	if err := json.Unmarshal(data, &original); err != nil {
		t.Fatalf("failed to parse original fixture: %v", err)
	}
	if err := json.Unmarshal(reEncoded, &roundTripped); err != nil {
		t.Fatalf("failed to parse re-encoded fixture: %v", err)
	}
	if !reflect.DeepEqual(original["antivirusStatus"], roundTripped["antivirusStatus"]) {
		t.Errorf("antivirusStatus did not round-trip.\noriginal:      %v\nre-marshalled: %v", original["antivirusStatus"], roundTripped["antivirusStatus"])
	}
}

// TestScenario_AC17_NilAntivirusStatusMarshalsWithoutKey covers the "Old
// fixtures and nil status" scenario's second half: a CheckInRequest with a
// nil AntivirusStatus marshals without "antivirusStatus". (The fixture
// decoding half is covered by TestAllMessageFilesRoundTrip.)
func TestScenario_AC17_NilAntivirusStatusMarshalsWithoutKey(t *testing.T) {
	req := CheckInRequest{CollectedAt: "2026-10-11T00:00:00Z"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	if strings.Contains(string(data), `"antivirusStatus"`) {
		t.Errorf("marshalled CheckInRequest should carry no antivirusStatus key, got %s", data)
	}
}

// ============================================================================
// TASK-070: agentActions contract (AC1, AC2).
// ============================================================================

// TestScenario_AC1_NilAgentActionsOmitsKey covers:
//
//	Given a CheckInRequest with nil AgentActions
//	Then its JSON has no "agentActions" key
func TestScenario_AC1_NilAgentActionsOmitsKey(t *testing.T) {
	req := CheckInRequest{CollectedAt: "2026-10-12T01:00:00Z"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	if strings.Contains(string(data), `"agentActions"`) {
		t.Errorf("marshalled CheckInRequest should carry no agentActions key when nil, got %s", data)
	}
}

// TestScenario_AC1_AgentActionWithNilDetailsMarshalsEmptyObject covers:
//
//	And an AgentAction with nil Details marshals "details":{}
func TestScenario_AC1_AgentActionWithNilDetailsMarshalsEmptyObject(t *testing.T) {
	action := AgentAction{Type: ActionFirewallEnabled, OccurredAt: "2026-10-12T01:00:00Z"}
	data, err := json.Marshal(action)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	if !strings.Contains(string(data), `"details":{}`) {
		t.Errorf("expected details to serialise as an empty object, got %s", data)
	}
}

// TestScenario_AC1_AgentActionConstantsHaveTheirWireValues pins the four
// Action* constants to the wire strings the backend and openapi.yaml expect.
func TestScenario_AC1_AgentActionConstantsHaveTheirWireValues(t *testing.T) {
	cases := map[string]string{
		ActionFirewallEnabled:       "enforce.firewall_enabled",
		ActionAntivirusEnabled:      "enforce.antivirus_enabled",
		ActionDomainsUpdated:        "enforce.domains_updated",
		ActionAgentUpdateRolledBack: "agent.update_rolled_back",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("constant = %q, want %q", got, want)
		}
	}
}

// TestScenario_AC2_AgentActionsFixtureRoundTrips covers the Gherkin scenario
// "The fixture round-trips and validates (AC2)": the fixture decodes into
// CheckInRequest with DisallowUnknownFields, carries one action of each type,
// and marshals back to the same JSON.
func TestScenario_AC2_AgentActionsFixtureRoundTrips(t *testing.T) {
	// Given contract/testdata/messages/checkin-request-with-agent-actions.json
	// with one action of each type
	messages := loadMessageFiles(t)
	data, ok := messages["checkin-request-with-agent-actions.json"]
	if !ok {
		t.Fatal("fixture checkin-request-with-agent-actions.json not loaded")
	}

	// When it decodes into contract.CheckInRequest with DisallowUnknownFields
	var req CheckInRequest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		t.Fatalf("failed to decode fixture with DisallowUnknownFields: %v", err)
	}

	if len(req.AgentActions) != 4 {
		t.Fatalf("expected 4 agentActions entries, got %d: %+v", len(req.AgentActions), req.AgentActions)
	}
	seen := map[string]AgentAction{}
	for _, a := range req.AgentActions {
		seen[a.Type] = a
	}
	for _, want := range []string{ActionFirewallEnabled, ActionAntivirusEnabled, ActionDomainsUpdated, ActionAgentUpdateRolledBack} {
		if _, ok := seen[want]; !ok {
			t.Errorf("expected an action of type %q in the fixture", want)
		}
	}
	rolledBack := seen[ActionAgentUpdateRolledBack]
	if rolledBack.Details["installedVersion"] != "1.5.0" || rolledBack.Details["runningVersion"] != "1.4.0" {
		t.Errorf("rollback action details = %+v", rolledBack.Details)
	}
	domains := seen[ActionDomainsUpdated]
	if domains.Details["blockedCount"] != "4" {
		t.Errorf("domains action details = %+v", domains.Details)
	}

	// And it marshals back to the same JSON (semantically)
	reEncoded, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to re-encode: %v", err)
	}
	var original, roundTripped interface{}
	if err := json.Unmarshal(data, &original); err != nil {
		t.Fatalf("failed to parse original fixture as generic JSON: %v", err)
	}
	if err := json.Unmarshal(reEncoded, &roundTripped); err != nil {
		t.Fatalf("failed to parse re-encoded fixture as generic JSON: %v", err)
	}
	if !reflect.DeepEqual(original, roundTripped) {
		t.Errorf("re-marshalled fixture is not semantically equal to the original.\noriginal:     %s\nre-marshalled: %s", data, reEncoded)
	}
}

// Helper functions for pointer conversions
func stringPtr(s string) *string {
	return &s
}

func float64Ptr(f float64) *float64 {
	return &f
}

func int64Ptr(i int64) *int64 {
	return &i
}
