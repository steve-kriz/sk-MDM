package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// ============================================================================
// Mock HTTP Doer
// ============================================================================

type FakeHTTPDoer struct {
	nextResponse *http.Response
	nextError    error
	requests     []*http.Request
}

func (f *FakeHTTPDoer) Do(req *http.Request) (*http.Response, error) {
	f.requests = append(f.requests, req)
	if f.nextError != nil {
		return nil, f.nextError
	}
	return f.nextResponse, nil
}

func newFakeHTTPDoer(statusCode int, body []byte) *FakeHTTPDoer {
	return &FakeHTTPDoer{
		nextResponse: &http.Response{
			StatusCode: statusCode,
			Body:       io.NopCloser(bytes.NewReader(body)),
		},
	}
}

// ============================================================================
// Test Helpers
// ============================================================================

func computeSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// ============================================================================
// Apply Tests
// ============================================================================

// Scenario: Download failure is inert
func TestScenario_DownloadFailureIsInert(t *testing.T) {
	// Given the download returns status 503
	fsys := fake.NewFS()
	doer := newFakeHTTPDoer(503, []byte{})

	restartCalled := false
	deps := &Deps{
		FS:             fsys,
		Doer:           doer,
		Path:           "/usr/local/bin/mdmagent",
		CurrentVersion: "1.2.0",
		Restart: func(ctx context.Context) error {
			restartCalled = true
			return nil
		},
	}

	// When Apply runs
	rel := contract.AgentRelease{
		Version: "1.3.0",
		URL:     "https://example.com/agent",
		SHA256:  "a" + strings.Repeat("0", 63),
	}
	err := Apply(context.Background(), rel, deps)

	// Then the error names 503
	if err == nil {
		t.Fatal("Expected an error")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("Expected error to contain '503', got %v", err)
	}

	// And the installed binary is byte-identical (not modified)
	// Check that .old file was not created
	if fsys.Exists("/usr/local/bin/mdmagent.old") {
		t.Error(".old file should not exist after failed download")
	}

	// And restart should not be called
	if restartCalled {
		t.Error("Restart should not be called on download failure")
	}
}

// Scenario: Checksum mismatch aborts
func TestScenario_ChecksumMismatchAborts(t *testing.T) {
	// Given a download whose digest differs from rel.sha256
	fsys := fake.NewFS()
	downloadedContent := []byte("different binary content")
	doer := newFakeHTTPDoer(200, downloadedContent)

	restartCalled := false
	deps := &Deps{
		FS:             fsys,
		Doer:           doer,
		Path:           "/usr/local/bin/mdmagent",
		CurrentVersion: "1.2.0",
		Restart: func(ctx context.Context) error {
			restartCalled = true
			return nil
		},
	}

	// When Apply runs
	rel := contract.AgentRelease{
		Version: "1.3.0",
		URL:     "https://example.com/agent",
		SHA256:  "wrongsha256" + strings.Repeat("0", 53), // wrong hash
	}
	err := Apply(context.Background(), rel, deps)

	// Then the error contains "checksum mismatch"
	if err == nil {
		t.Fatal("Expected an error")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("Expected error to contain 'checksum mismatch', got %v", err)
	}

	// And restart should not be called
	if restartCalled {
		t.Error("Restart should not be called on checksum mismatch")
	}
}

// Scenario: Downgrade is refused
func TestScenario_DowngradeIsRefused(t *testing.T) {
	// Given a running version of 1.3.0 and an advertised 1.2.0
	fsys := fake.NewFS()
	doer := &FakeHTTPDoer{}

	restartCalled := false
	deps := &Deps{
		FS:             fsys,
		Doer:           doer,
		Path:           "/usr/local/bin/mdmagent",
		CurrentVersion: "1.3.0",
		Restart: func(ctx context.Context) error {
			restartCalled = true
			return nil
		},
	}

	// When Apply runs
	rel := contract.AgentRelease{
		Version: "1.2.0",
		URL:     "https://example.com/agent",
		SHA256:  "a" + strings.Repeat("0", 63),
	}
	err := Apply(context.Background(), rel, deps)

	// Then the error contains "not an upgrade"
	if err == nil {
		t.Fatal("Expected an error")
	}
	if !strings.Contains(err.Error(), "not an upgrade") {
		t.Errorf("Expected error to contain 'not an upgrade', got %v", err)
	}

	// And no download was performed
	if len(doer.requests) > 0 {
		t.Error("HTTP Do should not be called for a downgrade")
	}

	// And restart should not be called
	if restartCalled {
		t.Error("Restart should not be called on downgrade")
	}
}

// Scenario: Swap order ends with the restart
func TestScenario_SwapOrderEndsWithRestart(t *testing.T) {
	// Given a stale /usr/local/bin/mdmagent.old from an earlier update and a valid 1.3.0 download
	fsys := fake.NewFS()
	oldBinary := []byte("old binary from previous update")
	newBinary := []byte("new binary content for 1.3.0")

	fsys.Seed("/usr/local/bin/mdmagent", []byte("1.2.0 binary"))
	fsys.Seed("/usr/local/bin/mdmagent.old", oldBinary)

	doer := newFakeHTTPDoer(200, newBinary)

	restartCalled := false
	deps := &Deps{
		FS:             fsys,
		Doer:           doer,
		Path:           "/usr/local/bin/mdmagent",
		CurrentVersion: "1.2.0",
		Restart: func(ctx context.Context) error {
			restartCalled = true
			return nil
		},
	}

	// When Apply runs
	rel := contract.AgentRelease{
		Version: "1.3.0",
		URL:     "https://example.com/agent",
		SHA256:  computeSHA256(newBinary),
	}
	err := Apply(context.Background(), rel, deps)

	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// Then the binary is replaced with the new one
	content, exists := fsys.Content("/usr/local/bin/mdmagent")
	if !exists {
		t.Fatal("mdmagent should exist after Apply")
	}
	if !bytes.Equal(content, newBinary) {
		t.Error("mdmagent should contain the new binary")
	}

	// And .old file contains the previous binary
	oldContent, exists := fsys.Content("/usr/local/bin/mdmagent.old")
	if !exists {
		t.Fatal("mdmagent.old should exist after Apply")
	}
	if !bytes.Equal(oldContent, []byte("1.2.0 binary")) {
		t.Error("mdmagent.old should contain the binary that was replaced")
	}

	// And .update-pending marker exists with the new version
	markerContent, exists := fsys.Content("/usr/local/bin/mdmagent.update-pending")
	if !exists {
		t.Fatal("mdmagent.update-pending should exist after Apply")
	}
	if string(markerContent) != "1.3.0" {
		t.Errorf("Expected update-pending to contain '1.3.0', got %q", string(markerContent))
	}

	// And the restart hook was called
	if !restartCalled {
		t.Error("Restart hook should be invoked by Apply")
	}
}

// Scenario: Version comparison strips -/+ suffix
func TestScenario_VersionComparisonStripsSuffix(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed("/usr/local/bin/mdmagent", []byte("1.2.0-dev binary"))
	newBinary := []byte("new binary")

	doer := newFakeHTTPDoer(200, newBinary)

	restartCalled := false
	deps := &Deps{
		FS:             fsys,
		Doer:           doer,
		Path:           "/usr/local/bin/mdmagent",
		CurrentVersion: "1.2.0-dev",
		Restart: func(ctx context.Context) error {
			restartCalled = true
			return nil
		},
	}

	// When Apply runs with 1.3.0 release and 1.2.0-dev running
	rel := contract.AgentRelease{
		Version: "1.3.0",
		URL:     "https://example.com/agent",
		SHA256:  computeSHA256(newBinary),
	}
	err := Apply(context.Background(), rel, deps)

	// Then it should succeed (1.3.0 > 1.2.0)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// And restart was called
	if !restartCalled {
		t.Error("Restart should be called for successful upgrade")
	}
}

// ============================================================================
// RollbackIfUnhealthy Tests
// ============================================================================

// Scenario: Healthy start clears the pending marker
func TestScenario_HealthyStartClearsMarker(t *testing.T) {
	// Given mdmagent.update-pending contains "1.3.0" and the running build reports 1.3.0
	fsys := fake.NewFS()
	fsys.Seed("/usr/local/bin/mdmagent.update-pending", []byte("1.3.0"))
	fsys.Seed("/usr/local/bin/mdmagent.old", []byte("old binary"))

	restartCalled := false
	deps := &Deps{
		FS:             fsys,
		Path:           "/usr/local/bin/mdmagent",
		CurrentVersion: "1.3.0",
		Restart: func(ctx context.Context) error {
			restartCalled = true
			return nil
		},
	}

	// When RollbackIfUnhealthy runs at start
	err := RollbackIfUnhealthy(deps)

	if err != nil {
		t.Fatalf("RollbackIfUnhealthy failed: %v", err)
	}

	// Then mdmagent.update-pending and mdmagent.old are deleted
	if fsys.Exists("/usr/local/bin/mdmagent.update-pending") {
		t.Error("update-pending should be deleted on healthy start")
	}

	if fsys.Exists("/usr/local/bin/mdmagent.old") {
		t.Error("mdmagent.old should be deleted on healthy start")
	}

	// And restart should not be called
	if restartCalled {
		t.Error("Restart should not be called on healthy start")
	}
}

// Scenario: Unhealthy start rolls back
func TestScenario_UnhealthyStartRollsBack(t *testing.T) {
	// Given mdmagent.update-pending contains "1.3.0" and the running build reports 0.0.0
	fsys := fake.NewFS()
	oldBinary := []byte("working binary")
	newBinary := []byte("broken binary")

	fsys.Seed("/usr/local/bin/mdmagent", newBinary)
	fsys.Seed("/usr/local/bin/mdmagent.old", oldBinary)
	fsys.Seed("/usr/local/bin/mdmagent.update-pending", []byte("1.3.0"))

	restartCalled := false
	deps := &Deps{
		FS:             fsys,
		Path:           "/usr/local/bin/mdmagent",
		CurrentVersion: "0.0.0",
		Restart: func(ctx context.Context) error {
			restartCalled = true
			return nil
		},
	}

	// When RollbackIfUnhealthy runs at start
	err := RollbackIfUnhealthy(deps)

	if err != nil {
		t.Fatalf("RollbackIfUnhealthy failed: %v", err)
	}

	// Then mdmagent.old was moved back over mdmagent
	content, exists := fsys.Content("/usr/local/bin/mdmagent")
	if !exists {
		t.Fatal("mdmagent should exist after rollback")
	}
	if !bytes.Equal(content, oldBinary) {
		t.Errorf("mdmagent should contain old binary after rollback")
	}

	// And the marker is deleted
	if fsys.Exists("/usr/local/bin/mdmagent.update-pending") {
		t.Error("update-pending should be deleted after rollback")
	}

	// And the restart hook was invoked
	if !restartCalled {
		t.Error("Restart hook should be invoked on rollback")
	}
}

// Scenario: Start with no pending update changes nothing
func TestScenario_NoPendingUpdateChangesNothing(t *testing.T) {
	// Given no mdmagent.update-pending file exists
	fsys := fake.NewFS()
	fsys.Seed("/usr/local/bin/mdmagent", []byte("working binary"))

	restartCalled := false
	deps := &Deps{
		FS:             fsys,
		Path:           "/usr/local/bin/mdmagent",
		CurrentVersion: "1.3.0",
		Restart: func(ctx context.Context) error {
			restartCalled = true
			return nil
		},
	}

	// When RollbackIfUnhealthy runs
	err := RollbackIfUnhealthy(deps)

	if err != nil {
		t.Fatalf("RollbackIfUnhealthy failed: %v", err)
	}

	// Then the binary is unchanged
	content, exists := fsys.Content("/usr/local/bin/mdmagent")
	if !exists {
		t.Fatal("Binary should still exist")
	}
	if !bytes.Equal(content, []byte("working binary")) {
		t.Error("Binary should be unchanged when no pending marker exists")
	}

	// And restart should not be called
	if restartCalled {
		t.Error("Restart should not be called when no pending marker exists")
	}
}

// Unit: Version parsing and comparison
func TestUnit_VersionParsing(t *testing.T) {
	tests := []struct {
		name   string
		a, b   string
		expect int // -1 if a<b, 0 if a==b, 1 if a>b
	}{
		{"1.2.0 vs 1.3.0", "1.2.0", "1.3.0", -1},
		{"1.3.0 vs 1.2.0", "1.3.0", "1.2.0", 1},
		{"1.3.0 vs 1.3.0", "1.3.0", "1.3.0", 0},
		{"1.3.0-dev vs 1.3.0", "1.3.0-dev", "1.3.0", 0},
		{"1.3.0-dev vs 1.4.0", "1.3.0-dev", "1.4.0", -1},
		{"2.0.0 vs 1.999.999", "2.0.0", "1.999.999", 1},
		{"dev string vs 1.0.0", "", "1.0.0", -1}, // dev (empty) vs 1.0.0
	}

	for _, test := range tests {
		a, ok1 := parseVersion(test.a)
		b, ok2 := parseVersion(test.b)

		// Handle the case where version parsing fails
		if !ok1 {
			a = nil
		}
		if !ok2 {
			b = nil
		}

		result := compareVersions(a, b)
		if result != test.expect {
			t.Errorf("%s: expected %d, got %d", test.name, test.expect, result)
		}
	}
}

// Unit: isUpgrade function
func TestUnit_IsUpgrade(t *testing.T) {
	tests := []struct {
		name     string
		current  string
		next     string
		expected bool
	}{
		{"1.2.0 to 1.3.0", "1.2.0", "1.3.0", true},
		{"1.3.0 to 1.2.0", "1.3.0", "1.2.0", false},
		{"1.3.0 to 1.3.0", "1.3.0", "1.3.0", false},
		{"dev to 1.3.0", "", "1.3.0", true},
		{"1.3.0-dev to 1.4.0", "1.3.0-dev", "1.4.0", true},
		{"invalid current to 1.3.0", "not-a-version", "1.3.0", true},
	}

	for _, test := range tests {
		result := isUpgrade(test.current, test.next)
		if result != test.expected {
			t.Errorf("%s: expected %v, got %v", test.name, test.expected, result)
		}
	}
}

// Unit: OldPath and PendingPath helpers
func TestUnit_PathHelpers(t *testing.T) {
	path := "/usr/local/bin/mdmagent"

	oldPath := OldPath(path)
	if oldPath != "/usr/local/bin/mdmagent.old" {
		t.Errorf("OldPath incorrect: %s", oldPath)
	}

	pendingPath := PendingPath(path)
	if pendingPath != "/usr/local/bin/mdmagent.update-pending" {
		t.Errorf("PendingPath incorrect: %s", pendingPath)
	}
}

// Unit: Apply requires all dependencies
func TestUnit_ApplyRequiresDeps(t *testing.T) {
	// Apply with nil deps
	err := Apply(context.Background(), contract.AgentRelease{}, nil)
	if err == nil {
		t.Error("Apply should fail with nil deps")
	}

	// Apply with nil FS
	err = Apply(context.Background(), contract.AgentRelease{}, &Deps{})
	if err == nil {
		t.Error("Apply should fail with nil FS")
	}

	// Apply with no Path
	err = Apply(context.Background(), contract.AgentRelease{}, &Deps{
		FS: fake.NewFS(),
	})
	if err == nil {
		t.Error("Apply should fail with no Path")
	}
}

// Unit: RollbackIfUnhealthy requires all dependencies
func TestUnit_RollbackRequiresDeps(t *testing.T) {
	// RollbackIfUnhealthy with nil deps
	err := RollbackIfUnhealthy(nil)
	if err == nil {
		t.Error("RollbackIfUnhealthy should fail with nil deps")
	}

	// RollbackIfUnhealthy with nil FS
	err = RollbackIfUnhealthy(&Deps{})
	if err == nil {
		t.Error("RollbackIfUnhealthy should fail with nil FS")
	}

	// RollbackIfUnhealthy with no Path
	err = RollbackIfUnhealthy(&Deps{
		FS: fake.NewFS(),
	})
	if err == nil {
		t.Error("RollbackIfUnhealthy should fail with no Path")
	}
}
