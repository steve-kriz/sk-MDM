package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/service"
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

// ============================================================================
// TASK-061: exit-to-restart sentinel
//
// E2E cucumber-style scenarios (Given/When/Then, from the ticket's Gherkin).
// Everything that would touch the host -- the filesystem and the download --
// is a fake; no real disk, network or database is used.
// ============================================================================

// AC2: A successful Apply swaps the binary then returns the restart sentinel.
func TestScenario_AC2_SuccessfulApplyReturnsRestartSentinel(t *testing.T) {
	// Given an installed binary of version "1.0.8" and a download of "1.0.9"
	// whose SHA-256 matches
	fsys := fake.NewFS()
	fsys.Seed("/usr/local/bin/mdmagent", []byte("1.0.8 binary"))
	newBinary := []byte("1.0.9 binary")
	doer := newFakeHTTPDoer(200, newBinary)

	// And the Restart hook returns service.ErrRestartRequired
	deps := &Deps{
		FS:             fsys,
		Doer:           doer,
		Path:           "/usr/local/bin/mdmagent",
		CurrentVersion: "1.0.8",
		Restart: func(ctx context.Context) error {
			return service.ErrRestartRequired
		},
	}

	rel := contract.AgentRelease{
		Version: "1.0.9",
		URL:     "https://example.com/agent",
		SHA256:  computeSHA256(newBinary),
	}

	// When update.Apply is called with release "1.0.9"
	err := Apply(context.Background(), rel, deps)

	// Then "<path>.old" holds the 1.0.8 bytes and "<path>" holds the 1.0.9 bytes
	old, ok := fsys.Content("/usr/local/bin/mdmagent.old")
	if !ok || !bytes.Equal(old, []byte("1.0.8 binary")) {
		t.Errorf(".old = %q (exists=%v), want the 1.0.8 bytes", old, ok)
	}
	cur, ok := fsys.Content("/usr/local/bin/mdmagent")
	if !ok || !bytes.Equal(cur, newBinary) {
		t.Errorf("binary = %q (exists=%v), want the 1.0.9 bytes", cur, ok)
	}
	// And "<path>.update-pending" contains "1.0.9"
	marker, ok := fsys.Content("/usr/local/bin/mdmagent.update-pending")
	if !ok || string(marker) != "1.0.9" {
		t.Errorf("marker = %q (exists=%v), want 1.0.9", marker, ok)
	}
	// And the returned error matches service.ErrRestartRequired
	if !errors.Is(err, service.ErrRestartRequired) {
		t.Errorf("Apply returned %v, want ErrRestartRequired", err)
	}
}

// AC2 edge: a checksum mismatch never reaches the restart.
func TestScenario_AC2_ChecksumMismatchNeverReachesRestart(t *testing.T) {
	// Given a download whose SHA-256 does not match the release
	fsys := fake.NewFS()
	fsys.Seed("/usr/local/bin/mdmagent", []byte("original binary"))
	doer := newFakeHTTPDoer(200, []byte("tampered build"))

	restartCalled := false
	deps := &Deps{
		FS:             fsys,
		Doer:           doer,
		Path:           "/usr/local/bin/mdmagent",
		CurrentVersion: "1.0.8",
		Restart: func(ctx context.Context) error {
			restartCalled = true
			return service.ErrRestartRequired
		},
	}

	rel := contract.AgentRelease{
		Version: "1.0.9",
		URL:     "https://example.com/agent",
		SHA256:  strings.Repeat("a", 64),
	}

	// When update.Apply is called
	err := Apply(context.Background(), rel, deps)

	// Then the Restart hook is not called
	if restartCalled {
		t.Error("Restart should not be called on a checksum mismatch")
	}
	// And the installed binary is byte-identical
	content, ok := fsys.Content("/usr/local/bin/mdmagent")
	if !ok || !bytes.Equal(content, []byte("original binary")) {
		t.Errorf("binary = %q (exists=%v), want it unchanged", content, ok)
	}
	if err == nil {
		t.Error("Apply should fail on a checksum mismatch")
	}
}

// AC8 (update half): RollbackIfUnhealthy forwards the restart sentinel,
// having already rolled the replaced binary back. The full AC8 scenario --
// settleUpdate's suppressed log, Start returning before the scheduler and the
// zero HTTP requests -- is covered end to end in
// agent/cmd/mdmagent/restart_test.go.
func TestScenario_AC8_RollbackForwardsRestartSentinel(t *testing.T) {
	// Given "<path>.update-pending" contains "1.0.9" while the running
	// version is "1.0.8", and "<path>.old" exists
	fsys := fake.NewFS()
	oldBinary := []byte("1.0.8 binary")
	fsys.Seed("/usr/local/bin/mdmagent", []byte("1.0.9 binary"))
	fsys.Seed("/usr/local/bin/mdmagent.old", oldBinary)
	fsys.Seed("/usr/local/bin/mdmagent.update-pending", []byte("1.0.9"))

	deps := &Deps{
		FS:             fsys,
		Path:           "/usr/local/bin/mdmagent",
		CurrentVersion: "1.0.8",
		Restart: func(ctx context.Context) error {
			return service.ErrRestartRequired
		},
	}

	// When RollbackIfUnhealthy runs at start
	err := RollbackIfUnhealthy(deps)

	// Then "<path>.old" has been renamed back to "<path>"
	content, ok := fsys.Content("/usr/local/bin/mdmagent")
	if !ok || !bytes.Equal(content, oldBinary) {
		t.Errorf("binary = %q (exists=%v), want the old bytes restored", content, ok)
	}
	if fsys.Exists("/usr/local/bin/mdmagent.update-pending") {
		t.Error("the pending marker should be deleted")
	}
	// And the returned error matches service.ErrRestartRequired
	if !errors.Is(err, service.ErrRestartRequired) {
		t.Errorf("RollbackIfUnhealthy returned %v, want ErrRestartRequired", err)
	}
}

// AC9 edge: RollbackIfUnhealthy returning a non-sentinel error (a failed
// rename, because "<path>.old" does not exist) is returned unchanged, and the
// Restart hook is never reached.
func TestScenario_AC9_RollbackRenameFailureIsReturnedUnchanged(t *testing.T) {
	// Given a pending marker naming another version and no "<path>.old" file
	fsys := fake.NewFS()
	fsys.Seed("/usr/local/bin/mdmagent.update-pending", []byte("1.0.9"))

	restartCalled := false
	deps := &Deps{
		FS:             fsys,
		Path:           "/usr/local/bin/mdmagent",
		CurrentVersion: "1.0.8",
		Restart: func(ctx context.Context) error {
			restartCalled = true
			return service.ErrRestartRequired
		},
	}

	// When RollbackIfUnhealthy runs at start
	err := RollbackIfUnhealthy(deps)

	// Then it fails with a plain error, not the restart sentinel, and the
	// restart hook is never reached
	if err == nil {
		t.Fatal("RollbackIfUnhealthy should fail when the rename fails")
	}
	if errors.Is(err, service.ErrRestartRequired) {
		t.Errorf("RollbackIfUnhealthy returned the restart sentinel, want a plain rename error: %v", err)
	}
	if restartCalled {
		t.Error("Restart should not be called when the rollback itself failed")
	}
}

// ============================================================================
// AC10: RollbackIfUnhealthy writes a rollback record before restarting.
// ============================================================================

// TestScenario_AC10_ARollbackWritesItsRecordBeforeRestarting covers:
//
//	Given a marker naming "1.5.0", a running build reporting "1.4.9" and a
//	     fake clock at 2026-10-12T02:00:00Z
//	When RollbackIfUnhealthy runs
//	Then <path>.update-rollback holds installedVersion "1.5.0", runningVersion
//	     "1.4.9", occurredAt "2026-10-12T02:00:00Z"
//	And the restart hook was called after the record was written
func TestScenario_AC10_ARollbackWritesItsRecordBeforeRestarting(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed("/usr/local/bin/mdmagent", []byte("broken binary"))
	fsys.Seed("/usr/local/bin/mdmagent.old", []byte("working binary"))
	fsys.Seed("/usr/local/bin/mdmagent.update-pending", []byte("1.5.0"))
	clock := fake.NewClock(time.Date(2026, 10, 12, 2, 0, 0, 0, time.UTC))

	var recordPresentAtRestart bool
	deps := &Deps{
		FS:             fsys,
		Path:           "/usr/local/bin/mdmagent",
		CurrentVersion: "1.4.9",
		Clock:          clock,
		Restart: func(ctx context.Context) error {
			recordPresentAtRestart = fsys.Exists(RollbackPath("/usr/local/bin/mdmagent"))
			return nil
		},
	}

	if err := RollbackIfUnhealthy(deps); err != nil {
		t.Fatalf("RollbackIfUnhealthy failed: %v", err)
	}

	if !recordPresentAtRestart {
		t.Fatal("expected the rollback record to exist before Restart was called")
	}

	data, ok := fsys.Content(RollbackPath("/usr/local/bin/mdmagent"))
	if !ok {
		t.Fatal("expected a rollback record file")
	}
	var record rollbackRecordFile
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("rollback record is not valid JSON: %v", err)
	}
	if record.InstalledVersion != "1.5.0" || record.RunningVersion != "1.4.9" || record.OccurredAt != "2026-10-12T02:00:00Z" {
		t.Errorf("record = %+v, want installedVersion=1.5.0 runningVersion=1.4.9 occurredAt=2026-10-12T02:00:00Z", record)
	}
	if mode, ok := fsys.Mode(RollbackPath("/usr/local/bin/mdmagent")); !ok || mode != MarkerFileMode {
		t.Errorf("rollback record mode = %v, want %v", mode, MarkerFileMode)
	}
}

// TestScenario_AC10_AFailedRecordWriteDoesNotStopTheRollback covers:
//
//	Given the record write fails
//	When RollbackIfUnhealthy takes the rollback branch
//	Then one warn line "update rollback record not written" is logged
//	And the old binary is back and the restart hook's error is returned
func TestScenario_AC10_AFailedRecordWriteDoesNotStopTheRollback(t *testing.T) {
	fsys := fake.NewFS()
	oldBinary := []byte("working binary")
	fsys.Seed("/usr/local/bin/mdmagent", []byte("broken binary"))
	fsys.Seed("/usr/local/bin/mdmagent.old", oldBinary)
	fsys.Seed("/usr/local/bin/mdmagent.update-pending", []byte("1.5.0"))
	fsys.FailWrite(RollbackPath("/usr/local/bin/mdmagent"), errors.New("disk full"))

	logFS := fake.NewFS()
	logger := logging.New(logFS, fake.NewClock(time.Now()), "/agent.log", logging.LevelInfo, "agent")

	restartErr := errors.New("restart sentinel")
	deps := &Deps{
		FS:             fsys,
		Path:           "/usr/local/bin/mdmagent",
		CurrentVersion: "1.4.9",
		Logger:         logger,
		Restart: func(ctx context.Context) error {
			return restartErr
		},
	}

	err := RollbackIfUnhealthy(deps)
	if !errors.Is(err, restartErr) {
		t.Fatalf("RollbackIfUnhealthy returned %v, want the restart hook's error", err)
	}

	content, exists := fsys.Content("/usr/local/bin/mdmagent")
	if !exists || !bytes.Equal(content, oldBinary) {
		t.Error("expected the old binary to be restored despite the record write failing")
	}

	logData, _ := logFS.Content("/agent.log")
	if !strings.Contains(string(logData), "update rollback record not written") {
		t.Errorf("expected a warn line \"update rollback record not written\", got log: %s", logData)
	}
}

// TestScenario_AC10_AHealthySettleWritesNoRecord covers:
//
//	Given a marker naming the running version
//	When RollbackIfUnhealthy runs
//	Then no <path>.update-rollback file exists
func TestScenario_AC10_AHealthySettleWritesNoRecord(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed("/usr/local/bin/mdmagent.update-pending", []byte("1.3.0"))

	deps := &Deps{
		FS:             fsys,
		Path:           "/usr/local/bin/mdmagent",
		CurrentVersion: "1.3.0",
	}
	if err := RollbackIfUnhealthy(deps); err != nil {
		t.Fatalf("RollbackIfUnhealthy failed: %v", err)
	}
	if fsys.Exists(RollbackPath("/usr/local/bin/mdmagent")) {
		t.Error("a healthy settle should write no rollback record")
	}
}

// TestScenario_AC10Edge_ASupersededSettleWritesNoRecord covers the superseded
// branch alongside the healthy one: an update.Apply that was never unhealthy
// and never rolled back must never leave a rollback record.
func TestScenario_AC10Edge_ASupersededSettleWritesNoRecord(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed("/usr/local/bin/mdmagent.update-pending", []byte("1.3.0"))
	fsys.Seed("/usr/local/bin/mdmagent.old", []byte("old binary"))

	deps := &Deps{
		FS:             fsys,
		Path:           "/usr/local/bin/mdmagent",
		CurrentVersion: "1.4.0", // ahead of the marker: superseded by a newer install
	}
	if err := RollbackIfUnhealthy(deps); err != nil {
		t.Fatalf("RollbackIfUnhealthy failed: %v", err)
	}
	if fsys.Exists(RollbackPath("/usr/local/bin/mdmagent")) {
		t.Error("a superseded settle should write no rollback record")
	}
}

// ============================================================================
// AC11: TakeRollbackRecord.
// ============================================================================

// TestScenario_AC11_TheNextStartTakesTheRecord covers the TakeRollbackRecord
// half of "The next start takes the record (AC11, AC12)":
//
//	Given <path>.update-rollback holds a valid record at 2026-10-12T02:00:00Z
//	When TakeRollbackRecord runs
//	Then the file is deleted and the record is returned
func TestScenario_AC11_TheNextStartTakesTheRecord(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed(RollbackPath("/usr/local/bin/mdmagent"), []byte(
		`{"installedVersion":"1.5.0","runningVersion":"1.4.9","occurredAt":"2026-10-12T02:00:00Z"}`,
	))
	deps := &Deps{FS: fsys, Path: "/usr/local/bin/mdmagent"}

	rec, ok := TakeRollbackRecord(deps)
	if !ok {
		t.Fatal("expected TakeRollbackRecord to return true")
	}
	if rec.InstalledVersion != "1.5.0" || rec.RunningVersion != "1.4.9" {
		t.Errorf("record = %+v", rec)
	}
	wantAt := time.Date(2026, 10, 12, 2, 0, 0, 0, time.UTC)
	if !rec.OccurredAt.Equal(wantAt) {
		t.Errorf("OccurredAt = %v, want %v", rec.OccurredAt, wantAt)
	}
	if fsys.Exists(RollbackPath("/usr/local/bin/mdmagent")) {
		t.Error("expected the record file to be deleted")
	}
}

// TestScenario_AC11_AbsentFileReturnsFalseAndTouchesNothing covers: "Absent
// file: returns false and touches nothing."
func TestScenario_AC11_AbsentFileReturnsFalseAndTouchesNothing(t *testing.T) {
	fsys := fake.NewFS()
	deps := &Deps{FS: fsys, Path: "/usr/local/bin/mdmagent"}

	_, ok := TakeRollbackRecord(deps)
	if ok {
		t.Error("expected false for an absent record file")
	}
	if len(fsys.Paths()) != 0 {
		t.Errorf("expected no files to be touched, got %v", fsys.Paths())
	}
}

// TestScenario_AC11_AnUnreadableRecordIsDiscarded covers:
//
//	Given <path>.update-rollback holds "not json"
//	When TakeRollbackRecord runs
//	Then it returns false, deletes the file and logs "update rollback record unreadable"
func TestScenario_AC11_AnUnreadableRecordIsDiscarded(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed(RollbackPath("/usr/local/bin/mdmagent"), []byte("not json"))

	logFS := fake.NewFS()
	logger := logging.New(logFS, fake.NewClock(time.Now()), "/agent.log", logging.LevelInfo, "agent")
	deps := &Deps{FS: fsys, Path: "/usr/local/bin/mdmagent", Logger: logger}

	_, ok := TakeRollbackRecord(deps)
	if ok {
		t.Error("expected false for unparseable content")
	}
	if fsys.Exists(RollbackPath("/usr/local/bin/mdmagent")) {
		t.Error("expected the unreadable record file to be deleted")
	}
	logData, _ := logFS.Content("/agent.log")
	if !strings.Contains(string(logData), "update rollback record unreadable") {
		t.Errorf("expected a warn line \"update rollback record unreadable\", got log: %s", logData)
	}
}

// TestScenario_AC11Edge_EmptyInstalledVersionIsDiscarded covers: valid JSON
// but an empty installedVersion is treated the same as unreadable content.
func TestScenario_AC11Edge_EmptyInstalledVersionIsDiscarded(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed(RollbackPath("/usr/local/bin/mdmagent"), []byte(
		`{"installedVersion":"","runningVersion":"1.4.9","occurredAt":"2026-10-12T02:00:00Z"}`,
	))
	deps := &Deps{FS: fsys, Path: "/usr/local/bin/mdmagent"}

	_, ok := TakeRollbackRecord(deps)
	if ok {
		t.Error("expected false for an empty installedVersion")
	}
	if fsys.Exists(RollbackPath("/usr/local/bin/mdmagent")) {
		t.Error("expected the record file to still be deleted")
	}
}

// TestScenario_AC11Edge_UnparseableOccurredAtIsDiscarded covers: valid JSON
// with a non-RFC-3339 occurredAt is discarded the same way.
func TestScenario_AC11Edge_UnparseableOccurredAtIsDiscarded(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed(RollbackPath("/usr/local/bin/mdmagent"), []byte(
		`{"installedVersion":"1.5.0","runningVersion":"1.4.9","occurredAt":"not-a-time"}`,
	))
	deps := &Deps{FS: fsys, Path: "/usr/local/bin/mdmagent"}

	_, ok := TakeRollbackRecord(deps)
	if ok {
		t.Error("expected false for an unparseable occurredAt")
	}
}

// TestScenario_AC11Edge_AFailedDeleteIsLoggedAndDoesNotChangeTheResult covers:
// "A failed delete is logged at warn and does not change the return value."
func TestScenario_AC11Edge_AFailedDeleteIsLoggedAndDoesNotChangeTheResult(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed(RollbackPath("/usr/local/bin/mdmagent"), []byte(
		`{"installedVersion":"1.5.0","runningVersion":"1.4.9","occurredAt":"2026-10-12T02:00:00Z"}`,
	))
	path := RollbackPath("/usr/local/bin/mdmagent")
	fsys.RemoveErr = func(candidate string) error {
		if candidate == path {
			return errors.New("remove failed")
		}
		return nil
	}

	logFS := fake.NewFS()
	logger := logging.New(logFS, fake.NewClock(time.Now()), "/agent.log", logging.LevelInfo, "agent")
	deps := &Deps{FS: fsys, Path: "/usr/local/bin/mdmagent", Logger: logger}

	rec, ok := TakeRollbackRecord(deps)
	if !ok {
		t.Fatal("expected the record to still be returned despite the failed delete")
	}
	if rec.InstalledVersion != "1.5.0" {
		t.Errorf("record = %+v", rec)
	}
	logData, _ := logFS.Content("/agent.log")
	if !strings.Contains(string(logData), "warn") {
		t.Errorf("expected a warn line logged for the failed delete, got log: %s", logData)
	}
}

// TestScenario_AC11Edge_NilDepsReturnsFalse covers TakeRollbackRecord's guard
// clauses: nil deps, nil FS and an empty Path all return false.
func TestScenario_AC11Edge_NilDepsReturnsFalse(t *testing.T) {
	if _, ok := TakeRollbackRecord(nil); ok {
		t.Error("TakeRollbackRecord(nil) should return false")
	}
	if _, ok := TakeRollbackRecord(&Deps{}); ok {
		t.Error("TakeRollbackRecord with a nil FS should return false")
	}
	if _, ok := TakeRollbackRecord(&Deps{FS: fake.NewFS()}); ok {
		t.Error("TakeRollbackRecord with an empty Path should return false")
	}
}

// TestScenario_AC10_RollbackPathHelper pins RollbackPath's shape.
func TestScenario_AC10_RollbackPathHelper(t *testing.T) {
	if got := RollbackPath("/usr/local/bin/mdmagent"); got != "/usr/local/bin/mdmagent.update-rollback" {
		t.Errorf("RollbackPath = %q", got)
	}
	if RollbackSuffix != ".update-rollback" {
		t.Errorf("RollbackSuffix = %q, want %q", RollbackSuffix, ".update-rollback")
	}
}
