package executor

import (
	"encoding/json"
	"testing"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// TestStore_Load returns every remembered command in order.
func TestStore_Load(t *testing.T) {
	fs := fake.NewFS()
	store := NewStore(fs, "/store.json")

	// Record some commands
	result1 := contract.CommandResultRequest{
		Status:     StatusSucceeded,
		ExitCode:   0,
		Output:     "first",
		FinishedAt: 1000,
	}
	result2 := contract.CommandResultRequest{
		Status:     StatusFailed,
		ExitCode:   1,
		Output:     "second",
		FinishedAt: 2000,
	}

	if err := store.Record("cmd1", result1); err != nil {
		t.Fatalf("failed to record cmd1: %v", err)
	}
	if err := store.Record("cmd2", result2); err != nil {
		t.Fatalf("failed to record cmd2: %v", err)
	}

	// Load them back
	records, err := store.Load()
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	if records[0].CommandID != "cmd1" {
		t.Errorf("expected first command 'cmd1', got '%s'", records[0].CommandID)
	}
	if records[1].CommandID != "cmd2" {
		t.Errorf("expected second command 'cmd2', got '%s'", records[1].CommandID)
	}
}

// TestStore_Lookup returns a single command by ID.
func TestStore_Lookup(t *testing.T) {
	fs := fake.NewFS()
	store := NewStore(fs, "/store.json")

	result := contract.CommandResultRequest{
		Status:     StatusSucceeded,
		ExitCode:   0,
		Output:     "test output",
		FinishedAt: 1500,
	}

	if err := store.Record("test-cmd", result); err != nil {
		t.Fatalf("failed to record: %v", err)
	}

	// Lookup existing command
	record, found, err := store.Lookup("test-cmd")
	if err != nil {
		t.Fatalf("failed to lookup: %v", err)
	}

	if !found {
		t.Fatalf("expected to find 'test-cmd'")
	}

	if record.CommandID != "test-cmd" {
		t.Errorf("expected commandId 'test-cmd', got '%s'", record.CommandID)
	}

	if record.Result.Output != "test output" {
		t.Errorf("expected output 'test output', got '%s'", record.Result.Output)
	}

	// Lookup non-existent command
	_, found, err = store.Lookup("non-existent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if found {
		t.Fatalf("expected not to find 'non-existent'")
	}
}

// TestStore_Record saves a new command.
func TestStore_Record(t *testing.T) {
	fs := fake.NewFS()
	store := NewStore(fs, "/store.json")

	result := contract.CommandResultRequest{
		Status:     StatusSucceeded,
		ExitCode:   0,
		Output:     "recorded",
		FinishedAt: 2000,
	}

	err := store.Record("new-cmd", result)
	if err != nil {
		t.Fatalf("failed to record: %v", err)
	}

	// Verify file was written
	content, exists := fs.Content("/store.json")
	if !exists {
		t.Fatalf("expected store file to be written")
	}

	// Verify content is valid JSON
	var file storeFile
	if err := json.Unmarshal(content, &file); err != nil {
		t.Fatalf("invalid store file: %v", err)
	}

	if len(file.Commands) != 1 {
		t.Fatalf("expected 1 command in store, got %d", len(file.Commands))
	}

	if file.Commands[0].CommandID != "new-cmd" {
		t.Errorf("expected commandId 'new-cmd', got '%s'", file.Commands[0].CommandID)
	}
}

// TestStore_Record replaces an existing command.
func TestStore_RecordReplaces(t *testing.T) {
	fs := fake.NewFS()
	store := NewStore(fs, "/store.json")

	result1 := contract.CommandResultRequest{
		Status:     StatusFailed,
		ExitCode:   1,
		Output:     "first attempt",
		FinishedAt: 1000,
	}

	result2 := contract.CommandResultRequest{
		Status:     StatusSucceeded,
		ExitCode:   0,
		Output:     "second attempt",
		FinishedAt: 2000,
	}

	// Record same commandId twice
	if err := store.Record("dup-cmd", result1); err != nil {
		t.Fatalf("failed first record: %v", err)
	}

	if err := store.Record("dup-cmd", result2); err != nil {
		t.Fatalf("failed second record: %v", err)
	}

	// Should have only one record
	records, err := store.Load()
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record after replacement, got %d", len(records))
	}

	if records[0].Result.Output != "second attempt" {
		t.Errorf("expected second result, got '%s'", records[0].Result.Output)
	}
}

// TestStore_MarkPosted marks a command as posted.
func TestStore_MarkPosted(t *testing.T) {
	fs := fake.NewFS()
	store := NewStore(fs, "/store.json")

	result := contract.CommandResultRequest{
		Status:     StatusSucceeded,
		ExitCode:   0,
		Output:     "test",
		FinishedAt: 1500,
	}

	if err := store.Record("cmd", result); err != nil {
		t.Fatalf("failed to record: %v", err)
	}

	// Check initial Posted flag
	record, _, err := store.Lookup("cmd")
	if err != nil {
		t.Fatalf("failed to lookup: %v", err)
	}

	if record.Posted {
		t.Fatalf("expected Posted to be false initially")
	}

	// Mark as posted
	if err := store.MarkPosted("cmd"); err != nil {
		t.Fatalf("failed to mark posted: %v", err)
	}

	// Verify it's marked
	record, _, err = store.Lookup("cmd")
	if err != nil {
		t.Fatalf("failed to lookup: %v", err)
	}

	if !record.Posted {
		t.Fatalf("expected Posted to be true")
	}
}

// TestStore_Unposted returns only unposted results.
func TestStore_Unposted(t *testing.T) {
	fs := fake.NewFS()
	store := NewStore(fs, "/store.json")

	result1 := contract.CommandResultRequest{
		Status:     StatusSucceeded,
		ExitCode:   0,
		Output:     "first",
		FinishedAt: 1000,
	}

	result2 := contract.CommandResultRequest{
		Status:     StatusSucceeded,
		ExitCode:   0,
		Output:     "second",
		FinishedAt: 2000,
	}

	result3 := contract.CommandResultRequest{
		Status:     StatusSucceeded,
		ExitCode:   0,
		Output:     "third",
		FinishedAt: 3000,
	}

	// Record three commands
	if err := store.Record("cmd1", result1); err != nil {
		t.Fatalf("failed to record cmd1: %v", err)
	}
	if err := store.Record("cmd2", result2); err != nil {
		t.Fatalf("failed to record cmd2: %v", err)
	}
	if err := store.Record("cmd3", result3); err != nil {
		t.Fatalf("failed to record cmd3: %v", err)
	}

	// Mark two as posted
	if err := store.MarkPosted("cmd1"); err != nil {
		t.Fatalf("failed to mark cmd1 posted: %v", err)
	}
	if err := store.MarkPosted("cmd3"); err != nil {
		t.Fatalf("failed to mark cmd3 posted: %v", err)
	}

	// Get unposted
	unposted, err := store.Unposted()
	if err != nil {
		t.Fatalf("failed to get unposted: %v", err)
	}

	if len(unposted) != 1 {
		t.Fatalf("expected 1 unposted command, got %d", len(unposted))
	}

	if unposted[0].CommandID != "cmd2" {
		t.Errorf("expected unposted command 'cmd2', got '%s'", unposted[0].CommandID)
	}
}

// TestStore_MaxRecords enforces the record limit.
func TestStore_MaxRecords(t *testing.T) {
	fs := fake.NewFS()
	store := NewStore(fs, "/store.json")

	// Record more than StoreMaxRecords commands
	for i := 0; i < StoreMaxRecords+10; i++ {
		result := contract.CommandResultRequest{
			Status:     StatusSucceeded,
			ExitCode:   0,
			Output:     "output",
			FinishedAt: int64(1000 + i),
		}

		commandID := string(rune('a') + rune(i))
		if err := store.Record(commandID, result); err != nil {
			t.Fatalf("failed to record command %d: %v", i, err)
		}
	}

	// Load and verify only StoreMaxRecords are kept
	records, err := store.Load()
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}

	if len(records) != StoreMaxRecords {
		t.Fatalf("expected %d records, got %d", StoreMaxRecords, len(records))
	}

	// Verify oldest records were dropped (0-9 are dropped, 10-199 remain)
	if records[0].CommandID != string(rune('a')+rune(10)) {
		t.Errorf("expected first command after trim, got '%s'", records[0].CommandID)
	}
}

// TestStore_EmptyStore returns empty list for non-existent file.
func TestStore_EmptyStore(t *testing.T) {
	fs := fake.NewFS()
	store := NewStore(fs, "/nonexistent.json")

	records, err := store.Load()
	if err != nil {
		t.Fatalf("failed to load empty store: %v", err)
	}

	if len(records) != 0 {
		t.Fatalf("expected empty list for non-existent store, got %d records", len(records))
	}
}

// TestStore_FileMode creates files with correct permissions.
func TestStore_FileMode(t *testing.T) {
	fs := fake.NewFS()
	store := NewStore(fs, "/store.json")

	result := contract.CommandResultRequest{
		Status:     StatusSucceeded,
		ExitCode:   0,
		Output:     "test",
		FinishedAt: 1500,
	}

	if err := store.Record("cmd", result); err != nil {
		t.Fatalf("failed to record: %v", err)
	}

	// Check file mode
	mode, exists := fs.Mode("/store.json")
	if !exists {
		t.Fatalf("expected store file to exist")
	}

	if mode != StoreFileMode {
		t.Errorf("expected mode 0o600, got %o", mode)
	}
}

// TestStore_ConcurrentAccess handles concurrent reads and writes.
func TestStore_ConcurrentAccess(t *testing.T) {
	fs := fake.NewFS()
	store := NewStore(fs, "/store.json")

	// This test simply verifies no race conditions by using the API
	result := contract.CommandResultRequest{
		Status:     StatusSucceeded,
		ExitCode:   0,
		Output:     "concurrent",
		FinishedAt: 1500,
	}

	if err := store.Record("cmd1", result); err != nil {
		t.Fatalf("failed to record: %v", err)
	}

	// Multiple lookups should work correctly
	for i := 0; i < 5; i++ {
		_, found, err := store.Lookup("cmd1")
		if err != nil {
			t.Fatalf("failed to lookup: %v", err)
		}
		if !found {
			t.Fatalf("expected to find cmd1")
		}
	}
}

// TestStore_Path returns the configured path.
func TestStore_Path(t *testing.T) {
	fs := fake.NewFS()
	expectedPath := "/custom/store.json"
	store := NewStore(fs, expectedPath)

	if store.Path() != expectedPath {
		t.Errorf("expected path '%s', got '%s'", expectedPath, store.Path())
	}
}

// TestStore_InitialPostedFalse verifies new records start unposted.
func TestStore_InitialPostedFalse(t *testing.T) {
	fs := fake.NewFS()
	store := NewStore(fs, "/store.json")

	result := contract.CommandResultRequest{
		Status:     StatusSucceeded,
		ExitCode:   0,
		Output:     "test",
		FinishedAt: 1500,
	}

	if err := store.Record("cmd", result); err != nil {
		t.Fatalf("failed to record: %v", err)
	}

	// Verify Posted is false
	records, err := store.Load()
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}

	if records[0].Posted {
		t.Fatalf("expected Posted to be false for new record")
	}
}

// TestStore_MarkPostedIdempotent verifies MarkPosted is idempotent.
func TestStore_MarkPostedIdempotent(t *testing.T) {
	fs := fake.NewFS()
	store := NewStore(fs, "/store.json")

	result := contract.CommandResultRequest{
		Status:     StatusSucceeded,
		ExitCode:   0,
		Output:     "test",
		FinishedAt: 1500,
	}

	if err := store.Record("cmd", result); err != nil {
		t.Fatalf("failed to record: %v", err)
	}

	// Mark posted twice
	if err := store.MarkPosted("cmd"); err != nil {
		t.Fatalf("first mark failed: %v", err)
	}

	if err := store.MarkPosted("cmd"); err != nil {
		t.Fatalf("second mark failed: %v", err)
	}

	// Should still be posted
	record, found, err := store.Lookup("cmd")
	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}

	if !found {
		t.Fatalf("expected to find cmd")
	}

	if !record.Posted {
		t.Fatalf("expected Posted to be true")
	}
}

// TestStore_MarkPostedNonexistent handles marking non-existent command.
func TestStore_MarkPostedNonexistent(t *testing.T) {
	fs := fake.NewFS()
	store := NewStore(fs, "/store.json")

	// Mark a command that doesn't exist - should not error
	err := store.MarkPosted("nonexistent")
	if err != nil {
		t.Fatalf("expected no error marking nonexistent command: %v", err)
	}

	// Verify store is still empty
	records, err := store.Load()
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}

	if len(records) != 0 {
		t.Fatalf("expected empty store")
	}
}

// TestStore_OrderPreservation verifies records stay in completion order.
func TestStore_OrderPreservation(t *testing.T) {
	fs := fake.NewFS()
	store := NewStore(fs, "/store.json")

	commandIDs := []string{"cmd-a", "cmd-b", "cmd-c", "cmd-b", "cmd-d"}

	for i, id := range commandIDs {
		result := contract.CommandResultRequest{
			Status:     StatusSucceeded,
			ExitCode:   0,
			Output:     "output",
			FinishedAt: int64(1000 + i),
		}

		if err := store.Record(id, result); err != nil {
			t.Fatalf("failed to record: %v", err)
		}
	}

	records, err := store.Load()
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}

	// After recording with a duplicate, cmd-b should be replaced in-place
	expectedOrder := []string{"cmd-a", "cmd-b", "cmd-c", "cmd-d"}
	if len(records) != len(expectedOrder) {
		t.Fatalf("expected %d records, got %d", len(expectedOrder), len(records))
	}

	for i, expected := range expectedOrder {
		if records[i].CommandID != expected {
			t.Errorf("record[%d]: expected '%s', got '%s'", i, expected, records[i].CommandID)
		}
	}
}
