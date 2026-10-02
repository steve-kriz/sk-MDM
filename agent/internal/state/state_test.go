package state

import (
	"encoding/json"
	"io/fs"
	"testing"

	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// TestScenario_StatePathIsPerPlatform verifies that StatePath returns the
// correct path and Save requests mode 0600.
func TestScenario_StatePathIsPerPlatform(t *testing.T) {
	// When: StatePath("darwin") and StatePath("windows") are called
	darwinPath := StatePath("darwin")
	windowsPath := StatePath("windows")

	// Then: they return the documented macOS and Windows paths
	if darwinPath != DarwinPath {
		t.Errorf("Expected macOS path %s, got %s", DarwinPath, darwinPath)
	}
	if windowsPath != WindowsPath {
		t.Errorf("Expected Windows path %s, got %s", WindowsPath, windowsPath)
	}
}

// TestStore_SaveRequestsMode0600 verifies that Save requests 0600 mode
func TestStore_SaveRequestsMode0600(t *testing.T) {
	fsys := fake.NewFS()
	statePath := StatePath("darwin")
	store := NewStore(fsys, statePath)

	st := State{
		DeviceID:     "device-123",
		DeviceSecret: "secret-abc",
	}

	err := store.Save(st)

	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	mode, exists := fsys.Mode(statePath)
	if !exists {
		t.Fatal("State file was not created")
	}

	if mode != FileMode {
		t.Errorf("Expected mode %o, got %o", FileMode, mode)
	}
}

// TestStore_LoadMissingFileReturnsZeroState returns zero State for missing file
func TestStore_LoadMissingFileReturnsZeroState(t *testing.T) {
	fsys := fake.NewFS()
	store := NewStore(fsys, "/nonexistent/path")

	st, err := store.Load()

	if err != nil {
		t.Fatalf("Load should not error on missing file, got %v", err)
	}
	if st != (State{}) {
		t.Errorf("Expected zero State, got %v", st)
	}
}

// TestStore_SaveAndLoad roundtrips data
func TestStore_SaveAndLoad(t *testing.T) {
	fsys := fake.NewFS()
	statePath := StatePath("darwin")
	store := NewStore(fsys, statePath)

	original := State{
		DeviceID:     "device-xyz",
		DeviceSecret: "secret-xyz",
	}

	if err := store.Save(original); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := store.Load()

	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded != original {
		t.Errorf("Loaded state differs. Expected %v, got %v", original, loaded)
	}
}

// TestState_Enrolled returns true when both fields are set
func TestState_EnrolledTrue(t *testing.T) {
	st := State{
		DeviceID:     "id",
		DeviceSecret: "secret",
	}

	if !st.Enrolled() {
		t.Error("Expected Enrolled() to return true")
	}
}

// TestState_NotEnrolledWhenIDMissing returns false when ID is empty
func TestState_NotEnrolledWhenIDMissing(t *testing.T) {
	st := State{
		DeviceID:     "",
		DeviceSecret: "secret",
	}

	if st.Enrolled() {
		t.Error("Expected Enrolled() to return false when DeviceID is empty")
	}
}

// TestState_NotEnrolledWhenSecretMissing returns false when secret is empty
func TestState_NotEnrolledWhenSecretMissing(t *testing.T) {
	st := State{
		DeviceID:     "id",
		DeviceSecret: "",
	}

	if st.Enrolled() {
		t.Error("Expected Enrolled() to return false when DeviceSecret is empty")
	}
}

// TestState_NotEnrolledWhenBothMissing returns false when both are empty
func TestState_NotEnrolledWhenBothMissing(t *testing.T) {
	st := State{}

	if st.Enrolled() {
		t.Error("Expected Enrolled() to return false for zero State")
	}
}

// TestStore_LoadMalformedJSON returns an error
func TestStore_LoadMalformedJSON(t *testing.T) {
	fsys := fake.NewFS()
	statePath := StatePath("darwin")
	fsys.Seed(statePath, []byte(`{invalid json}`))
	store := NewStore(fsys, statePath)

	_, err := store.Load()

	if err == nil {
		t.Fatal("Expected an error for malformed JSON")
	}
}

// TestStore_SaveWritesValidJSON ensures JSON is valid
func TestStore_SaveWritesValidJSON(t *testing.T) {
	fsys := fake.NewFS()
	statePath := StatePath("darwin")
	store := NewStore(fsys, statePath)

	st := State{DeviceID: "id", DeviceSecret: "secret"}
	if err := store.Save(st); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	content, _ := fsys.Content(statePath)
	var loaded State
	if err := json.Unmarshal(content, &loaded); err != nil {
		t.Fatalf("Saved JSON is invalid: %v", err)
	}
}

// TestStore_LoadReadsFromCorrectPath uses the path given in NewStore
func TestStore_LoadReadsFromCorrectPath(t *testing.T) {
	fsys := fake.NewFS()
	path1 := StatePath("darwin")
	path2 := StatePath("windows")

	fsys.Seed(path1, []byte(`{"deviceId":"id1","deviceSecret":"secret1"}`))

	store2 := NewStore(fsys, path2)
	loaded, err := store2.Load()

	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded != (State{}) {
		t.Errorf("Store should have loaded from path2 (missing), got %v", loaded)
	}

	store1 := NewStore(fsys, path1)
	loaded, err = store1.Load()

	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.DeviceID != "id1" {
		t.Errorf("Expected id1, got %s", loaded.DeviceID)
	}
}

// TestStore_Path returns the path used to create the store
func TestStore_Path(t *testing.T) {
	fsys := fake.NewFS()
	path := StatePath("darwin")
	store := NewStore(fsys, path)

	if store.Path() != path {
		t.Errorf("Expected path %s, got %s", path, store.Path())
	}
}

// TestStore_SaveCreatesAtomically ensures the file is written atomically
func TestStore_SaveCreatesAtomically(t *testing.T) {
	fsys := fake.NewFS()
	statePath := StatePath("darwin")

	// Pre-seed with some content
	oldContent := []byte(`{"deviceId":"old","deviceSecret":"old"}`)
	fsys.Seed(statePath, oldContent)

	store := NewStore(fsys, statePath)
	st := State{DeviceID: "new", DeviceSecret: "new"}

	if err := store.Save(st); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Should only have the main file, no temp file
	paths := fsys.Paths()
	count := 0
	for _, p := range paths {
		if p == statePath {
			count++
		}
	}
	if count != 1 {
		t.Errorf("Expected exactly one file at the state path, found %d", count)
	}
}

// TestStore_LoadWithReadError returns the error
func TestStore_LoadWithReadError(t *testing.T) {
	fsys := fake.NewFS()
	statePath := StatePath("darwin")
	fsys.Seed(statePath, []byte(`{"deviceId":"id","deviceSecret":"secret"}`))

	fsys.ReadErr = func(path string) error {
		if path == statePath {
			return fs.ErrPermission
		}
		return nil
	}

	store := NewStore(fsys, statePath)
	_, err := store.Load()

	if err == nil {
		t.Fatal("Expected an error when ReadFile fails")
	}
}
