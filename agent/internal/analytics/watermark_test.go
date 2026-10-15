package analytics_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/analytics"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// TestScenario_WatermarkStoreRoundTripAndPaths tests watermark store round-trip.
func TestScenario_WatermarkStoreRoundTripAndPaths(t *testing.T) {
	// Given an empty fake filesystem
	fsys := fake.NewFS()

	path := "/test/analytics.json"
	store := analytics.NewWatermarkStore(fsys, path)

	// Then Load returns the zero time and no error
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if !loaded.IsZero() {
		t.Errorf("Expected zero time, got %v", loaded)
	}

	// When Save is called with a specific time
	toSave := time.Date(2026, 10, 2, 6, 58, 12, 250000000, time.UTC)
	err = store.Save(toSave)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Then the file holds the expected JSON with mode 0600
	content, ok := fsys.Content(path)
	if !ok {
		t.Fatal("File was not created")
	}

	var wf map[string]string
	err = json.Unmarshal(content, &wf)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	expectedTimestamp := "2026-10-02T06:58:12.25Z"
	if wf["crashesReportedThrough"] != expectedTimestamp {
		t.Errorf("Expected %s, got %s", expectedTimestamp, wf["crashesReportedThrough"])
	}

	mode, ok := fsys.Mode(path)
	if !ok {
		t.Fatal("Mode not found")
	}
	if mode != 0o600 {
		t.Errorf("Expected mode 0600, got %o", mode)
	}

	// And Load returns that time
	loaded, err = store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded != toSave {
		t.Errorf("Expected %v, got %v", toSave, loaded)
	}

	// And WatermarkPath("windows") is the Windows path
	if analytics.WatermarkPath("windows") != `C:\ProgramData\OfficeHQ\MDM\analytics.json` {
		t.Errorf("Windows path incorrect: %s", analytics.WatermarkPath("windows"))
	}

	// And WatermarkPath("darwin") is the macOS path
	if analytics.WatermarkPath("darwin") != "/Library/Application Support/OfficeHQ/MDM/analytics.json" {
		t.Errorf("Darwin path incorrect: %s", analytics.WatermarkPath("darwin"))
	}
}

// TestScenario_CorruptWatermarkFileIsAnError tests corrupt file handling.
func TestScenario_CorruptWatermarkFileIsAnError(t *testing.T) {
	// Given the watermark file holds "not json"
	fsys := fake.NewFS()
	path := "/test/analytics.json"
	fsys.Seed(path, []byte("not json"))

	store := analytics.NewWatermarkStore(fsys, path)

	// Then Load returns an error
	_, err := store.Load()
	if err == nil {
		t.Fatal("Expected error for invalid JSON, got nil")
	}
}

// TestScenario_WatermarkPathSelection tests path selection.
func TestScenario_WatermarkPathSelection(t *testing.T) {
	// Test Windows path
	winPath := analytics.WatermarkPath("windows")
	if winPath != `C:\ProgramData\OfficeHQ\MDM\analytics.json` {
		t.Errorf("Windows path should be C:\\ProgramData\\OfficeHQ\\MDM\\analytics.json, got %s", winPath)
	}

	// Test Darwin path
	darwinPath := analytics.WatermarkPath("darwin")
	if darwinPath != "/Library/Application Support/OfficeHQ/MDM/analytics.json" {
		t.Errorf("Darwin path should be /Library/Application Support/OfficeHQ/MDM/analytics.json, got %s", darwinPath)
	}

	// Test other OS (should return Darwin path)
	linuxPath := analytics.WatermarkPath("linux")
	if linuxPath != "/Library/Application Support/OfficeHQ/MDM/analytics.json" {
		t.Errorf("Linux should default to Darwin path, got %s", linuxPath)
	}
}

// TestScenario_CorruptWatermarkFileIsOverwrittenWithNow tests that a corrupt watermark is overwritten.
func TestScenario_CorruptWatermarkFileIsOverwrittenWithNow(t *testing.T) {
	// Given a real WatermarkStore over a fake FS holding corrupt JSON
	fsys := fake.NewFS()
	path := "/test/analytics.json"
	fsys.Seed(path, []byte("not json"))

	store := analytics.NewWatermarkStore(fsys, path)

	// When Load is called, it returns an error
	_, err := store.Load()
	if err == nil {
		t.Fatal("Load should return an error for invalid JSON")
	}

	// When Save is called with a specific time
	now := time.Date(2026, 10, 2, 7, 20, 0, 0, time.UTC)
	err = store.Save(now)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Then the file is overwritten with the new time
	content, ok := fsys.Content(path)
	if !ok {
		t.Fatal("File should exist after Save")
	}

	var wf map[string]string
	err = json.Unmarshal(content, &wf)
	if err != nil {
		t.Fatalf("Failed to unmarshal saved JSON: %v", err)
	}

	expectedTimestamp := "2026-10-02T07:20:00Z"
	if wf["crashesReportedThrough"] != expectedTimestamp {
		t.Errorf("Expected %s, got %s", expectedTimestamp, wf["crashesReportedThrough"])
	}
}
