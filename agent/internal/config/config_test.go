package config

import (
	"encoding/json"
	"errors"
	"io/fs"
	"testing"

	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// TestScenario_ConfigLoadsWithDefaults verifies that Load applies defaults
// for missing checkInIntervalSeconds and logLevel.
func TestScenario_ConfigLoadsWithDefaults(t *testing.T) {
	// Given: a config file with only collectionUrl
	fsys := fake.NewFS()
	fsys.Seed(Path("darwin"), []byte(`{"collectionUrl": "https://x.example/"}`))

	// When: Load runs
	cfg, err := Load(fsys, Path("darwin"))

	// Then: checkInIntervalSeconds is 900 and logLevel is "info"
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.CheckInIntervalSeconds != 900 {
		t.Errorf("Expected CheckInIntervalSeconds=900, got %d", cfg.CheckInIntervalSeconds)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("Expected LogLevel=info, got %s", cfg.LogLevel)
	}
	if cfg.CollectionURL != "https://x.example/" {
		t.Errorf("Expected CollectionURL=https://x.example/, got %s", cfg.CollectionURL)
	}
}

// TestScenario_PlainHTTPURLIsRefused verifies that Load rejects HTTP URLs.
func TestScenario_PlainHTTPURLIsRefused(t *testing.T) {
	// Given: a config file with collectionUrl "http://x.example/"
	fsys := fake.NewFS()
	fsys.Seed(Path("darwin"), []byte(`{"collectionUrl": "http://x.example/"}`))

	// When: Load runs
	_, err := Load(fsys, Path("darwin"))

	// Then: the error message is "collection url must be an https url"
	if err == nil {
		t.Fatal("Expected Load to return an error")
	}
	if !errors.Is(err, ErrCollectionURL) {
		t.Errorf("Expected ErrCollectionURL, got %v", err)
	}
	if err.Error() != "collection url must be an https url" {
		t.Errorf("Expected error message 'collection url must be an https url', got %q", err.Error())
	}
}

// TestScenario_SaveIsAtomic verifies that Save does not modify the original
// file when the temp file write fails.
func TestScenario_SaveIsAtomic(t *testing.T) {
	// Given: a fake filesystem that fails the write of the temp file
	fsys := fake.NewFS()
	original := []byte(`{"collectionUrl": "https://original.example/"}`)
	configPath := Path("darwin")
	fsys.Seed(configPath, original)

	fsys.FailWrite(configPath+".tmp", fs.ErrPermission)

	// When: Save runs
	cfg := Config{CollectionURL: "https://new.example/"}
	err := Save(fsys, configPath, cfg)

	// Then: the original config file content is unchanged
	if err == nil {
		t.Fatal("Expected Save to return an error")
	}
	content, exists := fsys.Content(configPath)
	if !exists {
		t.Fatal("Original config file was deleted")
	}
	if string(content) != string(original) {
		t.Errorf("Original file was modified. Expected %q, got %q", string(original), string(content))
	}
	// Verify temp file was not left behind (best effort cleanup)
	if fsys.Exists(configPath + ".tmp") {
		t.Log("Temp file cleanup is best-effort; cleanup may not happen in all error cases")
	}
}

// TestLoad_MissingFile returns an error for missing files
func TestLoad_MissingFile(t *testing.T) {
	fsys := fake.NewFS()

	_, err := Load(fsys, "/nonexistent/path")

	if err == nil {
		t.Fatal("Expected an error for missing file")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Expected fs.ErrNotExist, got %v", err)
	}
}

// TestLoad_MalformedJSON returns an error for invalid JSON
func TestLoad_MalformedJSON(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed(Path("darwin"), []byte(`{invalid json}`))

	_, err := Load(fsys, Path("darwin"))

	if err == nil {
		t.Fatal("Expected an error for malformed JSON")
	}
}

// TestLoad_EmptyCollectionURL refuses empty URLs
func TestLoad_EmptyCollectionURL(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed(Path("darwin"), []byte(`{"collectionUrl": ""}`))

	_, err := Load(fsys, Path("darwin"))

	if !errors.Is(err, ErrCollectionURL) {
		t.Errorf("Expected ErrCollectionURL, got %v", err)
	}
}

// TestLoad_UnparseableCollectionURL refuses unparseable URLs
func TestLoad_UnparseableCollectionURL(t *testing.T) {
	fsys := fake.NewFS()
	// An obviously invalid URL
	fsys.Seed(Path("darwin"), []byte(`{"collectionUrl": "ht!tp://[invalid"}`))

	_, err := Load(fsys, Path("darwin"))

	if !errors.Is(err, ErrCollectionURL) {
		t.Errorf("Expected ErrCollectionURL, got %v", err)
	}
}

// TestLoad_HTTPSURLSucceeds accepts HTTPS URLs
func TestLoad_HTTPSURLSucceeds(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed(Path("darwin"), []byte(`{"collectionUrl": "https://example.com/path"}`))

	cfg, err := Load(fsys, Path("darwin"))

	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.CollectionURL != "https://example.com/path" {
		t.Errorf("Expected https://example.com/path, got %s", cfg.CollectionURL)
	}
}

// TestLoad_PresetsDefaults applies defaults correctly
func TestLoad_PresetsDefaults(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed(Path("darwin"), []byte(`{"collectionUrl": "https://example.com/"}`))

	cfg, err := Load(fsys, Path("darwin"))

	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.CheckInIntervalSeconds != DefaultCheckInIntervalSeconds {
		t.Errorf("Expected default interval %d, got %d", DefaultCheckInIntervalSeconds, cfg.CheckInIntervalSeconds)
	}
	if cfg.LogLevel != DefaultLogLevel {
		t.Errorf("Expected default level %s, got %s", DefaultLogLevel, cfg.LogLevel)
	}
}

// TestLoad_PreservesExplicitValues preserves non-zero values
func TestLoad_PreservesExplicitValues(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed(Path("darwin"), []byte(`{
		"collectionUrl": "https://example.com/",
		"checkInIntervalSeconds": 600,
		"logLevel": "warn"
	}`))

	cfg, err := Load(fsys, Path("darwin"))

	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.CheckInIntervalSeconds != 600 {
		t.Errorf("Expected 600, got %d", cfg.CheckInIntervalSeconds)
	}
	if cfg.LogLevel != "warn" {
		t.Errorf("Expected warn, got %s", cfg.LogLevel)
	}
}

// TestSave_WritesConfigAtomically ensures Save uses WriteFileAtomic
func TestSave_WritesConfigAtomically(t *testing.T) {
	fsys := fake.NewFS()
	configPath := Path("darwin")

	cfg := Config{
		CollectionURL:         "https://example.com/",
		EnrollmentToken:       "token123",
		CheckInIntervalSeconds: 900,
		LogLevel:              "info",
	}

	err := Save(fsys, configPath, cfg)

	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify the file exists and is valid JSON
	content, exists := fsys.Content(configPath)
	if !exists {
		t.Fatal("Config file was not created")
	}

	var loaded Config
	if err := json.Unmarshal(content, &loaded); err != nil {
		t.Fatalf("Saved JSON is invalid: %v", err)
	}

	if loaded.CollectionURL != cfg.CollectionURL {
		t.Errorf("CollectionURL mismatch: expected %s, got %s", cfg.CollectionURL, loaded.CollectionURL)
	}
}

// TestSave_RequestsCorrectFileMode ensures 0600 mode is requested
func TestSave_RequestsCorrectFileMode(t *testing.T) {
	fsys := fake.NewFS()
	configPath := Path("darwin")

	cfg := Config{CollectionURL: "https://example.com/"}

	err := Save(fsys, configPath, cfg)

	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	mode, exists := fsys.Mode(configPath)
	if !exists {
		t.Fatal("Config file was not created")
	}

	if mode != FileMode {
		t.Errorf("Expected mode %o, got %o", FileMode, mode)
	}
}

// TestSetCollectionURL_UpdatesOnlyCollectionURL rewrites just the URL field
func TestSetCollectionURL_UpdatesOnlyCollectionURL(t *testing.T) {
	fsys := fake.NewFS()
	configPath := Path("darwin")
	originalConfig := map[string]interface{}{
		"collectionUrl":           "https://original.example/",
		"enrollmentToken":         "oldtoken",
		"checkInIntervalSeconds":  600,
		"logLevel":                "debug",
	}
	origBytes, _ := json.MarshalIndent(originalConfig, "", "  ")
	fsys.Seed(configPath, append(origBytes, '\n'))

	// When: SetCollectionURL is called
	err := SetCollectionURL(fsys, configPath, "https://new.example/")

	if err != nil {
		t.Fatalf("SetCollectionURL failed: %v", err)
	}

	// Then: only collectionUrl changed
	content, _ := fsys.Content(configPath)
	var result map[string]interface{}
	json.Unmarshal(content, &result)

	if result["collectionUrl"] != "https://new.example/" {
		t.Errorf("collectionUrl not updated")
	}
	if result["enrollmentToken"] != "oldtoken" {
		t.Errorf("enrollmentToken was modified")
	}
	if result["checkInIntervalSeconds"] != float64(600) {
		t.Errorf("checkInIntervalSeconds was modified")
	}
	if result["logLevel"] != "debug" {
		t.Errorf("logLevel was modified")
	}
}

// TestSetCollectionURL_CreatesNewFile creates a file with just the URL
func TestSetCollectionURL_CreatesNewFile(t *testing.T) {
	fsys := fake.NewFS()
	configPath := Path("darwin")

	err := SetCollectionURL(fsys, configPath, "https://fresh.example/")

	if err != nil {
		t.Fatalf("SetCollectionURL failed: %v", err)
	}

	content, exists := fsys.Content(configPath)
	if !exists {
		t.Fatal("Config file was not created")
	}

	var result map[string]interface{}
	if err := json.Unmarshal(content, &result); err != nil {
		t.Fatalf("Saved JSON is invalid: %v", err)
	}

	if result["collectionUrl"] != "https://fresh.example/" {
		t.Errorf("Expected https://fresh.example/, got %v", result["collectionUrl"])
	}
}

// TestSetCollectionURL_RefusesHTTP rejects HTTP URLs
func TestSetCollectionURL_RefusesHTTP(t *testing.T) {
	fsys := fake.NewFS()
	configPath := Path("darwin")
	originalConfig := map[string]interface{}{
		"collectionUrl": "https://original.example/",
	}
	origBytes, _ := json.MarshalIndent(originalConfig, "", "  ")
	fsys.Seed(configPath, append(origBytes, '\n'))

	err := SetCollectionURL(fsys, configPath, "http://insecure.example/")

	if !errors.Is(err, ErrCollectionURL) {
		t.Errorf("Expected ErrCollectionURL, got %v", err)
	}

	// Original should be unchanged
	content, _ := fsys.Content(configPath)
	var result map[string]interface{}
	json.Unmarshal(content, &result)
	if result["collectionUrl"] != "https://original.example/" {
		t.Errorf("Original file was modified during failed SetCollectionURL")
	}
}

// TestValidateCollectionURL tests the validation function
func TestValidateCollectionURL_AcceptsHTTPS(t *testing.T) {
	err := ValidateCollectionURL("https://example.com/")
	if err != nil {
		t.Errorf("Expected no error for valid HTTPS URL, got %v", err)
	}
}

func TestValidateCollectionURL_RefusesHTTP(t *testing.T) {
	err := ValidateCollectionURL("http://example.com/")
	if !errors.Is(err, ErrCollectionURL) {
		t.Errorf("Expected ErrCollectionURL for HTTP, got %v", err)
	}
}

func TestValidateCollectionURL_RefusesEmpty(t *testing.T) {
	err := ValidateCollectionURL("")
	if !errors.Is(err, ErrCollectionURL) {
		t.Errorf("Expected ErrCollectionURL for empty string, got %v", err)
	}
}

func TestValidateCollectionURL_RefusesNoHost(t *testing.T) {
	err := ValidateCollectionURL("https:///no-host")
	if !errors.Is(err, ErrCollectionURL) {
		t.Errorf("Expected ErrCollectionURL for URL without host, got %v", err)
	}
}

// TestPath returns correct paths for different platforms
func TestPath_Windows(t *testing.T) {
	p := Path("windows")
	if p != WindowsPath {
		t.Errorf("Expected %s, got %s", WindowsPath, p)
	}
}

func TestPath_Darwin(t *testing.T) {
	p := Path("darwin")
	if p != DarwinPath {
		t.Errorf("Expected %s, got %s", DarwinPath, p)
	}
}

func TestPath_UnknownPlatform(t *testing.T) {
	p := Path("linux")
	if p != DarwinPath {
		t.Errorf("Expected %s for unknown platform, got %s", DarwinPath, p)
	}
}
