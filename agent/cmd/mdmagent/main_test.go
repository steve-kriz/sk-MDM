package main

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"strings"
	"testing"

	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

// TestScenario_CLIUpdatesTheCollectionURL tests the config set-url command with HTTPS.
func TestScenario_CLIUpdatesTheCollectionURL(t *testing.T) {
	// When: I run "mdmagent config set-url https://x.example/"
	fsys := fake.NewFS()
	original := map[string]interface{}{"collectionUrl": "https://old.example/"}
	origBytes, _ := json.MarshalIndent(original, "", "  ")
	fsys.Seed(config.Path("darwin"), append(origBytes, '\n'))

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := run(fsys, "darwin", []string{"config", "set-url", "https://x.example/"}, stdout, stderr)

	// Then: the exit code is 0
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. stderr: %s", exitCode, stderr.String())
	}

	// stdout contains "collection url updated"
	if !strings.Contains(stdout.String(), "collection url updated") {
		t.Errorf("Expected 'collection url updated' in stdout, got: %s", stdout.String())
	}

	// only collectionUrl changed in the file
	content, _ := fsys.Content(config.Path("darwin"))
	var result map[string]interface{}
	json.Unmarshal(content, &result)
	if result["collectionUrl"] != "https://x.example/" {
		t.Errorf("Expected collectionUrl to be https://x.example/, got %v", result["collectionUrl"])
	}
}

// TestScenario_CLIRefusesAnInsecureURL tests the config set-url command with HTTP.
func TestScenario_CLIRefusesAnInsecureURL(t *testing.T) {
	// When: I run "mdmagent config set-url http://x.example/"
	fsys := fake.NewFS()
	original := map[string]interface{}{"collectionUrl": "https://original.example/"}
	origBytes, _ := json.MarshalIndent(original, "", "  ")
	fsys.Seed(config.Path("darwin"), append(origBytes, '\n'))

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := run(fsys, "darwin", []string{"config", "set-url", "http://x.example/"}, stdout, stderr)

	// Then: the exit code is 2
	if exitCode != 2 {
		t.Errorf("Expected exit code 2, got %d", exitCode)
	}

	// stderr contains "collection url must be an https url"
	if !strings.Contains(stderr.String(), "collection url must be an https url") {
		t.Errorf("Expected error message in stderr, got: %s", stderr.String())
	}
}

// TestScenario_ShowRedactsSecrets tests that config show redacts the token
// and never shows the device secret.
func TestScenario_ShowRedactsSecrets(t *testing.T) {
	// Given: an enrolled agent
	fsys := fake.NewFS()

	// Create config with token
	cfg := config.Config{
		CollectionURL:          "https://x.example/",
		EnrollmentToken:        "secret-token-12345",
		CheckInIntervalSeconds: 900,
		LogLevel:               "info",
	}
	cfgPath := config.Path("darwin")
	config.Save(fsys, cfgPath, cfg)

	// Create state with device secret
	st := state.State{
		DeviceID:     "device-123",
		DeviceSecret: "hmac-secret-key-xyz",
	}
	statePath := state.StatePath("darwin")
	stateStore := state.NewStore(fsys, statePath)
	stateStore.Save(st)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	// When: I run "mdmagent config show"
	exitCode := run(fsys, "darwin", []string{"config", "show"}, stdout, stderr)

	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. stderr: %s", exitCode, stderr.String())
	}

	output := stdout.String()

	// Then: the output contains "<redacted>"
	if !strings.Contains(output, "<redacted>") {
		t.Errorf("Expected '<redacted>' in output, got: %s", output)
	}

	// and does not contain the device secret
	if strings.Contains(output, "hmac-secret-key-xyz") {
		t.Errorf("Device secret should not appear in output: %s", output)
	}

	// Also verify the actual token is not in the output
	if strings.Contains(output, "secret-token-12345") {
		t.Errorf("Enrollment token should not appear in output: %s", output)
	}

	// Should contain enrollment status
	if !strings.Contains(output, "enrolled") {
		t.Errorf("Expected 'enrolled' in output: %s", output)
	}

	// Should contain device ID
	if !strings.Contains(output, "device-123") {
		t.Errorf("Expected device ID 'device-123' in output: %s", output)
	}
}

// TestScenario_ShowNotEnrolled tests config show when agent is not enrolled
func TestScenario_ShowNotEnrolled(t *testing.T) {
	fsys := fake.NewFS()

	// Create config without state (not enrolled)
	cfg := config.Config{
		CollectionURL:          "https://x.example/",
		EnrollmentToken:        "token",
		CheckInIntervalSeconds: 900,
		LogLevel:               "info",
	}
	config.Save(fsys, config.Path("darwin"), cfg)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := run(fsys, "darwin", []string{"config", "show"}, stdout, stderr)

	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. stderr: %s", exitCode, stderr.String())
	}

	output := stdout.String()

	// Should show "not enrolled"
	if !strings.Contains(output, "not enrolled") {
		t.Errorf("Expected 'not enrolled' in output: %s", output)
	}

	// Device ID should be "(none)"
	if !strings.Contains(output, "(none)") {
		t.Errorf("Expected '(none)' for device ID: %s", output)
	}
}

// TestCLI_SetURLWithConfigPath uses the -config flag
func TestCLI_SetURLWithConfigPath(t *testing.T) {
	fsys := fake.NewFS()
	customPath := "/custom/config.json"
	fsys.Seed(customPath, []byte(`{"collectionUrl": "https://old.example/"}`))

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := run(fsys, "darwin", []string{"config", "set-url", "-config", customPath, "https://new.example/"}, stdout, stderr)

	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", exitCode)
	}

	content, _ := fsys.Content(customPath)
	var result map[string]interface{}
	json.Unmarshal(content, &result)
	if result["collectionUrl"] != "https://new.example/" {
		t.Errorf("Expected URL to be updated at custom path")
	}
}

// TestCLI_ShowWithConfigPath uses the -config flag
func TestCLI_ShowWithConfigPath(t *testing.T) {
	fsys := fake.NewFS()
	customConfigPath := "/custom/config.json"
	customStatePath := "/custom/state.json"

	cfg := config.Config{
		CollectionURL:          "https://custom.example/",
		EnrollmentToken:        "token",
		CheckInIntervalSeconds: 900,
		LogLevel:               "info",
	}
	cfgData, _ := json.MarshalIndent(cfg, "", "  ")
	fsys.Seed(customConfigPath, append(cfgData, '\n'))

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := run(fsys, "darwin", []string{"config", "show", "-config", customConfigPath, "-state", customStatePath}, stdout, stderr)

	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "https://custom.example/") {
		t.Errorf("Expected custom URL in output: %s", stdout.String())
	}
}

// TestCLI_SetURLMissingArgument returns error
func TestCLI_SetURLMissingArgument(t *testing.T) {
	fsys := fake.NewFS()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := run(fsys, "darwin", []string{"config", "set-url"}, stdout, stderr)

	if exitCode == 0 {
		t.Errorf("Expected non-zero exit code for missing URL argument")
	}
}

// TestCLI_UnknownCommand returns error
func TestCLI_UnknownCommand(t *testing.T) {
	fsys := fake.NewFS()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := run(fsys, "darwin", []string{"config", "unknown"}, stdout, stderr)

	if exitCode == 0 {
		t.Errorf("Expected non-zero exit code for unknown command")
	}
}

// TestCLI_VersionFlag prints version
func TestCLI_VersionFlag(t *testing.T) {
	fsys := fake.NewFS()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := run(fsys, "darwin", []string{"-version"}, stdout, stderr)

	if exitCode != 0 {
		t.Errorf("Expected exit code 0 for -version, got %d", exitCode)
	}

	if stdout.String() == "" {
		t.Errorf("Expected version output in stdout")
	}
}

// TestCLI_ShowWithoutConfig returns error when config is missing
func TestCLI_ShowWithoutConfig(t *testing.T) {
	fsys := fake.NewFS()
	// Don't seed any config file

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := run(fsys, "darwin", []string{"config", "show"}, stdout, stderr)

	if exitCode == 0 {
		t.Errorf("Expected non-zero exit code when config is missing")
	}
}

// TestCLI_SetURLInvalidHTTPSURL returns code 2
func TestCLI_SetURLInvalidHTTPSURL(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed(config.Path("darwin"), []byte(`{"collectionUrl": "https://old.example/"}`))

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	// URL without host
	exitCode := run(fsys, "darwin", []string{"config", "set-url", "https://"}, stdout, stderr)

	if exitCode != 2 {
		t.Errorf("Expected exit code 2 for invalid URL, got %d", exitCode)
	}
}

// TestCLI_SetURLEmptyURL returns code 2
func TestCLI_SetURLEmptyURL(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed(config.Path("darwin"), []byte(`{"collectionUrl": "https://old.example/"}`))

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := run(fsys, "darwin", []string{"config", "set-url", ""}, stdout, stderr)

	if exitCode != 2 {
		t.Errorf("Expected exit code 2 for empty URL, got %d", exitCode)
	}
}

// TestCLI_DefaultPathForWindows uses Windows path when goos is windows
func TestCLI_DefaultPathForWindows(t *testing.T) {
	fsys := fake.NewFS()
	windowsPath := config.Path("windows")
	fsys.Seed(windowsPath, []byte(`{"collectionUrl": "https://old.example/"}`))

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := run(fsys, "windows", []string{"config", "set-url", "https://new.example/"}, stdout, stderr)

	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", exitCode)
	}

	// Verify the Windows path was used
	content, exists := fsys.Content(windowsPath)
	if !exists {
		t.Fatal("Config file should be updated at Windows path")
	}

	var result map[string]interface{}
	json.Unmarshal(content, &result)
	if result["collectionUrl"] != "https://new.example/" {
		t.Errorf("Windows path was not used correctly")
	}
}

// TestCLI_SetURLCreatesNewFile creates config when it doesn't exist
func TestCLI_SetURLCreatesNewFile(t *testing.T) {
	fsys := fake.NewFS()
	configPath := config.Path("darwin")

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := run(fsys, "darwin", []string{"config", "set-url", "https://fresh.example/"}, stdout, stderr)

	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", exitCode)
	}

	if !fsys.Exists(configPath) {
		t.Fatal("Config file should have been created")
	}

	content, _ := fsys.Content(configPath)
	var result map[string]interface{}
	json.Unmarshal(content, &result)
	if result["collectionUrl"] != "https://fresh.example/" {
		t.Errorf("Expected https://fresh.example/, got %v", result["collectionUrl"])
	}
}

// TestCLI_SetURLRequestsCorrectFileMode ensures 0600 is requested
func TestCLI_SetURLRequestsCorrectFileMode(t *testing.T) {
	fsys := fake.NewFS()
	configPath := config.Path("darwin")

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	run(fsys, "darwin", []string{"config", "set-url", "https://x.example/"}, stdout, stderr)

	mode, _ := fsys.Mode(configPath)
	if mode != fs.FileMode(0o600) {
		t.Errorf("Expected mode 0o600, got %o", mode)
	}
}

// TestCLI_ShowPrintsAllFields prints all required fields
func TestCLI_ShowPrintsAllFields(t *testing.T) {
	fsys := fake.NewFS()

	cfg := config.Config{
		CollectionURL:          "https://example.com/api",
		EnrollmentToken:        "token-abc",
		CheckInIntervalSeconds: 600,
		LogLevel:               "warn",
	}
	config.Save(fsys, config.Path("darwin"), cfg)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	run(fsys, "darwin", []string{"config", "show"}, stdout, stderr)

	output := stdout.String()

	// Check all fields are present
	if !strings.Contains(output, "collectionUrl") {
		t.Errorf("Missing collectionUrl field")
	}
	if !strings.Contains(output, "https://example.com/api") {
		t.Errorf("Missing collection URL value")
	}
	if !strings.Contains(output, "enrollmentToken") {
		t.Errorf("Missing enrollmentToken field")
	}
	if !strings.Contains(output, "<redacted>") {
		t.Errorf("Missing redacted token")
	}
	if !strings.Contains(output, "enrollment") {
		t.Errorf("Missing enrollment field")
	}
	if !strings.Contains(output, "deviceId") {
		t.Errorf("Missing deviceId field")
	}
	if !strings.Contains(output, "checkInIntervalSeconds") {
		t.Errorf("Missing checkInIntervalSeconds field")
	}
	if !strings.Contains(output, "600") {
		t.Errorf("Missing interval value")
	}
	if !strings.Contains(output, "logLevel") {
		t.Errorf("Missing logLevel field")
	}
	if !strings.Contains(output, "warn") {
		t.Errorf("Missing log level value")
	}
}

// TestCLI_VersionPrintsVersion tests that --version prints the version
func TestCLI_VersionPrintsVersion(t *testing.T) {
	fsys := fake.NewFS()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := run(fsys, "darwin", []string{"--version"}, stdout, stderr)

	if exitCode != 0 {
		t.Errorf("Expected exit code 0 for --version, got %d", exitCode)
	}

	output := stdout.String()
	if strings.TrimSpace(output) == "" {
		t.Error("Expected version output, got empty string")
	}
}

// TestCLI_UninstallServiceNotInstalled tests uninstall-service when service doesn't exist
func TestCLI_UninstallServiceNotInstalled(t *testing.T) {
	fsys := fake.NewFS()
	runner := fake.NewCommandRunner()
	// Simulate service doesn't exist (exit code 1060)
	runner.Results["sc.exe query OfficeHQMDMAgent"] = platform.CommandResult{ExitCode: 1060}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	// Override the newRunner function for this test
	originalNewRunner := newRunner
	defer func() { newRunner = originalNewRunner }()
	newRunner = func() platform.CommandRunner { return runner }

	exitCode := run(fsys, "windows", []string{"uninstall-service"}, stdout, stderr)

	if exitCode != 0 {
		t.Errorf("Expected exit code 0 when service not installed, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "service not installed") {
		t.Errorf("Expected 'service not installed' in output, got: %s", stdout.String())
	}
}

// TestCLI_InstallServiceOnWindows tests install-service on Windows
func TestCLI_InstallServiceOnWindows(t *testing.T) {
	fsys := fake.NewFS()
	runner := fake.NewCommandRunner()
	runner.Results["sc.exe create OfficeHQMDMAgent binPath= \"C:\\Program Files\\mdmagent.exe\" run start= auto DisplayName= OfficeHQ MDM Agent"] = platform.CommandResult{ExitCode: 0}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	// Override the newRunner function for this test
	originalNewRunner := newRunner
	defer func() { newRunner = originalNewRunner }()
	newRunner = func() platform.CommandRunner { return runner }

	// Override executablePath to return a known binary path
	originalExePath := executablePath
	defer func() { executablePath = originalExePath }()
	executablePath = func() (string, error) {
		return "C:\\Program Files\\mdmagent.exe", nil
	}

	exitCode := run(fsys, "windows", []string{"install-service"}, stdout, stderr)

	if exitCode != 0 {
		t.Errorf("Expected exit code 0 for install-service, got %d. stderr: %s", exitCode, stderr.String())
	}

	if !strings.Contains(stdout.String(), "service installed") {
		t.Errorf("Expected 'service installed' in output, got: %s", stdout.String())
	}
}

// TestCLI_InstallServiceOnDarwin tests install-service on macOS
func TestCLI_InstallServiceOnDarwin(t *testing.T) {
	fsys := fake.NewFS()
	runner := fake.NewCommandRunner()
	runner.Results["launchctl bootstrap system /Library/LaunchDaemons/au.com.officehq.mdmagent.plist"] = platform.CommandResult{ExitCode: 0}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	// Override the newRunner function for this test
	originalNewRunner := newRunner
	defer func() { newRunner = originalNewRunner }()
	newRunner = func() platform.CommandRunner { return runner }

	// Override executablePath to return a known binary path
	originalExePath := executablePath
	defer func() { executablePath = originalExePath }()
	executablePath = func() (string, error) {
		return "/usr/local/bin/mdmagent", nil
	}

	exitCode := run(fsys, "darwin", []string{"install-service"}, stdout, stderr)

	if exitCode != 0 {
		t.Errorf("Expected exit code 0 for install-service, got %d. stderr: %s", exitCode, stderr.String())
	}

	if !strings.Contains(stdout.String(), "service installed") {
		t.Errorf("Expected 'service installed' in output, got: %s", stdout.String())
	}

	// Verify plist was written
	if !fsys.Exists("/Library/LaunchDaemons/au.com.officehq.mdmagent.plist") {
		t.Error("plist file was not written")
	}
}

// TestCLI_UninstallServiceOnDarwin tests uninstall-service on macOS
func TestCLI_UninstallServiceOnDarwin(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed("/Library/LaunchDaemons/au.com.officehq.mdmagent.plist", []byte("<plist></plist>"))

	runner := fake.NewCommandRunner()
	runner.Results["launchctl bootout system/au.com.officehq.mdmagent"] = platform.CommandResult{ExitCode: 0}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	// Override the newRunner function for this test
	originalNewRunner := newRunner
	defer func() { newRunner = originalNewRunner }()
	newRunner = func() platform.CommandRunner { return runner }

	exitCode := run(fsys, "darwin", []string{"uninstall-service"}, stdout, stderr)

	if exitCode != 0 {
		t.Errorf("Expected exit code 0 for uninstall-service, got %d. stderr: %s", exitCode, stderr.String())
	}

	if !strings.Contains(stdout.String(), "service removed") {
		t.Errorf("Expected 'service removed' in output, got: %s", stdout.String())
	}

	// Verify plist was removed
	if fsys.Exists("/Library/LaunchDaemons/au.com.officehq.mdmagent.plist") {
		t.Error("plist file was not removed")
	}
}
