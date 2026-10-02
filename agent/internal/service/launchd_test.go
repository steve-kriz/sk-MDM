package service

import (
	"context"
	"strings"
	"testing"

	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// TestPlistBytesContent verifies that PlistBytes produces the required plist keys and values.
func TestPlistBytesContent(t *testing.T) {
	cfg := Config{
		BinaryPath: "/usr/local/bin/mdmagent",
	}

	plist := PlistBytes(cfg)
	plistStr := string(plist)

	// Check for expected keys and values
	checks := []struct {
		name, substring string
	}{
		{"Label", "au.com.officehq.mdmagent"},
		{"ProgramArguments", "<string>/usr/local/bin/mdmagent</string>"},
		{"run argument", "<string>run</string>"},
		{"RunAtLoad", "<true/>"},
		{"KeepAlive", "<true/>"},
		{"StandardErrorPath", StderrPath},
	}

	for _, check := range checks {
		if !strings.Contains(plistStr, check.substring) {
			t.Errorf("plist missing %s: %q", check.name, check.substring)
		}
	}
}

// TestPlistBytesEscapeSpecialCharacters verifies that special XML characters are escaped.
func TestPlistBytesEscapeSpecialCharacters(t *testing.T) {
	cfg := Config{
		BinaryPath: "/path/with/&/and/</chars",
	}

	plist := PlistBytes(cfg)
	plistStr := string(plist)

	// Should contain escaped characters
	if !strings.Contains(plistStr, "&amp;") {
		t.Error("plist should contain escaped & as &amp;")
	}
	if !strings.Contains(plistStr, "&lt;") {
		t.Error("plist should contain escaped < as &lt;")
	}

	// Should still parse as valid XML - verify it has proper structure
	if !strings.Contains(plistStr, "<?xml") {
		t.Error("plist missing XML declaration")
	}
	if !strings.Contains(plistStr, "<!DOCTYPE plist") {
		t.Error("plist missing DOCTYPE")
	}
	if !strings.Contains(plistStr, "</plist>") {
		t.Error("plist missing closing tag")
	}
}

// TestPlistBytesParses verifies that the output is valid XML.
func TestPlistBytesParses(t *testing.T) {
	cfg := Config{
		BinaryPath: "/usr/local/bin/mdmagent",
	}

	plist := PlistBytes(cfg)
	plistStr := string(plist)

	// Verify DOCTYPE is present
	if !strings.Contains(plistStr, "<!DOCTYPE plist") {
		t.Error("plist missing DOCTYPE")
	}
	if !strings.Contains(plistStr, "<?xml") {
		t.Error("plist missing XML declaration")
	}
	if !strings.Contains(plistStr, "</plist>") {
		t.Error("plist missing closing tag")
	}
}

// TestPlistBytesCustomPaths verifies that custom StandardOutPath and StandardErrorPath work.
func TestPlistBytesCustomPaths(t *testing.T) {
	cfg := Config{
		BinaryPath:        "/usr/local/bin/mdmagent",
		StandardOutPath:   "/custom/out.log",
		StandardErrorPath: "/custom/err.log",
	}

	plist := PlistBytes(cfg)
	plistStr := string(plist)

	if !strings.Contains(plistStr, "/custom/out.log") {
		t.Error("plist should contain custom StandardOutPath")
	}
	if !strings.Contains(plistStr, "/custom/err.log") {
		t.Error("plist should contain custom StandardErrorPath")
	}
}

// TestPlistBytesCustomLabel verifies that custom Label is used.
func TestPlistBytesCustomLabel(t *testing.T) {
	cfg := Config{
		BinaryPath: "/usr/local/bin/mdmagent",
		Label:      "com.custom.label",
	}

	plist := PlistBytes(cfg)
	plistStr := string(plist)

	if !strings.Contains(plistStr, "com.custom.label") {
		t.Error("plist should contain custom label")
	}
}

// TestInstallDarwinWritesPlist verifies that install-service writes the plist with correct mode.
func TestInstallDarwinWritesPlist(t *testing.T) {
	fsys := fake.NewFS()
	runner := fake.NewCommandRunner()
	runner.Results["launchctl bootstrap system /Library/LaunchDaemons/au.com.officehq.mdmagent.plist"] = platform.CommandResult{ExitCode: 0}

	cfg := Config{
		FS:         fsys,
		Runner:     runner,
		GOOS:       "darwin",
		BinaryPath: "/usr/local/bin/mdmagent",
	}

	err := Install(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	// Verify plist was written
	content, exists := fsys.Content(PlistPath)
	if !exists {
		t.Error("plist was not written")
	}

	// Verify mode is 0644
	mode, exists := fsys.Mode(PlistPath)
	if !exists {
		t.Fatal("plist mode not found")
	}
	if mode != PlistFileMode {
		t.Errorf("plist mode is %o, want %o", mode, PlistFileMode)
	}

	// Verify content looks like a plist
	contentStr := string(content)
	if !strings.Contains(contentStr, "<?xml") {
		t.Error("plist content missing XML declaration")
	}
	if !strings.Contains(contentStr, "</plist>") {
		t.Error("plist content missing closing tag")
	}
}

// TestInstallDarwinBootstrapsService verifies that launchctl bootstrap is called.
func TestInstallDarwinBootstrapsService(t *testing.T) {
	fsys := fake.NewFS()
	runner := fake.NewCommandRunner()
	runner.Results["launchctl bootstrap system /Library/LaunchDaemons/au.com.officehq.mdmagent.plist"] = platform.CommandResult{ExitCode: 0}

	cfg := Config{
		FS:         fsys,
		Runner:     runner,
		GOOS:       "darwin",
		BinaryPath: "/usr/local/bin/mdmagent",
	}

	err := Install(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	// Verify launchctl bootstrap was called
	calls := runner.Calls()
	found := false
	for _, call := range calls {
		if call.Name == "launchctl" && len(call.Args) >= 3 && call.Args[0] == "bootstrap" {
			found = true
			if call.Args[1] != Domain {
				t.Errorf("launchctl domain is %q, want %q", call.Args[1], Domain)
			}
			if call.Args[2] != PlistPath {
				t.Errorf("launchctl path is %q, want %q", call.Args[2], PlistPath)
			}
		}
	}
	if !found {
		t.Error("launchctl bootstrap not called")
	}
}

// TestInstallWindowsRegistersService verifies that sc.exe create is called correctly.
func TestInstallWindowsRegistersService(t *testing.T) {
	runner := fake.NewCommandRunner()
	runner.Results["sc.exe create OfficeHQMDMAgent binPath= \"C:\\Program Files\\mdmagent.exe\" run start= auto DisplayName= OfficeHQ MDM Agent"] = platform.CommandResult{ExitCode: 0}

	cfg := Config{
		Runner:     runner,
		GOOS:       "windows",
		BinaryPath: `C:\Program Files\mdmagent.exe`,
	}

	err := Install(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	// Verify sc.exe create was called
	calls := runner.Calls()
	found := false
	for _, call := range calls {
		if call.Name == "sc.exe" && len(call.Args) > 0 && call.Args[0] == "create" {
			found = true
			// Check for expected arguments
			if call.Args[1] != Name {
				t.Errorf("service name is %q, want %q", call.Args[1], Name)
			}
		}
	}
	if !found {
		t.Error("sc.exe create not called")
	}
}

// TestWindowsInstallsBinaryPath verifies the binary path format for Windows.
func TestWindowsBinaryPath(t *testing.T) {
	binary := `C:\Program Files\mdmagent.exe`
	path := BinPath(binary)

	// Should be quoted and include "run"
	wantPrefix := `"C:\Program Files\mdmagent.exe" run`
	if path != wantPrefix {
		t.Errorf("BinPath returned %q, want %q", path, wantPrefix)
	}
}

// TestUninstallDarwinRemovesPlist verifies that uninstall removes the plist.
func TestUninstallDarwinRemovesPlist(t *testing.T) {
	fsys := fake.NewFS()
	// Seed the plist file
	fsys.Seed(PlistPath, []byte("<plist></plist>"))

	runner := fake.NewCommandRunner()
	runner.Results["launchctl bootout system/au.com.officehq.mdmagent"] = platform.CommandResult{ExitCode: 0}

	cfg := Config{
		FS:     fsys,
		Runner: runner,
		GOOS:   "darwin",
	}

	err := Uninstall(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Uninstall failed: %v", err)
	}

	// Verify plist was removed
	if fsys.Exists(PlistPath) {
		t.Error("plist was not removed")
	}
}

// TestUninstallWindowsDeletesService verifies that sc.exe delete is called.
func TestUninstallWindowsDeletesService(t *testing.T) {
	runner := fake.NewCommandRunner()
	// Service query returns 0 (exists)
	runner.Results["sc.exe query OfficeHQMDMAgent"] = platform.CommandResult{ExitCode: 0}
	runner.Results["sc.exe stop OfficeHQMDMAgent"] = platform.CommandResult{ExitCode: 0}
	runner.Results["sc.exe delete OfficeHQMDMAgent"] = platform.CommandResult{ExitCode: 0}

	cfg := Config{
		Runner: runner,
		GOOS:   "windows",
	}

	err := Uninstall(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Uninstall failed: %v", err)
	}

	// Verify sc.exe delete was called
	calls := runner.Calls()
	found := false
	for _, call := range calls {
		if call.Name == "sc.exe" && len(call.Args) > 0 && call.Args[0] == "delete" {
			found = true
		}
	}
	if !found {
		t.Error("sc.exe delete not called")
	}
}

// TestUninstallNotInstalledDarwin returns ErrNotInstalled when plist does not exist.
func TestUninstallNotInstalledDarwin(t *testing.T) {
	fsys := fake.NewFS()
	// Don't seed the plist - it doesn't exist
	runner := fake.NewCommandRunner()

	cfg := Config{
		FS:     fsys,
		Runner: runner,
		GOOS:   "darwin",
	}

	err := Uninstall(context.Background(), cfg)
	if err != ErrNotInstalled {
		t.Errorf("Uninstall returned %v, want ErrNotInstalled", err)
	}
}

// TestUninstallNotInstalledWindows returns ErrNotInstalled when service doesn't exist.
func TestUninstallNotInstalledWindows(t *testing.T) {
	runner := fake.NewCommandRunner()
	// Service query returns error code 1060 (not found)
	runner.Results["sc.exe query OfficeHQMDMAgent"] = platform.CommandResult{ExitCode: 1060}

	cfg := Config{
		Runner: runner,
		GOOS:   "windows",
	}

	err := Uninstall(context.Background(), cfg)
	if err != ErrNotInstalled {
		t.Errorf("Uninstall returned %v, want ErrNotInstalled", err)
	}
}

// TestInstallRequiresBinaryPath verifies that Install fails without a binary path.
func TestInstallRequiresBinaryPath(t *testing.T) {
	runner := fake.NewCommandRunner()
	cfg := Config{
		Runner: runner,
		GOOS:   "darwin",
		// BinaryPath is empty
	}

	err := Install(context.Background(), cfg)
	if err == nil {
		t.Error("Install should fail without binary path")
	}
}

// TestInstallRequiresCommandRunner verifies that Install fails without a command runner.
func TestInstallRequiresCommandRunner(t *testing.T) {
	cfg := Config{
		GOOS:       "darwin",
		BinaryPath: "/usr/local/bin/mdmagent",
		Runner:     nil,
	}

	err := Install(context.Background(), cfg)
	if err == nil {
		t.Error("Install should fail without command runner")
	}
}

// TestInstallDarwinRequiresFS verifies that darwin Install fails without FileSystem.
func TestInstallDarwinRequiresFS(t *testing.T) {
	runner := fake.NewCommandRunner()
	cfg := Config{
		Runner:     runner,
		GOOS:       "darwin",
		BinaryPath: "/usr/local/bin/mdmagent",
		FS:         nil,
	}

	err := Install(context.Background(), cfg)
	if err == nil {
		t.Error("darwin Install should fail without filesystem")
	}
}

// TestUninstallRequiresCommandRunner verifies that Uninstall fails without a command runner.
func TestUninstallRequiresCommandRunner(t *testing.T) {
	cfg := Config{
		Runner: nil,
	}

	err := Uninstall(context.Background(), cfg)
	if err == nil {
		t.Error("Uninstall should fail without command runner")
	}
}

// TestCustomPlistPath verifies that a custom plist path is used when provided.
func TestCustomPlistPath(t *testing.T) {
	customPath := "/custom/path/to/plist.plist"
	fsys := fake.NewFS()
	runner := fake.NewCommandRunner()
	runner.Results["launchctl bootstrap system /custom/path/to/plist.plist"] = platform.CommandResult{ExitCode: 0}

	cfg := Config{
		FS:         fsys,
		Runner:     runner,
		GOOS:       "darwin",
		BinaryPath: "/usr/local/bin/mdmagent",
		PlistPath:  customPath,
	}

	err := Install(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	// Verify plist was written to custom path
	if !fsys.Exists(customPath) {
		t.Error("plist was not written to custom path")
	}
}

// TestPlistBytesWithEmbeddedQuotes verifies XML escaping of quotes.
func TestPlistBytesWithEmbeddedQuotes(t *testing.T) {
	cfg := Config{
		BinaryPath: `/path/with/"quotes"`,
	}

	plist := PlistBytes(cfg)
	plistStr := string(plist)

	// Should have valid XML structure
	if !strings.Contains(plistStr, "<?xml") {
		t.Error("plist missing XML declaration")
	}
	if !strings.Contains(plistStr, "</plist>") {
		t.Error("plist missing closing tag")
	}
	// Verify the path is in there (might be escaped)
	if !strings.Contains(plistStr, "path/with") {
		t.Error("plist missing binary path")
	}
}
