package enforce

import (
	"context"
	"errors"
	"testing"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// TestUnit_DomainsNameIsDomains verifies that the domains enforcer's name is "domains".
func TestUnit_DomainsNameIsDomains(t *testing.T) {
	// Given: a domains enforcer
	d := &Domains{}

	// When: Name is called
	name := d.Name()

	// Then: it returns "domains"
	if name != "domains" {
		t.Errorf("Expected name 'domains', got %q", name)
	}
}

// TestUnit_BlockedNamesIncludesValidEntries verifies that BlockedNames includes valid blocked entries.
func TestUnit_BlockedNamesIncludesValidEntries(t *testing.T) {
	// Given: a domains enforcer with valid blocked entries
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	d := &Domains{Runner: runner, FS: fsys, GOOS: "windows", Logger: nil}
	effective := map[string]any{SettingFirewallBlockedDomains: []any{"example.com", "test.org"}}

	// When: BlockedNames is called
	names := d.BlockedNames(effective)

	// Then: the blocked names include the entries and their www variants, lowercased and sorted
	expected := []string{"example.com", "test.org", "www.example.com", "www.test.org"}
	if len(names) != len(expected) {
		t.Errorf("Expected %d names, got %d: %v", len(expected), len(names), names)
	}
	for i, exp := range expected {
		if i < len(names) && names[i] != exp {
			t.Errorf("Name %d: expected %q, got %q", i, exp, names[i])
		}
	}
}

// TestUnit_BlockedNamesLowercasesEntries verifies that BlockedNames lowercases entries.
func TestUnit_BlockedNamesLowercasesEntries(t *testing.T) {
	// Given: a domains enforcer with mixed-case entries
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	d := &Domains{Runner: runner, FS: fsys, GOOS: "windows", Logger: nil}
	effective := map[string]any{SettingFirewallBlockedDomains: []any{"Example.COM"}}

	// When: BlockedNames is called
	names := d.BlockedNames(effective)

	// Then: the names are lowercased
	if len(names) > 0 && names[0] != "example.com" {
		t.Errorf("Expected first name 'example.com', got %q", names[0])
	}
}

// TestUnit_BlockedNamesAddsWwwVariants verifies that BlockedNames adds www. variants.
func TestUnit_BlockedNamesAddsWwwVariants(t *testing.T) {
	// Given: a domains enforcer with an entry that doesn't start with www.
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	d := &Domains{Runner: runner, FS: fsys, GOOS: "windows", Logger: nil}
	effective := map[string]any{SettingFirewallBlockedDomains: []any{"example.com"}}

	// When: BlockedNames is called
	names := d.BlockedNames(effective)

	// Then: www.example.com is in the result
	found := false
	for _, name := range names {
		if name == "www.example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected www.example.com in result, got %v", names)
	}
}

// TestUnit_BlockedNamesDoesNotDuplicateWww verifies that BlockedNames doesn't add www. variant for entries already starting with www.
func TestUnit_BlockedNamesDoesNotDuplicateWww(t *testing.T) {
	// Given: a domains enforcer with www.example.com
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	d := &Domains{Runner: runner, FS: fsys, GOOS: "windows", Logger: nil}
	effective := map[string]any{SettingFirewallBlockedDomains: []any{"www.example.com"}}

	// When: BlockedNames is called
	names := d.BlockedNames(effective)

	// Then: www.example.com appears only once
	count := 0
	for _, name := range names {
		if name == "www.example.com" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("Expected www.example.com to appear once, got %d times in %v", count, names)
	}
}

// TestUnit_BlockedNamesRemovesAllowedEntries verifies that BlockedNames removes allowed entries.
func TestUnit_BlockedNamesRemovesAllowedEntries(t *testing.T) {
	// Given: a domains enforcer with blocked and allowed entries
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	d := &Domains{Runner: runner, FS: fsys, GOOS: "windows", Logger: nil}
	effective := map[string]any{
		SettingFirewallBlockedDomains: []any{"example.com", "allowed.com"},
		SettingFirewallAllowedDomains: []any{"allowed.com"},
	}

	// When: BlockedNames is called
	names := d.BlockedNames(effective)

	// Then: allowed.com is not in the result
	for _, name := range names {
		if name == "allowed.com" {
			t.Errorf("Expected allowed.com to be removed, but found it in %v", names)
		}
	}
}

// TestUnit_BlockedNamesRemovesWwwVariantsOfAllowed verifies that BlockedNames removes www variants of allowed entries.
func TestUnit_BlockedNamesRemovesWwwVariantsOfAllowed(t *testing.T) {
	// Given: a domains enforcer with example.com blocked and www.example.com allowed
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	d := &Domains{Runner: runner, FS: fsys, GOOS: "windows", Logger: nil}
	effective := map[string]any{
		SettingFirewallBlockedDomains: []any{"example.com"},
		SettingFirewallAllowedDomains: []any{"www.example.com"},
	}

	// When: BlockedNames is called
	names := d.BlockedNames(effective)

	// Then: www.example.com is not in the result
	for _, name := range names {
		if name == "www.example.com" {
			t.Errorf("Expected www.example.com to be removed by allow rule, but found it in %v", names)
		}
	}
}

// TestUnit_BlockedNamesSkipsInvalidEntries verifies that BlockedNames skips invalid entries.
func TestUnit_BlockedNamesSkipsInvalidEntries(t *testing.T) {
	// Given: a domains enforcer with invalid entries
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	d := &Domains{Runner: runner, FS: fsys, GOOS: "windows", Logger: nil}
	effective := map[string]any{
		SettingFirewallBlockedDomains: []any{"example.com", "localhost", "http://bad.com"},
	}

	// When: BlockedNames is called
	names := d.BlockedNames(effective)

	// Then: only example.com and www.example.com are in the result
	if len(names) != 2 {
		t.Errorf("Expected 2 names, got %d: %v", len(names), names)
	}
	found := false
	for _, name := range names {
		if name == "example.com" || name == "www.example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected example.com in result")
	}
}

// TestUnit_BlockedNamesHandlesNonListValue verifies that BlockedNames treats non-list values as absent.
func TestUnit_BlockedNamesHandlesNonListValue(t *testing.T) {
	// Given: a domains enforcer with a non-list firewallBlockedDomains value
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	d := &Domains{Runner: runner, FS: fsys, GOOS: "windows", Logger: nil}
	effective := map[string]any{SettingFirewallBlockedDomains: "example.com"}

	// When: BlockedNames is called
	names := d.BlockedNames(effective)

	// Then: the result is empty
	if len(names) != 0 {
		t.Errorf("Expected 0 names for non-list value, got %d: %v", len(names), names)
	}
}

// TestUnit_ApplyWritesHostsFileWhenBlockedNamesArePresent verifies that Apply
// writes the hosts file when there are blocked names.
func TestUnit_ApplyWritesHostsFileWhenBlockedNamesArePresent(t *testing.T) {
	// Given: a domains enforcer with blocked names and an empty hosts file
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	d := &Domains{Runner: runner, FS: fsys, GOOS: "windows", Logger: nil}
	effective := map[string]any{SettingFirewallBlockedDomains: []any{"a.com"}}

	// When: Apply is called
	ctx := context.Background()
	err := d.Apply(ctx, effective, contract.Posture{})

	// Then: no error and the hosts file was written
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	content, exists := fsys.Content(WindowsHostsPath)
	if !exists {
		t.Errorf("Expected hosts file to be written")
	}
	if !contains(string(content), "a.com") {
		t.Errorf("Expected hosts file to contain a.com")
	}
}

// TestUnit_ApplyRemovesBlockWhenNamesAreEmpty verifies that Apply removes the
// managed block when there are no blocked names.
func TestUnit_ApplyRemovesBlockWhenNamesAreEmpty(t *testing.T) {
	// Given: a domains enforcer with no blocked names but an existing managed block
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	hostsContent := "127.0.0.1 localhost\r\n# BEGIN sk-mdm managed block - do not edit\r\n0.0.0.0 a.com\r\n# END sk-mdm managed block\r\n"
	fsys.Seed(WindowsHostsPath, []byte(hostsContent))
	d := &Domains{Runner: runner, FS: fsys, GOOS: "windows", Logger: nil}
	effective := map[string]any{}

	// When: Apply is called
	ctx := context.Background()
	err := d.Apply(ctx, effective, contract.Posture{})

	// Then: no error and the managed block is removed but localhost line remains
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	content, _ := fsys.Content(WindowsHostsPath)
	if !contains(string(content), "127.0.0.1 localhost") {
		t.Errorf("Expected localhost line to be preserved")
	}
	if contains(string(content), "0.0.0.0 a.com") {
		t.Errorf("Expected managed block to be removed")
	}
}

// TestUnit_ApplyDoesNotWriteWhenContentUnchanged verifies that Apply doesn't
// write when the content would be unchanged.
func TestUnit_ApplyDoesNotWriteWhenContentUnchanged(t *testing.T) {
	// Given: a domains enforcer with blocked names and a hosts file already containing them
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	hostsContent := "# BEGIN sk-mdm managed block - do not edit\r\n0.0.0.0 a.com\r\n:: a.com\r\n0.0.0.0 www.a.com\r\n:: www.a.com\r\n# END sk-mdm managed block\r\n"
	fsys.Seed(WindowsHostsPath, []byte(hostsContent))
	d := &Domains{Runner: runner, FS: fsys, GOOS: "windows", Logger: nil}
	effective := map[string]any{SettingFirewallBlockedDomains: []any{"a.com"}}

	// When: Apply is called
	ctx := context.Background()
	err := d.Apply(ctx, effective, contract.Posture{})

	// Then: no error and no flush command was run
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(runner.Calls()) != 0 {
		t.Errorf("Expected 0 commands to be run when content unchanged, got %d", len(runner.Calls()))
	}
}

// TestUnit_ApplyFlushesOnWrite verifies that Apply runs flush commands after writing.
func TestUnit_ApplyFlushesOnWrite(t *testing.T) {
	// Given: a domains enforcer on windows with new blocked names
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	d := &Domains{Runner: runner, FS: fsys, GOOS: "windows", Logger: nil}
	effective := map[string]any{SettingFirewallBlockedDomains: []any{"a.com"}}

	// When: Apply is called
	ctx := context.Background()
	err := d.Apply(ctx, effective, contract.Posture{})

	// Then: no error and the flush command was run
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	calls := runner.Calls()
	if len(calls) == 0 {
		t.Errorf("Expected flush command to be run")
	}
	if len(calls) > 0 && calls[0].Name != "ipconfig.exe" {
		t.Errorf("Expected ipconfig.exe to be run, got %q", calls[0].Name)
	}
}

// TestUnit_ApplyFlushesOnDarwin verifies that Apply runs both darwin flush commands.
func TestUnit_ApplyFlushesOnDarwin(t *testing.T) {
	// Given: a domains enforcer on darwin with new blocked names
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	d := &Domains{Runner: runner, FS: fsys, GOOS: "darwin", Logger: nil}
	effective := map[string]any{SettingFirewallBlockedDomains: []any{"a.com"}}

	// When: Apply is called
	ctx := context.Background()
	err := d.Apply(ctx, effective, contract.Posture{})

	// Then: no error and both flush commands were run
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	calls := runner.Calls()
	if len(calls) != 2 {
		t.Errorf("Expected 2 flush commands on darwin, got %d", len(calls))
	}
	if len(calls) >= 1 && calls[0].Name != "/usr/bin/dscacheutil" {
		t.Errorf("Expected dscacheutil, got %q", calls[0].Name)
	}
	if len(calls) >= 2 && calls[1].Name != "/usr/bin/killall" {
		t.Errorf("Expected killall, got %q", calls[1].Name)
	}
}

// TestUnit_ApplyReturnsMissingFileAsEmpty verifies that Apply treats a missing
// hosts file as empty.
func TestUnit_ApplyReturnsMissingFileAsEmpty(t *testing.T) {
	// Given: a domains enforcer with no hosts file
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	d := &Domains{Runner: runner, FS: fsys, GOOS: "windows", Logger: nil}
	effective := map[string]any{SettingFirewallBlockedDomains: []any{"a.com"}}

	// When: Apply is called
	ctx := context.Background()
	err := d.Apply(ctx, effective, contract.Posture{})

	// Then: no error and the hosts file is created with the managed block
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	content, exists := fsys.Content(WindowsHostsPath)
	if !exists {
		t.Errorf("Expected hosts file to be created")
	}
	if !contains(string(content), "a.com") {
		t.Errorf("Expected a.com in created hosts file")
	}
}

// TestUnit_ApplyReturnsErrorOnReadFailure verifies that Apply returns an error
// when reading the hosts file fails.
func TestUnit_ApplyReturnsErrorOnReadFailure(t *testing.T) {
	// Given: a domains enforcer with a file read error
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	fsys.ReadErr = func(path string) error {
		return errors.New("permission denied")
	}
	d := &Domains{Runner: runner, FS: fsys, GOOS: "windows", Logger: nil}
	effective := map[string]any{SettingFirewallBlockedDomains: []any{"a.com"}}

	// When: Apply is called
	ctx := context.Background()
	err := d.Apply(ctx, effective, contract.Posture{})

	// Then: an error is returned
	if err == nil {
		t.Errorf("Expected an error for read failure")
	}
}

// TestUnit_ApplyReturnsMalformedBlockError verifies that Apply returns an error
// for malformed managed blocks.
func TestUnit_ApplyReturnsMalformedBlockError(t *testing.T) {
	// Given: a hosts file with a BEGIN marker but no END marker
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	hostsContent := "127.0.0.1 localhost\r\n# BEGIN sk-mdm managed block - do not edit\r\n0.0.0.0 a.com\r\n"
	fsys.Seed(WindowsHostsPath, []byte(hostsContent))
	d := &Domains{Runner: runner, FS: fsys, GOOS: "windows", Logger: nil}
	effective := map[string]any{SettingFirewallBlockedDomains: []any{"a.com"}}

	// When: Apply is called
	ctx := context.Background()
	err := d.Apply(ctx, effective, contract.Posture{})

	// Then: an error is returned containing "malformed"
	if err == nil {
		t.Errorf("Expected an error for malformed block")
	}
	if err != nil && !contains(err.Error(), "malformed") {
		t.Errorf("Expected error to contain 'malformed', got %q", err.Error())
	}
}

// TestUnit_ApplyReturnsErrorOnWriteFailure verifies that Apply returns an error
// when writing fails and doesn't run flush.
func TestUnit_ApplyReturnsErrorOnWriteFailure(t *testing.T) {
	// Given: a domains enforcer with a write error
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	fsys.WriteErr = func(path string) error {
		return errors.New("disk full")
	}
	d := &Domains{Runner: runner, FS: fsys, GOOS: "windows", Logger: nil}
	effective := map[string]any{SettingFirewallBlockedDomains: []any{"a.com"}}

	// When: Apply is called
	ctx := context.Background()
	err := d.Apply(ctx, effective, contract.Posture{})

	// Then: an error is returned and no flush command was run
	if err == nil {
		t.Errorf("Expected an error for write failure")
	}
	if len(runner.Calls()) != 0 {
		t.Errorf("Expected no flush commands after write failure, got %d", len(runner.Calls()))
	}
}

// TestUnit_ApplyReturnsErrorOnFlushFailure verifies that Apply returns an error
// when a flush command exits non-zero.
func TestUnit_ApplyReturnsErrorOnFlushFailure(t *testing.T) {
	// Given: a domains enforcer with a flush command that fails
	runner := fake.NewCommandRunner()
	runner.Results["ipconfig.exe /flushdns"] = platform.CommandResult{
		ExitCode: 1,
		Stderr:   "error",
	}
	fsys := fake.NewFS()
	d := &Domains{Runner: runner, FS: fsys, GOOS: "windows", Logger: nil}
	effective := map[string]any{SettingFirewallBlockedDomains: []any{"a.com"}}

	// When: Apply is called
	ctx := context.Background()
	err := d.Apply(ctx, effective, contract.Posture{})

	// Then: an error is returned containing "1"
	if err == nil {
		t.Errorf("Expected an error for flush failure")
	}
	if err != nil && !contains(err.Error(), "1") {
		t.Errorf("Expected error to contain exit code '1', got %q", err.Error())
	}
}

// TestUnit_ApplyPreservesExistingContent verifies that Apply preserves content
// outside the managed block.
func TestUnit_ApplyPreservesExistingContent(t *testing.T) {
	// Given: a hosts file with content outside the managed block
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	hostsContent := "127.0.0.1 localhost\r\n# Some other comment\r\n"
	fsys.Seed(WindowsHostsPath, []byte(hostsContent))
	d := &Domains{Runner: runner, FS: fsys, GOOS: "windows", Logger: nil}
	effective := map[string]any{SettingFirewallBlockedDomains: []any{"a.com"}}

	// When: Apply is called
	ctx := context.Background()
	err := d.Apply(ctx, effective, contract.Posture{})

	// Then: no error and the existing content is preserved
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	content, _ := fsys.Content(WindowsHostsPath)
	if !contains(string(content), "127.0.0.1 localhost") {
		t.Errorf("Expected localhost line to be preserved")
	}
	if !contains(string(content), "# Some other comment") {
		t.Errorf("Expected other comment to be preserved")
	}
}

// TestUnit_ApplyNoWriteWhenNoBlockAndNothingToBlock verifies that Apply doesn't
// write when there's no existing block and nothing to block.
func TestUnit_ApplyNoWriteWhenNoBlockAndNothingToBlock(t *testing.T) {
	// Given: a hosts file without a managed block and no blocked names
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	fsys.Seed(WindowsHostsPath, []byte("127.0.0.1 localhost\r\n"))
	d := &Domains{Runner: runner, FS: fsys, GOOS: "windows", Logger: nil}
	effective := map[string]any{SettingFirewallBlockedDomains: []any{}}

	// When: Apply is called
	ctx := context.Background()
	err := d.Apply(ctx, effective, contract.Posture{})

	// Then: no error and no commands were run
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(runner.Calls()) != 0 {
		t.Errorf("Expected 0 commands, got %d", len(runner.Calls()))
	}
}

// TestUnit_ApplyRespectsFileMode verifies that Apply writes the hosts file
// with the correct file mode.
func TestUnit_ApplyRespectsFileMode(t *testing.T) {
	// Given: a domains enforcer
	runner := fake.NewCommandRunner()
	fsys := fake.NewFS()
	d := &Domains{Runner: runner, FS: fsys, GOOS: "windows", Logger: nil}
	effective := map[string]any{SettingFirewallBlockedDomains: []any{"a.com"}}

	// When: Apply is called
	ctx := context.Background()
	err := d.Apply(ctx, effective, contract.Posture{})

	// Then: no error and the file mode is 0o644
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	mode, exists := fsys.Mode(WindowsHostsPath)
	if !exists {
		t.Errorf("Expected hosts file to be created")
	}
	if mode != HostsFileMode {
		t.Errorf("Expected mode %o, got %o", HostsFileMode, mode)
	}
}

// TestUnit_HostsContentAppendsManagedBlock verifies that hostsContent appends
// the managed block to a file without one.
func TestUnit_HostsContentAppendsManagedBlock(t *testing.T) {
	// Given: current hosts content and blocked names
	current := []byte("127.0.0.1 localhost\n")
	names := []string{"a.com"}

	// When: hostsContent is called
	next, err := hostsContent(current, names, "\n")

	// Then: no error and the managed block is appended
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if !contains(string(next), "127.0.0.1 localhost") {
		t.Errorf("Expected existing content to be preserved")
	}
	if !contains(string(next), HostsBeginMarker) {
		t.Errorf("Expected managed block to be appended")
	}
}

// TestUnit_HostsContentReplacesExistingBlock verifies that hostsContent replaces
// an existing managed block in place.
func TestUnit_HostsContentReplacesExistingBlock(t *testing.T) {
	// Given: current hosts content with a managed block
	current := []byte("127.0.0.1 localhost\n# BEGIN sk-mdm managed block - do not edit\n0.0.0.0 old.com\n# END sk-mdm managed block\n# Comment after block\n")
	names := []string{"new.com"}

	// When: hostsContent is called
	next, err := hostsContent(current, names, "\n")

	// Then: no error and the block is replaced in place
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	content := string(next)
	if !contains(content, "127.0.0.1 localhost") {
		t.Errorf("Expected localhost to be preserved")
	}
	if !contains(content, "# Comment after block") {
		t.Errorf("Expected comment after block to be preserved")
	}
	if contains(content, "0.0.0.0 old.com") {
		t.Errorf("Expected old block to be replaced")
	}
	if !contains(content, "0.0.0.0 new.com") {
		t.Errorf("Expected new block to be present")
	}
}

// TestUnit_HostsContentRemovesEmptyBlock verifies that hostsContent removes
// the managed block when names is empty.
func TestUnit_HostsContentRemovesEmptyBlock(t *testing.T) {
	// Given: current hosts content with a managed block and names is empty
	current := []byte("127.0.0.1 localhost\n# BEGIN sk-mdm managed block - do not edit\n0.0.0.0 a.com\n# END sk-mdm managed block\n")
	names := []string{}

	// When: hostsContent is called
	next, err := hostsContent(current, names, "\n")

	// Then: no error and the block is removed
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	content := string(next)
	if !contains(content, "127.0.0.1 localhost") {
		t.Errorf("Expected localhost to be preserved")
	}
	if contains(content, HostsBeginMarker) {
		t.Errorf("Expected managed block to be removed")
	}
}

// TestUnit_HostsContentReturnsMalformedError verifies that hostsContent returns
// an error for malformed managed blocks.
func TestUnit_HostsContentReturnsMalformedError(t *testing.T) {
	// Given: current hosts content with BEGIN but no END
	current := []byte("# BEGIN sk-mdm managed block - do not edit\n0.0.0.0 a.com\n")
	names := []string{"b.com"}

	// When: hostsContent is called
	next, err := hostsContent(current, names, "\n")

	// Then: an error is returned containing "malformed"
	if err == nil {
		t.Errorf("Expected an error for malformed block")
	}
	if err != nil && !contains(err.Error(), "malformed") {
		t.Errorf("Expected error to contain 'malformed', got %q", err.Error())
	}
	if next != nil {
		t.Errorf("Expected nil content on error")
	}
}

// TestUnit_ManagedBlockDetectsBeginAndEnd verifies that managedBlock correctly
// detects the managed block boundaries.
func TestUnit_ManagedBlockDetectsBeginAndEnd(t *testing.T) {
	// Given: content with a managed block
	content := []byte("line 1\n# BEGIN sk-mdm managed block - do not edit\n0.0.0.0 a.com\n# END sk-mdm managed block\nline after\n")

	// When: managedBlock is called
	start, end, found, err := managedBlock(content)

	// Then: no error, found=true, and boundaries are correct
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if !found {
		t.Errorf("Expected found=true")
	}
	if start != 7 { // "line 1\n" is 7 bytes
		t.Errorf("Expected start=7, got %d", start)
	}
	// Check that the extracted block contains BEGIN and END
	block := content[start:end]
	if !contains(string(block), HostsBeginMarker) {
		t.Errorf("Expected extracted block to contain BEGIN marker")
	}
	if !contains(string(block), HostsEndMarker) {
		t.Errorf("Expected extracted block to contain END marker")
	}
}

// TestUnit_ManagedBlockReturnsFalseWhenNoBlock verifies that managedBlock
// returns found=false when there's no managed block.
func TestUnit_ManagedBlockReturnsFalseWhenNoBlock(t *testing.T) {
	// Given: content without a managed block
	content := []byte("127.0.0.1 localhost\n")

	// When: managedBlock is called
	_, _, found, err := managedBlock(content)

	// Then: no error and found=false
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if found {
		t.Errorf("Expected found=false")
	}
}

// TestUnit_ManagedBlockErrorOnBeginWithoutEnd verifies that managedBlock returns
// an error when there's a BEGIN without an END.
func TestUnit_ManagedBlockErrorOnBeginWithoutEnd(t *testing.T) {
	// Given: content with BEGIN but no END
	content := []byte("# BEGIN sk-mdm managed block - do not edit\n0.0.0.0 a.com\n")

	// When: managedBlock is called
	_, _, _, err := managedBlock(content)

	// Then: an error is returned
	if err == nil {
		t.Errorf("Expected an error for BEGIN without END")
	}
}

// TestUnit_ManagedBlockErrorOnMultipleBegin verifies that managedBlock returns
// an error when there are multiple BEGIN markers.
func TestUnit_ManagedBlockErrorOnMultipleBegin(t *testing.T) {
	// Given: content with two BEGIN markers
	content := []byte("# BEGIN sk-mdm managed block - do not edit\n0.0.0.0 a.com\n# BEGIN sk-mdm managed block - do not edit\n# END sk-mdm managed block\n")

	// When: managedBlock is called
	_, _, _, err := managedBlock(content)

	// Then: an error is returned
	if err == nil {
		t.Errorf("Expected an error for multiple BEGIN markers")
	}
}

// TestUnit_ManagedBlockIgnoresTrilingCR verifies that managedBlock ignores
// trailing carriage returns when matching markers.
func TestUnit_ManagedBlockIgnoresTrailingCR(t *testing.T) {
	// Given: content with Windows line endings
	content := []byte("# BEGIN sk-mdm managed block - do not edit\r\n0.0.0.0 a.com\r\n# END sk-mdm managed block\r\n")

	// When: managedBlock is called
	_, _, found, err := managedBlock(content)

	// Then: no error and found=true
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if !found {
		t.Errorf("Expected found=true with Windows line endings")
	}
}
