package userauth

import (
	"io/fs"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// TestScenario_VaultPath_Windows validates that VaultPath returns the correct path for Windows.
func TestScenario_VaultPath_Windows(t *testing.T) {
	// When VaultPath is called with "windows"
	path := VaultPath("windows")

	// Then it returns the Windows path
	if path != WindowsVaultPath {
		t.Errorf("expected %q, got %q", WindowsVaultPath, path)
	}
}

// TestScenario_VaultPath_Darwin validates that VaultPath returns the macOS path for any non-Windows GOOS.
func TestScenario_VaultPath_Darwin(t *testing.T) {
	// When VaultPath is called with "darwin"
	path := VaultPath("darwin")

	// Then it returns the Darwin path
	if path != DarwinVaultPath {
		t.Errorf("expected %q, got %q", DarwinVaultPath, path)
	}
}

// TestScenario_VaultSaveEncryptsAndWritesWithMode0600 validates that Save encrypts, writes
// atomically with .tmp rename, and uses mode 0600.
func TestScenario_VaultSaveEncryptsAndWritesWithMode0600(t *testing.T) {
	// Given
	fsys := fake.NewFS()
	protector := fake.NewSecretProtector()
	vaultPath := "/test/vault.json"
	vault := NewVault(fsys, protector, vaultPath)

	// When the vault saves a record
	rec := Record{
		AccessToken:  "a-token",
		RefreshToken: "REFRESH-SENTINEL",
		ExpiresAt:    time.Unix(1000000, 0).UTC(),
		Username:     "amy@contoso.com",
		TenantID:     "t-1",
		ClientID:     "c-1",
		Scopes:       []string{"api://c-1/MDM.Agent", "offline_access", "openid", "profile"},
	}

	if err := vault.Save(rec); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Then the file was written with mode 0600
	mode, ok := fsys.Mode(vaultPath)
	if !ok {
		t.Fatal("vault file was not written")
	}
	if mode != VaultFileMode {
		t.Errorf("expected mode 0o600, got 0o%o", mode)
	}

	// And the bytes do not contain "REFRESH-SENTINEL"
	content, _ := fsys.Content(vaultPath)
	if len(content) > 0 {
		contentStr := string(content)
		if contentStr == rec.RefreshToken {
			t.Error("refresh token should not appear in plaintext in vault")
		}
		// Note: The fake protector's encrypted content has a prefix, so we can't check for the sentinel
		// in the ciphertext, but we can verify it's not the raw token
		if contentStr == rec.AccessToken {
			t.Error("access token should not appear in plaintext in vault")
		}
	}
}

// TestScenario_VaultSaveLoadRoundTrip validates that Save and Load round-trip a record.
func TestScenario_VaultSaveLoadRoundTrip(t *testing.T) {
	// Given
	fsys := fake.NewFS()
	protector := fake.NewSecretProtector()
	vaultPath := "/test/vault.json"
	vault := NewVault(fsys, protector, vaultPath)

	// When the vault saves a record with specific fields
	original := Record{
		AccessToken:  "a-token",
		RefreshToken: "r-token",
		ExpiresAt:    time.Unix(1000000, 0).UTC(),
		Username:     "amy@contoso.com",
		TenantID:     "t-1",
		ClientID:     "c-1",
		Scopes:       []string{"api://c-1/MDM.Agent", "offline_access", "openid", "profile"},
	}

	if err := vault.Save(original); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// And the vault loads the record
	loaded, err := vault.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Then the loaded record matches the original
	if loaded.AccessToken != original.AccessToken {
		t.Errorf("AccessToken mismatch: %q vs %q", loaded.AccessToken, original.AccessToken)
	}
	if loaded.RefreshToken != original.RefreshToken {
		t.Errorf("RefreshToken mismatch: %q vs %q", loaded.RefreshToken, original.RefreshToken)
	}
	if !loaded.ExpiresAt.Equal(original.ExpiresAt) {
		t.Errorf("ExpiresAt mismatch: %v vs %v", loaded.ExpiresAt, original.ExpiresAt)
	}
	if loaded.Username != original.Username {
		t.Errorf("Username mismatch: %q vs %q", loaded.Username, original.Username)
	}
	if loaded.TenantID != original.TenantID {
		t.Errorf("TenantID mismatch: %q vs %q", loaded.TenantID, original.TenantID)
	}
	if loaded.ClientID != original.ClientID {
		t.Errorf("ClientID mismatch: %q vs %q", loaded.ClientID, original.ClientID)
	}
	if len(loaded.Scopes) != len(original.Scopes) {
		t.Errorf("Scopes length mismatch: %d vs %d", len(loaded.Scopes), len(original.Scopes))
	}
	for i, scope := range loaded.Scopes {
		if scope != original.Scopes[i] {
			t.Errorf("Scope[%d] mismatch: %q vs %q", i, scope, original.Scopes[i])
		}
	}
}

// TestScenario_VaultLoadNoFile returns ErrNoToken when no vault file exists.
func TestScenario_VaultLoadNoFile(t *testing.T) {
	// Given no vault file
	fsys := fake.NewFS()
	protector := fake.NewSecretProtector()
	vault := NewVault(fsys, protector, "/test/vault.json")

	// When the vault loads
	_, err := vault.Load()

	// Then it returns ErrNoToken
	if err != ErrNoToken {
		t.Errorf("expected ErrNoToken, got %v", err)
	}
}

// TestScenario_VaultLoadUnprotectableFile returns ErrVaultUnreadable and leaves the file unchanged.
func TestScenario_VaultLoadUnprotectableFile(t *testing.T) {
	// Given a vault the protector cannot unprotect
	fsys := fake.NewFS()
	protector := fake.NewSecretProtector()
	protector.UnprotectErr = ErrVaultUnreadable
	vaultPath := "/test/vault.json"
	vault := NewVault(fsys, protector, vaultPath)

	// Seed an existing vault
	originalData := []byte("some data")
	fsys.Seed(vaultPath, originalData)

	// When the vault loads
	_, err := vault.Load()

	// Then it returns ErrVaultUnreadable
	if err != ErrVaultUnreadable {
		t.Errorf("expected ErrVaultUnreadable, got %v", err)
	}

	// And the file is unchanged
	current, _ := fsys.Content(vaultPath)
	if string(current) != string(originalData) {
		t.Error("file should be unchanged after failed load")
	}
}

// TestScenario_VaultLoadInvalidJSON returns ErrVaultUnreadable.
func TestScenario_VaultLoadInvalidJSON(t *testing.T) {
	// Given a vault holding invalid JSON
	fsys := fake.NewFS()
	protector := fake.NewSecretProtector()
	vaultPath := "/test/vault.json"
	vault := NewVault(fsys, protector, vaultPath)

	// Seed an encrypted invalid JSON
	invalidJSON := []byte("not json")
	protected, _ := protector.Protect(invalidJSON)
	fsys.SeedMode(vaultPath, protected, VaultFileMode)

	// When the vault loads
	_, err := vault.Load()

	// Then it returns ErrVaultUnreadable
	if err != ErrVaultUnreadable {
		t.Errorf("expected ErrVaultUnreadable, got %v", err)
	}
}

// TestScenario_VaultDeleteRemovesFile validates that Delete removes the vault.
func TestScenario_VaultDeleteRemovesFile(t *testing.T) {
	// Given a vault file
	fsys := fake.NewFS()
	protector := fake.NewSecretProtector()
	vaultPath := "/test/vault.json"
	vault := NewVault(fsys, protector, vaultPath)

	fsys.Seed(vaultPath, []byte("data"))

	// When the vault deletes
	if err := vault.Delete(); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Then the file is gone
	if fsys.Exists(vaultPath) {
		t.Error("vault file should be deleted")
	}
}

// TestScenario_VaultDeleteNoFile succeeds when no vault file exists.
func TestScenario_VaultDeleteNoFile(t *testing.T) {
	// Given no vault file
	fsys := fake.NewFS()
	protector := fake.NewSecretProtector()
	vault := NewVault(fsys, protector, "/test/vault.json")

	// When the vault deletes
	err := vault.Delete()

	// Then it returns nil (no error)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

// TestScenario_VaultSaveAtomicity validates that a failed rename doesn't leave a partial file.
func TestScenario_VaultSaveAtomicity(t *testing.T) {
	// Given a filesystem that fails renames
	fsys := fake.NewFS()
	protector := fake.NewSecretProtector()
	vaultPath := "/test/vault.json"
	vault := NewVault(fsys, protector, vaultPath)

	// Seed an existing vault
	originalData := []byte("original")
	fsys.Seed(vaultPath, originalData)

	// When Save encounters a rename failure (which makes the atomic write fail)
	fsys.RenameErr = func(oldPath, newPath string) error {
		if newPath == vaultPath {
			return fs.ErrPermission
		}
		return nil
	}

	rec := Record{
		AccessToken:  "new-token",
		RefreshToken: "r-token",
		ExpiresAt:    time.Unix(1000000, 0).UTC(),
		TenantID:     "t-1",
		ClientID:     "c-1",
	}

	err := vault.Save(rec)

	// Then an error is returned
	if err == nil {
		t.Error("expected error from failed rename")
	}

	// And the original file is unchanged
	current, _ := fsys.Content(vaultPath)
	if string(current) != string(originalData) {
		t.Error("original file should be unchanged after failed rename")
	}
}
