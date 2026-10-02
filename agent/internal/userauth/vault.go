// Package userauth signs a person in to the agent with their Entra ID account
// and keeps that sign-in alive without any user interaction.
//
// `mdmagent login` runs the OAuth 2.0 device authorization grant (RFC 8628)
// against Entra (entra.go) and stores the resulting tokens in the Vault. The
// service's Session (session.go) reads the vault on every call, refreshes the
// access token before it expires and hands it to the transport, which sends it
// as `Authorization: Bearer` alongside the device signature.
//
// Access tokens, refresh tokens and device codes are never logged, printed or
// put in an error message.
package userauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// Vault file locations, next to the agent's state file. Both the elevated CLI
// and the service (LocalSystem on Windows, root on macOS) read the same file.
const (
	// WindowsVaultPath holds the record encrypted with machine-scope DPAPI.
	WindowsVaultPath = `C:\ProgramData\OfficeHQ\MDM\usertoken.bin`
	// DarwinVaultPath holds the record as JSON, mode 0600, owned by root.
	DarwinVaultPath = "/Library/Application Support/OfficeHQ/MDM/usertoken.json"
)

// VaultFileMode is the mode the vault is written with: owner only.
const VaultFileMode fs.FileMode = 0o600

// Sentinel errors Load returns.
var (
	// ErrNoToken means no vault file exists: nobody is signed in.
	ErrNoToken = errors.New("no user sign-in stored")

	// ErrVaultUnreadable means the vault exists but could not be decrypted
	// or does not hold a valid record. The file is left as it is.
	ErrVaultUnreadable = errors.New("user sign-in store unreadable")
)

// Record is one signed-in user's tokens and what is needed to refresh them.
type Record struct {
	AccessToken  string
	RefreshToken string
	// ExpiresAt is when AccessToken expires. It is stored RFC3339, UTC.
	ExpiresAt time.Time
	// Username is the unverified `preferred_username` of the id token, for
	// display only.
	Username string
	TenantID string
	ClientID string
	// Scopes are the scopes the sign-in asked for, from the agent-auth
	// config fetched at login, reused for every refresh.
	Scopes []string
}

// recordJSON is the stored shape of a Record.
type recordJSON struct {
	AccessToken  string   `json:"accessToken"`
	RefreshToken string   `json:"refreshToken"`
	ExpiresAt    string   `json:"expiresAt"`
	Username     string   `json:"username"`
	TenantID     string   `json:"tenantId"`
	ClientID     string   `json:"clientId"`
	Scopes       []string `json:"scopes"`
}

// VaultPath returns the vault location for a GOOS value: the Windows path for
// "windows" and the macOS path for anything else.
func VaultPath(goos string) string {
	if goos == "windows" {
		return WindowsVaultPath
	}
	return DarwinVaultPath
}

// Vault reads and writes the stored sign-in.
type Vault struct {
	fsys      platform.FileSystem
	protector platform.SecretProtector
	path      string
}

// NewVault returns a vault over path, encrypting through protector.
func NewVault(fsys platform.FileSystem, protector platform.SecretProtector, path string) *Vault {
	return &Vault{fsys: fsys, protector: protector, path: path}
}

// Path is the file this vault reads and writes.
func (v *Vault) Path() string { return v.path }

// Load returns the stored record: ErrNoToken when there is none, and
// ErrVaultUnreadable when the file cannot be decrypted or parsed. Load never
// modifies the file.
func (v *Vault) Load() (Record, error) {
	data, err := v.fsys.ReadFile(v.path)
	if errors.Is(err, fs.ErrNotExist) {
		return Record{}, ErrNoToken
	}
	if err != nil {
		return Record{}, err
	}

	plain, err := v.protector.Unprotect(data)
	if err != nil {
		return Record{}, ErrVaultUnreadable
	}

	var stored recordJSON
	if err := json.Unmarshal(plain, &stored); err != nil {
		return Record{}, ErrVaultUnreadable
	}
	expiresAt, err := time.Parse(time.RFC3339, stored.ExpiresAt)
	if err != nil {
		return Record{}, ErrVaultUnreadable
	}

	return Record{
		AccessToken:  stored.AccessToken,
		RefreshToken: stored.RefreshToken,
		ExpiresAt:    expiresAt.UTC(),
		Username:     stored.Username,
		TenantID:     stored.TenantID,
		ClientID:     stored.ClientID,
		Scopes:       stored.Scopes,
	}, nil
}

// Save writes the record encrypted, atomically, with mode 0600. A failed save
// leaves any previous vault untouched.
func (v *Vault) Save(rec Record) error {
	scopes := rec.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	data, err := json.Marshal(recordJSON{
		AccessToken:  rec.AccessToken,
		RefreshToken: rec.RefreshToken,
		ExpiresAt:    rec.ExpiresAt.UTC().Format(time.RFC3339),
		Username:     rec.Username,
		TenantID:     rec.TenantID,
		ClientID:     rec.ClientID,
		Scopes:       scopes,
	})
	if err != nil {
		return err
	}

	protected, err := v.protector.Protect(data)
	if err != nil {
		return fmt.Errorf("protect: %w", err)
	}
	return platform.WriteFileAtomic(v.fsys, v.path, protected, VaultFileMode)
}

// Delete removes the vault. A vault that is already gone is not an error.
func (v *Vault) Delete() error {
	err := v.fsys.Remove(v.path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
