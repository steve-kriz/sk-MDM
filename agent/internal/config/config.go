// Package config reads and writes the agent's on-disk configuration: where to
// send collections, whether the machine is an OfficeHQ device or a BYOC one,
// the Entra tenant and client the sign-in uses, the legacy enrollment token
// when a silent install still carries one, how often to check in and how much
// to log.
//
// Every file operation goes through platform.FileSystem, so the whole package
// is testable without touching a real disk.
package config

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/url"
	"strings"

	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// FileSystem is platform.FileSystem; it is aliased here so a caller reads
// config.Load's signature without a second import.
type FileSystem = platform.FileSystem

// Defaults applied by Load when the field is absent from the file.
const (
	// DefaultCheckInIntervalSeconds is fifteen minutes.
	DefaultCheckInIntervalSeconds = 900
	// DefaultLogLevel is the level the agent logs at unless told otherwise.
	DefaultLogLevel = "info"
)

// Ownership values. Anything else in the file reads as OwnershipOfficeHQ.
const (
	// OwnershipOfficeHQ is a company-owned device; it is the default.
	OwnershipOfficeHQ = "officehq"
	// OwnershipBYOC is a personal device ("bring your own computer").
	OwnershipBYOC = "byoc"
)

// FileMode is the mode the config file is written with: it carries the
// enrollment token, so it is owner-only.
const FileMode fs.FileMode = 0o600

// Config file locations, created by the installer.
const (
	// WindowsPath is the config location on Windows.
	WindowsPath = `C:\ProgramData\OfficeHQ\MDM\config.json`
	// DarwinPath is the config location on macOS.
	DarwinPath = "/Library/Application Support/OfficeHQ/MDM/config.json"
)

// ErrCollectionURL is returned whenever the collection URL is missing,
// unparseable or not https. Its message is the exact text the CLI prints.
var ErrCollectionURL = errors.New("collection url must be an https url")

// Config is the agent's configuration file.
//
// The json tags are the field names in the file; they are not the contract
// field names and are free to differ from agent/internal/contract.
type Config struct {
	// CollectionURL is the base URL of the collection endpoint. It must be
	// https: the enrollment token and the device secret travel over it.
	CollectionURL string `json:"collectionUrl"`
	// EnrollmentToken is optional. When present it authenticates
	// POST /api/v1/enroll as X-MDM-Enrollment-Token. A legacy silent install
	// may carry one; otherwise the browser sign-in (or `mdmagent login`)
	// mints a single-use one and writes it with SetEnrollmentToken, and one
	// the backend refuses is removed with ClearEnrollmentToken so a new
	// sign-in is asked for.
	EnrollmentToken string `json:"enrollmentToken"`
	// Ownership is OwnershipOfficeHQ or OwnershipBYOC. Load turns an absent
	// or unknown value into OwnershipOfficeHQ.
	Ownership string `json:"ownership,omitempty"`
	// TenantID and ClientID are the Entra tenant and the agent's public
	// client, baked in at packaging. When either is empty the agent reads
	// both from GET /api/v1/agent-auth/config.
	TenantID string `json:"tenantId,omitempty"`
	ClientID string `json:"clientId,omitempty"`
	// CheckInIntervalSeconds is how often the agent checks in.
	CheckInIntervalSeconds int `json:"checkInIntervalSeconds"`
	// LogLevel is the lowest level written to the log file.
	LogLevel string `json:"logLevel"`
}

// Path returns the config file location for a GOOS value. Anything that is not
// "windows" gets the macOS path; the agent ships for those two platforms only.
func Path(goos string) string {
	if goos == "windows" {
		return WindowsPath
	}
	return DarwinPath
}

// Load reads and validates the config file at path.
//
// Absent checkInIntervalSeconds defaults to 900, absent logLevel to "info",
// and an ownership that is not exactly "officehq" or "byoc" to "officehq".
// A collection URL that is empty, unparseable or not https is refused with
// ErrCollectionURL; a missing file or malformed JSON is reported as the
// underlying error.
func Load(fsys FileSystem, path string) (Config, error) {
	data, err := fsys.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, err
	}

	if err := ValidateCollectionURL(c.CollectionURL); err != nil {
		return Config{}, err
	}

	if c.CheckInIntervalSeconds == 0 {
		c.CheckInIntervalSeconds = DefaultCheckInIntervalSeconds
	}
	if c.LogLevel == "" {
		c.LogLevel = DefaultLogLevel
	}
	c.Ownership = NormalizeOwnership(c.Ownership)
	return c, nil
}

// NormalizeOwnership returns raw when it is OwnershipOfficeHQ or
// OwnershipBYOC, and OwnershipOfficeHQ for anything else.
func NormalizeOwnership(raw string) string {
	if raw == OwnershipBYOC {
		return OwnershipBYOC
	}
	return OwnershipOfficeHQ
}

// Save writes c to path atomically: the JSON goes to path+".tmp" first and
// that file is renamed over path. When the write step fails, path keeps its
// previous contents.
func Save(fsys FileSystem, path string, c Config) error {
	data, err := marshal(c)
	if err != nil {
		return err
	}
	return platform.WriteFileAtomic(fsys, path, data, FileMode)
}

// ValidateCollectionURL reports whether raw is a URL the agent may send
// collections to. Everything but an https URL with a host is refused with
// ErrCollectionURL.
func ValidateCollectionURL(raw string) error {
	if raw == "" {
		return ErrCollectionURL
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ErrCollectionURL
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return ErrCollectionURL
	}
	return nil
}

// SetCollectionURL rewrites only the collectionUrl field of the config file at
// path, atomically.
//
// It deliberately does not go through Load and Save: that round trip would
// also materialise the defaults for absent fields and drop any key the agent
// does not know about, and this command promises to change one field. The URL
// is validated before the file is touched, so a refused URL leaves the file
// alone. A config file that does not exist yet is created holding just the URL,
// which is how the installer sets it after a silent install.
func SetCollectionURL(fsys FileSystem, path, raw string) error {
	if err := ValidateCollectionURL(raw); err != nil {
		return err
	}

	encoded, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return rewriteField(fsys, path, "collectionUrl", encoded)
}

// SetEnrollmentToken rewrites only the enrollmentToken field of the config
// file at path, atomically, the way SetCollectionURL rewrites the URL. An empty
// token removes the key altogether. A config file that does not exist yet is
// created holding just the token. The token is never logged.
func SetEnrollmentToken(fsys FileSystem, path, token string) error {
	if token == "" {
		return rewriteField(fsys, path, "enrollmentToken", nil)
	}
	encoded, err := json.Marshal(token)
	if err != nil {
		return err
	}
	return rewriteField(fsys, path, "enrollmentToken", encoded)
}

// ClearEnrollmentToken removes the enrollmentToken field from the config file
// at path, so the next enrollment waits for a sign-in again.
func ClearEnrollmentToken(fsys FileSystem, path string) error {
	return SetEnrollmentToken(fsys, path, "")
}

// ReadEnrollmentToken returns the enrollmentToken field of the config file at
// path, trimmed, and "" when the file has none. Unlike Load it validates
// nothing else: it is read per enrollment, so a token the sign-in wrote after
// the agent started is picked up without a restart.
func ReadEnrollmentToken(fsys FileSystem, path string) (string, error) {
	data, err := fsys.ReadFile(path)
	if err != nil {
		return "", err
	}
	var c struct {
		EnrollmentToken string `json:"enrollmentToken"`
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return "", err
	}
	return strings.TrimSpace(c.EnrollmentToken), nil
}

// rewriteField sets one top-level key of the config file at path to value, or
// removes it when value is nil, keeping every other key exactly as it is, and
// writes the result atomically. A missing file is treated as an empty object;
// a malformed one is refused and left alone.
func rewriteField(fsys FileSystem, path, key string, value json.RawMessage) error {
	fields := map[string]json.RawMessage{}
	data, err := fsys.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &fields); err != nil {
			return err
		}
		if fields == nil {
			fields = map[string]json.RawMessage{}
		}
	case errors.Is(err, fs.ErrNotExist):
		// A fresh install: write the first version of the file.
	default:
		return err
	}

	if value == nil {
		delete(fields, key)
	} else {
		fields[key] = value
	}

	out, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return err
	}
	return platform.WriteFileAtomic(fsys, path, append(out, '\n'), FileMode)
}

func marshal(c Config) ([]byte, error) {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
