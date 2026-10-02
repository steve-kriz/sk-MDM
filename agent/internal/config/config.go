// Package config reads and writes the agent's on-disk configuration: where to
// send collections, the enrollment token to present once, how often to check in
// and how much to log.
//
// Every file operation goes through platform.FileSystem, so the whole package
// is testable without touching a real disk.
package config

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/url"

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
	// EnrollmentToken authenticates POST /api/v1/enroll, once.
	EnrollmentToken string `json:"enrollmentToken"`
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
// Absent checkInIntervalSeconds defaults to 900 and absent logLevel to "info".
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
	return c, nil
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

	fields := map[string]json.RawMessage{}
	data, err := fsys.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &fields); err != nil {
			return err
		}
	case errors.Is(err, fs.ErrNotExist):
		// A fresh install: write the first version of the file.
	default:
		return err
	}

	encoded, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	fields["collectionUrl"] = encoded

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
