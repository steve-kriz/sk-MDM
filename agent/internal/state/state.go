// Package state persists what enrollment hands the agent once and the agent
// must keep: its device id and its device secret.
//
// The secret is the HMAC key every signed request uses (see
// agent/internal/contract), so the file is written owner-only and is never
// printed, logged or echoed back by any command.
package state

import (
	"encoding/json"
	"errors"
	"io/fs"

	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// FileSystem is platform.FileSystem, aliased for readable signatures.
type FileSystem = platform.FileSystem

// State file locations, under the same directory as the config file.
const (
	// WindowsPath is the state location on Windows.
	WindowsPath = `C:\ProgramData\OfficeHQ\MDM\state.json`
	// DarwinPath is the state location on macOS.
	DarwinPath = "/Library/Application Support/OfficeHQ/MDM/state.json"
)

// FileMode is the mode the state file is written with. It holds the device
// secret, so no group or world access is requested.
const FileMode fs.FileMode = 0o600

// State is the enrollment result the agent keeps across restarts.
type State struct {
	// DeviceID is the id the backend assigned at enrollment.
	DeviceID string `json:"deviceId"`
	// DeviceSecret is the lower-case hex HMAC key issued at enrollment.
	DeviceSecret string `json:"deviceSecret"`
}

// Enrolled reports whether the agent has both halves of its identity.
func (s State) Enrolled() bool {
	return s.DeviceID != "" && s.DeviceSecret != ""
}

// StatePath returns the state file location for a GOOS value: the documented
// Windows path for "windows" and the macOS path for anything else, the agent
// shipping for those two platforms only.
func StatePath(platform string) string {
	if platform == "windows" {
		return WindowsPath
	}
	return DarwinPath
}

// Store reads and writes the state file.
type Store struct {
	fsys FileSystem
	path string
}

// NewStore returns a store over path.
func NewStore(fsys FileSystem, path string) *Store {
	return &Store{fsys: fsys, path: path}
}

// Path is the file this store reads and writes.
func (s *Store) Path() string { return s.path }

// Load returns the stored state. A state file that does not exist is not an
// error: it is simply an agent that has not enrolled yet, so the zero State
// comes back.
func (s *Store) Load() (State, error) {
	data, err := s.fsys.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}

	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return State{}, err
	}
	return st, nil
}

// Save writes the state atomically, requesting mode 0600. A failed write
// leaves any previous state file untouched, so a crash mid-save cannot cost
// the agent the identity it already has.
func (s *Store) Save(st State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return platform.WriteFileAtomic(s.fsys, s.path, append(data, '\n'), FileMode)
}
