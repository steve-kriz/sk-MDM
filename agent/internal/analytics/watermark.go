package analytics

import (
	"encoding/json"
	"errors"
	"io/fs"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// Watermark file locations, under the same directory as the state file. The
// watermark has a file of its own rather than a key in state.json: clearing a
// rejected credential saves an empty state, which would wipe it.
const (
	// WindowsWatermarkPath is the watermark location on Windows.
	WindowsWatermarkPath = `C:\ProgramData\OfficeHQ\MDM\analytics.json`
	// DarwinWatermarkPath is the watermark location on macOS.
	DarwinWatermarkPath = "/Library/Application Support/OfficeHQ/MDM/analytics.json"
)

// WatermarkFileMode is the mode the watermark file is written with.
const WatermarkFileMode fs.FileMode = 0o600

// WatermarkPath returns the watermark location for a GOOS value: the Windows
// path for "windows" and the macOS path for anything else.
func WatermarkPath(goos string) string {
	if goos == "windows" {
		return WindowsWatermarkPath
	}
	return DarwinWatermarkPath
}

// watermarkFile is the on-disk shape of the watermark.
type watermarkFile struct {
	CrashesReportedThrough string `json:"crashesReportedThrough"`
}

// WatermarkStore reads and writes the crash watermark: the time of the newest
// crash the backend has accepted.
type WatermarkStore struct {
	fsys platform.FileSystem
	path string
}

// NewWatermarkStore returns a store over path.
func NewWatermarkStore(fsys platform.FileSystem, path string) *WatermarkStore {
	return &WatermarkStore{fsys: fsys, path: path}
}

// Path is the file this store reads and writes.
func (s *WatermarkStore) Path() string { return s.path }

// Load returns the stored watermark. A file that does not exist is not an
// error: the zero time comes back. A file that cannot be read or holds
// anything but a valid watermark is.
func (s *WatermarkStore) Load() (time.Time, error) {
	data, err := s.fsys.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}

	var wf watermarkFile
	if err := json.Unmarshal(data, &wf); err != nil {
		return time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339Nano, wf.CrashesReportedThrough)
	if err != nil {
		return time.Time{}, err
	}
	return t, nil
}

// Save writes t, in UTC at full precision, atomically with mode 0600.
func (s *WatermarkStore) Save(t time.Time) error {
	data, err := json.Marshal(watermarkFile{CrashesReportedThrough: t.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return err
	}
	return platform.WriteFileAtomic(s.fsys, s.path, data, WatermarkFileMode)
}
