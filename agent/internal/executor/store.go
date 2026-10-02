package executor

import (
	"encoding/json"
	"errors"
	"io/fs"
	"sync"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// Command store locations, beside the state file the installer creates.
const (
	// WindowsStorePath is the completed-command store on Windows.
	WindowsStorePath = `C:\ProgramData\OfficeHQ\MDM\commands.json`
	// DarwinStorePath is the completed-command store on macOS.
	DarwinStorePath = "/Library/Application Support/OfficeHQ/MDM/commands.json"
)

// StoreFileMode is the mode the store is written with. It holds command output
// from this device, so no group or world access is requested.
const StoreFileMode fs.FileMode = 0o600

// StoreMaxRecords is how many completed commands are remembered. Past that the
// oldest is dropped: the store exists to stop a re-leased command running
// twice, not to be an audit log.
const StoreMaxRecords = 200

// StorePath returns the store location for a GOOS value: the Windows path for
// "windows" and the macOS path for anything else, the agent shipping for those
// two platforms only.
func StorePath(goos string) string {
	if goos == "windows" {
		return WindowsStorePath
	}
	return DarwinStorePath
}

// Record is one command this device has finished.
//
// Posted says whether the backend has taken the result. A record that is not
// posted is what the next cycle retries, which is how a result survives an
// outage between running the command and reporting it.
type Record struct {
	CommandID string                        `json:"commandId"`
	Result    contract.CommandResultRequest `json:"result"`
	Posted    bool                          `json:"posted"`
}

// storeFile is the on-disk shape, an object rather than a bare array so the
// file can grow a field later without breaking an older agent.
type storeFile struct {
	Commands []Record `json:"commands"`
}

// Store remembers the commands this device has already run.
//
// Every write goes through platform.FileSystem, so the store behaves
// identically in a test with no disk. Records are kept in completion order,
// oldest first.
type Store struct {
	mu   sync.Mutex
	fsys platform.FileSystem
	path string
}

// NewStore returns a store over path.
func NewStore(fsys platform.FileSystem, path string) *Store {
	return &Store{fsys: fsys, path: path}
}

// Path is the file this store reads and writes.
func (s *Store) Path() string { return s.path }

// Load returns every remembered command, oldest first.
//
// A store file that does not exist is not an error: it is a device that has
// run no commands yet, so the empty list comes back.
func (s *Store) Load() ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

// Lookup returns the record for a command id, and whether this device has
// already completed it.
func (s *Store) Lookup(commandID string) (Record, bool, error) {
	records, err := s.Load()
	if err != nil {
		return Record{}, false, err
	}
	for _, record := range records {
		if record.CommandID == commandID {
			return record, true, nil
		}
	}
	return Record{}, false, nil
}

// Record remembers a finished command and its result, not yet posted.
//
// It is written before the result is reported, so a crash between running a
// command and reporting it costs the report, never a second execution.
func (s *Store) Record(commandID string, result contract.CommandResultRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	records, err := s.load()
	if err != nil {
		return err
	}

	replaced := false
	for i := range records {
		if records[i].CommandID == commandID {
			records[i] = Record{CommandID: commandID, Result: result}
			replaced = true
			break
		}
	}
	if !replaced {
		records = append(records, Record{CommandID: commandID, Result: result})
	}
	if len(records) > StoreMaxRecords {
		records = records[len(records)-StoreMaxRecords:]
	}
	return s.save(records)
}

// MarkPosted records that the backend has taken a result, so no later cycle
// sends it again. A command the store has never heard of is left alone.
func (s *Store) MarkPosted(commandID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	records, err := s.load()
	if err != nil {
		return err
	}
	for i := range records {
		if records[i].CommandID == commandID {
			if records[i].Posted {
				return nil
			}
			records[i].Posted = true
			return s.save(records)
		}
	}
	return nil
}

// Unposted is every result the backend has not taken yet, oldest first: the
// queue the next cycle retries.
func (s *Store) Unposted() ([]Record, error) {
	records, err := s.Load()
	if err != nil {
		return nil, err
	}

	pending := make([]Record, 0, len(records))
	for _, record := range records {
		if !record.Posted {
			pending = append(pending, record)
		}
	}
	return pending, nil
}

// load reads the store with the lock already held.
func (s *Store) load() ([]Record, error) {
	data, err := s.fsys.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var file storeFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	return file.Commands, nil
}

// save writes the store atomically, so a crash mid-save cannot leave a file
// that no longer says which commands have run.
func (s *Store) save(records []Record) error {
	data, err := json.MarshalIndent(storeFile{Commands: records}, "", "  ")
	if err != nil {
		return err
	}
	return platform.WriteFileAtomic(s.fsys, s.path, append(data, '\n'), StoreFileMode)
}
