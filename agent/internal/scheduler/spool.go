package scheduler

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// SpoolMaxFiles is how many check-in payloads are kept while the collection
// endpoint is unreachable. Beyond that the oldest is dropped: a device that has
// been offline for days reports what it can rather than filling the disk.
const SpoolMaxFiles = 50

// SpoolFileMode is the mode a spooled payload is written with. It holds an
// inventory of the machine, so no group or world access is requested.
const SpoolFileMode fs.FileMode = 0o600

// SpoolDirMode is the mode the spool directory is created with.
const SpoolDirMode fs.FileMode = 0o700

// Spool file names are "checkin-<utc timestamp>-<sequence>.json". The
// timestamp is fixed-width and the sequence is zero-padded, so sorting the
// names ascending is sorting the payloads oldest first — which is the order
// they have to be posted in, and the order the cap drops them in.
const (
	spoolPrefix     = "checkin-"
	spoolSuffix     = ".json"
	spoolTimeFormat = "20060102T150405.000Z"
	spoolMaxSeq     = 1000
)

// Spool is the on-disk queue of check-in payloads that could not be posted.
//
// Every file operation goes through platform.FileSystem and every timestamp
// comes from the injected clock, so the queue behaves identically in a test
// with no disk and no wall clock.
type Spool struct {
	fsys  platform.FileSystem
	clock platform.Clock
	dir   string

	// Max is how many payloads are kept; zero means SpoolMaxFiles.
	Max int
}

// NewSpool returns the spool over dir. The directory is created when a payload
// is first added, not here.
func NewSpool(fsys platform.FileSystem, clock platform.Clock, dir string) *Spool {
	return &Spool{fsys: fsys, clock: clock, dir: dir}
}

// Dir is the directory this spool keeps its payloads in.
func (s *Spool) Dir() string { return s.dir }

// Add writes payload as one file and prunes the queue back to the cap,
// returning the path it was written to.
func (s *Spool) Add(payload []byte) (string, error) {
	if err := s.fsys.MkdirAll(s.dir, SpoolDirMode); err != nil {
		return "", err
	}

	path, err := s.freeName()
	if err != nil {
		return "", err
	}
	if err := s.fsys.WriteFile(path, payload, SpoolFileMode); err != nil {
		return "", err
	}
	if err := s.prune(); err != nil {
		return path, err
	}
	return path, nil
}

// List is every spooled payload, oldest first.
//
// A spool directory that does not exist is not an error: it is an agent that
// has never been offline, so the empty list comes back.
func (s *Spool) List() ([]string, error) {
	entries, err := s.fsys.ReadDir(s.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !isSpoolName(name) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	paths := make([]string, 0, len(names))
	for _, name := range names {
		paths = append(paths, joinPath(s.dir, name))
	}
	return paths, nil
}

// Remove drops one spooled payload. A file that is already gone is not an
// error: the queue is as empty as the caller wanted it.
func (s *Spool) Remove(path string) error {
	if err := s.fsys.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// max is the cap in force, defaulting when Max was left zero.
func (s *Spool) max() int {
	if s.Max > 0 {
		return s.Max
	}
	return SpoolMaxFiles
}

// prune deletes the oldest payloads until the cap is met.
func (s *Spool) prune() error {
	paths, err := s.List()
	if err != nil {
		return err
	}
	if len(paths) <= s.max() {
		return nil
	}
	for _, path := range paths[:len(paths)-s.max()] {
		if err := s.Remove(path); err != nil {
			return err
		}
	}
	return nil
}

// freeName is the first unused file name for the current instant. Two payloads
// spooled inside the same millisecond differ by their sequence number, so one
// never overwrites the other.
func (s *Spool) freeName() (string, error) {
	stamp := s.clock.Now().UTC().Format(spoolTimeFormat)
	for seq := 0; seq < spoolMaxSeq; seq++ {
		path := joinPath(s.dir, fmt.Sprintf("%s%s-%03d%s", spoolPrefix, stamp, seq, spoolSuffix))
		_, err := s.fsys.Stat(path)
		if errors.Is(err, fs.ErrNotExist) {
			return path, nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("spool: no free file name at %s", stamp)
}

// isSpoolName reports whether a directory entry is one of this spool's
// payloads, so a stray file in the directory is never posted or deleted.
func isSpoolName(name string) bool {
	return strings.HasPrefix(name, spoolPrefix) && strings.HasSuffix(name, spoolSuffix)
}

// joinPath puts name under dir, keeping the separator dir is already written
// with. filepath.Join would rewrite a POSIX path on a Windows host, and the
// agent's filesystem uses paths as given.
func joinPath(dir, name string) string {
	if dir == "" {
		return name
	}
	if strings.HasSuffix(dir, "/") || strings.HasSuffix(dir, `\`) {
		return dir + name
	}
	if strings.Contains(dir, "/") && !strings.Contains(dir, `\`) {
		return dir + "/" + name
	}
	return dir + string(filepath.Separator) + name
}
