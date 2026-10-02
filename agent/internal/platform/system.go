package platform

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// OSFileSystem is the real filesystem.
type OSFileSystem struct{}

// Compile-time proof the real implementations satisfy the interfaces.
var (
	_ FileSystem    = OSFileSystem{}
	_ CommandRunner = ExecRunner{}
	_ Clock         = SystemClock{}
	_ HTTPDoer      = (*http.Client)(nil)
)

// ReadFile reads the whole file at path.
func (OSFileSystem) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

// WriteFile replaces the file at path.
func (OSFileSystem) WriteFile(path string, data []byte, perm fs.FileMode) error {
	return os.WriteFile(path, data, perm)
}

// AppendFile appends data to the file at path, creating it when absent.
func (OSFileSystem) AppendFile(path string, data []byte, perm fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Rename moves oldPath onto newPath, replacing an existing newPath.
//
// A plain os.Rename onto an existing file is not uniformly available across
// hosts — on Windows it depends on the file not being held open by another
// handle, and on some volumes it fails outright with ERROR_ALREADY_EXISTS.
// Every atomic save and every log rotation in the agent renames over a file
// that is already there, so the fallback lives here rather than at each call
// site: if the first rename fails and the target exists, drop the target and
// retry once.
func (OSFileSystem) Rename(oldPath, newPath string) error {
	err := os.Rename(oldPath, newPath)
	if err == nil {
		return nil
	}
	if _, statErr := os.Stat(newPath); statErr != nil {
		return err
	}
	if removeErr := os.Remove(newPath); removeErr != nil {
		return err
	}
	return os.Rename(oldPath, newPath)
}

// Remove deletes path.
func (OSFileSystem) Remove(path string) error { return os.Remove(path) }

// Stat reports on path.
func (OSFileSystem) Stat(path string) (fs.FileInfo, error) { return os.Stat(path) }

// ReadDir lists the directory at path, sorted by file name.
func (OSFileSystem) ReadDir(path string) ([]fs.DirEntry, error) { return os.ReadDir(path) }

// MkdirAll creates path and every missing parent.
func (OSFileSystem) MkdirAll(path string, perm fs.FileMode) error {
	return os.MkdirAll(path, perm)
}

// ExecRunner runs real external commands.
type ExecRunner struct{}

// Run executes name with args and captures stdout and stderr. A non-zero exit
// status is reported in the result, not as an error; only a command that could
// not run at all returns one.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	cmd := exec.CommandContext(ctx, name, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := CommandResult{Stdout: stdout.String(), Stderr: stderr.String()}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, nil
	}
	if err != nil {
		return result, err
	}
	return result, nil
}

// SystemClock is the real clock.
type SystemClock struct{}

// Now is the current wall-clock time.
func (SystemClock) Now() time.Time { return time.Now() }

// After delivers one value once d has passed.
func (SystemClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// NewHTTPClient returns the HTTP client the agent talks to the collection
// endpoint with. The timeout covers the whole exchange, so a stalled check-in
// cannot wedge the agent.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

// WriteFileAtomic writes data to path+".tmp" and renames that over path, so a
// reader of path never sees a half-written file and a failed write leaves the
// previous contents in place.
//
// The parent directory is created first when it is missing. When the write of
// the temp file fails, path is left exactly as it was.
func WriteFileAtomic(fsys FileSystem, path string, data []byte, perm fs.FileMode) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := fsys.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}

	tmp := path + ".tmp"
	if err := fsys.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := fsys.Rename(tmp, path); err != nil {
		// Best effort: a leftover temp file must not be mistaken for the
		// real one on the next read.
		_ = fsys.Remove(tmp)
		return err
	}
	return nil
}
