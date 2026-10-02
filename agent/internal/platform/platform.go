// Package platform holds every interface through which the agent touches the
// operating system: the filesystem, external commands, the clock and the
// network.
//
// The rule the rest of the agent follows is simple: no package under
// agent/internal outside this one imports os/exec or reads a file with os
// directly. Everything goes through the interfaces declared here, so the whole
// suite runs on a Windows or a macOS host, as a normal user, with no network,
// by handing the code the fakes in agent/internal/platform/fake.
//
// The concrete, OS-backed implementations live in system.go next door; they are
// the only code in the repository allowed to call os and os/exec.
package platform

import (
	"context"
	"io/fs"
	"net/http"
	"time"
)

// FileSystem is every file operation the agent performs.
//
// Paths are passed through untouched: a caller that hands over a Windows path
// gets that same key back from a fake. Implementations create nothing
// implicitly — a caller that needs a parent directory calls MkdirAll itself.
type FileSystem interface {
	// ReadFile returns the whole file. A missing file yields an error that
	// satisfies errors.Is(err, fs.ErrNotExist).
	ReadFile(path string) ([]byte, error)

	// WriteFile replaces the file at path, creating it with perm when it does
	// not exist yet.
	WriteFile(path string, data []byte, perm fs.FileMode) error

	// AppendFile appends to the file at path, creating it with perm when it
	// does not exist yet.
	AppendFile(path string, data []byte, perm fs.FileMode) error

	// Rename moves oldPath onto newPath, replacing newPath when it already
	// exists. Replacing an existing target is the part that differs between
	// hosts, so every implementation must guarantee it.
	Rename(oldPath, newPath string) error

	// Remove deletes path. Removing a file that is not there is an error that
	// satisfies errors.Is(err, fs.ErrNotExist).
	Remove(path string) error

	// Stat reports on path, principally its size for log rotation.
	Stat(path string) (fs.FileInfo, error)

	// ReadDir lists the entries of the directory at path, sorted by file
	// name. It is what lets the check-in spool find the payloads an earlier
	// run left behind without keeping an index of its own.
	ReadDir(path string) ([]fs.DirEntry, error)

	// MkdirAll creates path and every missing parent.
	MkdirAll(path string, perm fs.FileMode) error
}

// CommandResult is what a finished external command produced.
type CommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// CommandRunner runs an external command to completion and captures its
// output.
//
// A command that runs and exits non-zero is not an error: the exit code lands
// in CommandResult.ExitCode and err is nil. The error return is for commands
// that could not be started at all, or that the context cancelled.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) (CommandResult, error)
}

// Clock is the agent's view of time. Nothing outside this package calls
// time.Now, so tests can drive check-in intervals and log timestamps.
type Clock interface {
	// Now is the current time.
	Now() time.Time

	// After delivers one value on the returned channel once d has passed.
	After(d time.Duration) <-chan time.Time
}

// HTTPDoer is the one HTTP call shape the agent makes. *http.Client satisfies
// it, as does the fake in agent/internal/platform/fake.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}
