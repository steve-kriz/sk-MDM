// Package fake provides an in-memory stand-in for each interface in
// agent/internal/platform, so every test in the agent runs on a Windows or a
// macOS host, as a normal user, with no network and no temp files.
//
// Every fake is safe for concurrent use and every fake records what it was
// asked to do, so a test can assert on the file mode a save requested or the
// arguments a collector shelled out with.
package fake

import (
	"context"
	"io/fs"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// Compile-time proof the fakes satisfy the interfaces they stand in for.
var (
	_ platform.FileSystem    = (*FS)(nil)
	_ platform.CommandRunner = (*CommandRunner)(nil)
	_ platform.Clock         = (*Clock)(nil)
	_ platform.HTTPDoer      = (*HTTPDoer)(nil)
)

// FS is an in-memory platform.FileSystem.
//
// Paths are used as map keys exactly as given, so a test that seeds
// `C:\ProgramData\...\state.json` reads it back under that same string on any
// host. Directories are recorded by MkdirAll but never required: writing to a
// path whose parent was never created succeeds.
type FS struct {
	mu    sync.Mutex
	files map[string]*fakeFile
	dirs  map[string]bool

	// ReadErr, WriteErr, StatErr and RemoveErr, when set and when they return
	// a non-nil error, make that operation fail for that path. RenameErr does
	// the same for a rename.
	ReadErr   func(path string) error
	WriteErr  func(path string) error
	StatErr   func(path string) error
	RemoveErr func(path string) error
	RenameErr func(oldPath, newPath string) error
}

type fakeFile struct {
	data []byte
	perm fs.FileMode
	mod  time.Time
}

// NewFS returns an empty filesystem.
func NewFS() *FS {
	return &FS{files: map[string]*fakeFile{}, dirs: map[string]bool{}}
}

// Seed places data at path with mode 0600, bypassing every failure hook. It is
// how a test arranges a config or state file that already exists.
func (f *FS) Seed(path string, data []byte) {
	f.SeedMode(path, data, 0o600)
}

// SeedMode is Seed with an explicit mode.
func (f *FS) SeedMode(path string, data []byte, perm fs.FileMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[path] = &fakeFile{data: append([]byte(nil), data...), perm: perm}
}

// Content returns the bytes at path and whether the file exists.
func (f *FS) Content(path string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	file, ok := f.files[path]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), file.data...), true
}

// Mode returns the mode the file at path was created with.
func (f *FS) Mode(path string) (fs.FileMode, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	file, ok := f.files[path]
	if !ok {
		return 0, false
	}
	return file.perm, true
}

// Exists reports whether path holds a file.
func (f *FS) Exists(path string) bool {
	_, ok := f.Content(path)
	return ok
}

// Paths lists every file, sorted, which keeps assertions about leftover temp
// files readable.
func (f *FS) Paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	paths := make([]string, 0, len(f.files))
	for path := range f.files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

// Dirs lists every directory MkdirAll was asked for, sorted.
func (f *FS) Dirs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	dirs := make([]string, 0, len(f.dirs))
	for dir := range f.dirs {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	return dirs
}

// FailWrite makes every write to path fail with err. It is the short way to
// arrange "a fake filesystem that fails the write of the temp file".
func (f *FS) FailWrite(path string, err error) {
	f.WriteErr = func(candidate string) error {
		if candidate == path {
			return err
		}
		return nil
	}
}

// ReadFile returns the bytes at path.
func (f *FS) ReadFile(path string) ([]byte, error) {
	if f.ReadErr != nil {
		if err := f.ReadErr(path); err != nil {
			return nil, &fs.PathError{Op: "read", Path: path, Err: err}
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	file, ok := f.files[path]
	if !ok {
		return nil, &fs.PathError{Op: "read", Path: path, Err: fs.ErrNotExist}
	}
	return append([]byte(nil), file.data...), nil
}

// WriteFile replaces the file at path.
func (f *FS) WriteFile(path string, data []byte, perm fs.FileMode) error {
	if f.WriteErr != nil {
		if err := f.WriteErr(path); err != nil {
			return &fs.PathError{Op: "write", Path: path, Err: err}
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[path] = &fakeFile{data: append([]byte(nil), data...), perm: perm}
	return nil
}

// AppendFile appends to the file at path, creating it when absent.
func (f *FS) AppendFile(path string, data []byte, perm fs.FileMode) error {
	if f.WriteErr != nil {
		if err := f.WriteErr(path); err != nil {
			return &fs.PathError{Op: "append", Path: path, Err: err}
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	file, ok := f.files[path]
	if !ok {
		file = &fakeFile{perm: perm}
		f.files[path] = file
	}
	file.data = append(file.data, data...)
	return nil
}

// Rename moves oldPath onto newPath, replacing newPath when it exists.
func (f *FS) Rename(oldPath, newPath string) error {
	if f.RenameErr != nil {
		if err := f.RenameErr(oldPath, newPath); err != nil {
			return &fs.PathError{Op: "rename", Path: oldPath, Err: err}
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	file, ok := f.files[oldPath]
	if !ok {
		return &fs.PathError{Op: "rename", Path: oldPath, Err: fs.ErrNotExist}
	}
	delete(f.files, oldPath)
	f.files[newPath] = file
	return nil
}

// Remove deletes path.
func (f *FS) Remove(path string) error {
	if f.RemoveErr != nil {
		if err := f.RemoveErr(path); err != nil {
			return &fs.PathError{Op: "remove", Path: path, Err: err}
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.files[path]; !ok {
		return &fs.PathError{Op: "remove", Path: path, Err: fs.ErrNotExist}
	}
	delete(f.files, path)
	return nil
}

// Stat reports on path.
func (f *FS) Stat(path string) (fs.FileInfo, error) {
	if f.StatErr != nil {
		if err := f.StatErr(path); err != nil {
			return nil, &fs.PathError{Op: "stat", Path: path, Err: err}
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	file, ok := f.files[path]
	if !ok {
		return nil, &fs.PathError{Op: "stat", Path: path, Err: fs.ErrNotExist}
	}
	return fileInfo{name: baseName(path), size: int64(len(file.data)), mode: file.perm, mod: file.mod}, nil
}

// MkdirAll records the directory.
func (f *FS) MkdirAll(path string, _ fs.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dirs[path] = true
	return nil
}

// baseName is the last path element under either separator, so the fake stays
// host-independent for Windows and POSIX paths alike.
func baseName(path string) string {
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		return path[i+1:]
	}
	return path
}

type fileInfo struct {
	name string
	size int64
	mode fs.FileMode
	mod  time.Time
}

func (i fileInfo) Name() string       { return i.name }
func (i fileInfo) Size() int64        { return i.size }
func (i fileInfo) Mode() fs.FileMode  { return i.mode }
func (i fileInfo) ModTime() time.Time { return i.mod }
func (i fileInfo) IsDir() bool        { return false }
func (i fileInfo) Sys() any           { return nil }

// Command is one recorded call to CommandRunner.Run.
type Command struct {
	Name string
	Args []string
}

// String renders the call as "name arg arg", which is also the key Results and
// Errors are looked up under.
func (c Command) String() string {
	if len(c.Args) == 0 {
		return c.Name
	}
	return c.Name + " " + strings.Join(c.Args, " ")
}

// CommandRunner is an in-memory platform.CommandRunner.
//
// Results and Errors are keyed by the full command line, e.g.
// "powershell -Command Get-Disk". A command with no entry in either map
// returns an empty, successful result.
type CommandRunner struct {
	mu    sync.Mutex
	calls []Command

	Results map[string]platform.CommandResult
	Errors  map[string]error
}

// NewCommandRunner returns a runner with no canned results.
func NewCommandRunner() *CommandRunner {
	return &CommandRunner{Results: map[string]platform.CommandResult{}, Errors: map[string]error{}}
}

// Run records the call and replays whatever was arranged for it.
func (r *CommandRunner) Run(ctx context.Context, name string, args ...string) (platform.CommandResult, error) {
	call := Command{Name: name, Args: append([]string(nil), args...)}

	r.mu.Lock()
	r.calls = append(r.calls, call)
	r.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return platform.CommandResult{}, err
	}
	if err, ok := r.Errors[call.String()]; ok && err != nil {
		return platform.CommandResult{}, err
	}
	return r.Results[call.String()], nil
}

// Calls returns every recorded call, in order.
func (r *CommandRunner) Calls() []Command {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Command(nil), r.calls...)
}

// Clock is a manually driven platform.Clock: it never advances on its own, so
// a test that waits on an interval is instantaneous and never flaky.
//
// Every duration passed to After is recorded, so a test can assert on the
// backoff a retry loop slept through without timing anything.
type Clock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*timer
	waits  []time.Duration

	// AutoAdvance makes After move the clock forward by d and fire at once,
	// instead of waiting for Advance. It is how a single-goroutine test
	// drives a retry loop to completion; the waits are still recorded.
	AutoAdvance bool
}

type timer struct {
	at time.Time
	ch chan time.Time
}

// NewClock returns a clock stopped at start.
func NewClock(start time.Time) *Clock {
	return &Clock{now: start}
}

// Now is the current fake time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// After returns a channel that fires once Advance has moved the clock d past
// the moment of the call. A non-positive d fires immediately. With
// AutoAdvance set, the clock moves itself forward by d and the channel is
// already fired when it comes back.
func (c *Clock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	c.waits = append(c.waits, d)
	auto := c.AutoAdvance
	ch := make(chan time.Time, 1)

	if d <= 0 {
		ch <- c.now
		c.mu.Unlock()
		return ch
	}
	if auto {
		c.mu.Unlock()
		c.Advance(d)
		ch <- c.Now()
		return ch
	}

	c.timers = append(c.timers, &timer{at: c.now.Add(d), ch: ch})
	c.mu.Unlock()
	return ch
}

// Waits returns every duration After was asked for, in order: the sleeps the
// code under test performed.
func (c *Clock) Waits() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.waits...)
}

// Advance moves the clock forward and fires every timer that has come due.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now

	remaining := c.timers[:0]
	var due []*timer
	for _, t := range c.timers {
		if !t.at.After(now) {
			due = append(due, t)
			continue
		}
		remaining = append(remaining, t)
	}
	c.timers = remaining
	c.mu.Unlock()

	for _, t := range due {
		t.ch <- now
	}
}

// Set moves the clock to an absolute time, firing any timer that has come due.
func (c *Clock) Set(at time.Time) {
	c.mu.Lock()
	delta := at.Sub(c.now)
	c.mu.Unlock()
	c.Advance(delta)
}

// HTTPDoer is an in-memory platform.HTTPDoer. It records every request and
// replays whatever DoFunc returns; with no DoFunc it answers 200 with an empty
// body, so no test ever reaches the network.
type HTTPDoer struct {
	mu       sync.Mutex
	requests []*http.Request

	DoFunc func(req *http.Request) (*http.Response, error)
}

// NewHTTPDoer returns a doer that answers every request with 200 and an empty
// JSON object.
func NewHTTPDoer() *HTTPDoer { return &HTTPDoer{} }

// Do records the request and replays the arranged response.
func (d *HTTPDoer) Do(req *http.Request) (*http.Response, error) {
	d.mu.Lock()
	d.requests = append(d.requests, req)
	d.mu.Unlock()

	if d.DoFunc != nil {
		return d.DoFunc(req)
	}
	return Response(http.StatusOK, "{}"), nil
}

// Requests returns every recorded request, in order.
func (d *HTTPDoer) Requests() []*http.Request {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]*http.Request(nil), d.requests...)
}

// Response builds a response with this status and body, ready to return from
// a DoFunc.
func Response(status int, body string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Status:        http.StatusText(status),
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          newBody(body),
		ContentLength: int64(len(body)),
	}
}

func newBody(body string) *bodyReader {
	return &bodyReader{Reader: strings.NewReader(body)}
}

type bodyReader struct {
	*strings.Reader
}

func (b *bodyReader) Close() error { return nil }
