// Package update replaces the agent with the build the backend advertised.
//
// A check-in that answers with an agentRelease is the whole trigger: Apply
// downloads the build, refuses it unless its SHA-256 is the one the backend
// published and unless its version is actually ahead of this one, swaps it for
// the installed binary and asks the service manager to restart the agent.
//
// The swap is deliberately one-way and the verification is deliberately not
// part of it. Apply leaves the binary it replaced at <path>.old, writes
// <path>.update-pending naming the version it installed, and restarts the
// service as its very last action -- which kills the process that is running
// Apply. Nothing after that restart could be run by this process, so whether
// the new build actually works is settled by the build itself: the next process
// to start calls RollbackIfUnhealthy, which finds the marker, compares it with
// the version it was compiled as, and either clears the marker or puts the old
// binary back and restarts again.
//
// Everything that touches the host -- the filesystem, the download and the
// restart -- arrives through Deps, so the whole package runs in a test with no
// disk, no network and no service manager.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/version"
)

// The two files an update leaves beside the installed binary.
const (
	// OldSuffix names the binary that was replaced, kept until the new one
	// has reported itself healthy.
	OldSuffix = ".old"
	// PendingSuffix names the marker holding the version just installed. Its
	// presence at start-up is what makes that start a verification.
	PendingSuffix = ".update-pending"
)

// File modes for what an update writes.
const (
	// BinaryFileMode is the mode the installed agent is written with: owner
	// writable, everyone executable, the mode an installer gives it.
	BinaryFileMode fs.FileMode = 0o755
	// MarkerFileMode is the mode the pending marker is written with.
	MarkerFileMode fs.FileMode = 0o600
)

// MaxDownloadBytes caps what a download may feed into memory, so an endpoint
// answering with something other than an agent build cannot exhaust the device.
const MaxDownloadBytes int64 = 128 << 20 // 128 MB

// Deps is everything an update is performed through.
//
// Path is the installed binary, and the two files an update leaves are derived
// from it, so a test points the whole package at a directory of its own.
type Deps struct {
	// FS is where the binary, the replaced binary and the marker live.
	FS platform.FileSystem

	// Doer fetches the build.
	Doer platform.HTTPDoer

	// Logger, when non-nil, records the swap and the rollback. Nothing else
	// in this package writes a line.
	Logger *logging.Logger

	// Path is the installed agent binary: the file that is replaced.
	Path string

	// Restart asks the service manager to restart the agent. Left nil,
	// nothing is restarted and the new build takes over at the next start.
	Restart func(ctx context.Context) error

	// CurrentVersion is the version of the running build. Empty means
	// version.Version, which is what the production wiring leaves it as; a
	// test sets it to drive the upgrade check and the health check.
	CurrentVersion string
}

// OldPath is where the binary an update replaced is kept.
func OldPath(path string) string { return path + OldSuffix }

// PendingPath is where the marker naming the installed version is written.
func PendingPath(path string) string { return path + PendingSuffix }

// Apply installs rel over the running agent and restarts the service.
//
// Nothing is touched unless all three of these hold: rel names a version ahead
// of the running one, the build downloads, and its SHA-256 is the digest the
// backend published. A failure of any of them returns an error having created
// nothing, renamed nothing and left the installed binary byte-identical --
// an advertised update that cannot be trusted is simply not applied, and the
// next check-in advertises it again.
//
// On success the operations are, in order: the previous update's <path>.old is
// deleted, the running binary becomes <path>.old, the downloaded build becomes
// <path>, <path>.update-pending is written with rel's version, one line is
// logged, and the service manager is asked to restart. The restart is last
// because it ends this process; Apply makes no attempt to check the new build,
// which is RollbackIfUnhealthy's job on the next start.
func Apply(ctx context.Context, rel contract.AgentRelease, deps *Deps) error {
	if deps == nil {
		return errors.New("update: nil deps")
	}
	if deps.FS == nil {
		return errors.New("update: no filesystem")
	}
	if deps.Path == "" {
		return errors.New("update: no binary path")
	}

	// The upgrade check comes first, so a build that would not be installed
	// is never even downloaded.
	current := deps.currentVersion()
	if !isUpgrade(current, rel.Version) {
		return fmt.Errorf("update: %s is not an upgrade on %s", rel.Version, current)
	}

	build, err := deps.download(ctx, rel.URL)
	if err != nil {
		return err
	}

	digest := sha256.Sum256(build)
	got := hex.EncodeToString(digest[:])
	if !strings.EqualFold(got, rel.SHA256) {
		return fmt.Errorf("update: checksum mismatch: expected %s, downloaded %s", rel.SHA256, got)
	}

	old := OldPath(deps.Path)
	// Whatever an earlier update left is gone before this one starts, so the
	// rollback copy is always the build this update replaced.
	if err := deps.remove(old); err != nil {
		return err
	}
	if err := deps.FS.Rename(deps.Path, old); err != nil {
		return err
	}
	if err := deps.FS.WriteFile(deps.Path, build, BinaryFileMode); err != nil {
		return err
	}
	if err := deps.FS.WriteFile(PendingPath(deps.Path), []byte(rel.Version), MarkerFileMode); err != nil {
		return err
	}

	deps.log(logging.LevelInfo, "agent updated",
		logging.F("previousVersion", current),
		logging.F("version", rel.Version),
	)

	return deps.restart(ctx)
}

// RollbackIfUnhealthy settles the update the previous process applied. It is
// called once at start-up, before the scheduler runs.
//
// The marker <path>.update-pending is the whole question: absent, there is
// nothing to settle and nothing is touched. Present and naming the version this
// build was compiled as, the swap worked -- the marker and the replaced binary
// are deleted and the update is over. Present and naming anything else, the
// binary that is running is not the one that was installed, so the replaced
// build is put back and the service is restarted onto it.
func RollbackIfUnhealthy(deps *Deps) error {
	if deps == nil {
		return errors.New("update: nil deps")
	}
	if deps.FS == nil {
		return errors.New("update: no filesystem")
	}
	if deps.Path == "" {
		return errors.New("update: no binary path")
	}

	pending := PendingPath(deps.Path)
	marker, err := deps.FS.ReadFile(pending)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}

	installed := strings.TrimSpace(string(marker))
	current := deps.currentVersion()
	if installed == current {
		// The build that was installed is the build that is running.
		if err := deps.FS.Remove(pending); err != nil {
			return err
		}
		return deps.remove(OldPath(deps.Path))
	}

	if err := deps.FS.Rename(OldPath(deps.Path), deps.Path); err != nil {
		return err
	}
	if err := deps.FS.Remove(pending); err != nil {
		return err
	}

	deps.log(logging.LevelWarn, "update rollback",
		logging.F("installedVersion", installed),
		logging.F("runningVersion", current),
	)

	return deps.restart(context.Background())
}

// download fetches the build, refusing anything the endpoint did not answer
// 2xx with. The status is in the error text because it is the one thing that
// tells a misconfigured url from an expired one.
func (d *Deps) download(ctx context.Context, rawURL string) ([]byte, error) {
	if d.Doer == nil {
		return nil, errors.New("update: no http client")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("update: %w", err)
	}

	resp, err := d.Doer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("update: download failed: %w", err)
	}
	defer closeBody(resp)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("update: download failed with status %d", resp.StatusCode)
	}

	build, err := readBody(resp)
	if err != nil {
		return nil, fmt.Errorf("update: download failed: %w", err)
	}
	return build, nil
}

// remove deletes path, treating a file that is not there as deleted: a first
// update has no <path>.old to clear and a healthy start may have none either.
func (d *Deps) remove(path string) error {
	if err := d.FS.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// restart asks the service manager to restart the agent, when a hook was given.
func (d *Deps) restart(ctx context.Context) error {
	if d.Restart == nil {
		return nil
	}
	return d.Restart(ctx)
}

// currentVersion is the version of the running build.
func (d *Deps) currentVersion() string {
	if d.CurrentVersion != "" {
		return d.CurrentVersion
	}
	return version.Version
}

// log writes one record when a logger was given. A failed write is dropped: the
// agent has nowhere better to report it, and a full disk must not stop an
// update that has already happened.
func (d *Deps) log(level logging.Level, msg string, fields ...logging.Field) {
	if d.Logger == nil {
		return
	}
	_ = d.Logger.Log(level, msg, fields...)
}

// isUpgrade reports whether next is a later version than current.
//
// A version that cannot be read as major.minor.patch is never an upgrade: the
// agent replaces itself only when it can prove the replacement is newer. A
// running version that cannot be read -- a development build, say -- counts as
// zero, so a release always moves it forward.
func isUpgrade(current, next string) bool {
	wanted, ok := parseVersion(next)
	if !ok {
		return false
	}
	running, ok := parseVersion(current)
	if !ok {
		running = nil
	}
	return compareVersions(wanted, running) > 0
}

// parseVersion reads the dotted numeric components of a version, ignoring any
// pre-release or build suffix ("0.0.0-dev" is 0.0.0).
func parseVersion(value string) ([]int, bool) {
	text := strings.TrimSpace(value)
	if cut := strings.IndexAny(text, "-+"); cut >= 0 {
		text = text[:cut]
	}
	if text == "" {
		return nil, false
	}

	parts := strings.Split(text, ".")
	numbers := make([]int, 0, len(parts))
	for _, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return nil, false
		}
		numbers = append(numbers, number)
	}
	return numbers, true
}

// compareVersions orders two parsed versions, treating a missing component as
// zero so "1.3" and "1.3.0" are the same version.
func compareVersions(a, b []int) int {
	length := len(a)
	if len(b) > length {
		length = len(b)
	}
	for i := 0; i < length; i++ {
		left, right := componentAt(a, i), componentAt(b, i)
		if left != right {
			if left > right {
				return 1
			}
			return -1
		}
	}
	return 0
}

// componentAt is the i-th component of a parsed version, or zero.
func componentAt(numbers []int, i int) int {
	if i < len(numbers) {
		return numbers[i]
	}
	return 0
}

// readBody reads at most MaxDownloadBytes of a response body.
func readBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	return io.ReadAll(io.LimitReader(resp.Body, MaxDownloadBytes))
}

// closeBody closes a response body the download is done with.
func closeBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}
