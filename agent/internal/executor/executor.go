// Package executor runs the commands the backend leases to this device and
// reports what each one did.
//
// Three rules shape every execution:
//
//   - The result body is exactly the four fields TASK-008 validates —
//     status, exitCode, output and finishedAt — and nothing else. There is no
//     error field on the wire: a failure that is not a process exit folds into
//     output as a first line "error: <code>", with exitCode -1.
//   - Nothing runs unbounded. Every command is run with a timeout, its output
//     is truncated to the last MaxOutputBytes bytes, and a command that passes
//     its timeout is killed.
//   - A command runs at most once. Poll records each commandId with its result
//     before reporting it, so a command the backend leases again reports the
//     stored result instead of running a second time.
//
// Everything that touches the operating system — the clock, the filesystem and
// the commands themselves — arrives through agent/internal/platform, so the
// whole package runs in a test with no disk, no network and no wall clock.
package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// The command types this agent executes. Anything else is refused without
// running a thing.
const (
	TypeRunScript        = "run_script"
	TypeRestart          = "restart"
	TypeLock             = "lock"
	TypeInstallPackage   = "install_package"
	TypeUninstallPackage = "uninstall_package"
	TypeCollectLogs      = "collect_logs"
	// TypeInstallApplication installs an application from the backend's
	// application safe list (TASK-049).
	TypeInstallApplication = "install_application"
)

// The two result statuses the backend accepts.
const (
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
)

// FailureExitCode is the exit code reported for every failure that is not a
// process exit: there is no process, so there is no code to report.
const FailureExitCode = -1

// MaxOutputBytes is how much output a result carries: the last of it, because
// the tail of a failing run is what says why it failed.
const MaxOutputBytes = 8192

// The error codes that can appear as the first line of an output, as
// "error: <code>".
const (
	// ErrUnsupportedType is a command type this agent does not implement.
	ErrUnsupportedType = "unsupported_command_type"
	// ErrInvalidPayload is a payload missing a required field, or carrying
	// one of the wrong JSON type.
	ErrInvalidPayload = "invalid_payload"
	// ErrUnsupportedPlatform is a command this agent implements, on a
	// platform where it has no implementation.
	ErrUnsupportedPlatform = "unsupported_on_platform"
	// ErrTimeout is a command killed for passing its effective timeout.
	ErrTimeout = "timeout"
	// ErrLogsTooLarge is a log archive past MaxLogArchiveBytes.
	ErrLogsTooLarge = "logs_too_large"
	// ErrExecutionFailed is a command that could not be started at all, or a
	// temp file that could not be written.
	ErrExecutionFailed = "execution_failed"
	// ErrLogsFailed is a log archive that could not be built or written.
	ErrLogsFailed = "logs_failed"
	// ErrUnsupportedInterpreter is a run_script interpreter that is valid,
	// but not on this platform (cmd/powershell on macOS, bash/zsh on Windows).
	ErrUnsupportedInterpreter = "unsupported_interpreter"
	// ErrApplicationUnavailable is an install_application whose application
	// the backend no longer has (deleted after the install was queued).
	ErrApplicationUnavailable = "application_unavailable"
	// ErrDownloadFailed is an application whose download details or bytes
	// could not be fetched.
	ErrDownloadFailed = "download_failed"
	// ErrDownloadTooLarge is an application download past MaxApplicationBytes.
	ErrDownloadTooLarge = "download_too_large"
	// ErrChecksumMismatch is a downloaded application whose SHA-256 is not
	// the one the backend registered for it.
	ErrChecksumMismatch = "checksum_mismatch"
)

// MaxApplicationBytes is the largest application installer the agent will
// download (2 GiB); a larger one is refused and nothing is run.
const MaxApplicationBytes = 2147483648

// ApplicationDownloadTimeout bounds one whole application download, body
// included. It is the timeout of the Downloader the agent is wired with.
const ApplicationDownloadTimeout = 30 * time.Minute

// Temp directory locations, beside the config, state and spool the installer
// creates. Scripts and log archives are written here, never to a world-
// writable system temp directory.
const (
	// WindowsTempDir is the agent's scratch directory on Windows.
	WindowsTempDir = `C:\ProgramData\OfficeHQ\MDM\tmp`
	// DarwinTempDir is the agent's scratch directory on macOS.
	DarwinTempDir = "/Library/Application Support/OfficeHQ/MDM/tmp"
)

// File modes for what an execution writes. A script carries whatever the
// backend sent and an archive carries the agent's logs, so neither asks for
// group or world access.
const (
	// TempDirMode is the mode the temp directory is created with.
	TempDirMode = 0o700
	// TempFileMode is the mode a script or an archive is written with.
	TempFileMode = 0o600
)

// killGrace is how long a killed command is given to return what it captured
// before the result is reported without it. It is a backstop against a runner
// that ignores cancellation, not a timing decision: the timeout itself is
// measured on the injected clock.
const killGrace = 2 * time.Second

// Deps is everything an execution needs.
//
// Runner, FS and Clock are required; the rest have defaults or are only used
// by Poll.
type Deps struct {
	// Runner runs every external command.
	Runner platform.CommandRunner

	// FS writes the temp script and the log archive.
	FS platform.FileSystem

	// Clock stamps finishedAt and times every command out.
	Clock platform.Clock

	// Logger, when non-nil, records each command. Nothing written here
	// carries the script body or the device secret.
	Logger *logging.Logger

	// GOOS selects the argv for a command; empty means this build's GOOS.
	GOOS string

	// TempDir is where scripts and archives are written; empty means
	// TempDir(GOOS).
	TempDir string

	// LogDir is the directory collect_logs archives; empty means
	// LogDir(GOOS).
	LogDir string

	// Client is the transport Poll leases and reports through.
	Client Transport

	// DeviceID is the device the lease and result paths are built from.
	DeviceID string

	// Store holds the commands this agent has already completed, so a
	// re-leased command is reported rather than run again.
	Store *Store

	// MaxCommands is how many commands one lease asks for; zero means
	// DefaultMaxCommands.
	MaxCommands int

	// Downloader fetches application installers from their (presigned or
	// registered) URL with a plain, unsigned GET. Nil refuses every
	// install_application with download_failed.
	Downloader platform.HTTPDoer
}

// TempDir returns the scratch directory for a GOOS value: the Windows path for
// "windows" and the macOS path for anything else, the agent shipping for those
// two platforms only.
func TempDir(goos string) string {
	if goos == "windows" {
		return WindowsTempDir
	}
	return DarwinTempDir
}

// Execute runs one leased command and returns the result to report for it.
//
// It never returns an error: everything that can go wrong is a result the
// backend is told about. Every path through it — success, refusal, bad
// payload, timeout — stamps finishedAt from the injected clock.
func Execute(ctx context.Context, cmd Command, deps *Deps) contract.CommandResultRequest {
	switch cmd.Type {
	case TypeRunScript:
		return runScript(ctx, cmd, deps)
	case TypeRestart:
		return runPower(ctx, cmd, deps, restartArgv)
	case TypeLock:
		return runPower(ctx, cmd, deps, lockArgv)
	case TypeInstallPackage:
		return installPackage(ctx, cmd, deps)
	case TypeUninstallPackage:
		return uninstallPackage(ctx, cmd, deps)
	case TypeCollectLogs:
		return collectLogs(cmd, deps)
	case TypeInstallApplication:
		return installApplication(ctx, cmd, deps)
	default:
		return deps.fail(ErrUnsupportedType, "")
	}
}

// Transport is the part of the TASK-015 client the executor uses: one signed
// request. *client.Client satisfies it.
type Transport interface {
	Do(method, path string, body []byte) (*http.Response, error)
}

// DefaultMaxCommands is how many commands one lease asks for.
const DefaultMaxCommands = 10

// maxResponseBytes caps what a lease response may feed the JSON decoder, so a
// misbehaving endpoint cannot exhaust the agent's memory.
const maxResponseBytes = 1 << 20 // 1 MB

// LeasePath is the command lease endpoint for a device.
func LeasePath(deviceID string) string {
	return "/api/v1/devices/" + url.PathEscape(deviceID) + "/commands"
}

// ResultPath is the result endpoint for one leased command.
func ResultPath(deviceID, commandID string) string {
	return LeasePath(deviceID) + "/" + url.PathEscape(commandID) + "/result"
}

// Poll leases the device's commands, runs them and reports each result. It is
// what the scheduler's AfterCheckIn hook calls once a check-in has said there
// is work.
//
// Three things make a command run at most once and be reported at least once:
// a result that could not be posted stays in the store and is retried at the
// top of the next cycle; a command already in the store is reported from it
// rather than run again; and a lease that fails costs this cycle's commands,
// not the cycle.
//
// A command whose payload carries stopOnFailure: true and whose result is
// failed — fresh or replayed from the store — stops the batch: the rest of the
// leased commands are not run, not recorded and not reported.
func Poll(ctx context.Context, deps *Deps) error {
	if deps == nil {
		return errors.New("executor: nil deps")
	}
	if deps.Client == nil {
		return errors.New("executor: no client")
	}
	if deps.DeviceID == "" {
		return errors.New("executor: no device id")
	}
	if deps.Store == nil {
		return errors.New("executor: no command store")
	}

	deps.retryResults()

	commands, ok := deps.lease()
	if !ok {
		return nil
	}
	for _, cmd := range commands {
		result := deps.handle(ctx, cmd)
		if result.Status == StatusFailed && stopOnFailure(cmd.Payload) {
			deps.log(logging.LevelInfo, "command failed with stopOnFailure; batch stopped",
				logging.F("commandId", cmd.CommandID),
			)
			break
		}
	}
	return nil
}

// lease asks for this device's commands. The second return is false when there
// is nothing to run — the request failed, the status was not 200, or the body
// was not a lease — and the cycle then carries on with one warning.
func (d *Deps) lease() ([]Command, bool) {
	path := LeasePath(d.DeviceID) + "?max=" + strconv.Itoa(d.maxCommands())

	resp, err := d.Client.Do(http.MethodGet, path, nil)
	if err != nil {
		d.log(logging.LevelWarn, "command lease failed", logging.F("error", err.Error()))
		return nil, false
	}
	defer closeBody(resp)

	if resp.StatusCode != http.StatusOK {
		d.log(logging.LevelWarn, "command lease failed", logging.F("status", resp.StatusCode))
		return nil, false
	}

	data, err := readBody(resp)
	if err != nil {
		d.log(logging.LevelWarn, "command lease unreadable", logging.F("error", err.Error()))
		return nil, false
	}

	var lease contract.CommandLeaseResponse
	if err := json.Unmarshal(data, &lease); err != nil {
		d.log(logging.LevelWarn, "command lease unreadable", logging.F("error", err.Error()))
		return nil, false
	}

	commands := make([]Command, 0, len(lease.Commands))
	for _, item := range lease.Commands {
		commands = append(commands, Command(item))
	}
	return commands, true
}

// handle runs one leased command and reports it, or reports what it already
// knows about it.
//
// A command the store has seen is never run again: the backend leasing it a
// second time means it did not get the result, so it gets the stored one.
//
// It returns the result it reported, fresh or stored, so Poll can stop the
// batch after a flagged failure.
func (d *Deps) handle(ctx context.Context, cmd Command) contract.CommandResultRequest {
	record, found, err := d.Store.Lookup(cmd.CommandID)
	if err != nil {
		d.log(logging.LevelWarn, "command store unreadable", logging.F("error", err.Error()))
	}
	if found {
		d.log(logging.LevelInfo, "command already completed",
			logging.F("commandId", cmd.CommandID),
		)
		d.deliver(record.CommandID, record.Result)
		return record.Result
	}

	result := Execute(ctx, cmd, d)

	// Recorded before it is reported: a crash here costs the report, which
	// the next cycle retries, never a second execution.
	if err := d.Store.Record(cmd.CommandID, result); err != nil {
		d.log(logging.LevelWarn, "command result not recorded",
			logging.F("commandId", cmd.CommandID),
			logging.F("error", err.Error()),
		)
	}
	d.deliver(cmd.CommandID, result)
	return result
}

// retryResults posts every result an earlier cycle could not.
func (d *Deps) retryResults() {
	pending, err := d.Store.Unposted()
	if err != nil {
		d.log(logging.LevelWarn, "command store unreadable", logging.F("error", err.Error()))
		return
	}
	for _, record := range pending {
		d.deliver(record.CommandID, record.Result)
	}
}

// deliver posts one result and marks it posted when the backend took it. A
// result the backend did not take stays in the store for the next cycle.
func (d *Deps) deliver(commandID string, result contract.CommandResultRequest) {
	if !d.postResult(commandID, result) {
		return
	}
	if err := d.Store.MarkPosted(commandID); err != nil {
		d.log(logging.LevelWarn, "command result not marked posted",
			logging.F("commandId", commandID),
			logging.F("error", err.Error()),
		)
	}
}

// postResult reports one result, returning whether the backend is done with
// it.
//
// A 4xx counts as done: the backend understood the body and refused it, and
// sending the same bytes again next cycle would be refused again. A transport
// failure, a 5xx, a 408 or a 429 is not done, and is retried.
func (d *Deps) postResult(commandID string, result contract.CommandResultRequest) bool {
	body, err := json.Marshal(result)
	if err != nil {
		d.log(logging.LevelWarn, "command result not encodable",
			logging.F("commandId", commandID),
			logging.F("error", err.Error()),
		)
		return false
	}

	resp, err := d.Client.Do(http.MethodPost, ResultPath(d.DeviceID, commandID), body)
	if err != nil {
		d.log(logging.LevelWarn, "command result failed",
			logging.F("commandId", commandID),
			logging.F("error", err.Error()),
		)
		return false
	}
	status := resp.StatusCode
	closeBody(resp)

	switch {
	case status >= 200 && status < 300:
		d.log(logging.LevelInfo, "command result reported",
			logging.F("commandId", commandID),
			logging.F("status", result.Status),
		)
		return true
	case status >= 500 || status == http.StatusRequestTimeout || status == http.StatusTooManyRequests:
		// 408 and 429 say "not now", not "never": the result is kept and
		// retried, like a 5xx.
		d.log(logging.LevelWarn, "command result failed",
			logging.F("commandId", commandID),
			logging.F("status", status),
		)
		return false
	default:
		d.log(logging.LevelWarn, "command result rejected",
			logging.F("commandId", commandID),
			logging.F("status", status),
		)
		return true
	}
}

// maxCommands is how many commands this lease asks for.
func (d *Deps) maxCommands() int {
	if d.MaxCommands > 0 {
		return d.MaxCommands
	}
	return DefaultMaxCommands
}

// readBody reads at most maxResponseBytes of a response body.
func readBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
}

// closeBody closes a response body the cycle is done with.
func closeBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}

// runOutcome is what one attempt at an external command produced.
type runOutcome struct {
	result   platform.CommandResult
	err      error
	timedOut bool
}

// run executes name with args, bounded by timeout.
//
// The command runs on its own goroutine so the wait is on the injected clock:
// a test drives a timeout by advancing time, never by waiting for it. A
// command still running when the timeout fires has its context cancelled,
// which is what kills the process, and is then given killGrace to hand back
// whatever it captured before it died.
func (d *Deps) run(ctx context.Context, timeout time.Duration, name string, args ...string) runOutcome {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan runOutcome, 1)
	go func() {
		result, err := d.Runner.Run(runCtx, name, args...)
		done <- runOutcome{result: result, err: err}
	}()

	select {
	case outcome := <-done:
		return outcome
	case <-d.Clock.After(timeout):
	}

	// The clock and the command came due together: a command that has already
	// finished is reported as the exit it was, not as a timeout.
	select {
	case outcome := <-done:
		return outcome
	default:
	}

	cancel()

	outcome := runOutcome{timedOut: true}
	select {
	case finished := <-done:
		outcome.result = finished.result
	case <-time.After(killGrace):
	}
	return outcome
}

// report turns one attempt into the result to send.
//
// A process that exited is reported as that exit, with no "error:" line: a
// script that writes to stdout and exits 3 is a failed command with output and
// an exit code, not an agent error. Everything else is a failure with exit
// code -1 and a code on the first line.
func (d *Deps) report(outcome runOutcome) contract.CommandResultRequest {
	captured := tail(outcome.result.Stdout+outcome.result.Stderr, MaxOutputBytes)

	switch {
	case outcome.timedOut:
		return d.fail(ErrTimeout, captured)
	case outcome.err != nil:
		return d.fail(ErrExecutionFailed, outcome.err.Error())
	}

	status := StatusFailed
	if outcome.result.ExitCode == 0 {
		status = StatusSucceeded
	}
	return contract.CommandResultRequest{
		Status:     status,
		ExitCode:   outcome.result.ExitCode,
		Output:     captured,
		FinishedAt: d.now(),
	}
}

// fail is a failure that is not a process exit: status failed, exit code -1
// and an output whose first line is "error: <code>". Detail, when there is
// any, follows on the next line.
func (d *Deps) fail(code, detail string) contract.CommandResultRequest {
	output := "error: " + code
	if detail != "" {
		// The code must survive the truncation, so the detail is what gets
		// cut, not the line that says what went wrong.
		output += "\n" + tail(detail, MaxOutputBytes-len(output)-1)
	}
	return contract.CommandResultRequest{
		Status:     StatusFailed,
		ExitCode:   FailureExitCode,
		Output:     output,
		FinishedAt: d.now(),
	}
}

// succeed is a result with nothing to report but its own output.
func (d *Deps) succeed(output string) contract.CommandResultRequest {
	return contract.CommandResultRequest{
		Status:     StatusSucceeded,
		ExitCode:   0,
		Output:     tail(output, MaxOutputBytes),
		FinishedAt: d.now(),
	}
}

// now is finishedAt: epoch seconds from the injected clock, never milliseconds
// and never a formatted string.
func (d *Deps) now() int64 {
	if d == nil || d.Clock == nil {
		return 0
	}
	return d.Clock.Now().Unix()
}

// goos is the platform the argv is chosen for.
func (d *Deps) goos() string {
	if d.GOOS != "" {
		return d.GOOS
	}
	return runtime.GOOS
}

// tempDir is where this agent writes scripts and archives.
func (d *Deps) tempDir() string {
	if d.TempDir != "" {
		return d.TempDir
	}
	return TempDir(d.goos())
}

// tempPath builds a collision-free path under the temp directory for one
// command: the instant it ran, the command it ran for, and the extension the
// interpreter or the archive format needs.
func (d *Deps) tempPath(prefix, commandID, ext string) string {
	stamp := d.Clock.Now().UTC().Format("20060102T150405.000Z")
	return joinPath(d.tempDir(), prefix+stamp+"-"+safeName(commandID)+ext)
}

// writeTemp puts data at path, creating the temp directory first.
func (d *Deps) writeTemp(path string, data []byte) error {
	if dir := d.tempDir(); dir != "" {
		if err := d.FS.MkdirAll(dir, TempDirMode); err != nil {
			return err
		}
	}
	return d.FS.WriteFile(path, data, TempFileMode)
}

// removeTemp deletes a file the execution is done with. A file that is already
// gone is not a problem worth a line in the log.
func (d *Deps) removeTemp(path string) {
	_ = d.FS.Remove(path)
}

// log writes one record when a logger was given. A failed write is dropped:
// the agent has nowhere better to report it, and a full disk must not stop a
// command from being reported.
func (d *Deps) log(level logging.Level, msg string, fields ...logging.Field) {
	if d.Logger == nil {
		return
	}
	_ = d.Logger.Log(level, msg, fields...)
}

// tail is the last max bytes of s, which is what a result carries: the end of
// a long run says why it ended.
func tail(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	return s[len(s)-max:]
}

// safeName makes a command id usable as part of a file name on either
// platform, so an id from the backend can never climb out of the temp
// directory.
func safeName(id string) string {
	if id == "" {
		return "command"
	}

	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// joinPath puts name under dir, keeping the separator dir is already written
// with: filepath.Join would rewrite a POSIX path on a Windows host, and the
// agent's filesystem uses paths exactly as given.
func joinPath(dir, name string) string {
	switch {
	case dir == "":
		return name
	case strings.HasSuffix(dir, "/"), strings.HasSuffix(dir, `\`):
		return dir + name
	case strings.Contains(dir, "/") && !strings.Contains(dir, `\`):
		return dir + "/" + name
	default:
		return dir + string(filepath.Separator) + name
	}
}
