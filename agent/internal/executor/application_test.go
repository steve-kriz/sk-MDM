package executor

// E2E cucumber-style and unit tests for TASK-049's install_application command
// (AC23-AC26): agent/internal/executor/application.go.
//
// Every test runs through agent/internal/platform/fake -- no real disk, no
// real process and no real network. The device-signed "download details"
// fetch goes through the existing fakeTransport (poll_test.go, same package);
// the installer bytes themselves are served by a scripted platform.HTTPDoer
// standing in for Deps.Downloader.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// ----------------------------------------------------------------------------
// Test doubles
// ----------------------------------------------------------------------------

// recordedCall is one call a scriptedRunner captured.
type recordedCall struct {
	Name string
	Args []string
}

// scriptedRunner is a platform.CommandRunner that answers every call with one
// canned result, and records every call it was asked to run.
type scriptedRunner struct {
	calls    []recordedCall
	exitCode int
	err      error
	block    bool // when true, Run blocks on ctx.Done(), for the timeout scenario.
}

func (r *scriptedRunner) Run(ctx context.Context, name string, args ...string) (platform.CommandResult, error) {
	r.calls = append(r.calls, recordedCall{Name: name, Args: append([]string(nil), args...)})
	if r.block {
		<-ctx.Done()
		return platform.CommandResult{}, ctx.Err()
	}
	if r.err != nil {
		return platform.CommandResult{}, r.err
	}
	return platform.CommandResult{ExitCode: r.exitCode}, nil
}

// countingFS wraps a fake.FS and records every WriteFile/AppendFile call's
// size and the path it was asked to write, so a test can assert on the
// chunking without reimplementing the production streaming logic.
type countingFS struct {
	*fake.FS
	writeSizes  []int
	appendSizes []int
	path        string
}

func newCountingFS() *countingFS {
	return &countingFS{FS: fake.NewFS()}
}

func (c *countingFS) WriteFile(path string, data []byte, perm fs.FileMode) error {
	c.path = path
	c.writeSizes = append(c.writeSizes, len(data))
	return c.FS.WriteFile(path, data, perm)
}

func (c *countingFS) AppendFile(path string, data []byte, perm fs.FileMode) error {
	c.appendSizes = append(c.appendSizes, len(data))
	return c.FS.AppendFile(path, data, perm)
}

// countingTransport is a Transport that records how many times it was called,
// for the "no request was sent" assertion (AC23).
type countingTransport struct {
	calls int
}

func (c *countingTransport) Do(method, path string, body []byte) (*http.Response, error) {
	c.calls++
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}"))}, nil
}

// detailsResponse builds the JSON body the device-signed download-details
// endpoint answers with.
func detailsResponse(url, sha256Hex, installerType string, installArgs *string) string {
	payload := map[string]any{
		"url":           url,
		"sha256":        sha256Hex,
		"installerType": installerType,
	}
	if installArgs != nil {
		payload["installArgs"] = *installArgs
	}
	data, _ := json.Marshal(payload)
	return string(data)
}

func strPtr(s string) *string { return &s }

// validSHA is a syntactically valid 64 lowercase hex characters.
var validSHA = strings.Repeat("0123456789abcdef", 4)

func installApplicationCommand(commandID, applicationID string) Command {
	payload, _ := json.Marshal(map[string]any{
		"applicationId":   applicationID,
		"applicationName": "Test App",
		"timeoutSeconds":  3600,
	})
	return Command{CommandID: commandID, Type: TypeInstallApplication, Payload: payload}
}

// ----------------------------------------------------------------------------
// AC23: a missing/empty/non-string applicationId is invalid_payload, no request
// ----------------------------------------------------------------------------

func TestScenario_InstallApplicationMissingApplicationIdIsInvalidPayload(t *testing.T) {
	transport := &countingTransport{}
	deps := &Deps{
		Runner: &scriptedRunner{},
		FS:     fake.NewFS(),
		Clock:  fake.NewClock(time.Now()),
		GOOS:   "windows",
		Client: transport,
	}
	cmd := Command{CommandID: "cmd-1", Type: TypeInstallApplication, Payload: json.RawMessage(`{}`)}

	result := Execute(context.Background(), cmd, deps)

	if result.Status != StatusFailed || result.ExitCode != FailureExitCode {
		t.Fatalf("expected failed/-1, got %s/%d", result.Status, result.ExitCode)
	}
	if !strings.HasPrefix(result.Output, "error: "+ErrInvalidPayload) {
		t.Fatalf("expected output to start with error: %s, got %q", ErrInvalidPayload, result.Output)
	}
	if transport.calls != 0 {
		t.Fatalf("expected no request to be sent, got %d calls", transport.calls)
	}
}

// ----------------------------------------------------------------------------
// AC24: download details lookup failures
// ----------------------------------------------------------------------------

func TestScenario_DownloadDetailsLookupFails(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		code   string
	}{
		{"404 is application_unavailable", http.StatusNotFound, `{}`, ErrApplicationUnavailable},
		{"500 is download_failed", http.StatusInternalServerError, `{}`, ErrDownloadFailed},
		{"200 with installerType and sha256 but no url is download_failed", http.StatusOK, detailsResponse("", validSHA, "msi", nil), ErrDownloadFailed},
		{"200 with url and installerType but no sha256 is download_failed", http.StatusOK, detailsResponse("http://fake.invalid/x.msi", "", "msi", nil), ErrDownloadFailed},
		{"200 with installerType pkg on windows is unsupported_on_platform", http.StatusOK, detailsResponse("http://fake.invalid/x.pkg", validSHA, "pkg", nil), ErrUnsupportedPlatform},
		{"200 with installerType dmg is invalid_payload", http.StatusOK, detailsResponse("http://fake.invalid/x.dmg", validSHA, "dmg", nil), ErrInvalidPayload},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			transport := newFakeTransport([]byte(tc.body))
			transport.leaseStatus = tc.status

			runner := &scriptedRunner{}
			deps := &Deps{
				Runner: runner,
				FS:     fake.NewFS(),
				Clock:  fake.NewClock(time.Now()),
				GOOS:   "windows",
				Client: transport,
			}

			result := Execute(context.Background(), installApplicationCommand("cmd-1", "app-1"), deps)

			if !strings.HasPrefix(result.Output, "error: "+tc.code) {
				t.Fatalf("expected output to start with 'error: %s', got %q", tc.code, result.Output)
			}
			if len(runner.calls) != 0 {
				t.Fatalf("expected nothing to be run, got %v", runner.calls)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// AC25: the download is streamed in chunks of at most 1 MiB
// ----------------------------------------------------------------------------

func TestScenario_DownloadIsStreamedInChunks(t *testing.T) {
	// Given the downloader serves 2.5 MiB whose SHA-256 matches the details
	payload := bytes.Repeat([]byte("A"), (5*1024*1024)/2) // 2.5 MiB
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])

	transport := newFakeTransport([]byte(detailsResponse("http://fake.invalid/app.msi", digest, "msi", nil)))
	downloader := fake.NewHTTPDoer()
	downloader.DoFunc = func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(bytes.NewReader(payload)),
			ContentLength: int64(len(payload)),
		}, nil
	}

	fs := newCountingFS()
	runner := &scriptedRunner{exitCode: 0}
	deps := &Deps{
		Runner:     runner,
		FS:         fs,
		Clock:      fake.NewClock(time.Now()),
		GOOS:       "windows",
		Client:     transport,
		Downloader: downloader,
	}

	// When the executor runs install_application with commandId "cmd-1"
	result := Execute(context.Background(), installApplicationCommand("cmd-1", "app-1"), deps)

	if result.Status != StatusSucceeded {
		t.Fatalf("expected succeeded, got %s (%s)", result.Status, result.Output)
	}
	// Then the temp file was written with one WriteFile and two AppendFile
	// calls, none over 1 MiB
	if len(fs.writeSizes) != 1 {
		t.Fatalf("expected exactly one WriteFile call, got %d", len(fs.writeSizes))
	}
	if len(fs.appendSizes) != 2 {
		t.Fatalf("expected exactly two AppendFile calls, got %d", len(fs.appendSizes))
	}
	for _, size := range append(append([]int{}, fs.writeSizes...), fs.appendSizes...) {
		if size > 1<<20 {
			t.Fatalf("expected no chunk over 1 MiB, got %d", size)
		}
	}
	if !strings.Contains(fs.path, "app-") || !strings.HasSuffix(fs.path, "-cmd-1.msi") {
		t.Fatalf("expected the temp file name to follow app-<stamp>-cmd-1.msi, got %q", fs.path)
	}
	// The temp file is removed once the executor is done with it.
	if fs.Exists(fs.path) {
		t.Fatalf("expected the temp file to be removed, got %q still present", fs.path)
	}
}

// ----------------------------------------------------------------------------
// AC25 (failure): download rejected before running
// ----------------------------------------------------------------------------

func TestScenario_DownloadRejectedBeforeRunning(t *testing.T) {
	cases := []struct {
		name       string
		doFunc     func(req *http.Request) (*http.Response, error)
		detailsURL string
		sha        string
		code       string
	}{
		{
			name: "answers HTTP 403 is download_failed",
			doFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader(""))}, nil
			},
			detailsURL: "http://fake.invalid/x.msi",
			sha:        validSHA,
			code:       ErrDownloadFailed,
		},
		{
			name: "exceeds 2147483648 bytes is download_too_large",
			doFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode:    http.StatusOK,
					Body:          io.NopCloser(strings.NewReader("")),
					ContentLength: MaxApplicationBytes + 1,
				}, nil
			},
			detailsURL: "http://fake.invalid/x.msi",
			sha:        validSHA,
			code:       ErrDownloadTooLarge,
		},
		{
			name: "has a SHA-256 other than the details is checksum_mismatch",
			doFunc: func(req *http.Request) (*http.Response, error) {
				body := []byte("hello world")
				return &http.Response{
					StatusCode:    http.StatusOK,
					Body:          io.NopCloser(bytes.NewReader(body)),
					ContentLength: int64(len(body)),
				}, nil
			},
			detailsURL: "http://fake.invalid/x.msi",
			sha:        validSHA, // does not match sha256("hello world")
			code:       ErrChecksumMismatch,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			transport := newFakeTransport([]byte(detailsResponse(tc.detailsURL, tc.sha, "msi", nil)))
			downloader := fake.NewHTTPDoer()
			downloader.DoFunc = tc.doFunc

			fsys := newCountingFS()
			runner := &scriptedRunner{}
			deps := &Deps{
				Runner:     runner,
				FS:         fsys,
				Clock:      fake.NewClock(time.Now()),
				GOOS:       "windows",
				Client:     transport,
				Downloader: downloader,
			}

			result := Execute(context.Background(), installApplicationCommand("cmd-1", "app-1"), deps)

			if !strings.HasPrefix(result.Output, "error: "+tc.code) {
				t.Fatalf("expected output to start with 'error: %s', got %q", tc.code, result.Output)
			}
			if len(fsys.Paths()) != 0 {
				t.Fatalf("expected the temp file to be removed, got %v", fsys.Paths())
			}
			if len(runner.calls) != 0 {
				t.Fatalf("expected no process to be run, got %v", runner.calls)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// AC26: the installer is invoked per type, once verified
// ----------------------------------------------------------------------------

func TestScenario_InstallerInvocationPerType(t *testing.T) {
	cases := []struct {
		name          string
		installerType string
		goos          string
		installArgs   *string
		exitCode      int
		wantStatus    string
		wantExitCode  int
		checkArgv     func(t *testing.T, call recordedCall)
	}{
		{
			name: "msi succeeds on exit 0", installerType: "msi", goos: "windows", exitCode: 0,
			wantStatus: StatusSucceeded, wantExitCode: 0,
			checkArgv: func(t *testing.T, call recordedCall) {
				if call.Name != "msiexec" {
					t.Fatalf("expected msiexec, got %q", call.Name)
				}
				if len(call.Args) != 4 || call.Args[0] != "/i" || call.Args[2] != "/qn" || call.Args[3] != "/norestart" {
					t.Fatalf("unexpected argv: %v", call.Args)
				}
				if !strings.HasSuffix(call.Args[1], ".msi") {
					t.Fatalf("expected the installed path to end in .msi, got %q", call.Args[1])
				}
			},
		},
		{
			name: "msi exit 3010 still counts as succeeded", installerType: "msi", goos: "windows", exitCode: 3010,
			wantStatus: StatusSucceeded, wantExitCode: 3010,
			checkArgv: func(t *testing.T, call recordedCall) {
				if call.Name != "msiexec" {
					t.Fatalf("expected msiexec, got %q", call.Name)
				}
			},
		},
		{
			name: "exe runs with its installArgs split on whitespace", installerType: "exe", goos: "windows",
			installArgs: strPtr("/S /norestart"), exitCode: 0,
			wantStatus: StatusSucceeded, wantExitCode: 0,
			checkArgv: func(t *testing.T, call recordedCall) {
				if !strings.HasSuffix(call.Name, ".exe") {
					t.Fatalf("expected the exe path itself to be the command, got %q", call.Name)
				}
				if len(call.Args) != 2 || call.Args[0] != "/S" || call.Args[1] != "/norestart" {
					t.Fatalf("unexpected argv: %v", call.Args)
				}
			},
		},
		{
			name: "pkg fails on a non-zero exit", installerType: "pkg", goos: "darwin", exitCode: 1,
			wantStatus: StatusFailed, wantExitCode: 1,
			checkArgv: func(t *testing.T, call recordedCall) {
				if call.Name != "installer" {
					t.Fatalf("expected installer, got %q", call.Name)
				}
				if len(call.Args) != 4 || call.Args[0] != "-pkg" || call.Args[2] != "-target" || call.Args[3] != "/" {
					t.Fatalf("unexpected argv: %v", call.Args)
				}
				if !strings.HasSuffix(call.Args[1], ".pkg") {
					t.Fatalf("expected the installed path to end in .pkg, got %q", call.Args[1])
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte("installer-bytes")
			sum := sha256.Sum256(body)
			digest := hex.EncodeToString(sum[:])

			transport := newFakeTransport([]byte(detailsResponse("http://fake.invalid/x."+tc.installerType, digest, tc.installerType, tc.installArgs)))
			downloader := fake.NewHTTPDoer()
			downloader.DoFunc = func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}, nil
			}

			fsys := newCountingFS()
			runner := &scriptedRunner{exitCode: tc.exitCode}
			deps := &Deps{
				Runner:     runner,
				FS:         fsys,
				Clock:      fake.NewClock(time.Now()),
				GOOS:       tc.goos,
				Client:     transport,
				Downloader: downloader,
			}

			result := Execute(context.Background(), installApplicationCommand("cmd-1", "app-1"), deps)

			if result.Status != tc.wantStatus {
				t.Fatalf("expected status %s, got %s (%s)", tc.wantStatus, result.Status, result.Output)
			}
			if result.ExitCode != tc.wantExitCode {
				t.Fatalf("expected exitCode %d, got %d", tc.wantExitCode, result.ExitCode)
			}
			if len(runner.calls) != 1 {
				t.Fatalf("expected exactly one run, got %d", len(runner.calls))
			}
			tc.checkArgv(t, runner.calls[0])
			if len(fsys.Paths()) != 0 {
				t.Fatalf("expected the temp file to be removed, got %v", fsys.Paths())
			}
		})
	}
}

// ----------------------------------------------------------------------------
// AC26 (failure): a timed-out installer
// ----------------------------------------------------------------------------

func TestScenario_InstallerTimesOut(t *testing.T) {
	body := []byte("installer-bytes")
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])

	transport := newFakeTransport([]byte(detailsResponse("http://fake.invalid/x.msi", digest, "msi", nil)))
	downloader := fake.NewHTTPDoer()
	downloader.DoFunc = func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}, nil
	}

	clock := fake.NewClock(time.Now())
	clock.AutoAdvance = true
	fsys := newCountingFS()
	runner := &scriptedRunner{block: true}
	deps := &Deps{
		Runner:     runner,
		FS:         fsys,
		Clock:      clock,
		GOOS:       "windows",
		Client:     transport,
		Downloader: downloader,
	}

	result := Execute(context.Background(), installApplicationCommand("cmd-1", "app-1"), deps)

	if !strings.HasPrefix(result.Output, "error: "+ErrTimeout) {
		t.Fatalf("expected output to start with 'error: %s', got %q", ErrTimeout, result.Output)
	}
	if len(fsys.Paths()) != 0 {
		t.Fatalf("expected the temp file to be removed, got %v", fsys.Paths())
	}
}
