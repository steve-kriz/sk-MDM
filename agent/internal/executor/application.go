package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
)

// applicationChunkBytes is the most one write of a download puts on disk.
const applicationChunkBytes = 1 << 20 // 1 MiB

// The installer types the application safe list carries.
const (
	installerMSI = "msi"
	installerEXE = "exe"
	installerPKG = "pkg"
)

// installerGOOS is the GOOS each installer type runs on.
var installerGOOS = map[string]string{
	installerMSI: "windows",
	installerEXE: "windows",
	installerPKG: "darwin",
}

// msiSuccessCodes are the msiexec exits that mean the install succeeded:
// 3010 (a restart is required) and 1641 (a restart was started).
var msiSuccessCodes = map[int]bool{3010: true, 1641: true}

// sha256Hex is a SHA-256 written as 64 hex digits, in either case.
var sha256Hex = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// applicationDetails is what the device-signed download endpoint answers.
type applicationDetails struct {
	URL           string  `json:"url"`
	SHA256        string  `json:"sha256"`
	InstallerType string  `json:"installerType"`
	InstallArgs   *string `json:"installArgs"`
	FileName      *string `json:"fileName"`
}

// ApplicationDownloadPath is the device-signed endpoint that answers fresh
// download details for one application.
func ApplicationDownloadPath(deviceID, applicationID string) string {
	return "/api/v1/devices/" + url.PathEscape(deviceID) + "/applications/" + url.PathEscape(applicationID) + "/download"
}

// errDownloadTooLarge marks a download that passed MaxApplicationBytes.
var errDownloadTooLarge = errors.New("download larger than the maximum")

// errDownloadWrite marks a chunk that could not be written to disk.
type errDownloadWrite struct{ err error }

func (e errDownloadWrite) Error() string { return e.err.Error() }

// installApplication runs one install_application command:
//
//  1. decode the payload (applicationId is required);
//  2. fetch fresh download details through the signed client;
//  3. refuse an unknown installer type or one for the other platform;
//  4. stream the installer to the temp directory, hashing as it goes;
//  5. verify the SHA-256, then run the installer.
//
// Nothing runs unless every step before it passed, and the temp file is
// deleted on every path once it may exist.
func installApplication(ctx context.Context, cmd Command, deps *Deps) contract.CommandResultRequest {
	payload, ok := decodeInstallApplication(cmd.Payload)
	if !ok {
		return deps.fail(ErrInvalidPayload, "")
	}

	details, failure, failed := deps.applicationDetails(payload.ApplicationID)
	if failed {
		return failure
	}

	installerType := details.InstallerType
	goos, known := installerGOOS[installerType]
	if !known {
		return deps.fail(ErrInvalidPayload, "")
	}
	if goos != deps.goos() {
		return deps.fail(ErrUnsupportedPlatform, "")
	}

	deps.log(logging.LevelInfo, "installing application",
		logging.F("commandId", cmd.CommandID),
		logging.F("applicationId", payload.ApplicationID),
		logging.F("installerType", installerType),
	)

	path := deps.tempPath("app-", cmd.CommandID, "."+installerType)
	defer deps.removeTemp(path)

	if result, failed := deps.downloadApplication(ctx, details, path); failed {
		return result
	}

	name, args := installerArgv(installerType, path, details.InstallArgs)
	outcome := deps.run(ctx, EffectiveTimeout(payload.TimeoutSeconds), name, args...)
	result := deps.report(outcome)
	if installerType == installerMSI && !outcome.timedOut && outcome.err == nil && msiSuccessCodes[outcome.result.ExitCode] {
		result.Status = StatusSucceeded
	}
	return result
}

// applicationDetails asks the backend for the application's download details.
// The third return is true when the command must stop with the result in the
// second.
func (d *Deps) applicationDetails(applicationID string) (applicationDetails, contract.CommandResultRequest, bool) {
	if d.Client == nil {
		return applicationDetails{}, d.fail(ErrDownloadFailed, "no client"), true
	}
	resp, err := d.Client.Do(http.MethodGet, ApplicationDownloadPath(d.DeviceID, applicationID), nil)
	if err != nil {
		return applicationDetails{}, d.fail(ErrDownloadFailed, err.Error()), true
	}
	defer closeBody(resp)

	if resp.StatusCode == http.StatusNotFound {
		return applicationDetails{}, d.fail(ErrApplicationUnavailable, ""), true
	}
	if resp.StatusCode != http.StatusOK {
		return applicationDetails{}, d.fail(ErrDownloadFailed, "details HTTP "+strconv.Itoa(resp.StatusCode)), true
	}

	data, err := readBody(resp)
	if err != nil {
		return applicationDetails{}, d.fail(ErrDownloadFailed, err.Error()), true
	}
	var details applicationDetails
	if err := json.Unmarshal(data, &details); err != nil {
		return applicationDetails{}, d.fail(ErrDownloadFailed, "details unreadable"), true
	}
	if strings.TrimSpace(details.URL) == "" {
		return applicationDetails{}, d.fail(ErrDownloadFailed, "details carry no url"), true
	}
	if !sha256Hex.MatchString(details.SHA256) {
		return applicationDetails{}, d.fail(ErrDownloadFailed, "details carry no sha256"), true
	}
	return details, contract.CommandResultRequest{}, false
}

// downloadApplication streams the installer to path in chunks of at most
// applicationChunkBytes and verifies its SHA-256. The second return is true
// when the command must stop with the result in the first; the caller removes
// path either way.
func (d *Deps) downloadApplication(ctx context.Context, details applicationDetails, path string) (contract.CommandResultRequest, bool) {
	if d.Downloader == nil {
		return d.fail(ErrDownloadFailed, "no downloader"), true
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, details.URL, nil)
	if err != nil {
		return d.fail(ErrDownloadFailed, "invalid download url"), true
	}
	resp, err := d.Downloader.Do(req)
	if err != nil {
		return d.fail(ErrDownloadFailed, "download request failed"), true
	}
	defer closeBody(resp)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return d.fail(ErrDownloadFailed, "HTTP "+strconv.Itoa(resp.StatusCode)), true
	}
	if resp.ContentLength > MaxApplicationBytes {
		return d.fail(ErrDownloadTooLarge, ""), true
	}

	digest, err := d.streamToFile(resp.Body, path)
	switch {
	case errors.Is(err, errDownloadTooLarge):
		return d.fail(ErrDownloadTooLarge, ""), true
	case err != nil:
		var writeErr errDownloadWrite
		if errors.As(err, &writeErr) {
			return d.fail(ErrExecutionFailed, writeErr.Error()), true
		}
		return d.fail(ErrDownloadFailed, err.Error()), true
	}

	if !strings.EqualFold(digest, details.SHA256) {
		return d.fail(ErrChecksumMismatch, ""), true
	}
	return contract.CommandResultRequest{}, false
}

// streamToFile copies body to path — the first chunk with WriteFile, every
// later one with AppendFile — and returns the hex SHA-256 of what it wrote. A
// body past MaxApplicationBytes stops with errDownloadTooLarge before the
// chunk that would cross it is written.
func (d *Deps) streamToFile(body io.Reader, path string) (string, error) {
	hash := sha256.New()
	buf := make([]byte, applicationChunkBytes)
	var total int64
	first := true

	for {
		var n int
		var readErr error
		if body != nil {
			n, readErr = io.ReadFull(body, buf)
		} else {
			readErr = io.EOF
		}
		if n > 0 {
			total += int64(n)
			if total > MaxApplicationBytes {
				return "", errDownloadTooLarge
			}
			chunk := buf[:n]
			hash.Write(chunk)
			if err := d.writeChunk(path, chunk, first); err != nil {
				return "", errDownloadWrite{err}
			}
			first = false
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return "", readErr
		}
	}

	// An empty body still leaves a file behind for the installer to be
	// handed, and its digest is checked like any other.
	if first {
		if err := d.writeChunk(path, nil, true); err != nil {
			return "", errDownloadWrite{err}
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// writeChunk writes the first chunk of a download (creating the temp directory)
// or appends a later one.
func (d *Deps) writeChunk(path string, chunk []byte, first bool) error {
	if first {
		return d.writeTemp(path, chunk)
	}
	return d.FS.AppendFile(path, chunk, TempFileMode)
}

// installerArgv is how each installer type is run over the downloaded file:
// msiexec quietly with no restart, an exe with its registered arguments split
// on whitespace (no quoting), and a pkg through installer onto the boot volume.
func installerArgv(installerType, path string, installArgs *string) (string, []string) {
	switch installerType {
	case installerMSI:
		return "msiexec", []string{"/i", path, "/qn", "/norestart"}
	case installerPKG:
		return "installer", []string{"-pkg", path, "-target", "/"}
	}
	var args []string
	if installArgs != nil {
		args = strings.Fields(*installArgs)
	}
	return path, args
}
