package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// consoleUserTimeout bounds the console-user probe, so a hung shell cannot
// hold up the command poll that follows it.
const consoleUserTimeout = 30 * time.Second

// The console-user probes. Windows reports DOMAIN\user (or AzureAD\user) for
// whoever holds the console session; macOS reports the owner of /dev/console,
// which is root while the login window is up.
const (
	windowsConsoleUserShell  = "powershell.exe"
	windowsConsoleUserScript = "(Get-CimInstance Win32_ComputerSystem).UserName"
	darwinConsoleUserCmd     = "stat"
)

// darwinConsoleUserArgs are stat's arguments: the owner name of /dev/console.
var darwinConsoleUserArgs = []string{"-f%Su", "/dev/console"}

// windowsConsoleUserArgs runs the script the way the inventory probes do.
var windowsConsoleUserArgs = []string{"-NoProfile", "-NonInteractive", "-Command", windowsConsoleUserScript}

// msgUserReported is logged, at info, whenever the reported user changes.
const msgUserReported = "signed-in user reported"

// userSessionPath is the endpoint the signed-in user is reported on.
func userSessionPath(deviceID string) string {
	return "/api/v1/devices/" + url.PathEscape(deviceID) + "/user-session"
}

// consoleUser asks the operating system who is logged in at the console. nil
// means nobody: Windows printed nothing, or macOS named root, loginwindow or
// nobody at all. An error means the probe itself failed.
func consoleUser(ctx context.Context, runner platform.CommandRunner, goos string) (*string, error) {
	ctx, cancel := context.WithTimeout(ctx, consoleUserTimeout)
	defer cancel()

	name, args := darwinConsoleUserCmd, darwinConsoleUserArgs
	if goos == "windows" {
		name, args = windowsConsoleUserShell, windowsConsoleUserArgs
	}
	res, err := runner.Run(ctx, name, args...)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("%s exited %d", name, res.ExitCode)
	}

	user := strings.TrimSpace(res.Stdout)
	if user == "" {
		return nil, nil
	}
	if goos != "windows" && (user == "root" || user == "loginwindow") {
		return nil, nil
	}
	return &user, nil
}

// signedTransport is the signed half of the agent's client.
type signedTransport interface {
	Do(method, path string, body []byte) (*http.Response, error)
}

// userReporter tells the backend who is logged in to the operating system,
// once per successful check-in cycle. It replaces the Entra-token user
// session: the user named is the console user, not a signed-in identity.
type userReporter struct {
	transport signedTransport
	runner    platform.CommandRunner
	goos      string
	logger    *logging.Logger

	// reported and last are the last user the backend accepted, so a change
	// is logged once rather than every cycle.
	reported bool
	last     *string
}

// report reads the console user and POSTs {"username": <string|null>} to the
// device's user-session route, signed like every device request (the body is
// part of the signature). Whatever goes wrong costs one warning line: the
// device credential is left alone and the caller carries on with its cycle.
func (r *userReporter) report(ctx context.Context, deviceID string) {
	user, err := consoleUser(ctx, r.runner, r.goos)
	if err != nil {
		r.warn("signed-in user could not be read", logging.F("error", err.Error()))
		return
	}

	body, err := json.Marshal(struct {
		Username *string `json:"username"`
	}{user})
	if err != nil {
		r.warn("signed-in user could not be reported", logging.F("error", err.Error()))
		return
	}

	path := userSessionPath(deviceID)
	resp, err := r.transport.Do(http.MethodPost, path, body)
	if err != nil {
		// A 401 comes back as client.ErrUnauthorized. Unlike the check-in,
		// it does not clear the credential here: the check-in that just
		// succeeded is what vouches for the device.
		r.warn("signed-in user could not be reported", logging.F("path", path), logging.F("error", err.Error()))
		return
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusOK {
		var failure struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &failure)
		r.warn("signed-in user not accepted",
			logging.F("path", path),
			logging.F("status", resp.StatusCode),
			logging.F("error", failure.Error),
		)
		return
	}

	if r.reported && sameUser(r.last, user) {
		return
	}
	r.reported, r.last = true, user
	if r.logger != nil {
		var username any
		if user != nil {
			username = *user
		}
		_ = r.logger.Info(msgUserReported, logging.F("username", username))
	}
}

func (r *userReporter) warn(msg string, fields ...logging.Field) {
	if r.logger != nil {
		_ = r.logger.Warn(msg, fields...)
	}
}

// sameUser compares two optional usernames.
func sameUser(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// The user token vault of earlier builds, which kept the Entra tokens. The
// service deletes a leftover one at start: no Entra token is kept any more.
const (
	legacyWindowsVaultPath = `C:\ProgramData\OfficeHQ\MDM\usertoken.bin`
	legacyDarwinVaultPath  = "/Library/Application Support/OfficeHQ/MDM/usertoken.json"
)

// legacyVaultPath returns the old vault location for a GOOS value.
func legacyVaultPath(goos string) string {
	if goos == "windows" {
		return legacyWindowsVaultPath
	}
	return legacyDarwinVaultPath
}

// removeLegacyVault deletes the old user token vault, if one is left. A file
// already gone is the normal case and is not logged.
func removeLegacyVault(fsys platform.FileSystem, goos string, logger *logging.Logger) {
	path := legacyVaultPath(goos)
	err := fsys.Remove(path)
	switch {
	case err == nil:
		if logger != nil {
			_ = logger.Info("removed the stored user token of an earlier version", logging.F("path", path))
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		if logger != nil {
			_ = logger.Warn("stored user token of an earlier version could not be removed",
				logging.F("path", path), logging.F("error", err.Error()))
		}
	}
}
