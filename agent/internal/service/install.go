package service

import (
	"context"
	"errors"
	"runtime"

	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// ErrNotInstalled is returned by Uninstall when nothing is registered. It is
// not a failure: `mdmagent uninstall-service` says so and exits 0, so an
// installer's uninstall step is safe to run twice.
var ErrNotInstalled = errors.New("service not installed")

// Config is the registration install and uninstall act on, and the description
// PlistBytes renders.
//
// FS and Runner are the only way this package touches the host: the plist is
// written through the filesystem interface and every `sc.exe` and `launchctl`
// call goes through the command runner, so an install is recorded rather than
// performed in a test, on either host, without privileges.
type Config struct {
	// FS writes and removes the LaunchDaemon plist. It is unused on Windows.
	FS platform.FileSystem

	// Runner runs sc.exe and launchctl.
	Runner platform.CommandRunner

	// GOOS selects the platform to register on; empty means this build's
	// GOOS.
	GOOS string

	// BinaryPath is the installed agent executable. It is registered with
	// the `run` argument after it, so the service manager starts the agent's
	// own foreground loop.
	BinaryPath string

	// PlistPath overrides PlistPath on macOS; empty means PlistPath.
	PlistPath string

	// StandardOutPath and StandardErrorPath override where launchd sends
	// whatever the agent prints; empty means StdoutPath and StderrPath.
	StandardOutPath   string
	StandardErrorPath string

	// Label overrides the launchd job label; empty means Label.
	Label string
}

// Install registers the agent with the platform's service manager: a
// LaunchDaemon on macOS, a service on Windows.
func Install(ctx context.Context, cfg Config) error {
	if cfg.BinaryPath == "" {
		return errors.New("service: no binary path")
	}
	if cfg.Runner == nil {
		return errors.New("service: no command runner")
	}
	if cfg.goos() == "windows" {
		return installWindows(ctx, cfg)
	}
	return installDarwin(ctx, cfg)
}

// Uninstall removes the registration. It returns ErrNotInstalled when there was
// nothing registered to remove.
func Uninstall(ctx context.Context, cfg Config) error {
	if cfg.Runner == nil {
		return errors.New("service: no command runner")
	}
	if cfg.goos() == "windows" {
		return uninstallWindows(ctx, cfg)
	}
	return uninstallDarwin(ctx, cfg)
}

// goos is the platform the registration is for.
func (c Config) goos() string {
	if c.GOOS != "" {
		return c.GOOS
	}
	return runtime.GOOS
}
