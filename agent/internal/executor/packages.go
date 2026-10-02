package executor

import (
	"context"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
)

// installPackage installs a package by id.
//
// macOS has no package manager the agent may assume, so the command is refused
// there rather than guessed at: nothing is run and the backend is told why.
func installPackage(ctx context.Context, cmd Command, deps *Deps) contract.CommandResultRequest {
	return runPackage(ctx, cmd, deps, installArgv)
}

// uninstallPackage removes a package by id, with the same platform rule.
func uninstallPackage(ctx context.Context, cmd Command, deps *Deps) contract.CommandResultRequest {
	return runPackage(ctx, cmd, deps, uninstallArgv)
}

// runPackage is the shared half: refuse the platform, then the payload, then
// run winget and report its exit.
//
// The platform is checked first because a command that has no implementation
// here is refused whatever its payload says.
func runPackage(ctx context.Context, cmd Command, deps *Deps, argv func(packageID string) []string) contract.CommandResultRequest {
	if deps.goos() != "windows" {
		return deps.fail(ErrUnsupportedPlatform, "")
	}

	payload, ok := decodePackage(cmd.Payload)
	if !ok {
		return deps.fail(ErrInvalidPayload, "")
	}

	deps.log(logging.LevelInfo, "running package command",
		logging.F("commandId", cmd.CommandID),
		logging.F("type", cmd.Type),
		logging.F("packageId", payload.PackageID),
	)

	args := argv(payload.PackageID)

	// winget is a per-user App Installer component: from a LocalSystem
	// service it may not resolve on PATH or may find no source at all. That
	// failure arrives here as a non-zero exit with winget's own message,
	// which is what the backend is told, and it needs verifying on a real
	// device.
	return deps.report(deps.run(ctx, EffectiveTimeout(payload.TimeoutSeconds), args[0], args[1:]...))
}

// installArgv is the winget invocation for an install: exact id, no prompts,
// and both agreements accepted, because nobody is at the keyboard to accept
// them.
func installArgv(packageID string) []string {
	return []string{
		"winget", "install",
		"--id", packageID,
		"--exact",
		"--silent",
		"--accept-package-agreements",
		"--accept-source-agreements",
	}
}

// uninstallArgv is the winget invocation for an uninstall.
func uninstallArgv(packageID string) []string {
	return []string{
		"winget", "uninstall",
		"--id", packageID,
		"--exact",
		"--silent",
	}
}
