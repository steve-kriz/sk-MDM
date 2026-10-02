package service

import (
	"context"
	"fmt"
	"strings"
)

// The Windows registration is performed with sc.exe through
// platform.CommandRunner rather than by opening the service control manager
// directly, for two reasons: the call is then recorded by a fake in a test that
// runs unprivileged on either host, and the registration is the same one an
// administrator would make by hand, which is what support will compare it to.
//
// This file carries no build constraint: `install-service` decides what to do
// from the GOOS it was given, so the Windows path is exercised from a macOS
// host and the other way round.
const (
	// scProgram is the service control program every registration goes
	// through.
	scProgram = "sc.exe"
	// startAutomatic is the start type the agent is registered with: the
	// device must be managed from boot, with nobody logged in.
	startAutomatic = "auto"
)

// errServiceDoesNotExist is what sc.exe exits with when the service is not
// registered (ERROR_SERVICE_DOES_NOT_EXIST). It is how uninstall tells "nothing
// to remove" from "the removal failed".
const errServiceDoesNotExist = 1060

// BinPath is the `binPath=` value the service is registered with: the installed
// binary, quoted because Program Files has a space in it, followed by the
// agent's own `run` verb.
func BinPath(binary string) string {
	return `"` + binary + `" run`
}

// installWindows registers the service with the service control manager.
func installWindows(ctx context.Context, cfg Config) error {
	return runSC(ctx, cfg, "create", Name,
		"binPath=", BinPath(cfg.BinaryPath),
		"start=", startAutomatic,
		"DisplayName=", DisplayName,
	)
}

// uninstallWindows removes the registration.
//
// The query comes first so an uninstall that has nothing to remove is reported
// as such rather than as a failure, and the stop is best effort: a service that
// is already stopped, or that refuses to stop, is still deleted.
func uninstallWindows(ctx context.Context, cfg Config) error {
	result, err := cfg.Runner.Run(ctx, scProgram, "query", Name)
	if err != nil {
		return err
	}
	if result.ExitCode == errServiceDoesNotExist {
		return ErrNotInstalled
	}

	if _, err := cfg.Runner.Run(ctx, scProgram, "stop", Name); err != nil {
		return err
	}
	return runSC(ctx, cfg, "delete", Name)
}

// runSC runs one sc.exe subcommand and turns a non-zero exit into an error
// naming what failed.
func runSC(ctx context.Context, cfg Config, args ...string) error {
	result, err := cfg.Runner.Run(ctx, scProgram, args...)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("sc.exe %s failed with exit code %d%s",
			strings.Join(args, " "), result.ExitCode, detail(output(result.Stderr, result.Stdout)))
	}
	return nil
}

// output is the first of the two streams that said anything: sc.exe reports its
// failures on stdout as often as on stderr.
func output(stderr, stdout string) string {
	if strings.TrimSpace(stderr) != "" {
		return stderr
	}
	return stdout
}
