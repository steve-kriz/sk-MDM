package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/service"
)

// runInstallService is `mdmagent install-service`: it registers the agent with
// the platform's service manager, as a LaunchDaemon on macOS and as a service
// on Windows. The installer runs it, which is why the binary to register
// defaults to this one.
func runInstallService(fsys platform.FileSystem, goos string, args []string, stdout, stderr io.Writer) int {
	cfg, code := serviceConfig(fsys, goos, "mdmagent install-service", args, stderr)
	if code != exitOK {
		return code
	}

	if err := service.Install(context.Background(), cfg); err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}

	fmt.Fprintln(stdout, "service installed")
	return exitOK
}

// runUninstallService is `mdmagent uninstall-service`: it removes the
// registration. Having nothing to remove is not a failure — an uninstaller is
// run twice often enough — so it says so and exits 0.
func runUninstallService(fsys platform.FileSystem, goos string, args []string, stdout, stderr io.Writer) int {
	cfg, code := serviceConfig(fsys, goos, "mdmagent uninstall-service", args, stderr)
	if code != exitOK {
		return code
	}

	err := service.Uninstall(context.Background(), cfg)
	if errors.Is(err, service.ErrNotInstalled) {
		fmt.Fprintln(stdout, "service not installed")
		return exitOK
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}

	fmt.Fprintln(stdout, "service removed")
	return exitOK
}

// serviceConfig parses the flags both service verbs take and builds the
// registration they act on. The second return is the exit code to stop on, or
// exitOK when the config is good.
func serviceConfig(fsys platform.FileSystem, goos, name string, args []string, stderr io.Writer) (service.Config, int) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	binary := flags.String("binary", "", "path to the installed mdmagent executable; defaults to this one")
	if err := flags.Parse(args); err != nil {
		return service.Config{}, exitError
	}

	path := *binary
	if path == "" {
		resolved, err := executablePath()
		if err != nil {
			fmt.Fprintln(stderr, err)
			return service.Config{}, exitError
		}
		path = resolved
	}

	return service.Config{
		FS:         fsys,
		Runner:     newRunner(),
		GOOS:       goos,
		BinaryPath: path,
	}, exitOK
}
