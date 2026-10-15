// Command mdmagent is the SK-MDM device agent.
//
// Usage:
//
//	mdmagent [-version]
//	mdmagent run [-config <path>] [-state <path>]
//	mdmagent install-service [-binary <path>]
//	mdmagent uninstall-service [-binary <path>]
//	mdmagent config set-url [-config <path>] <https url>
//	mdmagent config show [-config <path>] [-state <path>]
//	mdmagent login [-config <path>]
//	mdmagent open-signin [-config <path>]
//
// `open-signin` runs as the desktop user: it opens, in the default browser, the
// MDM site's sign-in address the running service has published (waiting up to
// 30 seconds for it). Signing in there lets an agent with no enrollment token
// enroll. With nothing published it prints "no sign-in is pending" and exits 1.
//
// `login` is the same sign-in from an elevated console, by device code: it
// mints a single-use enrollment token and writes it to the config.
//
// `run` is the agent itself, and is the verb both service managers are pointed
// at: the Windows service and the macOS LaunchDaemon start this binary with it.
//
// Exit codes: 0 on success, 2 for a collection URL that is not https, and 1
// for anything else that went wrong, including a usage mistake. The installer
// drives `config set-url`, so the insecure-URL case has its own code.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/state"
	"github.com/officehq/sk-mdm/agent/internal/version"
)

// Exit codes.
const (
	exitOK         = 0
	exitError      = 1
	exitInvalidURL = 2
	// exitRestart asks the service manager to start the agent again: an
	// update or a rollback has put a different binary in place.
	// It is service.ExitRestart.
	exitRestart = 3
)

// redactedToken is printed in place of the enrollment token. The device secret
// has no placeholder at all: `config show` never mentions it.
const redactedToken = "<redacted>"

func main() {
	os.Exit(run(platform.OSFileSystem{}, runtime.GOOS, os.Args[1:], os.Stdout, os.Stderr))
}

// run is main's body with every dependency passed in, so the commands are
// exercised in-process against a fake filesystem.
func run(fsys platform.FileSystem, goos string, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "config":
			return runConfig(fsys, goos, args[1:], stdout, stderr)
		case "run":
			return runAgent(fsys, goos, args[1:], stdout, stderr)
		case "install-service":
			return runInstallService(fsys, goos, args[1:], stdout, stderr)
		case "login":
			return runLogin(fsys, goos, args[1:], stdout, stderr)
		case "open-signin":
			return runOpenSignIn(fsys, goos, args[1:], stdout, stderr)
		case "uninstall-service":
			return runUninstallService(fsys, goos, args[1:], stdout, stderr)
		}
	}

	flags := flag.NewFlagSet("mdmagent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	showVersion := flags.Bool("version", false, "print the agent version and exit")
	if err := flags.Parse(args); err != nil {
		return exitError
	}

	if *showVersion {
		fmt.Fprintln(stdout, version.Version)
		return exitOK
	}

	fmt.Fprintf(stdout, "mdmagent %s\n", version.Version)
	return exitOK
}

func runConfig(fsys platform.FileSystem, goos string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: mdmagent config (set-url <https url> | show)")
		return exitError
	}

	switch args[0] {
	case "set-url":
		return runConfigSetURL(fsys, goos, args[1:], stdout, stderr)
	case "show":
		return runConfigShow(fsys, goos, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown config command %q\n", args[0])
		return exitError
	}
}

func runConfigSetURL(fsys platform.FileSystem, goos string, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mdmagent config set-url", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", config.Path(goos), "path to the agent config file")
	if err := flags.Parse(args); err != nil {
		return exitError
	}

	rest := flags.Args()
	if len(rest) != 1 {
		fmt.Fprintln(stderr, "usage: mdmagent config set-url [-config <path>] <https url>")
		return exitError
	}

	if err := config.SetCollectionURL(fsys, *configPath, rest[0]); err != nil {
		fmt.Fprintln(stderr, err)
		if errors.Is(err, config.ErrCollectionURL) {
			return exitInvalidURL
		}
		return exitError
	}

	fmt.Fprintln(stdout, "collection url updated")
	return exitOK
}

func runConfigShow(fsys platform.FileSystem, goos string, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mdmagent config show", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", config.Path(goos), "path to the agent config file")
	statePath := flags.String("state", state.StatePath(goos), "path to the agent state file")
	if err := flags.Parse(args); err != nil {
		return exitError
	}

	cfg, err := config.Load(fsys, *configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		if errors.Is(err, config.ErrCollectionURL) {
			return exitInvalidURL
		}
		return exitError
	}

	st, err := state.NewStore(fsys, *statePath).Load()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}

	enrollment := "not enrolled"
	deviceID := "(none)"
	if st.Enrolled() {
		enrollment = "enrolled"
		deviceID = st.DeviceID
	}

	fmt.Fprintf(stdout, "collectionUrl: %s\n", cfg.CollectionURL)
	fmt.Fprintf(stdout, "enrollmentToken: %s\n", redactedToken)
	fmt.Fprintf(stdout, "enrollment: %s\n", enrollment)
	fmt.Fprintf(stdout, "deviceId: %s\n", deviceID)
	fmt.Fprintf(stdout, "checkInIntervalSeconds: %d\n", cfg.CheckInIntervalSeconds)
	fmt.Fprintf(stdout, "logLevel: %s\n", cfg.LogLevel)
	return exitOK
}
