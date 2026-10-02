package service

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"strings"
)

// The macOS registration: a LaunchDaemon, so the agent runs as root from boot
// with no user logged in.
const (
	// Label is the launchd job label, in reverse-DNS form as launchd expects.
	Label = "au.com.officehq.mdmagent"
	// PlistPath is where the LaunchDaemon plist is written. The file name is
	// the label, which is the convention launchd tooling assumes.
	PlistPath = "/Library/LaunchDaemons/" + Label + ".plist"
	// Domain is the launchd domain the daemon is bootstrapped into: system,
	// not a user's, because the agent manages the machine rather than a
	// session.
	Domain = "system"
)

// Where launchd sends whatever the agent prints. It is not the agent's own log
// — that is written by agent/internal/logging — but the place a panic or a
// startup failure lands, which is the first thing support looks for.
const (
	// LogDir holds the daemon's stdout and stderr.
	LogDir = "/Library/Logs/OfficeHQ"
	// StdoutPath is where launchd sends the daemon's stdout.
	StdoutPath = LogDir + "/mdmagent.out.log"
	// StderrPath is where launchd sends the daemon's stderr.
	StderrPath = LogDir + "/mdmagent.err.log"
)

// File modes for the two things an install creates.
const (
	// PlistFileMode is the mode the plist is written with. launchd refuses
	// to load a daemon plist that anyone but its owner may write, so this is
	// 0644 rather than anything looser.
	PlistFileMode fs.FileMode = 0o644
	// LogDirMode is the mode the log directory is created with.
	LogDirMode fs.FileMode = 0o755
)

// launchctl is the program a daemon is loaded and unloaded with.
const launchctl = "launchctl"

// plistDoctype is the document type every property list carries.
const plistDoctype = `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n"

// PlistBytes renders the LaunchDaemon plist for cfg.
//
// The daemon is the installed binary with the agent's own `run` verb after it,
// loaded at boot and restarted whenever it exits, so a crash costs one check-in
// rather than the device's management.
//
// Every value is escaped as XML text, because an installation path is allowed
// to contain `&` or `<` and a plist that does not parse is a daemon that never
// loads. Rendering cannot fail: it writes to a buffer and returns the bytes.
func PlistBytes(cfg Config) []byte {
	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	buf.WriteString(plistDoctype)
	buf.WriteString("<plist version=\"1.0\">\n")
	buf.WriteString("<dict>\n")

	writeStringEntry(&buf, "Label", cfg.label())

	buf.WriteString("\t<key>ProgramArguments</key>\n")
	buf.WriteString("\t<array>\n")
	for _, arg := range []string{cfg.BinaryPath, "run"} {
		buf.WriteString("\t\t<string>")
		writeEscaped(&buf, arg)
		buf.WriteString("</string>\n")
	}
	buf.WriteString("\t</array>\n")

	writeBoolEntry(&buf, "RunAtLoad", true)
	writeBoolEntry(&buf, "KeepAlive", true)
	writeStringEntry(&buf, "StandardOutPath", cfg.stdoutPath())
	writeStringEntry(&buf, "StandardErrorPath", cfg.stderrPath())

	buf.WriteString("</dict>\n")
	buf.WriteString("</plist>\n")
	return buf.Bytes()
}

// installDarwin writes the plist and bootstraps the daemon.
func installDarwin(ctx context.Context, cfg Config) error {
	if cfg.FS == nil {
		return errors.New("service: no filesystem")
	}

	// launchd creates neither directory: the log directory must exist before
	// the daemon writes a line to it, and the plist's own directory is there
	// on every macOS install but is created here for the fake filesystem a
	// test runs against.
	if err := cfg.FS.MkdirAll(LogDir, LogDirMode); err != nil {
		return err
	}

	path := cfg.plistPath()
	if err := cfg.FS.WriteFile(path, PlistBytes(cfg), PlistFileMode); err != nil {
		return err
	}

	return runLaunchctl(ctx, cfg, "bootstrap", Domain, path)
}

// uninstallDarwin boots the daemon out and removes its plist.
//
// The bootout is best effort: a daemon that is not loaded — because the machine
// has not been rebooted since an interrupted install, say — must still have its
// plist removed, or the next boot would start an agent nobody asked for.
func uninstallDarwin(ctx context.Context, cfg Config) error {
	if cfg.FS == nil {
		return errors.New("service: no filesystem")
	}

	path := cfg.plistPath()
	if _, err := cfg.FS.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotInstalled
		}
		return err
	}

	if _, err := cfg.Runner.Run(ctx, launchctl, "bootout", Domain+"/"+cfg.label()); err != nil {
		return err
	}
	return cfg.FS.Remove(path)
}

// runLaunchctl runs one launchctl subcommand and turns a non-zero exit into an
// error naming what failed.
func runLaunchctl(ctx context.Context, cfg Config, args ...string) error {
	result, err := cfg.Runner.Run(ctx, launchctl, args...)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("launchctl %s failed with exit code %d%s",
			strings.Join(args, " "), result.ExitCode, detail(result.Stderr))
	}
	return nil
}

// plistPath is where this configuration's plist lives.
func (c Config) plistPath() string {
	if c.PlistPath != "" {
		return c.PlistPath
	}
	return PlistPath
}

// label is this configuration's launchd job label.
func (c Config) label() string {
	if c.Label != "" {
		return c.Label
	}
	return Label
}

// stdoutPath is where launchd sends the daemon's stdout.
func (c Config) stdoutPath() string {
	if c.StandardOutPath != "" {
		return c.StandardOutPath
	}
	return StdoutPath
}

// stderrPath is where launchd sends the daemon's stderr.
func (c Config) stderrPath() string {
	if c.StandardErrorPath != "" {
		return c.StandardErrorPath
	}
	return StderrPath
}

// writeStringEntry writes one `<key>`/`<string>` pair, escaped.
func writeStringEntry(buf *bytes.Buffer, key, value string) {
	buf.WriteString("\t<key>")
	writeEscaped(buf, key)
	buf.WriteString("</key>\n\t<string>")
	writeEscaped(buf, value)
	buf.WriteString("</string>\n")
}

// writeBoolEntry writes one `<key>`/`<true/>` pair.
func writeBoolEntry(buf *bytes.Buffer, key string, value bool) {
	buf.WriteString("\t<key>")
	writeEscaped(buf, key)
	buf.WriteString("</key>\n\t")
	if value {
		buf.WriteString("<true/>\n")
		return
	}
	buf.WriteString("<false/>\n")
}

// writeEscaped writes s as XML character data. xml.EscapeText only fails on a
// writer that fails, and a bytes.Buffer does not.
func writeEscaped(buf *bytes.Buffer, s string) {
	_ = xml.EscapeText(buf, []byte(s))
}

// detail is a trailing ": <stderr>" for an error message, or nothing when the
// command said nothing.
func detail(stderr string) string {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return ""
	}
	return ": " + stderr
}
