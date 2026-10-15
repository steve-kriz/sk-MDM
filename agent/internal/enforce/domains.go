package enforce

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// Domain blocking lives in the hosts file, because Windows Firewall and macOS
// pf filter by IP address, not by name. The agent owns exactly one block of the
// file, between these two marker lines, and never touches a byte outside it.
const (
	// HostsBeginMarker opens the managed block.
	HostsBeginMarker = "# BEGIN sk-mdm managed block - do not edit"
	// HostsEndMarker closes the managed block.
	HostsEndMarker = "# END sk-mdm managed block"

	// WindowsHostsPath is the hosts file on Windows.
	WindowsHostsPath = `C:\Windows\System32\drivers\etc\hosts`
	// DarwinHostsPath is the hosts file on macOS.
	DarwinHostsPath = "/etc/hosts"

	// HostsFileMode is the mode the hosts file is written with.
	HostsFileMode fs.FileMode = 0o644

	// blockedIPv4 and blockedIPv6 are where a blocked name is pointed.
	blockedIPv4 = "0.0.0.0"
	blockedIPv6 = "::"
)

// Domains keeps the managed block of the hosts file in line with
// firewallBlockedDomains, less the exceptions in firewallAllowedDomains.
//
// Allow semantics are exceptions, not default-deny: a hosts file cannot block
// everything but a list, so an allowed domain is only ever removed from the
// blocked set. The lists are independent of firewallEnabled.
type Domains struct {
	Runner platform.CommandRunner
	FS     platform.FileSystem
	GOOS   string
	Logger *logging.Logger
	// Actions, when set, is told once each time Apply rewrote the hosts file,
	// whether or not the DNS flush that follows succeeds. Nil records nothing.
	Actions func(actionType string, details map[string]string)
}

// Name is "domains".
func (d *Domains) Name() string { return "domains" }

// Apply rewrites the managed block when the blocked set changed it, then
// flushes the DNS cache. A content that would not change is not written and
// nothing is flushed. A goos with no known hosts file does nothing.
func (d *Domains) Apply(ctx context.Context, effective map[string]any, _ contract.Posture) error {
	path, ok := hostsPath(d.GOOS)
	if !ok {
		return nil
	}
	eol := "\n"
	if d.GOOS == "windows" {
		eol = "\r\n"
	}

	names := d.BlockedNames(effective)

	current, err := d.FS.ReadFile(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("read hosts file: %w", err)
		}
		current = nil
	}

	next, err := hostsContent(current, names, eol)
	if err != nil {
		return err
	}
	if bytes.Equal(next, current) {
		return nil
	}

	if err := platform.WriteFileAtomic(d.FS, path, next, HostsFileMode); err != nil {
		return fmt.Errorf("write hosts file: %w", err)
	}
	if d.Actions != nil {
		d.Actions(contract.ActionDomainsUpdated, map[string]string{"blockedCount": strconv.Itoa(len(names))})
	}
	return d.flush(ctx)
}

// BlockedNames is the set of names the managed block points away: every valid
// blocked entry, lowercased, with its www. form, less every name an allowed
// entry names, deduplicated and sorted. Each invalid entry is skipped with one
// warning.
func (d *Domains) BlockedNames(effective map[string]any) []string {
	blocked := d.validEntries(effective, SettingFirewallBlockedDomains)
	allowed := map[string]bool{}
	for _, entry := range d.validEntries(effective, SettingFirewallAllowedDomains) {
		allowed[entry] = true
	}

	set := map[string]bool{}
	for _, entry := range blocked {
		set[entry] = true
		if !strings.HasPrefix(entry, "www.") {
			if www := "www." + entry; len(www) <= DomainMaxLength {
				set[www] = true
			}
		}
	}

	names := make([]string, 0, len(set))
	for name := range set {
		if !allowed[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// validEntries is every valid entry of the list under key, lowercased. A value
// that is not a list reads as absent.
func (d *Domains) validEntries(effective map[string]any, key string) []string {
	list, ok := listSetting(effective, key)
	if !ok {
		return nil
	}
	entries := make([]string, 0, len(list))
	for _, item := range list {
		entry, isString := item.(string)
		if !isString || !validDomain(entry) {
			warn(d.Logger, "domain entry ignored", logging.F("key", key), logging.F("entry", fmt.Sprint(item)))
			continue
		}
		entries = append(entries, strings.ToLower(entry))
	}
	return entries
}

// flush runs the platform's DNS cache flush commands, once each, so a name
// just blocked stops resolving straight away.
func (d *Domains) flush(ctx context.Context) error {
	var errs []error
	for _, cmd := range flushCommands(d.GOOS) {
		result, err := d.Runner.Run(ctx, cmd[0], cmd[1:]...)
		if err != nil {
			errs = append(errs, fmt.Errorf("flush dns cache: %s: %w", cmd[0], err))
			continue
		}
		if result.ExitCode != 0 {
			errs = append(errs, fmt.Errorf("flush dns cache: %s exited with code %d: %s",
				cmd[0], result.ExitCode, strings.TrimSpace(result.Stderr)))
		}
	}
	return errors.Join(errs...)
}

// hostsPath is the hosts file for goos.
func hostsPath(goos string) (string, bool) {
	switch goos {
	case "windows":
		return WindowsHostsPath, true
	case "darwin":
		return DarwinHostsPath, true
	default:
		return "", false
	}
}

// flushCommands are the DNS cache flush commands for goos, name first.
func flushCommands(goos string) [][]string {
	switch goos {
	case "windows":
		return [][]string{{"ipconfig.exe", "/flushdns"}}
	case "darwin":
		return [][]string{
			{"/usr/bin/dscacheutil", "-flushcache"},
			{"/usr/bin/killall", "-HUP", "mDNSResponder"},
		}
	default:
		return nil
	}
}

// hostsContent is the hosts file as it should be: current with its managed
// block replaced by one for names, appended when there is none, or removed
// when names is empty. Every byte outside the block is kept. A file whose
// markers do not form exactly one BEGIN followed by one END is malformed and
// refused, so the agent never guesses which lines it owns.
func hostsContent(current []byte, names []string, eol string) ([]byte, error) {
	start, end, found, err := managedBlock(current)
	if err != nil {
		return nil, err
	}

	var block []byte
	if len(names) > 0 {
		var b strings.Builder
		b.WriteString(HostsBeginMarker + eol)
		for _, name := range names {
			b.WriteString(blockedIPv4 + " " + name + eol)
			b.WriteString(blockedIPv6 + " " + name + eol)
		}
		b.WriteString(HostsEndMarker + eol)
		block = []byte(b.String())
	}

	var next []byte
	switch {
	case found:
		next = append(next, current[:start]...)
		next = append(next, block...)
		next = append(next, current[end:]...)
	case len(block) == 0:
		return current, nil
	default:
		next = append(next, current...)
		if len(current) > 0 && current[len(current)-1] != '\n' {
			next = append(next, eol...)
		}
		next = append(next, block...)
	}
	return next, nil
}

// managedBlock locates the managed block in content: the byte offset its BEGIN
// line starts at and the offset just past its END line, line ending included.
// A marker is a whole line, ignoring a trailing carriage return; a marker
// inside a longer line is not one.
func managedBlock(content []byte) (start, end int, found bool, err error) {
	begins, ends := 0, 0
	for offset := 0; offset < len(content); {
		lineEnd := bytes.IndexByte(content[offset:], '\n')
		next := len(content)
		if lineEnd >= 0 {
			next = offset + lineEnd + 1
		}
		line := strings.TrimSuffix(strings.TrimSuffix(string(content[offset:next]), "\n"), "\r")

		switch line {
		case HostsBeginMarker:
			begins++
			start = offset
		case HostsEndMarker:
			ends++
			if begins == 0 {
				return 0, 0, false, errors.New("hosts file managed block is malformed: END marker without BEGIN")
			}
			end = next
		}
		offset = next
	}

	switch {
	case begins == 0 && ends == 0:
		return 0, 0, false, nil
	case begins > 1:
		return 0, 0, false, errors.New("hosts file managed block is malformed: more than one BEGIN marker")
	case ends == 0:
		return 0, 0, false, errors.New("hosts file managed block is malformed: BEGIN marker without END")
	case ends > 1:
		return 0, 0, false, errors.New("hosts file managed block is malformed: more than one END marker")
	}
	return start, end, true, nil
}
