package platform

import (
	"context"
	"fmt"
)

// URLOpener opens an address in the desktop user's default browser.
type URLOpener interface {
	Open(ctx context.Context, url string) error
}

// CommandURLOpener opens an address with the platform's own handler, run
// through Runner: `rundll32 url.dll,FileProtocolHandler <url>` on Windows and
// `open <url>` on macOS. The address is passed as one argument and never
// through a shell.
type CommandURLOpener struct {
	Runner CommandRunner
	GOOS   string
}

var _ URLOpener = CommandURLOpener{}

// Open hands url to the platform's handler. A command that cannot start or
// exits non-zero is an error.
func (o CommandURLOpener) Open(ctx context.Context, url string) error {
	name, args := "open", []string{url}
	if o.GOOS == "windows" {
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	}
	res, err := o.Runner.Run(ctx, name, args...)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s exited %d", name, res.ExitCode)
	}
	return nil
}
