package platform

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// recordingRunner records one call and answers with a canned result.
type recordingRunner struct {
	name   string
	args   []string
	result CommandResult
	err    error
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) (CommandResult, error) {
	r.name, r.args = name, args
	return r.result, r.err
}

// TestCommandURLOpener_PerPlatform checks the command each platform opens a
// browser with: the URL is one argument, never passed through a shell.
func TestCommandURLOpener_PerPlatform(t *testing.T) {
	const target = "https://mdm.example.com/agent/signin/abc?x=1&y=2"
	cases := map[string]string{
		"windows": "rundll32 url.dll,FileProtocolHandler " + target,
		"darwin":  "open " + target,
	}
	for goos, want := range cases {
		r := &recordingRunner{}
		if err := (CommandURLOpener{Runner: r, GOOS: goos}).Open(context.Background(), target); err != nil {
			t.Fatalf("%s: %v", goos, err)
		}
		if got := r.name + " " + strings.Join(r.args, " "); got != want {
			t.Errorf("%s: %q, want %q", goos, got, want)
		}
		if r.args[len(r.args)-1] != target {
			t.Errorf("%s: url not a single argument: %q", goos, r.args)
		}
	}
}

// A command that cannot start, or exits non-zero, is an error.
func TestCommandURLOpener_Failures(t *testing.T) {
	if err := (CommandURLOpener{Runner: &recordingRunner{err: errors.New("not found")}, GOOS: "darwin"}).Open(context.Background(), "https://x"); err == nil {
		t.Error("start failure: want an error")
	}
	if err := (CommandURLOpener{Runner: &recordingRunner{result: CommandResult{ExitCode: 1}}, GOOS: "darwin"}).Open(context.Background(), "https://x"); err == nil {
		t.Error("non-zero exit: want an error")
	}
}
