package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/client"
	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/signin"
	"github.com/officehq/sk-mdm/agent/internal/state"
	"github.com/officehq/sk-mdm/agent/internal/userauth"
)

// openSignInWait is how long `mdmagent open-signin` waits for the service to
// publish a sign-in address, and openSignInPoll how often it looks.
const (
	openSignInWait = 30 * time.Second
	openSignInPoll = time.Second
)

// msgNoSignInPending is what `mdmagent open-signin` says when there is
// nothing to open.
const msgNoSignInPending = "no sign-in is pending"

// newOpener is what `mdmagent open-signin` opens the browser through.
var newOpener = func(goos string) platform.URLOpener {
	return platform.CommandURLOpener{Runner: newRunner(), GOOS: goos}
}

// newSignInBroker builds the brokered sign-in the service runs.
//
// It works only while a sign-in is needed: the device is unenrolled and the
// config file at configPath holds no enrollment token (read afresh each time,
// since the sign-in writes it and a rejected one is removed). The tenant and
// client come from the config when both are baked in, and otherwise from
// GET /api/v1/agent-auth/config, fetched when first needed and remembered once
// it succeeds. The minted enrollment token is written to the config, and the
// sign-in is signalled on wake without blocking: one pending wake is enough for
// the run loop to try enrolling again.
func newSignInBroker(cfg config.Config, goos, configPath string, transport *client.Client, store *state.Store,
	fsys platform.FileSystem, doer platform.HTTPDoer, clock platform.Clock,
	logger *logging.Logger, wake chan<- struct{}) *signin.Broker {

	var (
		mu     sync.Mutex
		cached *signin.AuthConfig
	)
	resolve := func(ctx context.Context) (signin.AuthConfig, error) {
		if cfg.TenantID != "" && cfg.ClientID != "" {
			return signin.AuthConfig{TenantID: cfg.TenantID, ClientID: cfg.ClientID}, nil
		}
		mu.Lock()
		defer mu.Unlock()
		if cached != nil {
			return *cached, nil
		}
		fetched, err := fetchAgentAuthConfig(transport)
		if err != nil {
			return signin.AuthConfig{}, err
		}
		cached = &signin.AuthConfig{TenantID: fetched.TenantID, ClientID: fetched.ClientID}
		return *cached, nil
	}

	needed := func() bool {
		st, err := store.Load()
		if err != nil || st.Enrolled() {
			return false
		}
		token, err := config.ReadEnrollmentToken(fsys, configPath)
		return err == nil && token == ""
	}

	return &signin.Broker{
		Transport: transport,
		Redeemer:  &userauth.Entra{Doer: doer, Clock: clock},
		SaveToken: func(token string) error {
			return config.SetEnrollmentToken(fsys, configPath, token)
		},
		FS:          fsys,
		Clock:       clock,
		Logger:      logger,
		SessionPath: signin.SessionPath(goos),
		URLPath:     signin.URLPath(goos),
		AuthConfig:  resolve,
		Needed:      needed,
		OnSignIn: func() {
			select {
			case wake <- struct{}{}:
			default:
			}
		},
	}
}

// runOpenSignIn is `mdmagent open-signin`, run as the desktop user by the
// installers and the "Sign in to OfficeHQ MDM" shortcut.
//
// It waits up to openSignInWait for the service to publish the sign-in
// address, checks it is an https address on the MDM site's sign-in path (and,
// when the config is readable, on the collection URL's host), and opens it in
// the default browser. With nothing published it prints msgNoSignInPending
// and exits 1.
func runOpenSignIn(fsys platform.FileSystem, goos string, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mdmagent open-signin", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", config.Path(goos), "path to the agent config file")
	if err := flags.Parse(args); err != nil {
		return exitError
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: mdmagent open-signin [-config <path>]")
		return exitError
	}

	clock := newClock()
	raw, ok := waitForSignInURL(fsys, clock, signin.URLPath(goos))
	if !ok {
		fmt.Fprintln(stderr, msgNoSignInPending)
		return exitError
	}

	// The config is owner-only on a locked-down install, so a desktop user
	// may not be able to read it; the path check still applies then.
	wantHost := ""
	if cfg, err := config.Load(fsys, *configPath); err == nil {
		if base, err := url.Parse(cfg.CollectionURL); err == nil {
			wantHost = base.Host
		}
	}
	if err := checkSignInURL(raw, wantHost); err != nil {
		fmt.Fprintf(stderr, "refusing to open the sign-in address: %v\n", err)
		return exitError
	}

	if err := newOpener(goos).Open(context.Background(), raw); err != nil {
		fmt.Fprintf(stderr, "could not open the browser: %v\n", err)
		return exitError
	}
	fmt.Fprintln(stdout, "opened "+raw)
	return exitOK
}

// waitForSignInURL reads path until it holds an address or openSignInWait
// has passed on clock. A file that is missing, unreadable or empty is "not
// yet".
func waitForSignInURL(fsys platform.FileSystem, clock platform.Clock, path string) (string, bool) {
	deadline := clock.Now().Add(openSignInWait)
	for {
		if data, err := fsys.ReadFile(path); err == nil {
			if raw := strings.TrimSpace(string(data)); raw != "" {
				return raw, true
			}
		}
		if !clock.Now().Before(deadline) {
			return "", false
		}
		<-clock.After(openSignInPoll)
	}
}

// checkSignInURL accepts only an https address on the sign-in path, on
// wantHost when that is known.
func checkSignInURL(raw, wantHost string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("not an absolute address")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("scheme is %q, not https", u.Scheme)
	}
	if u.User != nil {
		return errors.New("address carries credentials")
	}
	if !strings.HasPrefix(u.Path, signin.SignInPathPrefix) || len(u.Path) == len(signin.SignInPathPrefix) {
		return fmt.Errorf("path is not under %s", signin.SignInPathPrefix)
	}
	if wantHost != "" && !strings.EqualFold(u.Host, wantHost) {
		return fmt.Errorf("host %q is not the collection host %q", u.Host, wantHost)
	}
	return nil
}
