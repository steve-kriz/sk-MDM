package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"

	"github.com/officehq/sk-mdm/agent/internal/client"
	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/signin"
	"github.com/officehq/sk-mdm/agent/internal/state"
	"github.com/officehq/sk-mdm/agent/internal/userauth"
)

// agentAuthConfigPath is the public endpoint `mdmagent login` reads the tenant,
// client and scopes from.
const agentAuthConfigPath = "/api/v1/agent-auth/config"

// msgEnrollmentTokenStored is what `mdmagent login` prints once the minted
// enrollment token is in the config.
const msgEnrollmentTokenStored = "enrollment token stored; the service will enroll this device"

// agentAuthConfig is the body of GET /api/v1/agent-auth/config.
type agentAuthConfig struct {
	TenantID string   `json:"tenantId"`
	ClientID string   `json:"clientId"`
	Scopes   []string `json:"scopes"`
}

// fetchAgentAuthConfig reads the sign-in configuration, unauthenticated.
func fetchAgentAuthConfig(transport *client.Client) (agentAuthConfig, error) {
	resp, err := transport.FetchPublic(agentAuthConfigPath)
	if err != nil {
		return agentAuthConfig{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return agentAuthConfig{}, fmt.Errorf("agent-auth config answered %d", resp.StatusCode)
	}
	var cfg agentAuthConfig
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&cfg); err != nil {
		return agentAuthConfig{}, err
	}
	if cfg.TenantID == "" || cfg.ClientID == "" || len(cfg.Scopes) == 0 {
		return agentAuthConfig{}, errors.New("agent-auth config incomplete")
	}
	return cfg, nil
}

// signInFailure is the stderr line for a failed sign-in.
func signInFailure(ctx context.Context, err error) string {
	switch {
	case ctx.Err() != nil, errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "sign-in cancelled"
	case errors.Is(err, userauth.ErrSignInDeclined):
		return "sign-in was declined"
	case errors.Is(err, userauth.ErrSignInExpired):
		return "sign-in code expired"
	default:
		return "sign-in failed"
	}
}

// runLogin is `mdmagent login`: the OAuth 2.0 device authorization grant.
//
// It is run elevated. It prints a verification URL and a code, waits for the
// user to finish in any browser, spends the access token on minting a
// single-use enrollment token and writes that token to the config, where the
// service's next enrollment attempt picks it up. No Entra token is stored. A
// sign-in or mint that fails for any reason leaves the config exactly as it
// was.
func runLogin(fsys platform.FileSystem, goos string, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mdmagent login", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", config.Path(goos), "path to the agent config file")
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

	doer := newDoer()
	clock := newClock()

	transport := client.New(cfg, state.NewStore(fsys, state.StatePath(goos)), doer, clock)
	authCfg, err := fetchAgentAuthConfig(transport)
	if err != nil {
		if errors.Is(err, client.ErrInsecureTransport) {
			fmt.Fprintln(stderr, config.ErrCollectionURL)
			return exitInvalidURL
		}
		fmt.Fprintln(stderr, "sign-in configuration unavailable")
		return exitError
	}

	ctx, stop := signalContext(context.Background())
	defer stop()

	entra := &userauth.Entra{Doer: doer, Clock: clock}
	code, err := entra.StartSignIn(ctx, authCfg.TenantID, authCfg.ClientID, authCfg.Scopes)
	if err != nil {
		fmt.Fprintln(stderr, signInFailure(ctx, err))
		return exitError
	}

	fmt.Fprintf(stdout, "To sign in, open %s and enter the code %s\n", code.VerificationURI, code.UserCode)

	tok, err := entra.PollToken(ctx, authCfg.TenantID, authCfg.ClientID, code)
	if err != nil {
		fmt.Fprintln(stderr, signInFailure(ctx, err))
		return exitError
	}

	// The access token is spent on one request, minting a single-use
	// enrollment token, and is then dropped; it is never stored.
	enrollmentToken, err := signin.MintEnrollmentToken(transport, tok.AccessToken)
	if err != nil {
		fmt.Fprintf(stderr, "could not get an enrollment token: %v\n", err)
		return exitError
	}
	if err := config.SetEnrollmentToken(fsys, *configPath, enrollmentToken); err != nil {
		fmt.Fprintf(stderr, "could not store the enrollment token: %v\n", err)
		return exitError
	}

	fmt.Fprintf(stdout, "signed in as %s\n", userauth.UsernameFromIDToken(tok.IDToken))
	fmt.Fprintln(stdout, msgEnrollmentTokenStored)
	return exitOK
}
