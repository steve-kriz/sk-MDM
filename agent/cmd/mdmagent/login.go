package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/client"
	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/state"
	"github.com/officehq/sk-mdm/agent/internal/userauth"
)

// agentAuthConfigPath is the public endpoint `mdmagent login` reads the tenant,
// client and scopes from.
const agentAuthConfigPath = "/api/v1/agent-auth/config"

// newProtector is what the user token vault is encrypted with.
var newProtector = func() platform.SecretProtector { return platform.NewSecretProtector() }

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
// It prints a verification URL and a code, waits for the user to finish in any
// browser, and stores the resulting tokens in the vault the service reads. A
// sign-in that fails for any reason leaves an earlier one exactly as it was:
// the vault is only written once a token has been received.
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

	username := userauth.UsernameFromIDToken(tok.IDToken)
	vault := userauth.NewVault(fsys, newProtector(), userauth.VaultPath(goos))
	if err := vault.Save(userauth.Record{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		ExpiresAt:    clock.Now().Add(time.Duration(tok.ExpiresIn) * time.Second),
		Username:     username,
		TenantID:     authCfg.TenantID,
		ClientID:     authCfg.ClientID,
		Scopes:       authCfg.Scopes,
	}); err != nil {
		fmt.Fprintf(stderr, "could not store sign-in: %v\n", err)
		return exitError
	}

	fmt.Fprintf(stdout, "signed in as %s\n", username)
	return exitOK
}

// runLogout is `mdmagent logout`: the stored sign-in is deleted. Nobody being
// signed in already is not an error.
func runLogout(fsys platform.FileSystem, goos string, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mdmagent logout", flag.ContinueOnError)
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return exitError
	}

	vault := userauth.NewVault(fsys, newProtector(), userauth.VaultPath(goos))
	if err := vault.Delete(); err != nil {
		fmt.Fprintf(stderr, "could not remove sign-in: %v\n", err)
		return exitError
	}
	fmt.Fprintln(stdout, "signed out")
	return exitOK
}
