// Package signin is the browser sign-in brokered by the MDM site, so a person
// can enroll the device with their Entra ID account without typing a code.
//
// The service owns the config (SYSTEM/root only), so it is the service, not a
// process running as the desktop user, that completes the sign-in. The desktop
// user's only part is opening the sign-in address, which `mdmagent open-signin`
// reads from URLPath.
//
// The flow is the OAuth 2.0 authorization code grant with PKCE (S256) for a
// public client, with the MDM site standing in for the redirect:
//
//   - While the device is unenrolled and has no enrollment token, the Broker makes
//     a random verifier and creates a session with its S256 challenge (POST
//     /api/v1/agent-auth/sessions). The session, verifier included, is kept in
//     SessionPath (owner only); the sign-in address alone goes in URLPath
//     (world readable).
//   - The browser goes to the site's /agent/signin/<id>, on to Entra, and back
//     to the site's /agent/callback, which keeps the code on the session.
//   - The Broker polls GET /api/v1/agent-auth/sessions/<id> every
//     PollInterval. Once the code arrives it is redeemed at Entra with the
//     verifier, which never leaves the device, and both files go.
//   - The access token, held in memory only, is spent on one request: POST
//     /api/v1/agent-auth/enrollment-token mints a single-use enrollment
//     token, which SaveToken writes to the config. The access token is then
//     dropped and the run loop woken, to enroll with the enrollment token.
//
// A code, a verifier or a token is never logged, and no Entra token is ever
// written to disk.
package signin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/userauth"
)

// SessionsPath is the public route sessions are created at, and below which
// one is polled.
const SessionsPath = "/api/v1/agent-auth/sessions"

// SignInPathPrefix is the path every sign-in address the site hands out
// starts with.
const SignInPathPrefix = "/agent/signin/"

// EnrollmentTokenPath is the public route an Entra access token mints a
// single-use enrollment token at.
const EnrollmentTokenPath = "/api/v1/agent-auth/enrollment-token"

// ErrMintRefused is returned by MintEnrollmentToken when the backend refuses
// the access token (a 4xx): trying again with the same token will not help.
var ErrMintRefused = errors.New("enrollment token refused")

// defaultAccessLifetime is how long a redeemed access token is held for a
// retried mint when Entra named no lifetime.
const defaultAccessLifetime = 5 * time.Minute

// PollInterval is how often a pending session is looked at.
const PollInterval = 10 * time.Second

// File locations, next to the agent's config.
const (
	// WindowsSessionPath and DarwinSessionPath hold the pending session,
	// verifier included: owner only.
	WindowsSessionPath = `C:\ProgramData\OfficeHQ\MDM\signin.json`
	DarwinSessionPath  = "/Library/Application Support/OfficeHQ/MDM/signin.json"

	// WindowsURLPath and DarwinURLPath hold the sign-in address alone, for
	// `mdmagent open-signin` running as the desktop user.
	WindowsURLPath = `C:\ProgramData\OfficeHQ\MDM\signin-url.txt`
	DarwinURLPath  = "/Library/Application Support/OfficeHQ/MDM/signin-url.txt"
)

// File modes the two files are written with.
const (
	SessionFileMode fs.FileMode = 0o600
	URLFileMode     fs.FileMode = 0o644
)

// SessionPath returns the session file for a GOOS value: the Windows path for
// "windows" and the macOS path for anything else.
func SessionPath(goos string) string {
	if goos == "windows" {
		return WindowsSessionPath
	}
	return DarwinSessionPath
}

// URLPath returns the sign-in address file for a GOOS value.
func URLPath(goos string) string {
	if goos == "windows" {
		return WindowsURLPath
	}
	return DarwinURLPath
}

// sessionIDPattern is the only shape of session id put into a request path.
var sessionIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// verifierBytes makes a 43-character base64url verifier, RFC 7636's minimum.
const verifierBytes = 32

// maxBody bounds what is read of any broker answer.
const maxBody = 1 << 20

// AuthConfig is the Entra tenant and the agent's public client the sign-in
// uses. Scopes are always userauth.AgentScopes(ClientID).
type AuthConfig struct {
	TenantID string
	ClientID string
}

// BearerPoster sends a POST carrying a user's bearer token and nothing else;
// *client.Client is one.
type BearerPoster interface {
	PostPublicBearer(path string, body []byte, token string) (*http.Response, error)
}

// Transport is the half of the agent's client that carries no device
// credential.
type Transport interface {
	BearerPoster
	PostPublic(path string, body []byte) (*http.Response, error)
	FetchPublic(path string) (*http.Response, error)
}

// Redeemer exchanges an authorization code for tokens; *userauth.Entra is
// one.
type Redeemer interface {
	RedeemCode(ctx context.Context, tenantID, clientID, code, verifier, redirectURI string, scopes []string) (userauth.Token, error)
}

// Broker drives the sign-in from the service.
//
// Transport, Redeemer, SaveToken, FS, Clock, SessionPath, URLPath and
// AuthConfig are required. Logger, Needed, OnSignIn and Rand are optional.
type Broker struct {
	Transport Transport
	Redeemer  Redeemer
	// SaveToken stores a minted enrollment token: the enrollmentToken field
	// of the config.
	SaveToken func(token string) error
	// FS holds the two sign-in files.
	FS    platform.FileSystem
	Clock platform.Clock
	// Logger, when non-nil, records the sign-in. It never receives a code,
	// a verifier or a token.
	Logger *logging.Logger

	SessionPath string
	URLPath     string

	// AuthConfig resolves the tenant and client: the baked-in config
	// values, or the backend's agent-auth config.
	AuthConfig func(ctx context.Context) (AuthConfig, error)
	// Needed reports whether a sign-in is wanted now: the device is
	// unenrolled and the config holds no enrollment token. Nil means always.
	Needed func() bool
	// OnSignIn, when non-nil, is called after an enrollment token has been
	// saved.
	OnSignIn func()
	// Rand is the verifier's source; nil is crypto/rand.
	Rand io.Reader

	// lastErr is the last Run tick's error text, so a failure that repeats
	// every tick is logged once.
	lastErr string

	// held is a redeemed access token whose mint has not succeeded yet. It
	// lives in memory only, until it is spent, refused or expired.
	held *heldAccess
}

// heldAccess is a redeemed access token waiting to be spent on a mint.
type heldAccess struct {
	token    string
	username string
	expires  time.Time
}

// storedSession is the shape of SessionPath.
type storedSession struct {
	SessionID string    `json:"sessionId"`
	Verifier  string    `json:"verifier"`
	ExpiresAt time.Time `json:"expiresAt"`
	SignInURL string    `json:"signInUrl"`
}

// createAnswer is the body of a 201 from POST SessionsPath.
type createAnswer struct {
	SessionID string `json:"sessionId"`
	SignInURL string `json:"signInUrl"`
	ExpiresAt string `json:"expiresAt"`
}

// pollAnswer is the body of a 200 from GET SessionsPath/<id>.
type pollAnswer struct {
	Status      string `json:"status"`
	Code        string `json:"code"`
	RedirectURI string `json:"redirectUri"`
	Error       string `json:"error"`
	// Detail is Microsoft's own error and description for a failed sign-in;
	// it never carries the code.
	Detail string `json:"detail"`
}

// Run ticks at once and then every PollInterval until ctx ends. A tick that
// fails is logged, once per distinct failure, and retried at the next one.
func (b *Broker) Run(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		err := b.Tick(ctx)
		switch {
		case err == nil:
			b.lastErr = ""
		case ctx.Err() != nil:
			return
		case err.Error() != b.lastErr:
			b.lastErr = err.Error()
			b.log(logging.LevelWarn, "sign-in session unavailable, retrying",
				logging.F("error", b.lastErr),
				logging.F("seconds", int(PollInterval/time.Second)),
			)
		}
		select {
		case <-ctx.Done():
			return
		case <-b.Clock.After(PollInterval):
		}
	}
}

// Tick takes one step: with no sign-in needed it clears any leftover files and
// forgets a held access token; with an access token held it tries the mint
// again; otherwise it creates a session when none is usable, or polls the one
// held and acts on its answer. An error means "try again next tick"; the
// session held, if any, is kept.
func (b *Broker) Tick(ctx context.Context) error {
	if b.Needed != nil && !b.Needed() {
		b.held = nil
		b.clear()
		return nil
	}

	if b.held != nil {
		if b.Clock.Now().Before(b.held.expires) {
			return b.mint(ctx)
		}
		b.held = nil
		b.log(logging.LevelWarn, "sign-in expired before an enrollment token could be minted, starting a new one")
		return b.create(ctx)
	}

	sess, ok := b.load()
	if !ok || !b.Clock.Now().Before(sess.ExpiresAt) {
		return b.create(ctx)
	}

	resp, err := b.Transport.FetchPublic(SessionsPath + "/" + sess.SessionID)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		b.log(logging.LevelInfo, "sign-in session expired, starting a new one")
		return b.create(ctx)
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("sign-in session answered %d", resp.StatusCode)
	}

	var answer pollAnswer
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&answer); err != nil {
		return errors.New("sign-in session answer unreadable")
	}

	switch answer.Status {
	case "pending":
		return nil
	case "failed":
		reason := "sign_in_failed"
		if answer.Error == "access_denied" {
			reason = "access_denied"
		}
		fields := []logging.Field{logging.F("reason", reason)}
		if answer.Detail != "" {
			fields = append(fields, logging.F("detail", answer.Detail))
		}
		b.log(logging.LevelWarn, "sign-in did not complete, starting a new one", fields...)
		return b.create(ctx)
	case "complete":
		return b.complete(ctx, sess, answer)
	default:
		return errors.New("sign-in session answer unreadable")
	}
}

// complete redeems the code and goes on to mint the enrollment token. The
// backend has already forgotten the session, so whatever happens here the
// files go: a redeemed code leaves none, and a failed redemption is followed
// at once by a new session.
func (b *Broker) complete(ctx context.Context, sess storedSession, answer pollAnswer) error {
	if answer.Code == "" || answer.RedirectURI == "" {
		b.log(logging.LevelWarn, "sign-in answer incomplete, starting a new one")
		return b.create(ctx)
	}

	auth, err := b.AuthConfig(ctx)
	if err == nil && (auth.TenantID == "" || auth.ClientID == "") {
		err = errors.New("agent-auth config incomplete")
	}
	if err != nil {
		b.log(logging.LevelWarn, "sign-in could not be completed", logging.F("error", err.Error()))
		b.clear()
		return err
	}

	scopes := userauth.AgentScopes(auth.ClientID)
	tok, err := b.Redeemer.RedeemCode(ctx, auth.TenantID, auth.ClientID, answer.Code, sess.Verifier, answer.RedirectURI, scopes)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		// err is a userauth sentinel: it carries neither the code nor the
		// verifier.
		b.log(logging.LevelWarn, "sign-in could not be completed, starting a new one", logging.F("error", err.Error()))
		return b.create(ctx)
	}

	lifetime := time.Duration(tok.ExpiresIn) * time.Second
	if lifetime <= 0 {
		lifetime = defaultAccessLifetime
	}
	b.held = &heldAccess{
		token:    tok.AccessToken,
		username: userauth.UsernameFromIDToken(tok.IDToken),
		expires:  b.Clock.Now().Add(lifetime),
	}
	b.clear()
	return b.mint(ctx)
}

// mint spends the held access token on an enrollment token and saves it. A
// refusal drops the access token and starts a new session; any other failure
// keeps it, in memory only, for the next tick.
func (b *Broker) mint(ctx context.Context) error {
	held := b.held
	token, err := MintEnrollmentToken(b.Transport, held.token)
	if err != nil {
		if errors.Is(err, ErrMintRefused) {
			b.held = nil
			b.log(logging.LevelWarn, "enrollment token refused at sign-in, starting a new one", logging.F("error", err.Error()))
			return b.create(ctx)
		}
		return err
	}
	if err := b.SaveToken(token); err != nil {
		b.log(logging.LevelError, "enrollment token could not be stored", logging.F("error", err.Error()))
		return err
	}

	// The access token has done its one job.
	b.held = nil
	b.log(logging.LevelInfo, "user signed in, enrollment token stored", logging.F("upn", held.username))
	if b.OnSignIn != nil {
		b.OnSignIn()
	}
	return nil
}

// MintEnrollmentToken spends accessToken, a user's Entra access token for the
// agent's API, on one single-use enrollment token: POST EnrollmentTokenPath
// with "Authorization: Bearer <accessToken>" and body {}. A 4xx answer is
// ErrMintRefused, naming the backend's error code; a transport failure, a 5xx
// or an unreadable answer is a plain error, worth trying again. Neither token
// is ever put in an error.
func MintEnrollmentToken(t BearerPoster, accessToken string) (string, error) {
	resp, err := t.PostPublicBearer(EnrollmentTokenPath, []byte("{}"), accessToken)
	if err != nil {
		return "", fmt.Errorf("enrollment token request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return "", errors.New("enrollment token answer unreadable")
	}

	switch {
	case resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK:
		var answer struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(data, &answer); err != nil || strings.TrimSpace(answer.Token) == "" {
			return "", errors.New("enrollment token answer unusable")
		}
		return strings.TrimSpace(answer.Token), nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return "", fmt.Errorf("%w: status %d%s", ErrMintRefused, resp.StatusCode, errorCode(data))
	default:
		return "", fmt.Errorf("enrollment token request answered %d%s", resp.StatusCode, errorCode(data))
	}
}

// errorCode renders the {"error": "..."} body as " (code)", or "".
func errorCode(data []byte) string {
	var payload struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &payload) != nil || payload.Error == "" {
		return ""
	}
	return " (" + payload.Error + ")"
}

// create starts a new session and writes both files. Nothing is written
// unless the backend has answered with a usable session, and the tenant and
// client must be known first, since without them the code could not be
// redeemed.
func (b *Broker) create(ctx context.Context) error {
	if _, err := b.AuthConfig(ctx); err != nil {
		return fmt.Errorf("sign-in configuration unavailable: %w", err)
	}

	verifier, err := b.verifier()
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{
		"codeChallenge":       userauth.PKCEChallenge(verifier),
		"codeChallengeMethod": userauth.PKCEMethod,
	})
	if err != nil {
		return err
	}

	resp, err := b.Transport.PostPublic(SessionsPath, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sign-in session creation answered %d", resp.StatusCode)
	}

	var answer createAnswer
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&answer); err != nil {
		return errors.New("sign-in session creation answer unreadable")
	}
	expires, err := time.Parse(time.RFC3339, answer.ExpiresAt)
	if err != nil || !sessionIDPattern.MatchString(answer.SessionID) || !httpsURL(answer.SignInURL) {
		return errors.New("sign-in session creation answer unusable")
	}

	sess := storedSession{
		SessionID: answer.SessionID,
		Verifier:  verifier,
		ExpiresAt: expires.UTC(),
		SignInURL: answer.SignInURL,
	}
	data, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	if err := platform.WriteFileAtomic(b.FS, b.SessionPath, data, SessionFileMode); err != nil {
		return err
	}
	if err := platform.WriteFileAtomic(b.FS, b.URLPath, []byte(sess.SignInURL), URLFileMode); err != nil {
		b.clear()
		return err
	}
	b.log(logging.LevelInfo, "sign-in session created, waiting for a user to sign in",
		logging.F("expiresAt", sess.ExpiresAt.Format(time.RFC3339)))
	return nil
}

// load returns the held session, or false when there is none or the file is
// unreadable or carries a session id that is not ours to put in a path.
func (b *Broker) load() (storedSession, bool) {
	data, err := b.FS.ReadFile(b.SessionPath)
	if err != nil {
		return storedSession{}, false
	}
	var sess storedSession
	if err := json.Unmarshal(data, &sess); err != nil {
		return storedSession{}, false
	}
	if !sessionIDPattern.MatchString(sess.SessionID) || sess.Verifier == "" {
		return storedSession{}, false
	}
	return sess, true
}

// clear removes both files; one already gone is not an error.
func (b *Broker) clear() {
	for _, p := range []string{b.URLPath, b.SessionPath} {
		if err := b.FS.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			b.log(logging.LevelWarn, "sign-in file could not be removed", logging.F("path", p), logging.F("error", err.Error()))
		}
	}
}

// verifier returns a fresh RFC 7636 code verifier: verifierBytes random
// bytes, base64url-encoded without padding.
func (b *Broker) verifier() (string, error) {
	src := b.Rand
	if src == nil {
		src = rand.Reader
	}
	buf := make([]byte, verifierBytes)
	if _, err := io.ReadFull(src, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// httpsURL reports whether raw is an absolute https URL with a host.
func httpsURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

func (b *Broker) log(level logging.Level, msg string, fields ...logging.Field) {
	if b.Logger == nil {
		return
	}
	_ = b.Logger.Log(level, msg, fields...)
}
