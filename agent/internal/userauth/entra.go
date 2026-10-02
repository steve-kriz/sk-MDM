package userauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// Authority is the Entra ID login host every OAuth request goes to.
const Authority = "https://login.microsoftonline.com"

// DeviceCodeGrantType is the RFC 8628 grant polled for at sign-in.
const DeviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// RefreshGrantType is the grant a stored refresh token is redeemed with.
const RefreshGrantType = "refresh_token"

// DefaultPollInterval is the wait between polls when the device-code response
// names no interval, or names 0.
const DefaultPollInterval = 5 * time.Second

// SlowDownStep is what each `slow_down` answer adds to the interval.
const SlowDownStep = 5 * time.Second

// defaultExpiresIn is used when a device-code response names no lifetime.
const defaultExpiresIn = 900

// maxResponseBytes bounds what is read from an Entra response.
const maxResponseBytes = 1 << 20

// Sentinel errors. None of them ever carries a token, a device code or a
// response body.
var (
	// ErrSignInDeclined: the user declined the sign-in.
	ErrSignInDeclined = errors.New("sign-in was declined")
	// ErrSignInExpired: the device code expired before the user finished.
	ErrSignInExpired = errors.New("sign-in code expired")
	// ErrSignInFailed: any other sign-in failure.
	ErrSignInFailed = errors.New("sign-in failed")
	// ErrRefreshRejected: Entra answered invalid_grant; the refresh token is
	// revoked or expired and only a new sign-in helps.
	ErrRefreshRejected = errors.New("refresh token rejected")
	// ErrRefreshUnavailable: the refresh could not be completed this time
	// (a 5xx, a 429, a network error, an unreadable answer).
	ErrRefreshUnavailable = errors.New("token refresh unavailable")
)

// Entra talks to the Entra ID OAuth endpoints over the injected HTTP doer,
// timing every poll on the injected clock.
type Entra struct {
	Doer  platform.HTTPDoer
	Clock platform.Clock
}

// DeviceCode is a started device authorization.
type DeviceCode struct {
	// DeviceCode is the secret polled with. Never print or log it.
	DeviceCode string
	// UserCode is what the user types at VerificationURI.
	UserCode        string
	VerificationURI string
	// ExpiresIn is the code's lifetime, in seconds.
	ExpiresIn int
	// Interval is the minimum wait between polls, in seconds; 0 when the
	// response named none.
	Interval int
}

// Token is a successful token response.
type Token struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	// ExpiresIn is the access token's lifetime, in seconds.
	ExpiresIn int
}

// tokenEndpoint and deviceCodeEndpoint are the tenant's v2.0 endpoints.
func tokenEndpoint(tenantID string) string {
	return Authority + "/" + url.PathEscape(tenantID) + "/oauth2/v2.0/token"
}

func deviceCodeEndpoint(tenantID string) string {
	return Authority + "/" + url.PathEscape(tenantID) + "/oauth2/v2.0/devicecode"
}

// postForm sends an x-www-form-urlencoded POST and returns the status and the
// body. A transport error comes back as err.
func (e *Entra) postForm(ctx context.Context, endpoint string, form url.Values) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := e.Doer.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}

// tokenReply is the union of a token success and an OAuth error.
type tokenReply struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
}

func (r tokenReply) token() Token {
	return Token{
		AccessToken:  r.AccessToken,
		RefreshToken: r.RefreshToken,
		IDToken:      r.IDToken,
		ExpiresIn:    r.ExpiresIn,
	}
}

func isSuccess(status int) bool { return status >= 200 && status < 300 }

// StartSignIn requests a device code for clientID in tenantID, asking for
// scopes. A non-2xx answer, an unreadable body or one missing device_code,
// user_code or verification_uri is ErrSignInFailed. A cancelled context is
// returned as the context's error.
func (e *Entra) StartSignIn(ctx context.Context, tenantID, clientID string, scopes []string) (DeviceCode, error) {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("scope", strings.Join(scopes, " "))

	status, body, err := e.postForm(ctx, deviceCodeEndpoint(tenantID), form)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return DeviceCode{}, ctxErr
		}
		return DeviceCode{}, ErrSignInFailed
	}
	if !isSuccess(status) {
		return DeviceCode{}, ErrSignInFailed
	}

	var reply struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &reply); err != nil {
		return DeviceCode{}, ErrSignInFailed
	}
	if reply.DeviceCode == "" || reply.UserCode == "" || reply.VerificationURI == "" {
		return DeviceCode{}, ErrSignInFailed
	}
	return DeviceCode{
		DeviceCode:      reply.DeviceCode,
		UserCode:        reply.UserCode,
		VerificationURI: reply.VerificationURI,
		ExpiresIn:       reply.ExpiresIn,
		Interval:        reply.Interval,
	}, nil
}

// PollToken waits for the user to finish the sign-in code started.
//
// The first wait is the code's interval, or DefaultPollInterval when it named
// none. `authorization_pending` waits the current interval again and
// `slow_down` adds SlowDownStep to it. `authorization_declined` and
// `access_denied` are ErrSignInDeclined; `expired_token`, or the clock reaching
// the code's expiry, is ErrSignInExpired with no further request. Anything else
// is ErrSignInFailed, and a cancelled context returns the context's error with
// no further request.
func (e *Entra) PollToken(ctx context.Context, tenantID, clientID string, code DeviceCode) (Token, error) {
	interval := time.Duration(code.Interval) * time.Second
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	expiresIn := code.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = defaultExpiresIn
	}
	deadline := e.Clock.Now().Add(time.Duration(expiresIn) * time.Second)

	form := url.Values{}
	form.Set("grant_type", DeviceCodeGrantType)
	form.Set("client_id", clientID)
	form.Set("device_code", code.DeviceCode)

	for {
		if err := ctx.Err(); err != nil {
			return Token{}, err
		}
		select {
		case <-ctx.Done():
			return Token{}, ctx.Err()
		case <-e.Clock.After(interval):
		}
		if err := ctx.Err(); err != nil {
			return Token{}, err
		}
		if !e.Clock.Now().Before(deadline) {
			return Token{}, ErrSignInExpired
		}

		status, body, err := e.postForm(ctx, tokenEndpoint(tenantID), form)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return Token{}, ctxErr
			}
			return Token{}, ErrSignInFailed
		}

		var reply tokenReply
		if err := json.Unmarshal(body, &reply); err != nil {
			return Token{}, ErrSignInFailed
		}

		switch reply.Error {
		case "":
			if isSuccess(status) && reply.AccessToken != "" {
				return reply.token(), nil
			}
			return Token{}, ErrSignInFailed
		case "authorization_pending":
			continue
		case "slow_down":
			interval += SlowDownStep
			continue
		case "authorization_declined", "access_denied":
			return Token{}, ErrSignInDeclined
		case "expired_token":
			return Token{}, ErrSignInExpired
		default:
			return Token{}, ErrSignInFailed
		}
	}
}

// Refresh redeems refreshToken for a new access token, asking for scopes.
// A 400 invalid_grant is ErrRefreshRejected; every other failure is
// ErrRefreshUnavailable.
func (e *Entra) Refresh(ctx context.Context, tenantID, clientID, refreshToken string, scopes []string) (Token, error) {
	form := url.Values{}
	form.Set("grant_type", RefreshGrantType)
	form.Set("client_id", clientID)
	form.Set("refresh_token", refreshToken)
	form.Set("scope", strings.Join(scopes, " "))

	status, body, err := e.postForm(ctx, tokenEndpoint(tenantID), form)
	if err != nil {
		return Token{}, ErrRefreshUnavailable
	}

	var reply tokenReply
	if err := json.Unmarshal(body, &reply); err != nil {
		return Token{}, ErrRefreshUnavailable
	}
	if status == http.StatusBadRequest && reply.Error == "invalid_grant" {
		return Token{}, ErrRefreshRejected
	}
	if !isSuccess(status) || reply.Error != "" || reply.AccessToken == "" {
		return Token{}, ErrRefreshUnavailable
	}
	return reply.token(), nil
}

// UsernameFromIDToken returns the `preferred_username` claim of an id token's
// payload, decoded without verifying the signature: it is for display only.
// An absent or malformed token, or one without the claim, yields "".
func UsernameFromIDToken(idToken string) string {
	segments := strings.Split(idToken, ".")
	if len(segments) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(segments[1], "="))
	if err != nil {
		return ""
	}
	var claims struct {
		PreferredUsername any `json:"preferred_username"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	name, _ := claims.PreferredUsername.(string)
	return name
}
