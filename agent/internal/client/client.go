// Package client is the agent's transport: the one place that turns a method,
// a path and a body into an authenticated HTTPS request to the collection
// endpoint.
//
// Two rules are enforced here rather than at each call site:
//
//   - Nothing leaves the agent over plain HTTP. The enrollment token and the
//     device secret travel on these requests, so a collection URL whose scheme
//     is not https is refused locally, before any call is made.
//   - Every device request is signed. Do loads the persisted device id and
//     device secret on each call and signs the canonical string from
//     agent/internal/contract, so a caller cannot forget a header.
//
// POST /api/v1/enroll is the single exception to the signing rule: at enroll
// time there is no device secret yet, so it is authenticated by the enrollment
// token alone (see enroll.go).
//
// The device secret and the enrollment token are never logged, in any field,
// at any level.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

// The X-MDM-* headers the agent sends. They are written with Set, so Go
// renders them in its canonical form on the wire; HTTP header names are
// case-insensitive and Header.Get reads them back under these names.
const (
	// HeaderDeviceID carries the device id issued by enrollment.
	HeaderDeviceID = "X-MDM-Device-Id"
	// HeaderTimestamp carries epoch seconds, in decimal.
	HeaderTimestamp = "X-MDM-Timestamp"
	// HeaderNonce carries 32 lower-case hex characters, fresh per request.
	HeaderNonce = "X-MDM-Nonce"
	// HeaderSignature carries the "v1=" signature over the canonical string.
	HeaderSignature = "X-MDM-Signature"
	// HeaderEnrollmentToken authenticates POST /api/v1/enroll, and nothing
	// else.
	HeaderEnrollmentToken = "X-MDM-Enrollment-Token"
	// HeaderAuthorization carries the signed-in user's bearer token, when
	// one is held. It is not signed.
	HeaderAuthorization = "Authorization"
)

// BearerSource supplies the signed-in user's access token for Do. It returns
// false when no user is signed in or no valid token can be had.
type BearerSource interface {
	BearerToken(ctx context.Context) (string, bool)
}

// NonceBytes is the random length behind a nonce; hex-encoded it is the 32
// characters the contract requires.
const NonceBytes = 16

// Sentinel errors callers act on.
var (
	// ErrNotEnrolled is returned by Do when the state store holds no device
	// id or no device secret. No request is made and no header is set: there
	// is nothing to sign with.
	ErrNotEnrolled = errors.New("agent is not enrolled")

	// ErrAlreadyEnrolled is returned by Enroll when the state store already
	// holds a device id. Enrolling twice would strand the first identity.
	ErrAlreadyEnrolled = errors.New("agent is already enrolled")

	// ErrUnauthorized is returned by Do on a 401, so the caller can discard
	// the credential and enroll again.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrInsecureTransport is returned when the collection URL is not https.
	// The message is the text the acceptance criteria name.
	ErrInsecureTransport = errors.New("insecure transport refused")
)

// Client talks to the collection endpoint.
//
// Host and Logger are optional and may be set after New: Host describes the
// device to POST /api/v1/enroll, and Logger, when set, receives a record per
// request. A zero Logger means the client logs nothing at all.
type Client struct {
	cfg   config.Config
	store *state.Store
	doer  platform.HTTPDoer
	clock platform.Clock

	// Host is the device description Enroll sends. The agent has no OS
	// access of its own — everything goes through agent/internal/platform —
	// so the facts that need the operating system are handed in by the
	// caller that collects them.
	Host HostFacts

	// Logger, when non-nil, records requests, enrollment attempts and
	// failures. Nothing written here carries the device secret or the
	// enrollment token.
	Logger *logging.Logger

	// Bearer, when non-nil, supplies the signed-in user's access token. Do
	// sends it as "Authorization: Bearer <token>" in addition to the device
	// signature -- it is never part of the signed canonical string -- and
	// sends no Authorization header when Bearer is nil or holds no token.
	// The token is never logged.
	Bearer BearerSource

	// checkInIntervalSeconds is what the last enrollment asked for; see
	// CheckInIntervalSeconds.
	checkInIntervalSeconds int
}

// New returns a client for cfg, signing with whatever credential st holds at
// the moment of each call.
//
// The store is read on every request rather than cached, so an enrollment that
// happens while the agent is running is picked up by the next call without a
// restart.
func New(cfg config.Config, st *state.Store, doer platform.HTTPDoer, clk platform.Clock) *Client {
	return &Client{cfg: cfg, store: st, doer: doer, clock: clk}
}

// CheckInIntervalSeconds is the interval the backend returned at enrollment,
// or 0 when this client has not enrolled.
func (c *Client) CheckInIntervalSeconds() int { return c.checkInIntervalSeconds }

// Do sends a signed request to path and returns the response.
//
// path is the path on the collection endpoint, optionally carrying a query
// string, e.g. "/api/v1/devices/dev-001/commands?limit=5". The four signed
// headers are set from the persisted credential and the injected clock; the
// nonce is fresh for every call, so two identical requests never share one.
//
// A 401 is reported as ErrUnauthorized with the body closed and no response
// returned, which is the signal to re-enroll. Every other status comes back as
// a response with a nil error: what a 404 or a 500 means is the caller's
// business, not the transport's.
func (c *Client) Do(method, path string, body []byte) (*http.Response, error) {
	// The transport check comes first: an http collection URL is refused
	// whether or not this agent happens to hold a credential.
	endpoint, err := c.endpoint(path)
	if err != nil {
		return nil, err
	}

	st, err := c.store.Load()
	if err != nil {
		return nil, err
	}
	if st.DeviceID == "" || st.DeviceSecret == "" {
		return nil, ErrNotEnrolled
	}

	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}
	timestamp := c.clock.Now().UTC().Unix()

	signature, err := contract.SignRequest(st.DeviceSecret, contract.SigningParts{
		Method:    method,
		Path:      endpoint.EscapedPath(),
		Query:     endpoint.RawQuery,
		Body:      body,
		Timestamp: timestamp,
		Nonce:     nonce,
		DeviceID:  st.DeviceID,
	})
	if err != nil {
		return nil, err
	}

	req, err := c.newRequest(context.Background(), method, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set(HeaderDeviceID, st.DeviceID)
	// Epoch seconds in decimal: no padding, no sign, no fraction and no
	// RFC3339 text. The backend parses this as an integer.
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp, 10))
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, signature)

	// The user token rides alongside the signature, after it was computed.
	if c.Bearer != nil {
		if token, ok := c.Bearer.BearerToken(req.Context()); ok && token != "" {
			req.Header.Set(HeaderAuthorization, "Bearer "+token)
		}
	}

	resp, err := c.doer.Do(req)
	if err != nil {
		c.log(logging.LevelWarn, "request failed",
			logging.F("method", method),
			logging.F("path", endpoint.Path),
			logging.F("error", err.Error()),
		)
		return nil, err
	}

	c.log(logging.LevelDebug, "request sent",
		logging.F("method", method),
		logging.F("path", endpoint.Path),
		logging.F("deviceId", st.DeviceID),
		logging.F("status", resp.StatusCode),
	)

	if resp.StatusCode == http.StatusUnauthorized {
		closeBody(resp)
		return nil, ErrUnauthorized
	}
	return resp, nil
}

// FetchPublic sends an unauthenticated GET to path on the collection endpoint
// and returns the response whatever its status.
//
// It is for the few routes that need no credential, such as the agent sign-in
// configuration: no X-MDM-* header and no Authorization header is set. The
// https rule still applies, so an http collection URL is refused before any
// request is made.
func (c *Client) FetchPublic(path string) (*http.Response, error) {
	endpoint, err := c.endpoint(path)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(context.Background(), http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.doer.Do(req)
	if err != nil {
		c.log(logging.LevelWarn, "request failed",
			logging.F("method", http.MethodGet),
			logging.F("path", endpoint.Path),
			logging.F("error", err.Error()),
		)
		return nil, err
	}
	c.log(logging.LevelDebug, "request sent",
		logging.F("method", http.MethodGet),
		logging.F("path", endpoint.Path),
		logging.F("status", resp.StatusCode),
	)
	return resp, nil
}

// endpoint resolves path against the configured collection URL and refuses
// anything that is not https.
func (c *Client) endpoint(path string) (*url.URL, error) {
	base, err := url.Parse(c.cfg.CollectionURL)
	if err != nil {
		return nil, fmt.Errorf("invalid collection url: %w", err)
	}
	if base.Scheme != "https" {
		return nil, fmt.Errorf("%w: collection url scheme is %q", ErrInsecureTransport, base.Scheme)
	}
	if base.Host == "" {
		return nil, fmt.Errorf("invalid collection url: %q has no host", c.cfg.CollectionURL)
	}

	ref, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("invalid request path: %w", err)
	}
	if ref.Scheme != "" && ref.Scheme != "https" {
		return nil, fmt.Errorf("%w: request scheme is %q", ErrInsecureTransport, ref.Scheme)
	}

	resolved := *base
	resolved.Path = joinPath(base.Path, ref.Path)
	resolved.RawPath = ""
	resolved.RawQuery = ref.RawQuery
	resolved.Fragment = ""
	return &resolved, nil
}

// joinPath puts exactly one slash between a collection URL that may carry a
// prefix and a request path that may or may not start with one.
func joinPath(base, path string) string {
	base = strings.TrimSuffix(base, "/")
	if base == "" {
		if strings.HasPrefix(path, "/") {
			return path
		}
		return "/" + path
	}
	return base + "/" + strings.TrimPrefix(path, "/")
}

// newRequest builds the request with the body attached and its length known,
// which matters because every attempt must send the same bytes that were
// signed.
func (c *Client) newRequest(ctx context.Context, method string, endpoint *url.URL, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.ContentLength = int64(len(body))
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// newNonce returns 32 lower-case hex characters from the system CSPRNG.
func newNonce() (string, error) {
	buf := make([]byte, NonceBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// log writes one record when a logger was given. A failed write is dropped:
// the agent has nowhere better to report it, and a full disk must not stop a
// check-in.
func (c *Client) log(level logging.Level, msg string, fields ...logging.Field) {
	if c.Logger == nil {
		return
	}
	_ = c.Logger.Log(level, msg, fields...)
}

// closeBody drains nothing and closes the body of a response the caller will
// never see.
func closeBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}
