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
// token alone (see enroll.go). The few public routes go out unauthenticated,
// or, for minting an enrollment token at sign-in, with the user's bearer token
// alone (PostPublicBearer).
//
// The device secret, the enrollment token and a bearer token are never
// logged, in any field, at any level.
package client

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"

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
	// HeaderAuthorization carries a user's bearer token on PostPublicBearer,
	// and on no other request.
	HeaderAuthorization = "Authorization"
	// HeaderAcceptContentEncoding is the response header with which the
	// backend says it accepts gzip-compressed request bodies. Do compresses
	// only while the most recent response it received carried "gzip" here.
	HeaderAcceptContentEncoding = "X-MDM-Accept-Content-Encoding"
)

// CompressMinBytes is the smallest request body Do compresses once the
// backend has advertised gzip; anything shorter goes out as it is.
const CompressMinBytes = 1024

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

	// ErrAwaitingSignIn is returned by Enroll when there is no enrollment
	// token. No request is made; enrollment is possible once someone signs
	// in and the sign-in writes one to the config.
	ErrAwaitingSignIn = errors.New("waiting for a user to sign in")

	// ErrEnrollmentTokenRejected is returned by Enroll when the backend
	// answers 401 or 403 with one of EnrollmentTokenErrors: the token is
	// unknown, revoked, expired or used up, and only a new one (a new sign-in) helps.
	ErrEnrollmentTokenRejected = errors.New("enrollment token rejected")

	// ErrBadResponseEncoding is returned by Do when a response says
	// "Content-Encoding: gzip" but its body does not start a gzip stream.
	ErrBadResponseEncoding = errors.New("response body is not valid gzip")
)

// EnrollmentTokenErrors are the error codes a 401 or 403 from
// POST /api/v1/enroll carries when the enrollment token itself is the problem.
var EnrollmentTokenErrors = []string{
	"invalid_enrollment_token",
	"enrollment_token_expired",
	"enrollment_token_exhausted",
	"enrollment_token_revoked",
}

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

	// EnrollmentToken, when non-nil, is asked for the enrollment token at
	// every enrollment instead of the copy in the config New was given, so
	// a token the sign-in writes to the config file while the agent runs is
	// used without a restart. "" means there is none.
	EnrollmentToken func() string

	// checkInIntervalSeconds is what the last enrollment asked for; see
	// CheckInIntervalSeconds.
	checkInIntervalSeconds int

	// compressRequests is whether the most recent Do response advertised
	// gzip request bodies (HeaderAcceptContentEncoding). compressionRejected
	// is set, for the rest of the process, once a compressed request was
	// refused and retried uncompressed. Both are atomic because one Client
	// is shared by the heartbeat, the scheduler, the executor and the user
	// reporter, each on its own goroutine.
	compressRequests    atomic.Bool
	compressionRejected atomic.Bool
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
//
// Payload compression: every request asks for gzip responses, and a gzip
// response comes back already decompressed. A body of CompressMinBytes or
// more is gzip-compressed on the wire while the backend advertises it
// (HeaderAcceptContentEncoding on the most recent response); the signature
// always covers the uncompressed bytes. A compressed request answered 401,
// 415 or 400 invalid_gzip_body is retried once uncompressed, with a fresh
// nonce and signature, and compression stays off for the rest of the process.
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

	compress := len(body) >= CompressMinBytes &&
		c.compressRequests.Load() && !c.compressionRejected.Load()

	resp, err := c.sendSigned(method, endpoint, st.DeviceID, st.DeviceSecret, body, compress)
	if err != nil {
		return nil, err
	}

	if compress && compressionRefused(resp) {
		c.compressionRejected.Store(true)
		c.compressRequests.Store(false)
		c.log(logging.LevelWarn, "request compression rejected; sending uncompressed",
			logging.F("path", endpoint.Path),
			logging.F("status", resp.StatusCode),
		)
		closeBody(resp)
		resp, err = c.sendSigned(method, endpoint, st.DeviceID, st.DeviceSecret, body, false)
		if err != nil {
			return nil, err
		}
	}

	// The advertisement is re-read from every response, so a backend rolled
	// back between requests turns compression off again.
	c.compressRequests.Store(headerIsGzip(resp.Header.Get(HeaderAcceptContentEncoding)))

	if resp.StatusCode == http.StatusUnauthorized {
		closeBody(resp)
		return nil, ErrUnauthorized
	}
	return decodeResponse(resp)
}

// sendSigned signs body as it is, then sends it -- gzip-compressed when
// compress is set -- with the four signed headers and Accept-Encoding: gzip.
// Each call takes a fresh nonce and timestamp.
func (c *Client) sendSigned(method string, endpoint *url.URL, deviceID, secret string, body []byte, compress bool) (*http.Response, error) {
	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}
	timestamp := c.clock.Now().UTC().Unix()

	// The signature covers the uncompressed bytes, so compression is
	// invisible to verification: the backend inflates before it verifies.
	signature, err := contract.SignRequest(secret, contract.SigningParts{
		Method:    method,
		Path:      endpoint.EscapedPath(),
		Query:     endpoint.RawQuery,
		Body:      body,
		Timestamp: timestamp,
		Nonce:     nonce,
		DeviceID:  deviceID,
	})
	if err != nil {
		return nil, err
	}

	payload := body
	if compress {
		payload, err = gzipBytes(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := c.newRequest(context.Background(), method, endpoint, payload)
	if err != nil {
		return nil, err
	}
	if compress {
		req.Header.Set("Content-Encoding", "gzip")
	}
	// Set explicitly, which turns off Go's transparent decompression;
	// decodeResponse does it instead, so nothing is decompressed twice.
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set(HeaderDeviceID, deviceID)
	// Epoch seconds in decimal: no padding, no sign, no fraction and no
	// RFC3339 text. The backend parses this as an integer.
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(timestamp, 10))
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, signature)

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
		logging.F("deviceId", deviceID),
		logging.F("status", resp.StatusCode),
	)
	return resp, nil
}

// compressionRefused reports whether resp is the backend refusing a
// compressed body: 401 (an old backend hashed the compressed bytes), 415, or
// 400 {"error":"invalid_gzip_body"}. For any other 400 the body bytes it read
// are put back, so the caller still gets a readable body.
func compressionRefused(resp *http.Response) bool {
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusUnsupportedMediaType:
		return true
	case http.StatusBadRequest:
	default:
		return false
	}
	if resp.Body == nil {
		return false
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(data))
	var parsed struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &parsed) != nil {
		return false
	}
	return parsed.Error == "invalid_gzip_body"
}

// decodeResponse unwraps a gzip response body, so the caller always reads
// the decompressed bytes. A response with any other Content-Encoding, or none,
// is returned unchanged.
func decodeResponse(resp *http.Response) (*http.Response, error) {
	if !headerIsGzip(resp.Header.Get("Content-Encoding")) || resp.Body == nil {
		return resp, nil
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		closeBody(resp)
		return nil, fmt.Errorf("%w: %v", ErrBadResponseEncoding, err)
	}
	resp.Body = &gzipBody{Reader: zr, underlying: resp.Body}
	resp.Header.Del("Content-Encoding")
	resp.ContentLength = -1
	resp.Uncompressed = true
	return resp, nil
}

// gzipBody reads the decompressed stream and, on Close, closes both the gzip
// reader and the response body underneath it.
type gzipBody struct {
	*gzip.Reader
	underlying io.ReadCloser
}

func (b *gzipBody) Close() error {
	zerr := b.Reader.Close()
	if err := b.underlying.Close(); err != nil {
		return err
	}
	return zerr
}

// headerIsGzip reports whether a header value is exactly "gzip", ignoring
// case and surrounding whitespace.
func headerIsGzip(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "gzip")
}

// gzipBytes returns body gzip-compressed.
func gzipBytes(body []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(body); err != nil {
		return nil, fmt.Errorf("gzip request body: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("gzip request body: %w", err)
	}
	return buf.Bytes(), nil
}

// FetchPublic sends an unauthenticated GET to path on the collection endpoint
// and returns the response whatever its status.
//
// It is for the few routes that need no credential, such as the agent sign-in
// configuration: no X-MDM-* header and no Authorization header is set. The
// https rule still applies, so an http collection URL is refused before any
// request is made.
func (c *Client) FetchPublic(path string) (*http.Response, error) {
	return c.public(http.MethodGet, path, nil, "")
}

// PostPublic sends an unauthenticated POST of the JSON body to path on the
// collection endpoint and returns the response whatever its status.
//
// It is FetchPublic's counterpart for the public routes that take a body, such
// as creating an agent sign-in session: no X-MDM-* header and no Authorization
// header is set, and an http collection URL is refused before any request is
// made.
func (c *Client) PostPublic(path string, body []byte) (*http.Response, error) {
	return c.public(http.MethodPost, path, body, "")
}

// PostPublicBearer is PostPublic with "Authorization: Bearer <token>" added,
// and no other credential: no X-MDM-* header. It is how the sign-in mints an
// enrollment token with the user's Entra access token, the one request that
// token is ever used for. A blank token is refused before any request is made.
// The token is never logged.
func (c *Client) PostPublicBearer(path string, body []byte, token string) (*http.Response, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("no bearer token to send")
	}
	return c.public(http.MethodPost, path, body, token)
}

// public sends one request with no device credential, carrying bearer as the
// Authorization header when it is not empty. The path is logged, never the
// body or the bearer.
func (c *Client) public(method, path string, body []byte, bearer string) (*http.Response, error) {
	endpoint, err := c.endpoint(path)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(context.Background(), method, endpoint, body)
	if err != nil {
		return nil, err
	}
	if bearer != "" {
		req.Header.Set(HeaderAuthorization, "Bearer "+bearer)
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
