// E2E cucumber-style tests for TASK-068 (gzip agent<->backend payloads).
// Every scenario below implements a Gherkin scenario from the ticket by name
// (AC1-AC13). Doer, Store, FS and Clock are all fakes; no real network,
// filesystem or database is used anywhere in this file.
package client

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const gzipTestDeviceID = "dev-1"
const gzipTestDeviceSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const gzipTestCheckinPath = "/api/v1/devices/dev-1/checkin"
const gzipTestPoliciesPath = "/api/v1/devices/dev-1/policies"

// newEnrolledGzipClient returns a Client whose store already holds a device
// id and secret, over a fresh fake doer and a fixed clock.
func newEnrolledGzipClient(t *testing.T) (*Client, *fake.HTTPDoer, *fake.Clock) {
	t.Helper()
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1764633600, 0))
	doer := fake.NewHTTPDoer()
	store := state.NewStore(fsys, "state.json")
	if err := store.Save(state.State{DeviceID: gzipTestDeviceID, DeviceSecret: gzipTestDeviceSecret}); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	cfg := config.Config{CollectionURL: "https://api.example.com"}
	c := New(cfg, store, doer, clock)
	return c, doer, clock
}

// primeCompressionOn sends one Do call whose response advertises gzip, so the
// client's compression flag is on afterwards. The doer's DoFunc is restored
// to whatever it held before.
func primeCompressionOn(t *testing.T, c *Client, doer *fake.HTTPDoer) {
	t.Helper()
	original := doer.DoFunc
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		resp := fake.Response(http.StatusOK, "{}")
		resp.Header.Set(HeaderAcceptContentEncoding, "gzip")
		return resp, nil
	}
	if _, err := c.Do(http.MethodGet, gzipTestPoliciesPath, nil); err != nil {
		t.Fatalf("priming Do call failed: %v", err)
	}
	doer.DoFunc = original
}

// makeBody returns n arbitrary bytes, standing in for a JSON check-in payload
// of that size; its content does not matter to the compression decision.
func makeBody(n int) []byte {
	return bytes.Repeat([]byte("a"), n)
}

// gzipResponse builds a 200 response whose body is plain, gzip-compressed and
// marked "Content-Encoding: gzip".
func gzipResponse(t *testing.T, plain string) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(plain)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return &http.Response{
		StatusCode:    http.StatusOK,
		Status:        http.StatusText(http.StatusOK),
		Header:        http.Header{"Content-Type": []string{"application/json"}, "Content-Encoding": []string{"gzip"}},
		Body:          io.NopCloser(bytes.NewReader(buf.Bytes())),
		ContentLength: int64(buf.Len()),
	}
}

// trackedCloser records whether Close was called, for asserting a response
// body was closed on an error path.
type trackedCloser struct {
	io.Reader
	closed bool
}

func (c *trackedCloser) Close() error {
	c.closed = true
	return nil
}

// gunzip decompresses data fully, failing the test on error.
func gunzip(t *testing.T, data []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("reading gunzip stream: %v", err)
	}
	return plain
}

// ---------------------------------------------------------------------------
// AC1: Do asks for gzip responses
// ---------------------------------------------------------------------------

func TestScenario_DoAsksForGzipResponses_AC1(t *testing.T) {
	// Given an enrolled agent client with a fake HTTP doer and a fixed clock
	c, doer, _ := newEnrolledGzipClient(t)

	// When the agent calls Do GET "/api/v1/devices/dev-1/policies"
	if _, err := c.Do(http.MethodGet, gzipTestPoliciesPath, nil); err != nil {
		t.Fatalf("Do failed: %v", err)
	}

	// Then the recorded request has header "Accept-Encoding" equal to "gzip"
	reqs := doer.Requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if got := reqs[0].Header.Get("Accept-Encoding"); got != "gzip" {
		t.Errorf("Accept-Encoding = %q, want %q", got, "gzip")
	}
}

// ---------------------------------------------------------------------------
// AC2: A gzip response is decompressed
// ---------------------------------------------------------------------------

func TestScenario_GzipResponseIsDecompressed_AC2(t *testing.T) {
	// Given the doer answers 200 with header "Content-Encoding: gzip" and a
	// gzipped body of '{"ok":true}'
	c, doer, _ := newEnrolledGzipClient(t)
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return gzipResponse(t, `{"ok":true}`), nil
	}

	// When the agent calls Do GET "/api/v1/devices/dev-1/policies"
	resp, err := c.Do(http.MethodGet, gzipTestPoliciesPath, nil)
	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}
	defer resp.Body.Close()

	// Then the response body reads '{"ok":true}'
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Errorf("body = %q, want %q", body, `{"ok":true}`)
	}
	// And the response has no "Content-Encoding" header
	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty", got)
	}
	// And the response ContentLength is -1
	if resp.ContentLength != -1 {
		t.Errorf("ContentLength = %d, want -1", resp.ContentLength)
	}
}

// ---------------------------------------------------------------------------
// AC3: An uncompressed response is unchanged
// ---------------------------------------------------------------------------

func TestScenario_UncompressedResponseIsUnchanged_AC3(t *testing.T) {
	// Given the doer answers 200 with body '{"ok":true}' and no Content-Encoding
	c, doer, _ := newEnrolledGzipClient(t)
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return fake.Response(http.StatusOK, `{"ok":true}`), nil
	}

	// When the agent calls Do GET "/api/v1/devices/dev-1/policies"
	resp, err := c.Do(http.MethodGet, gzipTestPoliciesPath, nil)
	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}
	defer resp.Body.Close()

	// Then the response body reads '{"ok":true}'
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Errorf("body = %q, want %q", body, `{"ok":true}`)
	}
}

// ---------------------------------------------------------------------------
// AC4 (failure): A corrupt gzip response is an error
// ---------------------------------------------------------------------------

func TestScenario_CorruptGzipResponseIsAnError_AC4(t *testing.T) {
	// Given the doer answers 200 with header "Content-Encoding: gzip" and
	// body "not gzip"
	c, doer, _ := newEnrolledGzipClient(t)
	tracked := &trackedCloser{Reader: strings.NewReader("not gzip")}
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     http.StatusText(http.StatusOK),
			Header:     http.Header{"Content-Encoding": []string{"gzip"}},
			Body:       tracked,
		}, nil
	}

	// When the agent calls Do GET "/api/v1/devices/dev-1/policies"
	resp, err := c.Do(http.MethodGet, gzipTestPoliciesPath, nil)

	// Then Do returns an error matching ErrBadResponseEncoding
	if !errors.Is(err, ErrBadResponseEncoding) {
		t.Fatalf("expected ErrBadResponseEncoding, got %v", err)
	}
	// And the response is nil
	if resp != nil {
		t.Errorf("expected nil response, got %+v", resp)
	}
	// (the body is closed by Do, since the caller never sees it)
	if !tracked.closed {
		t.Errorf("expected the corrupt response body to be closed")
	}
}

// ---------------------------------------------------------------------------
// AC5: The first request of a new client is uncompressed
// ---------------------------------------------------------------------------

func TestScenario_FirstRequestOfNewClientIsUncompressed_AC5(t *testing.T) {
	// When the agent calls Do POST "/api/v1/devices/dev-1/checkin" with a
	// 5000-byte JSON body
	c, doer, _ := newEnrolledGzipClient(t)
	body := makeBody(5000)
	if _, err := c.Do(http.MethodPost, gzipTestCheckinPath, body); err != nil {
		t.Fatalf("Do failed: %v", err)
	}

	// Then the recorded request has no "Content-Encoding" header
	reqs := doer.Requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if got := reqs[0].Header.Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty", got)
	}
	// And the recorded request body equals the 5000-byte JSON body
	sent, err := io.ReadAll(reqs[0].Body)
	if err != nil {
		t.Fatalf("reading recorded body: %v", err)
	}
	if !bytes.Equal(sent, body) {
		t.Errorf("recorded body does not equal the original 5000-byte body")
	}
}

// ---------------------------------------------------------------------------
// AC6: Compression turns on after the backend advertises it
// ---------------------------------------------------------------------------

func TestScenario_CompressionTurnsOnAfterAdvertisement_AC6(t *testing.T) {
	// Given the doer answers every request with header
	// "X-MDM-Accept-Content-Encoding: gzip"
	c, doer, _ := newEnrolledGzipClient(t)
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		resp := fake.Response(http.StatusOK, "{}")
		resp.Header.Set(HeaderAcceptContentEncoding, "gzip")
		return resp, nil
	}

	// And the agent has made one Do call
	if _, err := c.Do(http.MethodGet, gzipTestPoliciesPath, nil); err != nil {
		t.Fatalf("first Do failed: %v", err)
	}

	// When the agent calls Do POST "/api/v1/devices/dev-1/checkin" with a
	// 5000-byte JSON body
	body := makeBody(5000)
	if _, err := c.Do(http.MethodPost, gzipTestCheckinPath, body); err != nil {
		t.Fatalf("second Do failed: %v", err)
	}

	reqs := doer.Requests()
	if len(reqs) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(reqs))
	}
	req := reqs[1]

	// Then the recorded request has header "Content-Encoding" equal to "gzip"
	if got := req.Header.Get("Content-Encoding"); got != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip", got)
	}
	// And the recorded request has header "Content-Type" equal to
	// "application/json"
	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	// And the recorded request ContentLength equals the length of its
	// compressed body
	sent, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading recorded body: %v", err)
	}
	if req.ContentLength != int64(len(sent)) {
		t.Errorf("ContentLength = %d, want %d (the actual sent body length)", req.ContentLength, len(sent))
	}
	// Sanity: the sent bytes are in fact smaller than the original 5000 and
	// gunzip back to it (double-checked fully under AC8).
	if len(sent) >= len(body) {
		t.Errorf("compressed body (%d bytes) is not smaller than the original (%d bytes)", len(sent), len(body))
	}
}

// ---------------------------------------------------------------------------
// AC7 (edge): Small and empty bodies are never compressed
// ---------------------------------------------------------------------------

func TestScenario_SmallAndEmptyBodiesAreNeverCompressed_AC7(t *testing.T) {
	for _, size := range []int{0, 1023} {
		size := size
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			// Given compression is on after an advertising response
			c, doer, _ := newEnrolledGzipClient(t)
			primeCompressionOn(t, c, doer)

			var captured *http.Request
			doer.DoFunc = func(req *http.Request) (*http.Response, error) {
				captured = req
				return fake.Response(http.StatusOK, "{}"), nil
			}

			// When the agent calls Do POST
			// "/api/v1/devices/dev-1/heartbeat" with a <size>-byte body
			var body []byte
			if size > 0 {
				body = makeBody(size)
			}
			if _, err := c.Do(http.MethodPost, "/api/v1/devices/dev-1/heartbeat", body); err != nil {
				t.Fatalf("Do failed: %v", err)
			}

			// Then the recorded request has no "Content-Encoding" header
			if got := captured.Header.Get("Content-Encoding"); got != "" {
				t.Errorf("size=%d: Content-Encoding = %q, want empty", size, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AC8: The signature covers the uncompressed body
// ---------------------------------------------------------------------------

func TestScenario_SignatureCoversUncompressedBody_AC8(t *testing.T) {
	// Given compression is on after an advertising response
	c, doer, _ := newEnrolledGzipClient(t)
	primeCompressionOn(t, c, doer)

	var captured *http.Request
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		captured = req
		return fake.Response(http.StatusOK, "{}"), nil
	}

	// When the agent calls Do POST "/api/v1/devices/dev-1/checkin" with a
	// 5000-byte JSON body
	body := makeBody(5000)
	if _, err := c.Do(http.MethodPost, gzipTestCheckinPath, body); err != nil {
		t.Fatalf("Do failed: %v", err)
	}

	if got := captured.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("precondition failed: Content-Encoding = %q, want gzip", got)
	}

	// Then gunzipping the recorded body yields the original 5000 bytes
	sent, err := io.ReadAll(captured.Body)
	if err != nil {
		t.Fatalf("reading recorded body: %v", err)
	}
	plain := gunzip(t, sent)
	if !bytes.Equal(plain, body) {
		t.Fatalf("gunzipped body does not match the original")
	}

	// And the X-MDM-Signature equals SignRequest over the uncompressed body
	// with the recorded timestamp and nonce
	timestamp, err := strconv.ParseInt(captured.Header.Get(HeaderTimestamp), 10, 64)
	if err != nil {
		t.Fatalf("parsing timestamp: %v", err)
	}
	nonce := captured.Header.Get(HeaderNonce)
	wantSig, err := contract.SignRequest(gzipTestDeviceSecret, contract.SigningParts{
		Method:    http.MethodPost,
		Path:      gzipTestCheckinPath,
		Query:     "",
		Body:      body,
		Timestamp: timestamp,
		Nonce:     nonce,
		DeviceID:  gzipTestDeviceID,
	})
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	if got := captured.Header.Get(HeaderSignature); got != wantSig {
		t.Errorf("X-MDM-Signature = %q, want %q", got, wantSig)
	}
}

// ---------------------------------------------------------------------------
// AC9: A response without the advertisement turns compression off
// ---------------------------------------------------------------------------

func TestScenario_ResponseWithoutAdvertisementTurnsCompressionOff_AC9(t *testing.T) {
	// Given compression is on after an advertising response
	c, doer, _ := newEnrolledGzipClient(t)
	primeCompressionOn(t, c, doer)

	// And the next response has no "X-MDM-Accept-Content-Encoding" header
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return fake.Response(http.StatusOK, "{}"), nil
	}
	if _, err := c.Do(http.MethodPost, gzipTestCheckinPath, makeBody(5000)); err != nil {
		t.Fatalf("second Do failed: %v", err)
	}

	// When the agent calls Do POST "/api/v1/devices/dev-1/checkin" with a
	// 5000-byte JSON body (compression having just turned off)
	var captured *http.Request
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		captured = req
		return fake.Response(http.StatusOK, "{}"), nil
	}
	body := makeBody(5000)
	if _, err := c.Do(http.MethodPost, gzipTestCheckinPath, body); err != nil {
		t.Fatalf("third Do failed: %v", err)
	}

	// Then the recorded request has no "Content-Encoding" header
	if got := captured.Header.Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// AC10 (failure): A rejected compressed request is retried uncompressed once
// ---------------------------------------------------------------------------

func TestScenario_RejectedCompressedRequestIsRetriedOnce_AC10(t *testing.T) {
	cases := []struct {
		status int
		body   string
	}{
		{http.StatusUnauthorized, `{"error":"bad_signature"}`},
		{http.StatusUnsupportedMediaType, `{"error":"unsupported_content_encoding"}`},
		{http.StatusBadRequest, `{"error":"invalid_gzip_body"}`},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			// Given compression is on after an advertising response
			c, doer, _ := newEnrolledGzipClient(t)
			primeCompressionOn(t, c, doer)

			fsys := fake.NewFS()
			logger := logging.New(fsys, fake.NewClock(time.Unix(0, 0)), "agent.log", logging.LevelDebug, "client")
			c.Logger = logger

			var reqs []*http.Request
			// And the doer answers the compressed request with <status> and
			// body <body>, and the uncompressed retry with 200
			doer.DoFunc = func(req *http.Request) (*http.Response, error) {
				reqs = append(reqs, req)
				if req.Header.Get("Content-Encoding") == "gzip" {
					return fake.Response(tc.status, tc.body), nil
				}
				return fake.Response(http.StatusOK, `{"ok":true}`), nil
			}

			before := len(doer.Requests())

			// When the agent calls Do POST "/api/v1/devices/dev-1/checkin"
			// with a 5000-byte JSON body
			resp, err := c.Do(http.MethodPost, gzipTestCheckinPath, makeBody(5000))

			// Then exactly two requests were recorded for this call
			after := len(doer.Requests())
			if after-before != 2 {
				t.Fatalf("expected 2 requests for this call, got %d", after-before)
			}
			if len(reqs) != 2 {
				t.Fatalf("expected 2 captured requests, got %d", len(reqs))
			}

			// And the second request has no "Content-Encoding" header and a
			// different X-MDM-Nonce
			if got := reqs[1].Header.Get("Content-Encoding"); got != "" {
				t.Errorf("retry Content-Encoding = %q, want empty", got)
			}
			if reqs[0].Header.Get(HeaderNonce) == reqs[1].Header.Get(HeaderNonce) {
				t.Errorf("expected the retry to carry a different nonce")
			}

			// And Do returns the 200 response (the retry succeeds in every
			// row of this outline, including the row whose first, compressed
			// attempt was itself a 401: it is the retry's outcome that
			// counts, not the first attempt's).
			if err != nil {
				t.Fatalf("Do failed: %v", err)
			}
			if resp == nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("expected the 200 retry response, got %+v", resp)
			}
			resp.Body.Close()

			// And one warn record "request compression rejected; sending
			// uncompressed" is logged with the path and status
			lines := readLogLines(t, fsys)
			found := 0
			for _, line := range lines {
				if line["msg"] != "request compression rejected; sending uncompressed" {
					continue
				}
				found++
				if line["path"] != gzipTestCheckinPath {
					t.Errorf("logged path = %v, want %v", line["path"], gzipTestCheckinPath)
				}
				if status, ok := line["status"].(float64); !ok || int(status) != tc.status {
					t.Errorf("logged status = %v, want %d", line["status"], tc.status)
				}
			}
			if found != 1 {
				t.Fatalf("expected exactly 1 warn record, got %d: %v", found, lines)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AC10 (failure): A retry that is also unauthorized returns ErrUnauthorized
// ---------------------------------------------------------------------------

func TestScenario_RetryAlsoUnauthorizedReturnsErrUnauthorized_AC10(t *testing.T) {
	// Given compression is on after an advertising response
	c, doer, _ := newEnrolledGzipClient(t)
	primeCompressionOn(t, c, doer)

	// And the doer answers every request with 401
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return fake.Response(http.StatusUnauthorized, ""), nil
	}
	before := len(doer.Requests())

	// When the agent calls Do POST "/api/v1/devices/dev-1/checkin" with a
	// 5000-byte JSON body
	_, err := c.Do(http.MethodPost, gzipTestCheckinPath, makeBody(5000))

	// Then exactly two requests were recorded for this call
	after := len(doer.Requests())
	if after-before != 2 {
		t.Fatalf("expected 2 requests for this call, got %d", after-before)
	}
	// And Do returns ErrUnauthorized
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// AC11: Compression stays off after a fallback
// ---------------------------------------------------------------------------

func TestScenario_CompressionStaysOffAfterFallback_AC11(t *testing.T) {
	// Given a compressed request was rejected with 415 and retried
	// uncompressed
	c, doer, _ := newEnrolledGzipClient(t)
	primeCompressionOn(t, c, doer)

	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Content-Encoding") == "gzip" {
			return fake.Response(http.StatusUnsupportedMediaType, `{"error":"unsupported_content_encoding"}`), nil
		}
		return fake.Response(http.StatusOK, "{}"), nil
	}
	if _, err := c.Do(http.MethodPost, gzipTestCheckinPath, makeBody(5000)); err != nil {
		t.Fatalf("fallback Do failed: %v", err)
	}

	// And later responses carry "X-MDM-Accept-Content-Encoding: gzip"
	var captured []*http.Request
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		captured = append(captured, req)
		resp := fake.Response(http.StatusOK, "{}")
		resp.Header.Set(HeaderAcceptContentEncoding, "gzip")
		return resp, nil
	}

	// When the agent calls Do POST "/api/v1/devices/dev-1/checkin" with a
	// 5000-byte JSON body twice
	if _, err := c.Do(http.MethodPost, gzipTestCheckinPath, makeBody(5000)); err != nil {
		t.Fatalf("first post-fallback Do failed: %v", err)
	}
	if _, err := c.Do(http.MethodPost, gzipTestCheckinPath, makeBody(5000)); err != nil {
		t.Fatalf("second post-fallback Do failed: %v", err)
	}

	// Then neither recorded request has a "Content-Encoding" header
	if len(captured) != 2 {
		t.Fatalf("expected 2 captured requests, got %d", len(captured))
	}
	for i, req := range captured {
		if got := req.Header.Get("Content-Encoding"); got != "" {
			t.Errorf("request %d: Content-Encoding = %q, want empty", i, got)
		}
	}
}

// ---------------------------------------------------------------------------
// AC12 (edge): An uncompressed 401 is not retried
// ---------------------------------------------------------------------------

func TestScenario_UncompressedUnauthorizedIsNotRetried_AC12(t *testing.T) {
	// Given the doer answers 401
	c, doer, _ := newEnrolledGzipClient(t)
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return fake.Response(http.StatusUnauthorized, ""), nil
	}

	// When the agent calls Do POST "/api/v1/devices/dev-1/checkin" with a
	// 100-byte body
	_, err := c.Do(http.MethodPost, gzipTestCheckinPath, makeBody(100))

	// Then exactly one request was recorded
	if len(doer.Requests()) != 1 {
		t.Fatalf("expected 1 request, got %d", len(doer.Requests()))
	}
	// And Do returns ErrUnauthorized
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// AC13: Enroll and public requests are never compressed
// ---------------------------------------------------------------------------

func TestScenario_EnrollAndPublicRequestsAreNeverCompressed_AC13(t *testing.T) {
	// Given compression is on after an advertising response. public() and
	// Enroll() never consult the compression flag at all, but a fresh (not
	// yet enrolled) store is required for Enroll to run, so the flag is set
	// directly here to simulate having already received the advertisement
	// without needing an enrolled Do call first.
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1764633600, 0))
	doer := fake.NewHTTPDoer()
	store := state.NewStore(fsys, "state.json") // not enrolled: Enroll must succeed
	cfg := config.Config{CollectionURL: "https://api.example.com", EnrollmentToken: "enroll-token-0123456789abcdef"}
	c := New(cfg, store, doer, clock)
	c.compressRequests.Store(true)

	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Path, "/enroll") {
			data, _ := json.Marshal(contract.EnrollResponse{
				DeviceID:               "d2",
				DeviceSecret:           gzipTestDeviceSecret,
				CheckInIntervalSeconds: 900,
			})
			return fake.Response(http.StatusOK, string(data)), nil
		}
		return fake.Response(http.StatusOK, "{}"), nil
	}

	// When the agent calls PostPublic, PostPublicBearer and Enroll with
	// 5000-byte bodies
	bigBody := makeBody(5000)
	if _, err := c.PostPublic("/api/v1/agent-auth/sessions", bigBody); err != nil {
		t.Fatalf("PostPublic failed: %v", err)
	}
	if _, err := c.PostPublicBearer("/api/v1/agent-auth/enrollment-token", bigBody, "a-bearer-token"); err != nil {
		t.Fatalf("PostPublicBearer failed: %v", err)
	}
	if err := c.Enroll(context.Background()); err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}

	// Then none of the recorded requests has a "Content-Encoding" header
	reqs := doer.Requests()
	if len(reqs) == 0 {
		t.Fatal("expected at least one recorded request")
	}
	for i, req := range reqs {
		if got := req.Header.Get("Content-Encoding"); got != "" {
			t.Errorf("request %d (%s): Content-Encoding = %q, want empty", i, req.URL.Path, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Shared small helpers
// ---------------------------------------------------------------------------

// readLogLines parses every line the fake logger wrote at "agent.log" as a
// JSON object.
func readLogLines(t *testing.T, fsys *fake.FS) []map[string]any {
	t.Helper()
	data, ok := fsys.Content("agent.log")
	if !ok {
		return nil
	}
	var lines []map[string]any
	for _, raw := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if raw == "" {
			continue
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			t.Fatalf("parsing log line %q: %v", raw, err)
		}
		lines = append(lines, parsed)
	}
	return lines
}
