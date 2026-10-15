// Unit tests for the small gzip helpers TASK-068 adds to client.go:
// headerIsGzip, gzipBytes, compressionRefused, decodeResponse and gzipBody.
// These exercise the functions directly, in isolation from Do.
package client

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestUnit_HeaderIsGzip(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"gzip", true},
		{"GZIP", true},
		{"GzIp", true},
		{" gzip ", true},
		{"gzip ", true},
		{" gzip", true},
		{"", false},
		{"identity", false},
		{"gzip;q=0", false},
		{"gzip, deflate", false},
		{"deflate", false},
		{"x-gzip", false},
	}
	for _, tc := range cases {
		if got := headerIsGzip(tc.value); got != tc.want {
			t.Errorf("headerIsGzip(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestUnit_GzipBytesRoundTrip(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"a":1}`),
		bytes.Repeat([]byte("x"), 5000),
		{},
		nil,
	}
	for _, plain := range cases {
		compressed, err := gzipBytes(plain)
		if err != nil {
			t.Fatalf("gzipBytes(%d bytes): %v", len(plain), err)
		}
		zr, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			t.Fatalf("gzip.NewReader: %v", err)
		}
		got, err := io.ReadAll(zr)
		if err != nil {
			t.Fatalf("reading gunzip stream: %v", err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("round trip mismatch: got %q, want %q", got, plain)
		}
	}
}

func TestUnit_GzipBytesIsDeterministic(t *testing.T) {
	plain := bytes.Repeat([]byte("the quick brown fox "), 100)
	first, err := gzipBytes(plain)
	if err != nil {
		t.Fatalf("gzipBytes: %v", err)
	}
	second, err := gzipBytes(plain)
	if err != nil {
		t.Fatalf("gzipBytes: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("compressing the same input twice produced different bytes")
	}
}

func TestUnit_CompressionRefused(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"401 any body", http.StatusUnauthorized, "", true},
		{"415 any body", http.StatusUnsupportedMediaType, "", true},
		{"400 invalid_gzip_body", http.StatusBadRequest, `{"error":"invalid_gzip_body"}`, true},
		{"400 other error", http.StatusBadRequest, `{"error":"invalid_request"}`, false},
		{"400 non-JSON body", http.StatusBadRequest, "not json", false},
		{"200 ok", http.StatusOK, `{"error":"invalid_gzip_body"}`, false},
		{"500 error", http.StatusInternalServerError, `{"error":"invalid_gzip_body"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tc.status,
				Body:       io.NopCloser(strings.NewReader(tc.body)),
			}
			got := compressionRefused(resp)
			if got != tc.want {
				t.Errorf("compressionRefused(%d, %q) = %v, want %v", tc.status, tc.body, got, tc.want)
			}
			// For a 400, the body bytes are read and must be put back
			// unchanged, so a caller that still wants to read the response
			// (the non-refusal case) can.
			if tc.status == http.StatusBadRequest && resp.Body != nil {
				replay, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("reading replayed body: %v", err)
				}
				if string(replay) != tc.body {
					t.Errorf("replayed body = %q, want %q", replay, tc.body)
				}
			}
		})
	}
}

func TestUnit_CompressionRefused_NilBody(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusBadRequest, Body: nil}
	if compressionRefused(resp) {
		t.Errorf("expected false for a nil body")
	}
}

func TestUnit_DecodeResponse_NoContentEncoding(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
	}
	got, err := decodeResponse(resp)
	if err != nil {
		t.Fatalf("decodeResponse: %v", err)
	}
	if got != resp {
		t.Errorf("expected the same *http.Response back unchanged")
	}
}

func TestUnit_DecodeResponse_NilBody(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Encoding": []string{"gzip"}},
		Body:       nil,
	}
	got, err := decodeResponse(resp)
	if err != nil {
		t.Fatalf("decodeResponse: %v", err)
	}
	if got != resp {
		t.Errorf("expected the same *http.Response back unchanged for a nil body")
	}
}

func TestUnit_DecodeResponse_BadGzipClosesBody(t *testing.T) {
	tracked := &trackedCloser{Reader: strings.NewReader("not gzip")}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Encoding": []string{"gzip"}},
		Body:       tracked,
	}
	got, err := decodeResponse(resp)
	if !errors.Is(err, ErrBadResponseEncoding) {
		t.Fatalf("expected ErrBadResponseEncoding, got %v", err)
	}
	if got != nil {
		t.Errorf("expected a nil response, got %+v", got)
	}
	if !tracked.closed {
		t.Errorf("expected the body to be closed")
	}
}

func TestUnit_DecodeResponse_ValidGzip(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(`{"ok":true}`)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Encoding": []string{"gzip"}},
		Body:          io.NopCloser(bytes.NewReader(buf.Bytes())),
		ContentLength: int64(buf.Len()),
	}
	got, err := decodeResponse(resp)
	if err != nil {
		t.Fatalf("decodeResponse: %v", err)
	}
	defer got.Body.Close()
	if got.Header.Get("Content-Encoding") != "" {
		t.Errorf("Content-Encoding header should be removed")
	}
	if got.ContentLength != -1 {
		t.Errorf("ContentLength = %d, want -1", got.ContentLength)
	}
	if !got.Uncompressed {
		t.Errorf("expected Uncompressed to be set")
	}
	data, err := io.ReadAll(got.Body)
	if err != nil {
		t.Fatalf("reading decoded body: %v", err)
	}
	if string(data) != `{"ok":true}` {
		t.Errorf("body = %q, want %q", data, `{"ok":true}`)
	}
}

// recordingCloser records whether Close was called and can be made to fail.
// It implements io.ReadCloser; Read is never exercised in these tests.
type recordingCloser struct {
	closed bool
	err    error
}

func (r *recordingCloser) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (r *recordingCloser) Close() error {
	r.closed = true
	return r.err
}

func TestUnit_GzipBodyClose_ClosesBoth(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte("hello"))
	_ = zw.Close()

	zr, err := gzip.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	underlying := &recordingCloser{}
	body := &gzipBody{Reader: zr, underlying: underlying}

	if err := body.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !underlying.closed {
		t.Errorf("expected the underlying body to be closed")
	}
}

func TestUnit_GzipBodyClose_PropagatesUnderlyingError(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte("hello"))
	_ = zw.Close()

	zr, err := gzip.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	wantErr := errors.New("underlying close failed")
	underlying := &recordingCloser{err: wantErr}
	body := &gzipBody{Reader: zr, underlying: underlying}

	if err := body.Close(); !errors.Is(err, wantErr) {
		t.Errorf("Close() = %v, want %v", err, wantErr)
	}
	if !underlying.closed {
		t.Errorf("expected the underlying body to be closed even though it errors")
	}
}
