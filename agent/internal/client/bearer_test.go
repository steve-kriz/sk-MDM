package client

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

// fakeBearer is a BearerSource a test controls directly.
type fakeBearer struct {
	token string
	ok    bool
}

func (b fakeBearer) BearerToken(ctx context.Context) (string, bool) { return b.token, b.ok }

const bearerTestSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestScenario_Bearer_AddsAuthorizationWithoutChangingSignature is the A11
// Gherkin scenario "Bearer is added without changing the HMAC signature".
func TestScenario_Bearer_AddsAuthorizationWithoutChangingSignature(t *testing.T) {
	// Given the same clock, nonce source and body
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1764633600, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{CollectionURL: "https://api.example.com"}
	store := state.NewStore(fsys, "state.json")
	if err := store.Save(state.State{DeviceID: "d1", DeviceSecret: bearerTestSecret}); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	c := New(cfg, store, doer, clock)

	// When Do runs once with Bearer nil ...
	if _, err := c.Do("GET", "/api/v1/test", nil); err != nil {
		t.Fatalf("Do (no bearer) failed: %v", err)
	}
	// ... and once with a Bearer returning "ACCESS-SENTINEL"
	c.Bearer = fakeBearer{token: "ACCESS-SENTINEL", ok: true}
	if _, err := c.Do("GET", "/api/v1/test", nil); err != nil {
		t.Fatalf("Do (bearer) failed: %v", err)
	}

	reqs := doer.Requests()
	if len(reqs) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(reqs))
	}
	first, second := reqs[0], reqs[1]

	// Then the second request has "Authorization: Bearer ACCESS-SENTINEL"
	if got := first.Header.Get(HeaderAuthorization); got != "" {
		t.Errorf("first request should carry no Authorization header, got %q", got)
	}
	if got := second.Header.Get(HeaderAuthorization); got != "Bearer ACCESS-SENTINEL" {
		t.Errorf("expected Authorization: Bearer ACCESS-SENTINEL, got %q", got)
	}

	// And both requests have identical X-MDM-Device-Id, X-MDM-Timestamp ...
	if first.Header.Get(HeaderDeviceID) != second.Header.Get(HeaderDeviceID) {
		t.Errorf("device id header differs between requests: %q vs %q",
			first.Header.Get(HeaderDeviceID), second.Header.Get(HeaderDeviceID))
	}
	if first.Header.Get(HeaderTimestamp) != second.Header.Get(HeaderTimestamp) {
		t.Errorf("timestamp header differs between requests: %q vs %q",
			first.Header.Get(HeaderTimestamp), second.Header.Get(HeaderTimestamp))
	}

	// ... and X-MDM-Signature for the same nonce: the bearer is not in the
	// canonical string, which is proven by recomputing the signature from
	// each request's own captured nonce, independently of whether a bearer
	// was present.
	for i, req := range reqs {
		nonce := req.Header.Get(HeaderNonce)
		if nonce == "" {
			t.Fatalf("request %d: missing nonce header", i)
		}
		var ts int64
		if _, err := fmt.Sscanf(req.Header.Get(HeaderTimestamp), "%d", &ts); err != nil {
			t.Fatalf("request %d: bad timestamp header %q: %v", i, req.Header.Get(HeaderTimestamp), err)
		}

		want, err := contract.SignRequest(bearerTestSecret, contract.SigningParts{
			Method:    "GET",
			Path:      "/api/v1/test",
			Query:     "",
			Body:      nil,
			Timestamp: ts,
			Nonce:     nonce,
			DeviceID:  "d1",
		})
		if err != nil {
			t.Fatalf("recompute signature for request %d: %v", i, err)
		}
		if got := req.Header.Get(HeaderSignature); got != want {
			t.Errorf("request %d: signature %q does not match the recomputed %q; the bearer must not affect signing", i, got, want)
		}
	}
}

// TestScenario_Bearer_NilOrFalseMeansNoAuthorizationHeader is the A11 edge
// scenario "No Authorization header when no token is held".
func TestScenario_Bearer_NilOrFalseMeansNoAuthorizationHeader(t *testing.T) {
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Unix(1764633600, 0))
	doer := fake.NewHTTPDoer()
	cfg := config.Config{CollectionURL: "https://api.example.com"}
	store := state.NewStore(fsys, "state.json")
	if err := store.Save(state.State{DeviceID: "d1", DeviceSecret: bearerTestSecret}); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	// Given a Bearer source returning "" and false
	c := New(cfg, store, doer, clock)
	c.Bearer = fakeBearer{token: "", ok: false}

	// When Do sends a signed request
	if _, err := c.Do("GET", "/api/v1/test", nil); err != nil {
		t.Fatalf("Do failed: %v", err)
	}

	// Then the request has no Authorization header
	reqs := doer.Requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if got := reqs[0].Header.Get(HeaderAuthorization); got != "" {
		t.Errorf("expected no Authorization header, got %q", got)
	}

	// And a nil Bearer behaves the same way
	fsys2 := fake.NewFS()
	doer2 := fake.NewHTTPDoer()
	store2 := state.NewStore(fsys2, "state2.json")
	if err := store2.Save(state.State{DeviceID: "d1", DeviceSecret: bearerTestSecret}); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	c2 := New(cfg, store2, doer2, clock)
	if _, err := c2.Do("GET", "/api/v1/test", nil); err != nil {
		t.Fatalf("Do failed: %v", err)
	}
	reqs2 := doer2.Requests()
	if got := reqs2[0].Header.Get(HeaderAuthorization); got != "" {
		t.Errorf("expected no Authorization header with nil Bearer, got %q", got)
	}
}
