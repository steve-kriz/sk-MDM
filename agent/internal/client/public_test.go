package client

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

// PostPublic sends the body unauthenticated: no device headers and no
// Authorization, even when the agent is enrolled.
func TestPostPublic_SendsBodyWithoutCredentials(t *testing.T) {
	fsys := fake.NewFS()
	store := state.NewStore(fsys, "state.json")
	if err := store.Save(state.State{DeviceID: "d1", DeviceSecret: testDeviceSecret}); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	doer := fake.NewHTTPDoer()
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return fake.Response(http.StatusCreated, `{"ok":true}`), nil
	}
	c := New(config.Config{CollectionURL: "https://api.example.com/prefix"}, store, doer, fake.NewClock(time.Unix(0, 0)))

	resp, err := c.PostPublic("/api/v1/agent-auth/sessions", []byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("PostPublic: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d", resp.StatusCode)
	}

	reqs := doer.Requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d", len(reqs))
	}
	req := reqs[0]
	if req.Method != http.MethodPost || req.URL.String() != "https://api.example.com/prefix/api/v1/agent-auth/sessions" {
		t.Errorf("request = %s %s", req.Method, req.URL)
	}
	if req.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q", req.Header.Get("Content-Type"))
	}
	for _, h := range []string{"Authorization", HeaderDeviceID, HeaderSignature, HeaderNonce, HeaderTimestamp} {
		if req.Header.Get(h) != "" {
			t.Errorf("header %s must be absent", h)
		}
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != `{"a":1}` {
		t.Errorf("body = %s", body)
	}
}

// An http collection URL is refused before any request is made.
func TestPostPublic_RefusesInsecureURL(t *testing.T) {
	doer := fake.NewHTTPDoer()
	c := New(config.Config{CollectionURL: "http://api.example.com"}, state.NewStore(fake.NewFS(), "s.json"), doer, fake.NewClock(time.Unix(0, 0)))
	if _, err := c.PostPublic("/x", []byte("{}")); !errors.Is(err, ErrInsecureTransport) {
		t.Fatalf("err = %v", err)
	}
	if len(doer.Requests()) != 0 {
		t.Error("no request expected")
	}
}

// PostPublicBearer sends the body with "Authorization: Bearer <token>" and
// nothing else: no device headers, no enrollment token. The token is never
// logged.
func TestPostPublicBearer_SendsOnlyTheBearer(t *testing.T) {
	fsys := fake.NewFS()
	store := state.NewStore(fsys, "state.json")
	if err := store.Save(state.State{DeviceID: "d1", DeviceSecret: testDeviceSecret}); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	doer := fake.NewHTTPDoer()
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		return fake.Response(http.StatusCreated, `{"token":"t"}`), nil
	}
	clock := fake.NewClock(time.Unix(0, 0))
	c := New(config.Config{CollectionURL: "https://api.example.com", EnrollmentToken: enrollmentTokenValue}, store, doer, clock)
	c.Logger = logging.New(fsys, clock, "agent.log", logging.LevelDebug, "client")

	resp, err := c.PostPublicBearer("/api/v1/agent-auth/enrollment-token", []byte(`{}`), "ACCESS-SENTINEL")
	if err != nil {
		t.Fatalf("PostPublicBearer: %v", err)
	}
	resp.Body.Close()

	req := doer.Requests()[0]
	if req.Method != http.MethodPost || req.URL.String() != "https://api.example.com/api/v1/agent-auth/enrollment-token" {
		t.Errorf("request = %s %s", req.Method, req.URL)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer ACCESS-SENTINEL" {
		t.Errorf("Authorization = %q", got)
	}
	for _, h := range []string{HeaderEnrollmentToken, HeaderDeviceID, HeaderSignature, HeaderNonce, HeaderTimestamp} {
		if req.Header.Get(h) != "" {
			t.Errorf("header %s must be absent", h)
		}
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != `{}` {
		t.Errorf("body = %s", body)
	}
	if logged, _ := fsys.Content("agent.log"); strings.Contains(string(logged), "SENTINEL") {
		t.Error("bearer token logged")
	}

	// A blank token is refused locally.
	if _, err := c.PostPublicBearer("/x", nil, " "); err == nil {
		t.Error("blank bearer accepted")
	}
	if n := len(doer.Requests()); n != 1 {
		t.Errorf("requests = %d, want 1", n)
	}
}
