package signin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/userauth"
)

const (
	testSessionID  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testSessionID2 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	testCode       = "CODE-SENTINEL"
	testRedirect   = "https://mdm.example.com/agent/callback"
	testLogPath    = "agent.log"
	// testEnrollToken is the minted enrollment token.
	testEnrollToken = "0123456789abcdef.ENROLL-SENTINEL"
)

// fakeTransport answers the two public broker routes from canned replies and
// records what was asked.
type fakeTransport struct {
	mu sync.Mutex

	// sessions are handed out by successive POSTs.
	sessions []string
	created  int
	// postStatus overrides the POST answer when non-zero.
	postStatus int
	// postBodies records each POST body.
	postBodies [][]byte

	// poll answers GET /api/v1/agent-auth/sessions/{id}.
	poll func(id string) (*http.Response, error)
	// polled records each polled session id.
	polled []string

	// mint answers POST EnrollmentTokenPath; nil is a 201 with
	// testEnrollToken.
	mint func() (*http.Response, error)
	// mints records each mint request.
	mints []mintCall
}

type mintCall struct {
	path, body, bearer string
}

func (f *fakeTransport) PostPublic(path string, body []byte) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if path != SessionsPath {
		return fake.Response(http.StatusNotFound, `{"error":"not_found"}`), nil
	}
	f.postBodies = append(f.postBodies, append([]byte(nil), body...))
	if f.postStatus != 0 {
		return fake.Response(f.postStatus, `{"error":"x"}`), nil
	}
	id := testSessionID
	if f.created < len(f.sessions) {
		id = f.sessions[f.created]
	}
	f.created++
	data, _ := json.Marshal(map[string]string{
		"sessionId": id,
		"signInUrl": "https://mdm.example.com/agent/signin/" + id,
		"expiresAt": "2026-10-10T08:00:00.000Z",
	})
	return fake.Response(http.StatusCreated, string(data)), nil
}

func (f *fakeTransport) PostPublicBearer(path string, body []byte, token string) (*http.Response, error) {
	f.mu.Lock()
	f.mints = append(f.mints, mintCall{path: path, body: string(body), bearer: token})
	mint := f.mint
	f.mu.Unlock()
	if mint == nil {
		return fake.Response(http.StatusCreated, `{"tokenId":"0123456789abcdef","token":"`+testEnrollToken+`","expiresAt":"2026-10-09T09:00:00.000Z"}`), nil
	}
	return mint()
}

func (f *fakeTransport) FetchPublic(path string) (*http.Response, error) {
	f.mu.Lock()
	poll := f.poll
	id := strings.TrimPrefix(path, SessionsPath+"/")
	f.polled = append(f.polled, id)
	f.mu.Unlock()
	if poll == nil {
		return fake.Response(http.StatusOK, `{"status":"pending"}`), nil
	}
	return poll(id)
}

// fakeRedeemer stands in for Entra's token endpoint.
type fakeRedeemer struct {
	calls []redeemCall
	err   error
}

type redeemCall struct {
	tenant, client, code, verifier, redirect string
	scopes                                   []string
}

func (r *fakeRedeemer) RedeemCode(_ context.Context, tenant, client, code, verifier, redirect string, scopes []string) (userauth.Token, error) {
	r.calls = append(r.calls, redeemCall{tenant, client, code, verifier, redirect, scopes})
	if r.err != nil {
		return userauth.Token{}, r.err
	}
	return userauth.Token{
		AccessToken:  "ACCESS-SENTINEL",
		RefreshToken: "REFRESH-SENTINEL",
		ExpiresIn:    3600,
		// {"preferred_username":"alice@officehq.com.au"}
		IDToken: "x.eyJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhbGljZUBvZmZpY2VocS5jb20uYXUifQ.y",
	}, nil
}

type fixture struct {
	fs        *fake.FS
	clock     *fake.Clock
	transport *fakeTransport
	redeemer  *fakeRedeemer
	broker    *Broker
	needed    bool
	wakes     int
	authErr   error
	// saved records every token handed to SaveToken; saveErr fails it.
	saved   []string
	saveErr error
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		fs:        fake.NewFS(),
		clock:     fake.NewClock(time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC)),
		transport: &fakeTransport{},
		redeemer:  &fakeRedeemer{},
		needed:    true,
	}
	f.broker = &Broker{
		Transport: f.transport,
		Redeemer:  f.redeemer,
		SaveToken: func(token string) error {
			if f.saveErr != nil {
				return f.saveErr
			}
			f.saved = append(f.saved, token)
			return nil
		},
		FS:          f.fs,
		Clock:       f.clock,
		Logger:      logging.New(f.fs, f.clock, testLogPath, logging.LevelDebug, "signin"),
		SessionPath: SessionPath("windows"),
		URLPath:     URLPath("windows"),
		AuthConfig: func(context.Context) (AuthConfig, error) {
			return AuthConfig{TenantID: "t-1", ClientID: "c-1"}, f.authErr
		},
		Needed:   func() bool { return f.needed },
		OnSignIn: func() { f.wakes++ },
		Rand:     bytes.NewReader(bytes.Repeat([]byte{7}, 4096)),
	}
	return f
}

func (f *fixture) tick(t *testing.T) error {
	t.Helper()
	return f.broker.Tick(context.Background())
}

func (f *fixture) storedSession(t *testing.T) storedSession {
	t.Helper()
	data, ok := f.fs.Content(SessionPath("windows"))
	if !ok {
		t.Fatal("signin.json missing")
	}
	var s storedSession
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("signin.json: %v", err)
	}
	return s
}

func (f *fixture) log() string {
	data, _ := f.fs.Content(testLogPath)
	return string(data)
}

func TestPaths(t *testing.T) {
	cases := map[string][2]string{
		"windows": {`C:\ProgramData\OfficeHQ\MDM\signin.json`, `C:\ProgramData\OfficeHQ\MDM\signin-url.txt`},
		"darwin":  {"/Library/Application Support/OfficeHQ/MDM/signin.json", "/Library/Application Support/OfficeHQ/MDM/signin-url.txt"},
	}
	for goos, want := range cases {
		if SessionPath(goos) != want[0] || URLPath(goos) != want[1] {
			t.Errorf("%s: %s, %s", goos, SessionPath(goos), URLPath(goos))
		}
	}
}

// The first tick creates a session with an S256 challenge of a fresh
// verifier, and writes the two files with their modes.
func TestTick_CreatesSession(t *testing.T) {
	f := newFixture(t)
	if err := f.tick(t); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(f.transport.postBodies) != 1 {
		t.Fatalf("posts = %d", len(f.transport.postBodies))
	}
	var body map[string]string
	if err := json.Unmarshal(f.transport.postBodies[0], &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	s := f.storedSession(t)
	if len(s.Verifier) != 43 {
		t.Errorf("verifier length = %d, want 43", len(s.Verifier))
	}
	if body["codeChallengeMethod"] != "S256" || body["codeChallenge"] != userauth.PKCEChallenge(s.Verifier) || len(body["codeChallenge"]) != 43 {
		t.Errorf("body = %v", body)
	}
	if strings.Contains(string(f.transport.postBodies[0]), s.Verifier) {
		t.Error("the verifier must never leave the device")
	}
	if s.SessionID != testSessionID || s.SignInURL != "https://mdm.example.com/agent/signin/"+testSessionID {
		t.Errorf("stored = %+v", s)
	}
	if !s.ExpiresAt.Equal(time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)) {
		t.Errorf("expiresAt = %v", s.ExpiresAt)
	}
	if mode, _ := f.fs.Mode(SessionPath("windows")); mode != 0o600 {
		t.Errorf("signin.json mode = %o", mode)
	}
	url, _ := f.fs.Content(URLPath("windows"))
	if string(url) != s.SignInURL {
		t.Errorf("signin-url.txt = %q", url)
	}
	if mode, _ := f.fs.Mode(URLPath("windows")); mode != 0o644 {
		t.Errorf("signin-url.txt mode = %o", mode)
	}
	if strings.Contains(f.log(), s.Verifier) {
		t.Error("verifier logged")
	}
}

// A pending session is polled, not replaced.
func TestTick_PendingKeepsSession(t *testing.T) {
	f := newFixture(t)
	_ = f.tick(t)
	if err := f.tick(t); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if f.transport.created != 1 || len(f.transport.polled) != 1 || f.transport.polled[0] != testSessionID {
		t.Errorf("created %d, polled %v", f.transport.created, f.transport.polled)
	}
	if !f.fs.Exists(URLPath("windows")) {
		t.Error("url file removed")
	}
}

// completeAnswer makes the next poll answer "complete".
func (f *fixture) completeAnswer() {
	f.transport.poll = func(string) (*http.Response, error) {
		return fake.Response(http.StatusOK, `{"status":"complete","code":"`+testCode+`","redirectUri":"`+testRedirect+`"}`), nil
	}
}

// A complete session is redeemed with the stored verifier and the returned
// redirect URI; the access token mints an enrollment token, which is saved;
// the files go, nothing else is written and the run loop is woken.
func TestTick_CompleteRedeemsMintsAndSaves(t *testing.T) {
	f := newFixture(t)
	_ = f.tick(t)
	verifier := f.storedSession(t).Verifier
	f.completeAnswer()
	if err := f.tick(t); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(f.redeemer.calls) != 1 {
		t.Fatalf("redeem calls = %d", len(f.redeemer.calls))
	}
	c := f.redeemer.calls[0]
	if c.tenant != "t-1" || c.client != "c-1" || c.code != testCode || c.verifier != verifier || c.redirect != testRedirect ||
		strings.Join(c.scopes, " ") != "api://c-1/MDM.Agent offline_access openid profile" {
		t.Errorf("redeem = %+v", c)
	}
	if len(f.transport.mints) != 1 {
		t.Fatalf("mints = %d, want 1", len(f.transport.mints))
	}
	m := f.transport.mints[0]
	if EnrollmentTokenPath != "/api/v1/agent-auth/enrollment-token" || m.path != EnrollmentTokenPath || m.body != "{}" || m.bearer != "ACCESS-SENTINEL" {
		t.Errorf("mint = %+v", m)
	}
	if len(f.saved) != 1 || f.saved[0] != testEnrollToken {
		t.Errorf("saved = %v", f.saved)
	}
	if f.fs.Exists(SessionPath("windows")) || f.fs.Exists(URLPath("windows")) {
		t.Error("signin files must be deleted")
	}
	// Nothing but the log may have been written: no token store.
	for _, p := range f.fs.Paths() {
		if p != testLogPath {
			t.Errorf("unexpected file %s", p)
		}
	}
	if f.wakes != 1 {
		t.Errorf("wakes = %d", f.wakes)
	}
	logged := f.log()
	for _, secret := range []string{testCode, verifier, "ACCESS-SENTINEL", "REFRESH-SENTINEL", "ENROLL-SENTINEL"} {
		if strings.Contains(logged, secret) {
			t.Errorf("log carries %q:\n%s", secret, logged)
		}
	}
	if !strings.Contains(logged, "alice@officehq.com.au") {
		t.Errorf("sign-in not logged:\n%s", logged)
	}

	// The next tick (Needed now false in production) does nothing more.
	f.needed = false
	if err := f.tick(t); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(f.transport.mints) != 1 || f.transport.created != 1 {
		t.Errorf("unexpected requests: mints %d created %d", len(f.transport.mints), f.transport.created)
	}
}

// A mint that fails in passing (transport error or 5xx) keeps the access token
// in memory only and is retried at the next tick, with no new session.
func TestTick_MintTransientFailureRetried(t *testing.T) {
	answers := map[string]func() (*http.Response, error){
		"transport": func() (*http.Response, error) { return nil, errors.New("connection reset") },
		"503":       func() (*http.Response, error) { return fake.Response(http.StatusServiceUnavailable, `{"error":"jwks_unavailable"}`), nil },
	}
	for name, answer := range answers {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			_ = f.tick(t)
			f.completeAnswer()
			f.transport.mint = answer
			if err := f.tick(t); err == nil {
				t.Fatal("want an error")
			}
			if len(f.saved) != 0 || f.wakes != 0 {
				t.Errorf("saved %v wakes %d", f.saved, f.wakes)
			}
			if f.fs.Exists(SessionPath("windows")) || f.fs.Exists(URLPath("windows")) {
				t.Error("the redeemed session's files must go")
			}
			for _, p := range f.fs.Paths() {
				if p != testLogPath {
					t.Errorf("unexpected file %s", p)
				}
			}

			f.transport.mint = nil
			if err := f.tick(t); err != nil {
				t.Fatalf("retry tick: %v", err)
			}
			if len(f.transport.mints) != 2 || f.transport.mints[1].bearer != "ACCESS-SENTINEL" {
				t.Errorf("mints = %+v", f.transport.mints)
			}
			if len(f.redeemer.calls) != 1 || f.transport.created != 1 || len(f.transport.polled) != 1 {
				t.Errorf("redeem %d created %d polled %d", len(f.redeemer.calls), f.transport.created, len(f.transport.polled))
			}
			if len(f.saved) != 1 || f.wakes != 1 {
				t.Errorf("saved %v wakes %d", f.saved, f.wakes)
			}
			if strings.Contains(f.log(), "ACCESS-SENTINEL") {
				t.Error("access token logged")
			}
		})
	}
}

// A mint the backend refuses drops the access token and starts a new session.
func TestTick_MintRefusedStartsOver(t *testing.T) {
	f := newFixture(t)
	f.transport.sessions = []string{testSessionID, testSessionID2}
	_ = f.tick(t)
	f.completeAnswer()
	f.transport.mint = func() (*http.Response, error) {
		return fake.Response(http.StatusUnauthorized, `{"error":"invalid_user_token"}`), nil
	}
	if err := f.tick(t); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if f.storedSession(t).SessionID != testSessionID2 {
		t.Error("a new session should follow a refused mint")
	}
	if len(f.saved) != 0 || f.wakes != 0 {
		t.Errorf("saved %v wakes %d", f.saved, f.wakes)
	}
	if !strings.Contains(f.log(), "invalid_user_token") {
		t.Errorf("refusal not logged:\n%s", f.log())
	}
	// The next tick polls the new session; the old token is gone.
	f.transport.poll = nil
	_ = f.tick(t)
	if len(f.transport.mints) != 1 {
		t.Errorf("mints = %d, want 1", len(f.transport.mints))
	}
}

// An access token that expires before a mint succeeds is dropped and a new
// session started.
func TestTick_HeldAccessTokenExpires(t *testing.T) {
	f := newFixture(t)
	_ = f.tick(t)
	f.completeAnswer()
	f.transport.mint = func() (*http.Response, error) { return nil, errors.New("offline") }
	_ = f.tick(t)
	f.clock.Advance(2 * time.Hour)
	f.transport.mint = nil
	f.transport.poll = nil
	if err := f.tick(t); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(f.transport.mints) != 1 || f.transport.created != 2 || len(f.saved) != 0 {
		t.Errorf("mints %d created %d saved %v", len(f.transport.mints), f.transport.created, f.saved)
	}
}

// A minted token that cannot be saved is reported, and minting is tried again
// at the next tick.
func TestTick_SaveFailureRetried(t *testing.T) {
	f := newFixture(t)
	_ = f.tick(t)
	f.completeAnswer()
	f.saveErr = errors.New("disk full")
	if err := f.tick(t); err == nil {
		t.Fatal("want an error")
	}
	if f.wakes != 0 {
		t.Error("no wake expected")
	}
	f.saveErr = nil
	if err := f.tick(t); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(f.saved) != 1 || f.wakes != 1 || len(f.transport.mints) != 2 {
		t.Errorf("saved %v wakes %d mints %d", f.saved, f.wakes, len(f.transport.mints))
	}
}

// A sign-in that becomes unnecessary while an access token is held drops it.
func TestTick_NotNeededDropsHeldToken(t *testing.T) {
	f := newFixture(t)
	_ = f.tick(t)
	f.completeAnswer()
	f.transport.mint = func() (*http.Response, error) { return nil, errors.New("offline") }
	_ = f.tick(t)
	f.needed = false
	_ = f.tick(t)
	f.needed = true
	f.transport.mint = nil
	f.transport.poll = nil
	_ = f.tick(t)
	if len(f.transport.mints) != 1 || f.transport.created != 2 {
		t.Errorf("mints %d created %d", len(f.transport.mints), f.transport.created)
	}
}

// failed, 404 and a locally expired session each start a new session.
func TestTick_NewSessionWhenFailedGoneOrExpired(t *testing.T) {
	cases := map[string]func(f *fixture){
		"failed": func(f *fixture) {
			f.transport.poll = func(string) (*http.Response, error) {
				return fake.Response(http.StatusOK, `{"status":"failed","error":"access_denied"}`), nil
			}
		},
		"not found": func(f *fixture) {
			f.transport.poll = func(string) (*http.Response, error) {
				return fake.Response(http.StatusNotFound, `{"error":"not_found"}`), nil
			}
		},
		"expired locally": func(f *fixture) {
			f.clock.Advance(25 * time.Hour)
		},
	}
	for name, arrange := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.transport.sessions = []string{testSessionID, testSessionID2}
			_ = f.tick(t)
			arrange(f)
			if err := f.tick(t); err != nil {
				t.Fatalf("tick: %v", err)
			}
			if f.transport.created != 2 {
				t.Fatalf("created = %d, want 2", f.transport.created)
			}
			if got := f.storedSession(t).SessionID; got != testSessionID2 {
				t.Errorf("session = %s", got)
			}
			url, _ := f.fs.Content(URLPath("windows"))
			if !strings.HasSuffix(string(url), testSessionID2) {
				t.Errorf("url = %s", url)
			}
			if name == "expired locally" && len(f.transport.polled) != 0 {
				t.Error("an expired session must not be polled")
			}
		})
	}
}

// A failed sign-in logs Microsoft's error detail, the only diagnosis there is.
func TestTick_FailedLogsMicrosoftDetail(t *testing.T) {
	f := newFixture(t)
	f.transport.sessions = []string{testSessionID, testSessionID2}
	_ = f.tick(t)
	f.transport.poll = func(string) (*http.Response, error) {
		return fake.Response(http.StatusOK, `{"status":"failed","error":"sign_in_failed","detail":"invalid_scope: AADSTS70011: bad scope"}`), nil
	}
	if err := f.tick(t); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if logged := f.log(); !strings.Contains(logged, "AADSTS70011: bad scope") {
		t.Errorf("detail not logged:\n%s", logged)
	}
}

// A transport error or a 5xx keeps the session for the next tick.
func TestTick_TransientErrorKeepsSession(t *testing.T) {
	answers := map[string]func(string) (*http.Response, error){
		"transport": func(string) (*http.Response, error) { return nil, errors.New("connection reset") },
		"5xx":       func(string) (*http.Response, error) { return fake.Response(http.StatusBadGateway, "bad"), nil },
	}
	for name, answer := range answers {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			_ = f.tick(t)
			f.transport.poll = answer
			if err := f.tick(t); err == nil {
				t.Fatal("want an error")
			}
			if f.transport.created != 1 || !f.fs.Exists(URLPath("windows")) {
				t.Errorf("session replaced or dropped: created %d", f.transport.created)
			}
		})
	}
}

// A refused session creation writes nothing and is retried next tick.
func TestTick_CreateRefusedWritesNothing(t *testing.T) {
	f := newFixture(t)
	f.transport.postStatus = http.StatusInternalServerError
	if err := f.tick(t); err == nil {
		t.Fatal("want an error")
	}
	if f.fs.Exists(SessionPath("windows")) || f.fs.Exists(URLPath("windows")) {
		t.Error("nothing should be written")
	}
}

// Without the tenant and client no session is created: its code could not be
// redeemed.
func TestTick_NoAuthConfigNoSession(t *testing.T) {
	f := newFixture(t)
	f.authErr = errors.New("offline")
	if err := f.tick(t); err == nil {
		t.Fatal("want an error")
	}
	if f.transport.created != 0 {
		t.Error("no session expected")
	}
}

// A failed redemption starts over with a new session and mints nothing.
func TestTick_RedeemFailureStartsOver(t *testing.T) {
	f := newFixture(t)
	f.transport.sessions = []string{testSessionID, testSessionID2}
	_ = f.tick(t)
	f.transport.poll = func(string) (*http.Response, error) {
		return fake.Response(http.StatusOK, `{"status":"complete","code":"`+testCode+`","redirectUri":"`+testRedirect+`"}`), nil
	}
	f.redeemer.err = userauth.ErrSignInFailed
	_ = f.tick(t)
	if len(f.saved) != 0 || len(f.transport.mints) != 0 {
		t.Error("nothing may be minted or saved")
	}
	if f.wakes != 0 {
		t.Error("no wake expected")
	}
	if f.storedSession(t).SessionID != testSessionID2 {
		t.Error("a new session should replace the redeemed one")
	}
	if strings.Contains(f.log(), testCode) {
		t.Error("code logged")
	}
}

// When no sign-in is needed (enrolled, or a token is configured) nothing is
// asked and leftover files are removed.
func TestTick_NotNeededClearsFiles(t *testing.T) {
	f := newFixture(t)
	_ = f.tick(t)
	f.needed = false
	if err := f.tick(t); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if f.fs.Exists(SessionPath("windows")) || f.fs.Exists(URLPath("windows")) {
		t.Error("files should be removed")
	}
	if len(f.transport.polled) != 0 || f.transport.created != 1 {
		t.Errorf("unexpected requests: polled %v created %d", f.transport.polled, f.transport.created)
	}
}

// A corrupt or tampered signin.json is replaced, and a session id that is not
// 64 hex characters is never put in a path.
func TestTick_BadStoredSessionReplaced(t *testing.T) {
	f := newFixture(t)
	f.fs.Seed(SessionPath("windows"), []byte(`{"sessionId":"../../admin","verifier":"v","expiresAt":"2027-01-01T00:00:00Z","signInUrl":"https://x"}`))
	if err := f.tick(t); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(f.transport.polled) != 0 || f.transport.created != 1 {
		t.Errorf("polled %v created %d", f.transport.polled, f.transport.created)
	}
}

// A creation answer with a malformed session id or a non-https URL is refused.
func TestTick_BadCreateAnswerRefused(t *testing.T) {
	f := newFixture(t)
	f.transport.sessions = []string{"not-hex"}
	if err := f.tick(t); err == nil {
		t.Fatal("want an error")
	}
	if f.fs.Exists(URLPath("windows")) {
		t.Error("nothing should be written")
	}
}

// Run ticks at once and then every PollInterval until ctx ends.
func TestRun_PollsEveryTenSeconds(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.broker.Run(ctx); close(done) }()

	waitFor(t, func() bool { return len(f.clock.Waits()) >= 1 })
	if w := f.clock.Waits()[0]; w != PollInterval || PollInterval != 10*time.Second {
		t.Errorf("wait = %v", w)
	}
	f.clock.Advance(PollInterval)
	waitFor(t, func() bool { return len(f.clock.Waits()) >= 2 })
	cancel()
	<-done
	f.transport.mu.Lock()
	defer f.transport.mu.Unlock()
	if f.transport.created != 1 || len(f.transport.polled) != 1 {
		t.Errorf("created %d polled %d", f.transport.created, len(f.transport.polled))
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(time.Millisecond)
	}
}
