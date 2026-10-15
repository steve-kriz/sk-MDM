package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/client"
	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/scheduler"
	"github.com/officehq/sk-mdm/agent/internal/signin"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

const (
	enrollTestSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testSessionHex   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	mintedToken      = "0123456789abcdef.MINTED-SENTINEL"
)

type enrollFixture struct {
	fs    *fake.FS
	clock *fake.Clock
	doer  *fake.HTTPDoer
	agent *agent

	mu sync.Mutex
	// enrollStatus and enrollError are POST /api/v1/enroll's answer when
	// enrollStatus is not 200.
	enrollStatus int
	enrollError  string
	// complete flips the sign-in session to complete.
	complete bool
	// mintBearers records the Authorization of each mint request.
	mintBearers []string
}

// newEnrollFixture assembles the agent through newAgent with an unenrolled
// state and the given config. The doer plays the MDM backend and Entra.
func newEnrollFixture(t *testing.T, cfg config.Config) *enrollFixture {
	t.Helper()
	f := &enrollFixture{
		fs:           fake.NewFS(),
		clock:        fake.NewClock(time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC)),
		doer:         fake.NewHTTPDoer(),
		enrollStatus: http.StatusOK,
	}
	f.doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case req.URL.Path == client.EnrollPath:
			if f.enrollStatus != http.StatusOK {
				return fake.Response(f.enrollStatus, `{"error":"`+f.enrollError+`"}`), nil
			}
			data, _ := json.Marshal(contract.EnrollResponse{DeviceID: "d1", DeviceSecret: enrollTestSecret, CheckInIntervalSeconds: 900})
			return fake.Response(http.StatusOK, string(data)), nil
		case req.URL.Path == signin.SessionsPath:
			return fake.Response(http.StatusCreated, `{"sessionId":"`+testSessionHex+`","signInUrl":"https://collect.example.com/agent/signin/`+testSessionHex+`","expiresAt":"2026-10-10T08:00:00Z"}`), nil
		case req.URL.Path == signin.SessionsPath+"/"+testSessionHex:
			if !f.complete {
				return fake.Response(http.StatusOK, `{"status":"pending"}`), nil
			}
			return fake.Response(http.StatusOK, `{"status":"complete","code":"CODE-SENTINEL","redirectUri":"https://collect.example.com/agent/callback"}`), nil
		case req.URL.Host == "login.microsoftonline.com" && strings.HasSuffix(req.URL.Path, "/token"):
			return fake.Response(http.StatusOK, `{"access_token":"USER-ACCESS-SENTINEL","refresh_token":"USER-REFRESH-SENTINEL","expires_in":3600,"id_token":"`+idTokenWithUsername("alice@officehq.com.au")+`"}`), nil
		case req.URL.Path == signin.EnrollmentTokenPath:
			f.mintBearers = append(f.mintBearers, req.Header.Get("Authorization"))
			return fake.Response(http.StatusCreated, `{"tokenId":"0123456789abcdef","token":"`+mintedToken+`","expiresAt":"2026-10-09T09:00:00Z"}`), nil
		}
		return fake.Response(http.StatusOK, "{}"), nil
	}
	data, _ := json.Marshal(cfg)
	f.fs.Seed(config.Path("windows"), data)

	a, err := newAgent(agentEnv{
		FS:         f.fs,
		Runner:     fake.NewCommandRunner(),
		Clock:      f.clock,
		Doer:       f.doer,
		GOOS:       "windows",
		ConfigPath: config.Path("windows"),
		StatePath:  state.StatePath("windows"),
	})
	if err != nil {
		t.Fatalf("newAgent: %v", err)
	}
	// Collection is not under test here.
	a.deps.CollectInventory = func() (contract.Inventory, error) { return contract.Inventory{}, nil }
	a.deps.CollectPosture = func() (contract.Posture, error) { return contract.Posture{}, nil }
	a.deps.CollectAntivirusFindings = func() ([]contract.AntivirusFinding, []string) { return nil, nil }
	a.deps.AfterCheckIn = nil
	f.agent = a
	return f
}

func (f *enrollFixture) enrollRequests() []*http.Request {
	var out []*http.Request
	for _, r := range f.doer.Requests() {
		if r.URL.Path == client.EnrollPath {
			out = append(out, r)
		}
	}
	return out
}

func (f *enrollFixture) configToken(t *testing.T) string {
	t.Helper()
	tok, err := config.ReadEnrollmentToken(f.fs, config.Path("windows"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	return tok
}

// With no enrollment token the agent waits for a sign-in. The brokered
// sign-in redeems the code, spends the access token on minting an enrollment
// token, writes only that to the config and wakes the loop, which then enrolls
// with X-MDM-Enrollment-Token and no Authorization header.
func TestRunLoop_EnrollsWithMintedTokenAfterSignIn(t *testing.T) {
	f := newEnrollFixture(t, config.Config{CollectionURL: "https://collect.example.com", Ownership: "byoc", TenantID: "t-1", ClientID: "c-1"})

	err := scheduler.RunOnce(context.Background(), f.agent.deps)
	if !errors.Is(err, client.ErrAwaitingSignIn) {
		t.Fatalf("first cycle err = %v, want ErrAwaitingSignIn", err)
	}
	if n := len(f.doer.Requests()); n != 0 {
		t.Fatalf("no request expected before sign-in, got %d", n)
	}

	b := f.agent.signin
	if !b.Needed() {
		t.Fatal("sign-in should be needed")
	}
	if err := b.Tick(context.Background()); err != nil {
		t.Fatalf("create session: %v", err)
	}
	f.mu.Lock()
	f.complete = true
	f.mu.Unlock()
	if err := b.Tick(context.Background()); err != nil {
		t.Fatalf("complete sign-in: %v", err)
	}

	if got := f.configToken(t); got != mintedToken {
		t.Fatalf("config enrollmentToken = %q", got)
	}
	if len(f.mintBearers) != 1 || f.mintBearers[0] != "Bearer USER-ACCESS-SENTINEL" {
		t.Errorf("mint bearers = %v", f.mintBearers)
	}
	select {
	case <-f.agent.deps.SignInWake:
	default:
		t.Error("the run loop was not woken")
	}
	if b.Needed() {
		t.Error("a token is configured: no sign-in needed")
	}
	// No Entra token reaches the disk, in any file.
	for _, p := range f.fs.Paths() {
		data, _ := f.fs.Content(p)
		if strings.Contains(string(data), "USER-ACCESS-SENTINEL") || strings.Contains(string(data), "USER-REFRESH-SENTINEL") {
			t.Errorf("%s holds an Entra token", p)
		}
	}

	if err := scheduler.RunOnce(context.Background(), f.agent.deps); err != nil {
		t.Fatalf("second cycle: %v", err)
	}
	reqs := f.enrollRequests()
	if len(reqs) != 1 {
		t.Fatalf("enroll requests = %d, want 1", len(reqs))
	}
	if got := reqs[0].Header.Get(client.HeaderEnrollmentToken); got != mintedToken {
		t.Errorf("enrollment token header = %q", got)
	}
	if got := reqs[0].Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want none", got)
	}
	body, _ := io.ReadAll(reqs[0].Body)
	if !strings.Contains(string(body), `"ownership":"byoc"`) {
		t.Errorf("body = %s", body)
	}
	st, _ := state.NewStore(f.fs, state.StatePath("windows")).Load()
	if st.DeviceID != "d1" {
		t.Errorf("not enrolled: %+v", st)
	}
}

// A configured enrollment token is used as before.
func TestRunLoop_LegacyTokenStillUsed(t *testing.T) {
	f := newEnrollFixture(t, config.Config{CollectionURL: "https://collect.example.com", EnrollmentToken: "legacy-token"})
	if err := scheduler.RunOnce(context.Background(), f.agent.deps); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	reqs := f.enrollRequests()
	if len(reqs) != 1 {
		t.Fatalf("enroll requests = %d", len(reqs))
	}
	if reqs[0].Header.Get(client.HeaderEnrollmentToken) != "legacy-token" {
		t.Errorf("token header = %q", reqs[0].Header.Get(client.HeaderEnrollmentToken))
	}
	if reqs[0].Header.Get("Authorization") != "" {
		t.Error("enroll must carry no Authorization header")
	}
}

// An enrollment token the backend rejects is removed from the config, keeping
// the rest of it, and a sign-in is needed again.
func TestRunLoop_RejectedTokenClearedFromConfig(t *testing.T) {
	for _, code := range []string{"invalid_enrollment_token", "enrollment_token_expired", "enrollment_token_exhausted"} {
		t.Run(code, func(t *testing.T) {
			f := newEnrollFixture(t, config.Config{CollectionURL: "https://collect.example.com", EnrollmentToken: "used-token", Ownership: "byoc"})
			f.enrollStatus = http.StatusForbidden
			f.enrollError = code

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- scheduler.Run(ctx, f.agent.deps) }()
			waitUntil(t, func() bool { return len(f.clock.Waits()) >= 1 })
			cancel()
			<-done

			if got := f.configToken(t); got != "" {
				t.Errorf("enrollmentToken = %q, want removed", got)
			}
			cfg, err := config.Load(f.fs, config.Path("windows"))
			if err != nil || cfg.CollectionURL != "https://collect.example.com" || cfg.Ownership != "byoc" {
				t.Errorf("rest of the config changed: %+v, %v", cfg, err)
			}
			if !f.agent.signin.Needed() {
				t.Error("a sign-in should be needed again")
			}
			logged, _ := f.fs.Content(agentLogPath("windows"))
			if !strings.Contains(string(logged), "enrollment token rejected") || !strings.Contains(string(logged), code) {
				t.Errorf("rejection not logged:\n%s", logged)
			}
			if strings.Contains(string(logged), "used-token") {
				t.Error("token logged")
			}
		})
	}
}

// The service deletes the user token vault an earlier version left behind.
func TestStart_RemovesLegacyVault(t *testing.T) {
	cases := map[string]string{
		"windows": `C:\ProgramData\OfficeHQ\MDM\usertoken.bin`,
		"darwin":  "/Library/Application Support/OfficeHQ/MDM/usertoken.json",
	}
	for goos, path := range cases {
		fsys := fake.NewFS()
		data, _ := json.Marshal(config.Config{CollectionURL: "https://collect.example.com"})
		fsys.Seed(config.Path(goos), data)
		fsys.Seed(path, []byte("old tokens"))
		a, err := newAgent(agentEnv{
			FS: fsys, Runner: fake.NewCommandRunner(), Clock: fake.NewClock(time.Unix(0, 0)),
			Doer: fake.NewHTTPDoer(), GOOS: goos, ConfigPath: config.Path(goos), StatePath: state.StatePath(goos),
		})
		if err != nil {
			t.Fatalf("%s: newAgent: %v", goos, err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = a.hooks().Start(ctx)
		if fsys.Exists(path) {
			t.Errorf("%s: %s not removed", goos, path)
		}
		// Nothing left is not an error, and is not logged.
		_ = a.hooks().Start(ctx)
		logged, _ := fsys.Content(agentLogPath(goos))
		if strings.Count(string(logged), "removed the stored user token") != 1 {
			t.Errorf("%s: removal logged wrongly:\n%s", goos, logged)
		}
	}
}

// A vault that cannot be removed costs a warning.
func TestStart_LegacyVaultRemovalFailureLogged(t *testing.T) {
	fsys := fake.NewFS()
	fsys.RemoveErr = func(path string) error {
		if path == legacyVaultPath("windows") {
			return fs.ErrPermission
		}
		return nil
	}
	removeLegacyVault(fsys, "windows", nil) // a nil logger is tolerated
	logger := newTestLogger(fsys)
	removeLegacyVault(fsys, "windows", logger)
	logged, _ := fsys.Content(testLogFile)
	if !strings.Contains(string(logged), "could not be removed") {
		t.Errorf("failure not logged:\n%s", logged)
	}
}

// newAgent wires the brokered sign-in with the baked-in tenant and client,
// without asking the backend.
func TestNewAgent_SignInUsesConfiguredTenant(t *testing.T) {
	f := newEnrollFixture(t, config.Config{CollectionURL: "https://collect.example.com", TenantID: "t-9", ClientID: "c-9"})
	if f.agent.signin == nil {
		t.Fatal("sign-in server not wired")
	}
	if f.agent.deps.SignInWake == nil {
		t.Fatal("SignInWake not wired")
	}
	if f.agent.deps.ClearEnrollmentToken == nil {
		t.Fatal("ClearEnrollmentToken not wired")
	}
	auth, err := f.agent.signin.AuthConfig(context.Background())
	if err != nil || auth.TenantID != "t-9" || auth.ClientID != "c-9" {
		t.Errorf("auth = %+v, %v", auth, err)
	}
	if n := len(f.doer.Requests()); n != 0 {
		t.Errorf("no request expected, got %d", n)
	}
}

// Without baked-in values the tenant and client come from the backend's
// agent-auth config, fetched once.
func TestNewAgent_SignInFetchesAuthConfig(t *testing.T) {
	f := newEnrollFixture(t, config.Config{CollectionURL: "https://collect.example.com"})
	f.doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == agentAuthConfigPath {
			return fake.Response(http.StatusOK, validConfigBody), nil
		}
		return fake.Response(http.StatusNotFound, "{}"), nil
	}
	for i := 0; i < 2; i++ {
		auth, err := f.agent.signin.AuthConfig(context.Background())
		if err != nil || auth.TenantID != "t-1" || auth.ClientID != "c-1" {
			t.Fatalf("auth = %+v, %v", auth, err)
		}
	}
	if n := len(f.doer.Requests()); n != 1 {
		t.Errorf("config fetched %d times, want 1", n)
	}
}

// A completed sign-in wakes the run loop.
func TestNewAgent_SignInWakesRunLoop(t *testing.T) {
	f := newEnrollFixture(t, config.Config{CollectionURL: "https://collect.example.com"})
	f.agent.signin.OnSignIn()
	f.agent.signin.OnSignIn() // a second notification must not block
	select {
	case <-f.agent.deps.SignInWake:
	default:
		t.Fatal("no wake after a sign-in")
	}
}

// The broker is wired to the data directory and is only active while the
// device is unenrolled and the config holds no enrollment token.
func TestNewAgent_SignInNeeded(t *testing.T) {
	f := newEnrollFixture(t, config.Config{CollectionURL: "https://collect.example.com"})
	b := f.agent.signin
	if b.SessionPath != `C:\ProgramData\OfficeHQ\MDM\signin.json` || b.URLPath != `C:\ProgramData\OfficeHQ\MDM\signin-url.txt` {
		t.Errorf("paths = %s, %s", b.SessionPath, b.URLPath)
	}
	if !b.Needed() {
		t.Error("unenrolled with no token: sign-in needed")
	}
	if err := config.SetEnrollmentToken(f.fs, config.Path("windows"), "tok"); err != nil {
		t.Fatal(err)
	}
	if b.Needed() {
		t.Error("token written after start: no sign-in needed")
	}
	if err := config.ClearEnrollmentToken(f.fs, config.Path("windows")); err != nil {
		t.Fatal(err)
	}
	if !b.Needed() {
		t.Error("token removed: sign-in needed again")
	}

	enrolled := newEnrollFixture(t, config.Config{CollectionURL: "https://collect.example.com"})
	if err := state.NewStore(enrolled.fs, state.StatePath("windows")).Save(state.State{DeviceID: "d1", DeviceSecret: enrollTestSecret}); err != nil {
		t.Fatal(err)
	}
	if enrolled.agent.signin.Needed() {
		t.Error("enrolled: no sign-in needed")
	}

	legacy := newEnrollFixture(t, config.Config{CollectionURL: "https://collect.example.com", EnrollmentToken: "tok"})
	if legacy.agent.signin.Needed() {
		t.Error("enrollment token configured: no sign-in needed")
	}
}

// fakeOpener records what open-signin asked to open.
type fakeOpener struct {
	opened []string
	err    error
}

func (o *fakeOpener) Open(_ context.Context, u string) error {
	o.opened = append(o.opened, u)
	return o.err
}

// swapOpenSignInSeams installs a self-advancing clock and a recording opener.
func swapOpenSignInSeams(t *testing.T) (*fake.Clock, *fakeOpener, *string) {
	t.Helper()
	clock := fake.NewClock(time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC))
	clock.AutoAdvance = true
	opener := &fakeOpener{}
	var goos string
	origClock, origOpener := newClock, newOpener
	newClock = func() platform.Clock { return clock }
	newOpener = func(g string) platform.URLOpener { goos = g; return opener }
	t.Cleanup(func() { newClock, newOpener = origClock, origOpener })
	return clock, opener, &goos
}

const pendingSignInURL = "https://collect.example.com/agent/signin/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// A published address on the collection host is opened at once.
func TestCLI_OpenSignIn_OpensPublishedURL(t *testing.T) {
	for _, goos := range []string{"windows", "darwin"} {
		_, opener, gotGOOS := swapOpenSignInSeams(t)
		fsys := fake.NewFS()
		cfg, _ := json.Marshal(config.Config{CollectionURL: "https://collect.example.com"})
		fsys.Seed(config.Path(goos), cfg)
		fsys.SeedMode(signin.URLPath(goos), []byte(pendingSignInURL+"\n"), 0o644)

		stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
		if code := run(fsys, goos, []string{"open-signin"}, stdout, stderr); code != exitOK {
			t.Fatalf("%s: exit = %d, stderr %s", goos, code, stderr)
		}
		if len(opener.opened) != 1 || opener.opened[0] != pendingSignInURL || *gotGOOS != goos {
			t.Errorf("%s: opened %v on %q", goos, opener.opened, *gotGOOS)
		}
	}
}

// The address may appear while open-signin waits.
func TestCLI_OpenSignIn_WaitsForURL(t *testing.T) {
	clock, opener, _ := swapOpenSignInSeams(t)
	clock.AutoAdvance = false
	fsys := fake.NewFS()

	done := make(chan int, 1)
	go func() { done <- run(fsys, "windows", []string{"open-signin"}, io.Discard, io.Discard) }()

	waitUntil(t, func() bool { return len(clock.Waits()) >= 1 })
	clock.Advance(time.Second)
	waitUntil(t, func() bool { return len(clock.Waits()) >= 2 })
	fsys.SeedMode(signin.URLPath("windows"), []byte(pendingSignInURL), 0o644)
	clock.Advance(time.Second)

	if code := <-done; code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if len(opener.opened) != 1 {
		t.Errorf("opened = %v", opener.opened)
	}
}

// With nothing published after 30 s, open-signin says so and exits 1.
func TestCLI_OpenSignIn_NothingPending(t *testing.T) {
	clock, opener, _ := swapOpenSignInSeams(t)
	start := clock.Now()
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	if code := run(fake.NewFS(), "darwin", []string{"open-signin"}, stdout, stderr); code != exitError {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(stderr.String(), "no sign-in is pending") {
		t.Errorf("stderr = %q", stderr.String())
	}
	if waited := clock.Now().Sub(start); waited != 30*time.Second {
		t.Errorf("waited %v, want 30s", waited)
	}
	if len(opener.opened) != 0 {
		t.Error("nothing should be opened")
	}
}

// Only an https address on the sign-in path, and on the collection host when
// the config is readable, is opened.
func TestCLI_OpenSignIn_RefusesForeignURLs(t *testing.T) {
	cases := []struct {
		name       string
		url        string
		readConfig bool
		ok         bool
	}{
		{"other host", "https://evil.example.com/agent/signin/abc", true, false},
		{"http", "http://collect.example.com/agent/signin/abc", true, false},
		{"other path", "https://collect.example.com/admin", true, false},
		{"credentials", "https://u:p@collect.example.com/agent/signin/abc", true, false},
		{"not a url", "javascript:alert(1)", true, false},
		{"host case", "https://COLLECT.example.com/agent/signin/abc", true, true},
		{"config unreadable, any https host on the path", "https://other.example.com/agent/signin/abc", false, true},
		{"config unreadable, wrong path", "https://other.example.com/x", false, false},
		{"config unreadable, http", "http://other.example.com/agent/signin/abc", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, opener, _ := swapOpenSignInSeams(t)
			fsys := fake.NewFS()
			if c.readConfig {
				cfg, _ := json.Marshal(config.Config{CollectionURL: "https://collect.example.com"})
				fsys.Seed(config.Path("windows"), cfg)
			} else {
				fsys.Seed(config.Path("windows"), []byte("{}"))
				fsys.ReadErr = func(p string) error {
					if p == config.Path("windows") {
						return fs.ErrPermission
					}
					return nil
				}
			}
			fsys.SeedMode(signin.URLPath("windows"), []byte(c.url), 0o644)
			code := run(fsys, "windows", []string{"open-signin"}, io.Discard, io.Discard)
			if c.ok && (code != exitOK || len(opener.opened) != 1) {
				t.Errorf("want opened, exit %d opened %v", code, opener.opened)
			}
			if !c.ok && (code != exitError || len(opener.opened) != 0) {
				t.Errorf("want refused, exit %d opened %v", code, opener.opened)
			}
		})
	}
}

// A browser that cannot be started is an error.
func TestCLI_OpenSignIn_OpenerFails(t *testing.T) {
	_, opener, _ := swapOpenSignInSeams(t)
	opener.err = errors.New("rundll32 missing")
	fsys := fake.NewFS()
	fsys.SeedMode(signin.URLPath("windows"), []byte(pendingSignInURL), 0o644)
	stderr := &bytes.Buffer{}
	if code := run(fsys, "windows", []string{"open-signin"}, io.Discard, stderr); code != exitError {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(stderr.String(), "could not open the browser") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// The removed loopback verb is gone.
func TestCLI_SignInURLRemoved(t *testing.T) {
	stdout := &bytes.Buffer{}
	_ = run(fake.NewFS(), "windows", []string{"signin-url"}, stdout, io.Discard)
	if strings.Contains(stdout.String(), "localhost:47615") {
		t.Error("signin-url must no longer print the loopback address")
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(time.Millisecond)
	}
}
