package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/signin"
)

// idTokenWithUsername builds a syntactically valid, unverified id_token
// carrying preferred_username in its payload segment.
func idTokenWithUsername(username string) string {
	payload, _ := json.Marshal(map[string]interface{}{"preferred_username": username})
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

// loginMintedToken is what the fake backend mints for `mdmagent login`.
const loginMintedToken = "fedcba9876543210.LOGIN-MINTED"

// loginDoer builds a fake HTTPDoer that answers the agent-auth config fetch,
// the device-code request, the token poll and the enrollment-token mint from
// fixed bodies, dispatching on the request's path so the same doer serves the
// collection endpoint and the Entra authority. mintStatus 0 means a 201 with
// loginMintedToken. The mint's Authorization is checked to be the access token.
func loginDoer(t *testing.T, configBody, deviceCodeBody, tokenBody string, configStatus, deviceCodeStatus, tokenStatus int) *fake.HTTPDoer {
	return loginDoerMint(t, configBody, deviceCodeBody, tokenBody, configStatus, deviceCodeStatus, tokenStatus, 0)
}

func loginDoerMint(t *testing.T, configBody, deviceCodeBody, tokenBody string, configStatus, deviceCodeStatus, tokenStatus, mintStatus int) *fake.HTTPDoer {
	t.Helper()
	doer := fake.NewHTTPDoer()
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		switch {
		case req.URL.Path == agentAuthConfigPath:
			if got := req.Header.Get("Authorization"); got != "" {
				t.Errorf("config fetch should carry no Authorization header, got %q", got)
			}
			for _, h := range []string{"X-Mdm-Device-Id", "X-Mdm-Timestamp", "X-Mdm-Nonce", "X-Mdm-Signature"} {
				if got := req.Header.Get(h); got != "" {
					t.Errorf("config fetch should carry no %s header, got %q", h, got)
				}
			}
			return fake.Response(configStatus, configBody), nil
		case req.URL.Path == signin.EnrollmentTokenPath:
			if got := req.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") || got == "Bearer " {
				t.Errorf("mint Authorization = %q", got)
			}
			if mintStatus != 0 {
				return fake.Response(mintStatus, `{"error":"invalid_user_token"}`), nil
			}
			return fake.Response(http.StatusCreated, `{"tokenId":"fedcba9876543210","token":"`+loginMintedToken+`","expiresAt":"2026-10-09T09:00:00Z"}`), nil
		case strings.HasSuffix(req.URL.Path, "/devicecode"):
			if err := req.Context().Err(); err != nil {
				return nil, err
			}
			return fake.Response(deviceCodeStatus, deviceCodeBody), nil
		case strings.HasSuffix(req.URL.Path, "/token"):
			if err := req.Context().Err(); err != nil {
				return nil, err
			}
			return fake.Response(tokenStatus, tokenBody), nil
		}
		return fake.Response(http.StatusNotFound, "{}"), nil
	}
	return doer
}

// swapLoginSeams overrides newDoer and newClock for the duration of a test,
// restoring the production values afterwards.
func swapLoginSeams(t *testing.T, doer platform.HTTPDoer, clock platform.Clock) {
	t.Helper()
	origDoer, origClock := newDoer, newClock
	newDoer = func() platform.HTTPDoer { return doer }
	newClock = func() platform.Clock { return clock }
	t.Cleanup(func() { newDoer, newClock = origDoer, origClock })
}

// seedLoginConfig writes a config with no enrollment token and returns its
// bytes.
func seedLoginConfig(t *testing.T, fsys *fake.FS, goos, collectionURL string) []byte {
	t.Helper()
	fsys.Seed(config.Path(goos), []byte(`{"collectionUrl":"`+collectionURL+`","ownership":"byoc"}`))
	data, _ := fsys.Content(config.Path(goos))
	return data
}

func assertConfigUnchanged(t *testing.T, fsys *fake.FS, goos string, before []byte) {
	t.Helper()
	after, _ := fsys.Content(config.Path(goos))
	if !bytes.Equal(before, after) {
		t.Errorf("config changed: before=%q after=%q", before, after)
	}
}

const (
	validConfigBody = `{"tenantId":"t-1","clientId":"c-1","scopes":["api://c-1/MDM.Agent","offline_access","openid","profile"]}`
)

func validDeviceCodeBody() string {
	return `{"device_code":"DEVICECODE-SENTINEL","user_code":"WXYZ-1234","verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":5}`
}

func validTokenBody(username string) string {
	body, _ := json.Marshal(map[string]interface{}{
		"access_token":  "ACCESS-SENTINEL",
		"refresh_token": "REFRESH-SENTINEL",
		"expires_in":    3600,
		"id_token":      idTokenWithUsername(username),
	})
	return string(body)
}

// A successful login mints an enrollment token with the access token, writes
// only that field to the config, and stores no Entra token anywhere.
func TestScenario_Login_MintsEnrollmentToken(t *testing.T) {
	fsys := fake.NewFS()
	goos := "darwin"
	seedLoginConfig(t, fsys, goos, "https://collector.example")

	clock := fake.NewClock(time.Unix(1700000000, 0))
	clock.AutoAdvance = true
	doer := loginDoer(t, validConfigBody, validDeviceCodeBody(), validTokenBody("amy@contoso.com"), 200, 200, 200)
	swapLoginSeams(t, doer, clock)

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	if code := run(fsys, goos, []string{"login"}, stdout, stderr); code != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "To sign in, open https://microsoft.com/devicelogin and enter the code WXYZ-1234") {
		t.Errorf("missing verification line in stdout: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "signed in as amy@contoso.com") || !strings.Contains(stdout.String(), msgEnrollmentTokenStored) {
		t.Errorf("stdout = %s", stdout.String())
	}

	var mints int
	for _, r := range doer.Requests() {
		if r.URL.Path == signin.EnrollmentTokenPath {
			mints++
			if r.Header.Get("Authorization") != "Bearer ACCESS-SENTINEL" {
				t.Errorf("mint Authorization = %q", r.Header.Get("Authorization"))
			}
		}
	}
	if mints != 1 {
		t.Errorf("mints = %d, want 1", mints)
	}

	cfg, err := config.Load(fsys, config.Path(goos))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if cfg.EnrollmentToken != loginMintedToken || cfg.CollectionURL != "https://collector.example" || cfg.Ownership != "byoc" {
		t.Errorf("config = %+v", cfg)
	}
	for _, p := range fsys.Paths() {
		data, _ := fsys.Content(p)
		if strings.Contains(string(data), "ACCESS-SENTINEL") || strings.Contains(string(data), "REFRESH-SENTINEL") {
			t.Errorf("%s holds an Entra token", p)
		}
	}
}

// Every failure leaves the config exactly as it was.
func TestScenario_LoginFailuresLeaveConfigAlone(t *testing.T) {
	t.Run("the collection URL is http", func(t *testing.T) {
		fsys := fake.NewFS()
		goos := "darwin"
		before := seedLoginConfig(t, fsys, goos, "http://collector.example")
		doer := fake.NewHTTPDoer()
		doer.DoFunc = func(req *http.Request) (*http.Response, error) {
			t.Fatalf("no request should be made, got one to %s", req.URL)
			return nil, nil
		}
		swapLoginSeams(t, doer, fake.NewClock(time.Unix(1700000000, 0)))

		stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
		if code := run(fsys, goos, []string{"login"}, stdout, stderr); code != 2 {
			t.Errorf("expected exit 2, got %d", code)
		}
		if !strings.Contains(stderr.String(), "collection url must be an https url") {
			t.Errorf("stderr = %q", stderr.String())
		}
		assertConfigUnchanged(t, fsys, goos, before)
	})

	t.Run("agent-auth config answers 500", func(t *testing.T) {
		fsys := fake.NewFS()
		goos := "darwin"
		before := seedLoginConfig(t, fsys, goos, "https://collector.example")
		clock := fake.NewClock(time.Unix(1700000000, 0))
		clock.AutoAdvance = true
		swapLoginSeams(t, loginDoer(t, `{"error":"not_configured"}`, "", "", 500, 200, 200), clock)

		stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
		if code := run(fsys, goos, []string{"login"}, stdout, stderr); code != 1 {
			t.Errorf("expected exit 1, got %d", code)
		}
		if !strings.Contains(stderr.String(), "sign-in configuration unavailable") {
			t.Errorf("stderr = %q", stderr.String())
		}
		assertConfigUnchanged(t, fsys, goos, before)
	})

	cases := []struct {
		name      string
		tokenBody string
		wantMsg   string
	}{
		{"polling returns ErrSignInDeclined", `{"error":"authorization_declined"}`, "sign-in was declined"},
		{"polling returns ErrSignInExpired", `{"error":"expired_token"}`, "sign-in code expired"},
		{"polling returns ErrSignInFailed", `{"error":"invalid_client"}`, "sign-in failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fake.NewFS()
			goos := "darwin"
			before := seedLoginConfig(t, fsys, goos, "https://collector.example")
			clock := fake.NewClock(time.Unix(1700000000, 0))
			clock.AutoAdvance = true
			swapLoginSeams(t, loginDoer(t, validConfigBody, validDeviceCodeBody(), tc.tokenBody, 200, 200, 400), clock)

			stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
			if code := run(fsys, goos, []string{"login"}, stdout, stderr); code != 1 {
				t.Errorf("expected exit 1, got %d; stderr=%s", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.wantMsg) {
				t.Errorf("expected %q in stderr, got %q", tc.wantMsg, stderr.String())
			}
			assertConfigUnchanged(t, fsys, goos, before)
		})
	}

	t.Run("the context is cancelled while polling", func(t *testing.T) {
		fsys := fake.NewFS()
		goos := "darwin"
		before := seedLoginConfig(t, fsys, goos, "https://collector.example")
		clock := fake.NewClock(time.Unix(1700000000, 0))
		clock.AutoAdvance = true
		swapLoginSeams(t, loginDoer(t, validConfigBody, validDeviceCodeBody(), `{"access_token":"x","expires_in":3600}`, 200, 200, 200), clock)

		origSignalContext := signalContext
		signalContext = func(parent context.Context) (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(parent)
			cancel()
			return ctx, cancel
		}
		t.Cleanup(func() { signalContext = origSignalContext })

		stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
		if code := run(fsys, goos, []string{"login"}, stdout, stderr); code != 1 {
			t.Errorf("expected exit 1, got %d; stderr=%s", code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "sign-in cancelled") {
			t.Errorf("stderr = %q", stderr.String())
		}
		assertConfigUnchanged(t, fsys, goos, before)
	})

	t.Run("the mint is refused", func(t *testing.T) {
		fsys := fake.NewFS()
		goos := "windows"
		before := seedLoginConfig(t, fsys, goos, "https://collector.example")
		clock := fake.NewClock(time.Unix(1700000000, 0))
		clock.AutoAdvance = true
		swapLoginSeams(t, loginDoerMint(t, validConfigBody, validDeviceCodeBody(), validTokenBody("amy@contoso.com"), 200, 200, 200, 401), clock)

		stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
		if code := run(fsys, goos, []string{"login"}, stdout, stderr); code != 1 {
			t.Errorf("expected exit 1, got %d", code)
		}
		if !strings.HasPrefix(stderr.String(), "could not get an enrollment token:") || !strings.Contains(stderr.String(), "invalid_user_token") {
			t.Errorf("stderr = %q", stderr.String())
		}
		if strings.Contains(stderr.String()+stdout.String(), "ACCESS-SENTINEL") {
			t.Error("access token printed")
		}
		assertConfigUnchanged(t, fsys, goos, before)
	})
}

// A config that cannot be written is reported.
func TestScenario_Login_ConfigWriteError(t *testing.T) {
	fsys := fake.NewFS()
	goos := "darwin"
	seedLoginConfig(t, fsys, goos, "https://collector.example")
	clock := fake.NewClock(time.Unix(1700000000, 0))
	clock.AutoAdvance = true
	swapLoginSeams(t, loginDoer(t, validConfigBody, validDeviceCodeBody(), validTokenBody("amy@contoso.com"), 200, 200, 200), clock)
	fsys.FailWrite(config.Path(goos)+".tmp", errors.New("disk full"))

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	if code := run(fsys, goos, []string{"login"}, stdout, stderr); code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	if !strings.HasPrefix(strings.TrimSpace(stderr.String()), "could not store the enrollment token:") {
		t.Errorf("stderr = %q", stderr.String())
	}
	if strings.Contains(stderr.String(), loginMintedToken) {
		t.Error("enrollment token printed")
	}
}

// `mdmagent logout` is gone: there is no stored sign-in to remove.
func TestScenario_LogoutRemoved(t *testing.T) {
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	if _ = run(fake.NewFS(), "windows", []string{"logout"}, stdout, stderr); strings.Contains(stdout.String(), "signed out") {
		t.Errorf("logout should no longer be a verb; stdout=%q", stdout.String())
	}
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	if !strings.Contains(string(data), "mdmagent login") {
		t.Error("usage comment does not mention 'mdmagent login'")
	}
	if strings.Contains(string(data), "mdmagent logout") {
		t.Error("usage comment still mentions 'mdmagent logout'")
	}
}
