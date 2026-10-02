package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/userauth"
)

// idTokenWithUsername builds a syntactically valid, unverified id_token
// carrying preferred_username in its payload segment.
func idTokenWithUsername(username string) string {
	payload, _ := json.Marshal(map[string]interface{}{"preferred_username": username})
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

// loginDoer builds a fake HTTPDoer that answers the agent-auth config fetch,
// the device-code request and the token poll from fixed bodies, dispatching
// on the request's host and path so the same doer serves the collection
// endpoint and the Entra authority.
func loginDoer(t *testing.T, configBody, deviceCodeBody, tokenBody string, configStatus, deviceCodeStatus, tokenStatus int) *fake.HTTPDoer {
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

// swapLoginSeams overrides newDoer, newClock and newProtector for the
// duration of a test, restoring the production values afterwards.
func swapLoginSeams(t *testing.T, doer platform.HTTPDoer, clock platform.Clock, protector platform.SecretProtector) {
	t.Helper()
	origDoer, origClock, origProtector := newDoer, newClock, newProtector
	newDoer = func() platform.HTTPDoer { return doer }
	newClock = func() platform.Clock { return clock }
	newProtector = func() platform.SecretProtector { return protector }
	t.Cleanup(func() { newDoer, newClock, newProtector = origDoer, origClock, origProtector })
}

func seedLoginConfig(t *testing.T, fsys *fake.FS, goos, collectionURL string) {
	t.Helper()
	cfg := config.Config{
		CollectionURL:          collectionURL,
		EnrollmentToken:        "irrelevant-for-login",
		CheckInIntervalSeconds: 900,
		LogLevel:               "info",
	}
	if err := config.Save(fsys, config.Path(goos), cfg); err != nil {
		t.Fatalf("seed config: %v", err)
	}
}

const (
	validConfigBody = `{"tenantId":"t-1","clientId":"c-1","scopes":["api://c-1/MDM.Agent","offline_access","openid","profile"]}`
)

func validDeviceCodeBody() string {
	return `{"device_code":"DEVICECODE-SENTINEL","user_code":"WXYZ-1234","verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":5}`
}

// TestScenario_Login_Success is the A5 Gherkin scenario "Successful login".
func TestScenario_Login_Success(t *testing.T) {
	fsys := fake.NewFS()
	goos := "darwin"
	seedLoginConfig(t, fsys, goos, "https://collector.example")

	clock := fake.NewClock(time.Unix(1700000000, 0))
	clock.AutoAdvance = true

	idToken := idTokenWithUsername("amy@contoso.com")
	tokenBody, _ := json.Marshal(map[string]interface{}{
		"access_token":  "ACCESS-SENTINEL",
		"refresh_token": "REFRESH-SENTINEL",
		"expires_in":    3600,
		"id_token":      idToken,
	})
	doer := loginDoer(t, validConfigBody, validDeviceCodeBody(), string(tokenBody), 200, 200, 200)

	protector := fake.NewSecretProtector()
	swapLoginSeams(t, doer, clock, protector)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	// When "mdmagent login" runs
	exitCode := run(fsys, goos, []string{"login"}, stdout, stderr)

	// Then the exit code is 0
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%s", exitCode, stderr.String())
	}

	// And stdout contains the verification line
	if !strings.Contains(stdout.String(), "To sign in, open https://microsoft.com/devicelogin and enter the code WXYZ-1234") {
		t.Errorf("missing verification line in stdout: %s", stdout.String())
	}
	// And stdout contains "signed in as amy@contoso.com"
	if !strings.Contains(stdout.String(), "signed in as amy@contoso.com") {
		t.Errorf("missing signed-in line in stdout: %s", stdout.String())
	}

	// And the vault holds the expected record
	vault := userauth.NewVault(fsys, protector, userauth.VaultPath(goos))
	rec, err := vault.Load()
	if err != nil {
		t.Fatalf("vault load: %v", err)
	}
	if rec.AccessToken != "ACCESS-SENTINEL" {
		t.Errorf("expected accessToken ACCESS-SENTINEL, got %q", rec.AccessToken)
	}
	if rec.RefreshToken != "REFRESH-SENTINEL" {
		t.Errorf("expected refreshToken REFRESH-SENTINEL, got %q", rec.RefreshToken)
	}
	wantExpiry := clock.Now().Add(3600 * time.Second)
	if !rec.ExpiresAt.Equal(wantExpiry) {
		t.Errorf("expected expiresAt %v, got %v", wantExpiry, rec.ExpiresAt)
	}
	if rec.Username != "amy@contoso.com" {
		t.Errorf("expected username amy@contoso.com, got %q", rec.Username)
	}
	if rec.TenantID != "t-1" || rec.ClientID != "c-1" {
		t.Errorf("expected tenantId t-1 / clientId c-1, got %q / %q", rec.TenantID, rec.ClientID)
	}
	wantScopes := []string{"api://c-1/MDM.Agent", "offline_access", "openid", "profile"}
	if len(rec.Scopes) != len(wantScopes) {
		t.Fatalf("expected scopes %v, got %v", wantScopes, rec.Scopes)
	}
	for i := range wantScopes {
		if rec.Scopes[i] != wantScopes[i] {
			t.Errorf("scope %d: expected %q, got %q", i, wantScopes[i], rec.Scopes[i])
		}
	}
}

// TestScenario_Login_MalformedIDTokenStoresEmptyUsername is the A5 edge
// scenario "Login with a malformed id_token stores an empty username".
func TestScenario_Login_MalformedIDTokenStoresEmptyUsername(t *testing.T) {
	fsys := fake.NewFS()
	goos := "darwin"
	seedLoginConfig(t, fsys, goos, "https://collector.example")

	clock := fake.NewClock(time.Unix(1700000000, 0))
	clock.AutoAdvance = true

	tokenBody, _ := json.Marshal(map[string]interface{}{
		"access_token":  "ACCESS-SENTINEL",
		"refresh_token": "REFRESH-SENTINEL",
		"expires_in":    3600,
		"id_token":      "not.a-jwt",
	})
	doer := loginDoer(t, validConfigBody, validDeviceCodeBody(), string(tokenBody), 200, 200, 200)
	protector := fake.NewSecretProtector()
	swapLoginSeams(t, doer, clock, protector)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	// When "mdmagent login" runs
	exitCode := run(fsys, goos, []string{"login"}, stdout, stderr)

	// Then the exit code is 0
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%s", exitCode, stderr.String())
	}

	// And the vault username is ""
	vault := userauth.NewVault(fsys, protector, userauth.VaultPath(goos))
	rec, err := vault.Load()
	if err != nil {
		t.Fatalf("vault load: %v", err)
	}
	if rec.Username != "" {
		t.Errorf("expected empty username, got %q", rec.Username)
	}
}

// seedOldVault writes an older sign-in and returns its serialised bytes, so a
// test can assert the vault is byte-for-byte unchanged after a failed login.
func seedOldVault(t *testing.T, fsys *fake.FS, protector platform.SecretProtector, goos string) []byte {
	t.Helper()
	vault := userauth.NewVault(fsys, protector, userauth.VaultPath(goos))
	rec := userauth.Record{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		ExpiresAt:    time.Unix(1700000000, 0),
		Username:     "old@contoso.com",
		TenantID:     "t-0",
		ClientID:     "c-0",
		Scopes:       []string{"openid"},
	}
	if err := vault.Save(rec); err != nil {
		t.Fatalf("seed old vault: %v", err)
	}
	content, ok := fsys.Content(userauth.VaultPath(goos))
	if !ok {
		t.Fatalf("old vault was not written")
	}
	return content
}

func assertVaultUnchanged(t *testing.T, fsys *fake.FS, goos string, before []byte) {
	t.Helper()
	after, ok := fsys.Content(userauth.VaultPath(goos))
	if !ok {
		t.Fatalf("vault file disappeared")
	}
	if !bytes.Equal(before, after) {
		t.Errorf("vault changed: before=%q after=%q", before, after)
	}
}

// TestScenario_LoginFailuresKeepOlderSignIn is the A6 Gherkin scenario
// outline "Login failures keep an older sign-in".
func TestScenario_LoginFailuresKeepOlderSignIn(t *testing.T) {
	t.Run("the collection URL is http", func(t *testing.T) {
		fsys := fake.NewFS()
		goos := "darwin"
		seedLoginConfig(t, fsys, goos, "http://collector.example")
		protector := fake.NewSecretProtector()
		before := seedOldVault(t, fsys, protector, goos)

		doer := fake.NewHTTPDoer()
		doer.DoFunc = func(req *http.Request) (*http.Response, error) {
			t.Fatalf("no request should be made, got one to %s", req.URL)
			return nil, nil
		}
		clock := fake.NewClock(time.Unix(1700000000, 0))
		swapLoginSeams(t, doer, clock, protector)

		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}
		exitCode := run(fsys, goos, []string{"login"}, stdout, stderr)

		if exitCode != 2 {
			t.Errorf("expected exit 2, got %d", exitCode)
		}
		if !strings.Contains(stderr.String(), "collection url must be an https url") {
			t.Errorf("expected https message in stderr, got %q", stderr.String())
		}
		assertVaultUnchanged(t, fsys, goos, before)
	})

	t.Run("agent-auth config answers 500", func(t *testing.T) {
		fsys := fake.NewFS()
		goos := "darwin"
		seedLoginConfig(t, fsys, goos, "https://collector.example")
		protector := fake.NewSecretProtector()
		before := seedOldVault(t, fsys, protector, goos)

		doer := loginDoer(t, `{"error":"not_configured"}`, "", "", 500, 200, 200)
		clock := fake.NewClock(time.Unix(1700000000, 0))
		clock.AutoAdvance = true
		swapLoginSeams(t, doer, clock, protector)

		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}
		exitCode := run(fsys, goos, []string{"login"}, stdout, stderr)

		if exitCode != 1 {
			t.Errorf("expected exit 1, got %d", exitCode)
		}
		if !strings.Contains(stderr.String(), "sign-in configuration unavailable") {
			t.Errorf("expected config-unavailable message, got %q", stderr.String())
		}
		assertVaultUnchanged(t, fsys, goos, before)
	})

	cases := []struct {
		name      string
		tokenBody string
		wantMsg   string
	}{
		{
			name:      "polling returns ErrSignInDeclined",
			tokenBody: `{"error":"authorization_declined"}`,
			wantMsg:   "sign-in was declined",
		},
		{
			name:      "polling returns ErrSignInExpired",
			tokenBody: `{"error":"expired_token"}`,
			wantMsg:   "sign-in code expired",
		},
		{
			name:      "polling returns ErrSignInFailed",
			tokenBody: `{"error":"invalid_client"}`,
			wantMsg:   "sign-in failed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fake.NewFS()
			goos := "darwin"
			seedLoginConfig(t, fsys, goos, "https://collector.example")
			protector := fake.NewSecretProtector()
			before := seedOldVault(t, fsys, protector, goos)

			doer := loginDoer(t, validConfigBody, validDeviceCodeBody(), tc.tokenBody, 200, 200, 400)
			clock := fake.NewClock(time.Unix(1700000000, 0))
			clock.AutoAdvance = true
			swapLoginSeams(t, doer, clock, protector)

			stdout := &bytes.Buffer{}
			stderr := &bytes.Buffer{}
			exitCode := run(fsys, goos, []string{"login"}, stdout, stderr)

			if exitCode != 1 {
				t.Errorf("expected exit 1, got %d; stderr=%s", exitCode, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.wantMsg) {
				t.Errorf("expected %q in stderr, got %q", tc.wantMsg, stderr.String())
			}
			assertVaultUnchanged(t, fsys, goos, before)
		})
	}

	t.Run("the context is cancelled while polling", func(t *testing.T) {
		fsys := fake.NewFS()
		goos := "darwin"
		seedLoginConfig(t, fsys, goos, "https://collector.example")
		protector := fake.NewSecretProtector()
		before := seedOldVault(t, fsys, protector, goos)

		doer := loginDoer(t, validConfigBody, validDeviceCodeBody(), `{"access_token":"x","expires_in":3600}`, 200, 200, 200)
		clock := fake.NewClock(time.Unix(1700000000, 0))
		clock.AutoAdvance = true
		swapLoginSeams(t, doer, clock, protector)

		origSignalContext := signalContext
		signalContext = func(parent context.Context) (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(parent)
			cancel()
			return ctx, cancel
		}
		t.Cleanup(func() { signalContext = origSignalContext })

		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}
		exitCode := run(fsys, goos, []string{"login"}, stdout, stderr)

		if exitCode != 1 {
			t.Errorf("expected exit 1, got %d; stderr=%s", exitCode, stderr.String())
		}
		if !strings.Contains(stderr.String(), "sign-in cancelled") {
			t.Errorf("expected sign-in cancelled message, got %q", stderr.String())
		}
		assertVaultUnchanged(t, fsys, goos, before)
	})
}

// TestScenario_Login_VaultWriteError is the A6 (failure) scenario "Vault
// cannot be written".
func TestScenario_Login_VaultWriteError(t *testing.T) {
	fsys := fake.NewFS()
	goos := "darwin"
	seedLoginConfig(t, fsys, goos, "https://collector.example")

	clock := fake.NewClock(time.Unix(1700000000, 0))
	clock.AutoAdvance = true
	tokenBody := `{"access_token":"ACCESS-SENTINEL","refresh_token":"REFRESH-SENTINEL","expires_in":3600}`
	doer := loginDoer(t, validConfigBody, validDeviceCodeBody(), tokenBody, 200, 200, 200)
	protector := fake.NewSecretProtector()
	swapLoginSeams(t, doer, clock, protector)

	// Given no vault exists and the FileSystem WriteErr fails for the vault
	// .tmp path
	fsys.FailWrite(userauth.VaultPath(goos)+".tmp", errors.New("disk full"))

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	// When "mdmagent login" completes polling with a token
	exitCode := run(fsys, goos, []string{"login"}, stdout, stderr)

	// Then the exit code is 1 and stderr starts with "could not store sign-in:"
	if exitCode != 1 {
		t.Fatalf("expected exit 1, got %d", exitCode)
	}
	if !strings.HasPrefix(strings.TrimSpace(stderr.String()), "could not store sign-in:") {
		t.Errorf("expected stderr to start with 'could not store sign-in:', got %q", stderr.String())
	}
}

// TestScenario_Logout_WithAndWithoutVault is the A7 Gherkin scenario "Logout
// with and without a vault".
func TestScenario_Logout_WithAndWithoutVault(t *testing.T) {
	fsys := fake.NewFS()
	goos := "windows"
	protector := fake.NewSecretProtector()
	origProtector := newProtector
	newProtector = func() platform.SecretProtector { return protector }
	t.Cleanup(func() { newProtector = origProtector })

	// Given a vault record exists
	vault := userauth.NewVault(fsys, protector, userauth.VaultPath(goos))
	if err := vault.Save(userauth.Record{
		AccessToken: "a", RefreshToken: "r", ExpiresAt: time.Unix(1700003600, 0),
	}); err != nil {
		t.Fatalf("seed vault: %v", err)
	}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	// When "mdmagent logout" runs
	exitCode := run(fsys, goos, []string{"logout"}, stdout, stderr)

	// Then the vault file is gone, stdout is "signed out" and the exit code is 0
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%s", exitCode, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "signed out" {
		t.Errorf("expected stdout 'signed out', got %q", stdout.String())
	}
	if fsys.Exists(userauth.VaultPath(goos)) {
		t.Errorf("expected vault file removed")
	}

	// When "mdmagent logout" runs again
	stdout2 := &bytes.Buffer{}
	stderr2 := &bytes.Buffer{}
	exitCode2 := run(fsys, goos, []string{"logout"}, stdout2, stderr2)

	// Then stdout is "signed out" and the exit code is 0
	if exitCode2 != 0 {
		t.Fatalf("expected exit 0 on second logout, got %d; stderr=%s", exitCode2, stderr2.String())
	}
	if strings.TrimSpace(stdout2.String()) != "signed out" {
		t.Errorf("expected stdout 'signed out' on second logout, got %q", stdout2.String())
	}
}

// TestScenario_Logout_DeleteError is the A7 (failure) scenario "Logout delete
// error".
func TestScenario_Logout_DeleteError(t *testing.T) {
	fsys := fake.NewFS()
	goos := "windows"
	protector := fake.NewSecretProtector()
	origProtector := newProtector
	newProtector = func() platform.SecretProtector { return protector }
	t.Cleanup(func() { newProtector = origProtector })

	vault := userauth.NewVault(fsys, protector, userauth.VaultPath(goos))
	if err := vault.Save(userauth.Record{AccessToken: "a", ExpiresAt: time.Unix(1700003600, 0)}); err != nil {
		t.Fatalf("seed vault: %v", err)
	}

	// Given RemoveErr returns a permission error for the vault path
	fsys.RemoveErr = func(path string) error {
		if path == userauth.VaultPath(goos) {
			return fs.ErrPermission
		}
		return nil
	}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	// When "mdmagent logout" runs
	exitCode := run(fsys, goos, []string{"logout"}, stdout, stderr)

	// Then the exit code is 1
	if exitCode != 1 {
		t.Errorf("expected exit 1, got %d", exitCode)
	}
}

// TestScenario_UsageListsLoginAndLogout is the A7 wiring check: the
// top-of-file usage comment in main.go lists login and logout.
func TestScenario_UsageListsLoginAndLogout(t *testing.T) {
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "mdmagent login") {
		t.Errorf("usage comment does not mention 'mdmagent login'")
	}
	if !strings.Contains(content, "mdmagent logout") {
		t.Errorf("usage comment does not mention 'mdmagent logout'")
	}
}
