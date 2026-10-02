package userauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// TestScenario_BearerToken_FreshTokenNoHTTP validates reuse of fresh access token.
func TestScenario_BearerToken_FreshTokenNoHTTP(t *testing.T) {
	// Given a vault with an access token valid for > 300 seconds
	fsys := fake.NewFS()
	protector := fake.NewSecretProtector()
	vault := NewVault(fsys, protector, "/vault.json")
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()

	now := time.Unix(1000000, 0)
	expiresAt := now.Add(301 * time.Second)

	rec := Record{
		AccessToken:  "fresh-token",
		RefreshToken: "r-token",
		ExpiresAt:    expiresAt,
		Username:     "amy@contoso.com",
		TenantID:     "t-1",
		ClientID:     "c-1",
		Scopes:       []string{"api://c-1/MDM.Agent"},
	}

	vault.Save(rec)

	session := NewSession(vault, doer, clock, nil)

	// When BearerToken is called
	token, ok := session.BearerToken(context.Background())

	// Then it returns the stored access token and true
	if !ok {
		t.Error("expected ok=true")
	}
	if token != "fresh-token" {
		t.Errorf("expected fresh-token, got %q", token)
	}

	// And no HTTP request was made
	if len(doer.Requests()) > 0 {
		t.Error("should not make HTTP request for fresh token")
	}
}

// TestScenario_BearerToken_DueRefresh validates refresh when token is near expiry.
func TestScenario_BearerToken_DueRefresh(t *testing.T) {
	// Given a vault with a token expiring in 300 seconds
	fsys := fake.NewFS()
	protector := fake.NewSecretProtector()
	vault := NewVault(fsys, protector, "/vault.json")
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()

	expiresAt := clock.Now().Add(300 * time.Second)
	rec := Record{
		AccessToken:  "old-token",
		RefreshToken: "r-old",
		ExpiresAt:    expiresAt,
		TenantID:     "t-1",
		ClientID:     "c-1",
		Scopes:       []string{"api://c-1/MDM.Agent"},
	}
	vault.Save(rec)

	// And the token endpoint returns a new token
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		resp := map[string]interface{}{
			"access_token":  "new-token",
			"refresh_token": "r-new",
			"expires_in":    3600,
		}
		body, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(body))),
			Header:     make(http.Header),
		}, nil
	}

	session := NewSession(vault, doer, clock, nil)

	// When BearerToken is called
	token, ok := session.BearerToken(context.Background())

	// Then it returns the new access token and true
	if !ok {
		t.Error("expected ok=true")
	}
	if token != "new-token" {
		t.Errorf("expected new-token, got %q", token)
	}

	// And the vault was updated
	loaded, _ := vault.Load()
	if loaded.AccessToken != "new-token" {
		t.Errorf("vault should have new token, got %q", loaded.AccessToken)
	}
	if loaded.RefreshToken != "r-new" {
		t.Errorf("vault should have new refresh token, got %q", loaded.RefreshToken)
	}
}

// TestScenario_BearerToken_InvalidGrant signs out locally.
func TestScenario_BearerToken_InvalidGrant(t *testing.T) {
	// Given a vault with a due token
	fsys := fake.NewFS()
	protector := fake.NewSecretProtector()
	vault := NewVault(fsys, protector, "/vault.json")
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()

	expiresAt := clock.Now().Add(100 * time.Second)
	rec := Record{
		AccessToken:  "old-token",
		RefreshToken: "r-old",
		ExpiresAt:    expiresAt,
		TenantID:     "t-1",
		ClientID:     "c-1",
	}
	vault.Save(rec)

	// And the token endpoint answers 400 invalid_grant
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		resp := map[string]interface{}{
			"error": "invalid_grant",
		}
		body, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 400,
			Body:       io.NopCloser(strings.NewReader(string(body))),
			Header:     make(http.Header),
		}, nil
	}

	session := NewSession(vault, doer, clock, nil)

	// When BearerToken is called
	token, ok := session.BearerToken(context.Background())

	// Then it returns "" and false
	if ok {
		t.Error("expected ok=false")
	}
	if token != "" {
		t.Errorf("expected empty token, got %q", token)
	}

	// And the vault was deleted
	_, err := vault.Load()
	if err != ErrNoToken {
		t.Errorf("vault should be deleted, got error %v", err)
	}
}

// TestScenario_BearerToken_TransientError backs off for 60 seconds.
func TestScenario_BearerToken_TransientError(t *testing.T) {
	// Given a vault with a due token
	fsys := fake.NewFS()
	protector := fake.NewSecretProtector()
	vault := NewVault(fsys, protector, "/vault.json")
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()

	expiresAt := clock.Now().Add(100 * time.Second)
	rec := Record{
		AccessToken:  "old-token",
		RefreshToken: "r-old",
		ExpiresAt:    expiresAt,
		TenantID:     "t-1",
		ClientID:     "c-1",
	}
	vault.Save(rec)

	// And the token endpoint answers 503
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		resp := map[string]interface{}{"error": "service_unavailable"}
		body, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 503,
			Body:       io.NopCloser(strings.NewReader(string(body))),
			Header:     make(http.Header),
		}, nil
	}

	session := NewSession(vault, doer, clock, nil)

	// When BearerToken is called
	token, ok := session.BearerToken(context.Background())

	// Then it returns "" and false
	if ok {
		t.Error("expected ok=false")
	}
	if token != "" {
		t.Errorf("expected empty token, got %q", token)
	}

	// And the vault is unchanged
	loaded, _ := vault.Load()
	if loaded.AccessToken != "old-token" {
		t.Error("vault should be unchanged after transient error")
	}

	// When BearerToken is called again 59 seconds later
	clock.Advance(59 * time.Second)
	_, ok2 := session.BearerToken(context.Background())

	// Then it returns "" and false with no new request
	if ok2 {
		t.Error("expected ok=false at 59s")
	}
	initialReqs := len(doer.Requests())
	if initialReqs != 1 {
		t.Errorf("expected 1 request at 59s, got %d", initialReqs)
	}

	// When BearerToken is called at 60 seconds
	clock.Advance(1 * time.Second)
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		resp := map[string]interface{}{
			"access_token": "new-token",
			"expires_in":   3600,
		}
		body, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(body))),
			Header:     make(http.Header),
		}, nil
	}
	token3, ok3 := session.BearerToken(context.Background())

	// Then it succeeds with a new token
	if !ok3 {
		t.Error("expected ok=true after 60s")
	}
	if token3 != "new-token" {
		t.Errorf("expected new token at 60s, got %q", token3)
	}
}

// TestScenario_BearerToken_NoVault returns false with no request.
func TestScenario_BearerToken_NoVault(t *testing.T) {
	// Given no vault file
	fsys := fake.NewFS()
	protector := fake.NewSecretProtector()
	vault := NewVault(fsys, protector, "/vault.json")
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()

	session := NewSession(vault, doer, clock, nil)

	// When BearerToken is called
	token, ok := session.BearerToken(context.Background())

	// Then it returns "" and false
	if ok {
		t.Error("expected ok=false")
	}
	if token != "" {
		t.Errorf("expected empty token, got %q", token)
	}

	// And no HTTP request was made
	if len(doer.Requests()) > 0 {
		t.Error("should not make HTTP request when no vault exists")
	}
}

// TestScenario_BearerToken_UnreadableVault returns false and leaves file unchanged.
func TestScenario_BearerToken_UnreadableVault(t *testing.T) {
	// Given an unreadable vault
	fsys := fake.NewFS()
	protector := fake.NewSecretProtector()
	vaultPath := "/vault.json"

	// First, seed a vault normally
	protector2 := fake.NewSecretProtector()
	vault2 := NewVault(fsys, protector2, vaultPath)
	rec := Record{
		AccessToken:  "token",
		RefreshToken: "r-token",
		ExpiresAt:    time.Unix(1000000, 0).Add(3600 * time.Second),
		TenantID:     "t-1",
		ClientID:     "c-1",
	}
	vault2.Save(rec)

	// Now set the error for subsequent reads
	protector.UnprotectErr = ErrVaultUnreadable

	vault := NewVault(fsys, protector, vaultPath)
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()

	session := NewSession(vault, doer, clock, nil)

	// When BearerToken is called
	token, ok := session.BearerToken(context.Background())

	// Then it returns "" and false
	if ok {
		t.Error("expected ok=false")
	}
	if token != "" {
		t.Errorf("expected empty token, got %q", token)
	}

	// And the file is unmodified
	content, exists := fsys.Content(vaultPath)
	if !exists {
		t.Error("vault file should still exist")
	}
	if len(content) == 0 {
		t.Error("vault file should be unchanged")
	}
}

// TestScenario_MarkStale forces refresh on next call.
func TestScenario_MarkStale(t *testing.T) {
	// Given a vault with a fresh token
	fsys := fake.NewFS()
	protector := fake.NewSecretProtector()
	vault := NewVault(fsys, protector, "/vault.json")
	clock := fake.NewClock(time.Unix(1000000, 0))
	doer := fake.NewHTTPDoer()

	expiresAt := clock.Now().Add(3600 * time.Second)
	rec := Record{
		AccessToken:  "old-token",
		RefreshToken: "r-old",
		ExpiresAt:    expiresAt,
		TenantID:     "t-1",
		ClientID:     "c-1",
		Scopes:       []string{"api://c-1/MDM.Agent"},
	}
	vault.Save(rec)

	// And the token endpoint returns a new token
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		resp := map[string]interface{}{
			"access_token": "new-token",
			"expires_in":   3600,
		}
		body, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(body))),
			Header:     make(http.Header),
		}, nil
	}

	session := NewSession(vault, doer, clock, nil)

	// When MarkStale is called
	session.MarkStale()

	// And BearerToken is called
	token, ok := session.BearerToken(context.Background())

	// Then it performs a refresh
	if !ok {
		t.Error("expected ok=true")
	}
	if token != "new-token" {
		t.Errorf("expected new-token, got %q", token)
	}

	// And an HTTP request was made
	if len(doer.Requests()) != 1 {
		t.Errorf("expected 1 request, got %d", len(doer.Requests()))
	}
}
