package userauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// TestAgentScopes checks the scope list is derived from the client id and
// matches what the backend publishes.
func TestAgentScopes(t *testing.T) {
	got := AgentScopes("c-1")
	want := []string{"api://c-1/MDM.Agent", "offline_access", "openid", "profile"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("AgentScopes = %v, want %v", got, want)
	}
}

// TestPKCEChallenge checks the S256 transform against RFC 7636 appendix B.
func TestPKCEChallenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	if got := PKCEChallenge(verifier); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Errorf("PKCEChallenge = %q", got)
	}
	sum := sha256.Sum256([]byte("x"))
	if PKCEChallenge("x") != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Error("PKCEChallenge is not base64url(sha256(verifier))")
	}
}

// TestRedeemCode_Success checks the token request is an authorization_code
// grant with the verifier, the same redirect URI and no secret.
func TestRedeemCode_Success(t *testing.T) {
	doer := fake.NewHTTPDoer()
	var form url.Values
	var endpoint string
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		endpoint = req.URL.String()
		form = tokenRequestForm(t, req)
		return fake.Response(http.StatusOK,
			`{"access_token":"AT","refresh_token":"RT","id_token":"ID","expires_in":3600}`), nil
	}
	e := &Entra{Doer: doer, Clock: fake.NewClock(time.Unix(0, 0))}

	tok, err := e.RedeemCode(context.Background(), "t-1", "c-1", "CODE", "VERIFIER",
		"https://mdm.example.com/agent/callback", AgentScopes("c-1"))
	if err != nil {
		t.Fatalf("RedeemCode: %v", err)
	}
	if tok.AccessToken != "AT" || tok.RefreshToken != "RT" || tok.IDToken != "ID" || tok.ExpiresIn != 3600 {
		t.Errorf("token = %+v", tok)
	}
	if endpoint != "https://login.microsoftonline.com/t-1/oauth2/v2.0/token" {
		t.Errorf("endpoint = %s", endpoint)
	}
	want := map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     "c-1",
		"code":          "CODE",
		"code_verifier": "VERIFIER",
		"redirect_uri":  "https://mdm.example.com/agent/callback",
		"scope":         "api://c-1/MDM.Agent offline_access openid profile",
	}
	for k, v := range want {
		if got := form.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if form.Has("client_secret") {
		t.Error("token request must carry no client secret")
	}
}

// TestRedeemCode_Failures maps every failure onto the sentinel errors, none
// of which carries the code, the verifier or a response body.
func TestRedeemCode_Failures(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		err    error
		want   error
	}{
		{"declined", http.StatusBadRequest, `{"error":"access_denied"}`, nil, ErrSignInDeclined},
		{"invalid grant", http.StatusBadRequest, `{"error":"invalid_grant"}`, nil, ErrSignInFailed},
		{"server error", http.StatusInternalServerError, `{}`, nil, ErrSignInFailed},
		{"no access token", http.StatusOK, `{"refresh_token":"RT"}`, nil, ErrSignInFailed},
		{"unreadable", http.StatusOK, `not json`, nil, ErrSignInFailed},
		{"transport", 0, ``, errors.New("dial failed"), ErrSignInFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doer := fake.NewHTTPDoer()
			doer.DoFunc = func(req *http.Request) (*http.Response, error) {
				if tc.err != nil {
					return nil, tc.err
				}
				return fake.Response(tc.status, tc.body), nil
			}
			e := &Entra{Doer: doer, Clock: fake.NewClock(time.Unix(0, 0))}
			_, err := e.RedeemCode(context.Background(), "t-1", "c-1", "CODE-SENTINEL", "VERIFIER-SENTINEL",
				"https://mdm.example.com/agent/callback", AgentScopes("c-1"))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), "SENTINEL") {
				t.Errorf("error leaks a secret: %v", err)
			}
		})
	}
}
