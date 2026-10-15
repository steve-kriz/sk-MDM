package userauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
)

// AuthorizationCodeGrantType is the grant an authorization code is redeemed
// with.
const AuthorizationCodeGrantType = "authorization_code"

// PKCEMethod is the only code challenge method the agent uses.
const PKCEMethod = "S256"

// AgentScopes is the scope list every agent sign-in asks for, derived from the
// agent's client id. It is the same list GET /api/v1/agent-auth/config
// publishes.
func AgentScopes(clientID string) []string {
	return []string{"api://" + clientID + "/MDM.Agent", "offline_access", "openid", "profile"}
}

// PKCEChallenge is the RFC 7636 S256 code challenge for verifier:
// base64url(sha256(verifier)), unpadded.
func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// RedeemCode exchanges an authorization code for tokens, proving possession
// of the PKCE verifier. redirectURI must be the one the authorize request
// named: for the brokered sign-in, the MDM site's /agent/callback, as the
// site reports it with the code. The authorize request itself is made by the
// MDM site, so the agent never builds one.
//
// An `access_denied` or `authorization_declined` answer is ErrSignInDeclined;
// every other failure (a non-2xx, an unreadable body, a body without an
// access token, a transport error) is ErrSignInFailed. A cancelled context is
// returned as the context's error. The code and the verifier never appear in
// an error.
func (e *Entra) RedeemCode(ctx context.Context, tenantID, clientID, code, verifier, redirectURI string, scopes []string) (Token, error) {
	form := url.Values{}
	form.Set("grant_type", AuthorizationCodeGrantType)
	form.Set("client_id", clientID)
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", redirectURI)
	form.Set("scope", strings.Join(scopes, " "))

	status, body, err := e.postForm(ctx, tokenEndpoint(tenantID), form)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Token{}, ctxErr
		}
		return Token{}, ErrSignInFailed
	}

	var reply tokenReply
	if err := json.Unmarshal(body, &reply); err != nil {
		return Token{}, ErrSignInFailed
	}
	switch reply.Error {
	case "":
	case "access_denied", "authorization_declined":
		return Token{}, ErrSignInDeclined
	default:
		return Token{}, ErrSignInFailed
	}
	if !isSuccess(status) || reply.AccessToken == "" {
		return Token{}, ErrSignInFailed
	}
	return reply.token(), nil
}
