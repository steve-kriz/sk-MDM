package userauth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// RefreshMargin is how long before expiry an access token is refreshed.
const RefreshMargin = 300 * time.Second

// RefreshBackoff is how long a failed refresh is not retried for.
const RefreshBackoff = 60 * time.Second

// Log messages the session writes. None of them carries a token.
const (
	msgSignInExpired  = "user sign-in expired, run mdmagent login"
	msgUnreadable     = "user token unreadable"
	msgRefreshFailed  = "user token refresh failed, retrying later"
	msgRefreshNotSave = "refreshed user token could not be stored"
)

// Session is the service's view of the signed-in user: it hands out a valid
// access token, refreshing it with the stored refresh token when it is close
// to expiry.
//
// The vault is read on every call, so a `mdmagent login` the CLI made while
// the service runs is picked up by the next request. Only one call runs at a
// time, so a refresh that several requests need at once is made once and the
// rest read its result back from the vault.
type Session struct {
	vault  *Vault
	entra  *Entra
	clock  platform.Clock
	logger *logging.Logger

	mu         sync.Mutex
	stale      bool
	retryAfter time.Time
}

// NewSession returns a session over vault, refreshing through doer and timing
// everything on clock. logger may be nil.
func NewSession(vault *Vault, doer platform.HTTPDoer, clock platform.Clock, logger *logging.Logger) *Session {
	return &Session{
		vault:  vault,
		entra:  &Entra{Doer: doer, Clock: clock},
		clock:  clock,
		logger: logger,
	}
}

// MarkStale makes the next BearerToken call refresh even when the stored
// access token is not near expiry. It is how a token the backend refused is
// replaced.
func (s *Session) MarkStale() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stale = true
}

// BearerToken returns the signed-in user's access token, or ("", false) when
// nobody is signed in or no valid token can be had right now.
func (s *Session) BearerToken(ctx context.Context) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.vault.Load()
	if errors.Is(err, ErrNoToken) {
		return "", false
	}
	if err != nil {
		s.log(logging.LevelWarn, msgUnreadable)
		return "", false
	}

	now := s.clock.Now()
	if !s.stale && now.Before(rec.ExpiresAt.Add(-RefreshMargin)) {
		return rec.AccessToken, true
	}
	if now.Before(s.retryAfter) {
		return "", false
	}

	tok, err := s.entra.Refresh(ctx, rec.TenantID, rec.ClientID, rec.RefreshToken, rec.Scopes)
	if errors.Is(err, ErrRefreshRejected) {
		s.stale = false
		s.retryAfter = time.Time{}
		if delErr := s.vault.Delete(); delErr != nil {
			s.log(logging.LevelWarn, msgSignInExpired, logging.F("error", delErr.Error()))
			return "", false
		}
		s.log(logging.LevelWarn, msgSignInExpired)
		return "", false
	}
	if err != nil {
		s.retryAfter = now.Add(RefreshBackoff)
		s.log(logging.LevelWarn, msgRefreshFailed)
		return "", false
	}

	rec.AccessToken = tok.AccessToken
	rec.ExpiresAt = now.Add(time.Duration(tok.ExpiresIn) * time.Second)
	if tok.RefreshToken != "" {
		rec.RefreshToken = tok.RefreshToken
	}
	if err := s.vault.Save(rec); err != nil {
		s.log(logging.LevelWarn, msgRefreshNotSave, logging.F("error", err.Error()))
	}
	s.stale = false
	s.retryAfter = time.Time{}
	return rec.AccessToken, true
}

func (s *Session) log(level logging.Level, msg string, fields ...logging.Field) {
	if s.logger == nil {
		return
	}
	_ = s.logger.Log(level, msg, fields...)
}
