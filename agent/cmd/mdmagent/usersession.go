package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"github.com/officehq/sk-mdm/agent/internal/client"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/userauth"
)

// userSessionPath is the endpoint the signed-in user is reported on.
func userSessionPath(deviceID string) string {
	return "/api/v1/devices/" + url.PathEscape(deviceID) + "/user-session"
}

// reportUserSession tells the backend which Entra user is signed in on this
// device, once per successful check-in cycle.
//
// Nothing is sent when nobody is signed in. Whatever the backend answers, the
// device credential is left alone and the caller carries on with its cycle: a
// user-session problem costs one warning line and nothing else. A token the
// backend refused is marked stale so the next request refreshes it. The token
// itself is never logged.
func reportUserSession(ctx context.Context, transport *client.Client, session *userauth.Session, deviceID string, logger *logging.Logger) {
	if _, ok := session.BearerToken(ctx); !ok {
		return
	}

	path := userSessionPath(deviceID)
	resp, err := transport.Do(http.MethodPost, path, nil)
	if err != nil {
		// A 401 comes back as client.ErrUnauthorized. Unlike the check-in,
		// it does not clear the credential here: the check-in that just
		// succeeded is what vouches for the device.
		logWarn(logger, "user session request failed",
			logging.F("path", path),
			logging.F("error", err.Error()),
		)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusOK {
		var out struct {
			User struct {
				UPN *string `json:"upn"`
			} `json:"user"`
		}
		_ = json.Unmarshal(body, &out)
		upn := ""
		if out.User.UPN != nil {
			upn = *out.User.UPN
		}
		if logger != nil {
			_ = logger.Info("user session verified", logging.F("upn", upn))
		}
		return
	}

	var failure struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &failure)
	if resp.StatusCode == http.StatusForbidden && failure.Error == "user_token_invalid" {
		session.MarkStale()
	}
	logWarn(logger, "user session not verified",
		logging.F("path", path),
		logging.F("status", resp.StatusCode),
		logging.F("error", failure.Error),
	)
}

func logWarn(logger *logging.Logger, msg string, fields ...logging.Field) {
	if logger != nil {
		_ = logger.Warn(msg, fields...)
	}
}
