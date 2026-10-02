package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/version"
)

// EnrollPath is the enrollment endpoint on the collection URL.
const EnrollPath = "/api/v1/enroll"

// MaxEnrollAttempts is how many times Enroll sends the request before giving
// up: the first try plus one per backoff delay.
const MaxEnrollAttempts = 6

// maxEnrollBodyBytes caps what Enroll reads from a response. A hostile or
// broken endpoint must not be able to grow the agent's memory.
const maxEnrollBodyBytes = 1 << 20 // 1 MB

// enrollBackoff is the delay before each retry, measured on the injected
// clock: 1, 2, 4, 8 then 16 seconds. Five delays for six attempts.
var enrollBackoff = []time.Duration{
	1 * time.Second,
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
	16 * time.Second,
}

// HostFacts is how the device describes itself at enrollment.
//
// These are the facts that need the operating system, and no package outside
// agent/internal/platform reaches the operating system, so the caller that
// collects them hands them in. Platform and AgentVersion fall back to the
// build's own values when left empty; the rest are sent as given.
type HostFacts struct {
	// Hostname is the machine name.
	Hostname string
	// Platform is "windows" or "darwin"; empty means this build's GOOS,
	// mapped by PlatformName.
	Platform string
	// OSVersion is the OS version string, e.g. "10.0.22631".
	OSVersion string
	// HardwareUUID is the stable hardware identifier that lets the backend
	// recognise this machine across re-installs.
	HardwareUUID string
	// AgentVersion is the agent build; empty means version.Version.
	AgentVersion string
}

// PlatformName maps a GOOS value to the platform value on the wire contract:
// "windows" for Windows and "darwin" for anything else, the agent shipping
// for those two platforms only. Both values are GOOS values, so this is the
// identity for every platform the agent supports.
func PlatformName(goos string) string {
	if goos == "windows" {
		return "windows"
	}
	return "darwin"
}

// Enroll performs first-run enrollment: it POSTs the device description to
// /api/v1/enroll with the enrollment token as its only X-MDM header, and
// persists the device id and device secret the backend returns.
//
// Enrollment is the one unsigned call the agent makes — there is no device
// secret to sign with until it succeeds — so it carries no signature, no
// timestamp, no nonce and no device id.
//
// An agent that already holds a device id is refused locally with
// ErrAlreadyEnrolled: a second enrollment would strand the first identity on
// the backend. A transport failure or a 5xx is retried with the backoff in
// enrollBackoff; a 4xx is final, and leaves the state file untouched, because
// a token the backend rejected will not be accepted a second later.
func (c *Client) Enroll(ctx context.Context) error {
	st, err := c.store.Load()
	if err != nil {
		return err
	}
	if st.DeviceID != "" {
		return ErrAlreadyEnrolled
	}

	endpoint, err := c.endpoint(EnrollPath)
	if err != nil {
		return err
	}

	body, err := json.Marshal(c.enrollRequest())
	if err != nil {
		return err
	}

	var lastErr error
	for attempt := 1; attempt <= MaxEnrollAttempts; attempt++ {
		if attempt > 1 {
			delay := enrollBackoff[attempt-2]
			c.log(logging.LevelDebug, "retrying enrollment",
				logging.F("attempt", attempt),
				logging.F("delaySeconds", int(delay/time.Second)),
			)
			select {
			case <-c.clock.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		res, retryable, err := c.enrollAttempt(ctx, endpoint, body)
		if err == nil {
			st.DeviceID = res.DeviceID
			st.DeviceSecret = res.DeviceSecret
			if err := c.store.Save(st); err != nil {
				return err
			}
			c.checkInIntervalSeconds = res.CheckInIntervalSeconds

			c.log(logging.LevelInfo, "enrolled",
				logging.F("deviceId", res.DeviceID),
				logging.F("checkInIntervalSeconds", res.CheckInIntervalSeconds),
			)
			return nil
		}

		if !retryable {
			c.log(logging.LevelError, "enrollment refused",
				logging.F("attempt", attempt),
				logging.F("error", err.Error()),
			)
			return err
		}

		lastErr = err
		c.log(logging.LevelWarn, "enrollment attempt failed",
			logging.F("attempt", attempt),
			logging.F("error", err.Error()),
		)
	}

	return fmt.Errorf("enrollment failed after %d attempts: %w", MaxEnrollAttempts, lastErr)
}

// enrollRequest fills the wire type from Host, defaulting the two fields the
// build knows about itself.
func (c *Client) enrollRequest() contract.EnrollRequest {
	host := c.Host
	if host.Platform == "" {
		host.Platform = PlatformName(runtime.GOOS)
	}
	if host.AgentVersion == "" {
		host.AgentVersion = version.Version
	}

	return contract.EnrollRequest{
		Hostname:     host.Hostname,
		Platform:     host.Platform,
		OSVersion:    host.OSVersion,
		HardwareUUID: host.HardwareUUID,
		AgentVersion: host.AgentVersion,
	}
}

// enrollAttempt sends one enrollment request. It reports whether a failure is
// worth retrying: transport errors and 5xx are, a refused token is not.
func (c *Client) enrollAttempt(ctx context.Context, endpoint *url.URL, body []byte) (contract.EnrollResponse, bool, error) {
	req, err := c.newRequest(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return contract.EnrollResponse{}, false, err
	}
	// The enrollment token is the only X-MDM header on this call.
	req.Header.Set(HeaderEnrollmentToken, c.cfg.EnrollmentToken)

	resp, err := c.doer.Do(req)
	if err != nil {
		return contract.EnrollResponse{}, true, fmt.Errorf("enrollment request failed: %w", err)
	}
	defer closeBody(resp)

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxEnrollBodyBytes))
	if err != nil {
		return contract.EnrollResponse{}, true, fmt.Errorf("enrollment response: %w", err)
	}

	switch {
	case resp.StatusCode == http.StatusOK:
		var res contract.EnrollResponse
		if err := json.Unmarshal(data, &res); err != nil {
			return contract.EnrollResponse{}, false, fmt.Errorf("enrollment response: %w", err)
		}
		if res.DeviceID == "" || res.DeviceSecret == "" {
			return contract.EnrollResponse{}, false, errors.New("enrollment response: missing deviceId or deviceSecret")
		}
		return res, false, nil

	case resp.StatusCode >= 500:
		return contract.EnrollResponse{}, true, fmt.Errorf("enrollment failed with status %d%s", resp.StatusCode, errorSuffix(data))

	default:
		return contract.EnrollResponse{}, false, fmt.Errorf("enrollment refused with status %d%s", resp.StatusCode, errorSuffix(data))
	}
}

// errorSuffix renders the contract's {"error": "..."} body as " (code)", or
// nothing at all when the body carries no error key. The code is what support
// greps for, so it belongs in the message the agent reports.
func errorSuffix(data []byte) string {
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(data, &payload); err != nil || payload.Error == "" {
		return ""
	}
	return " (" + payload.Error + ")"
}
