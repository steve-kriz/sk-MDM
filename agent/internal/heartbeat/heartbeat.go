// Package heartbeat sends the per-device performance heartbeat: an opt-in,
// point-in-time performance sample posted to
// POST /api/v1/devices/{deviceId}/heartbeat at the frequency an admin picked.
//
// It runs its own loop beside the check-in loop. The frequency arrives from
// two places: each decoded check-in response (scheduler.Deps.OnHeartbeatInterval
// calls SetInterval; the key is present only while the heartbeat is on) and
// each heartbeat response (0 when the admin has turned it off). While the
// interval is 0 nothing is collected or sent.
//
// Heartbeats are point-in-time. A failed heartbeat costs one warn line and
// nothing else: it is never spooled or retried, never clears the credential,
// and never changes the interval.
package heartbeat

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

// IdlePoll is how long Run waits between looks at the interval while the
// heartbeat is off.
const IdlePoll = 60 * time.Second

// MinIntervalSeconds is the shortest interval the agent honours; a shorter
// positive one is raised to it.
const MinIntervalSeconds = 60

// maxResponseBytes bounds what is read from a heartbeat response.
const maxResponseBytes = 64 << 10

// Transport is the part of the agent's client the heartbeat uses. Do signs
// and sends one request; it is stateless per call, so the scheduler's client
// is shared safely.
type Transport interface {
	Do(method, path string, body []byte) (*http.Response, error)
}

// Store is where the device id comes from. The heartbeat only reads it.
type Store interface {
	Load() (state.State, error)
}

// Deps is everything the heartbeat loop needs. A Deps must not be copied once
// SetInterval or Interval has been called.
type Deps struct {
	// Client is the transport every heartbeat goes through.
	Client Transport

	// Store holds the device id the request path is built from.
	Store Store

	// Clock stamps each sample and times the wait between heartbeats.
	Clock platform.Clock

	// Logger, when non-nil, records each failed heartbeat and each change to
	// the stored interval.
	Logger *logging.Logger

	// Collect takes one performance sample and returns it with the warnings
	// it produced.
	Collect func() (contract.AnalyticsPerformance, []string)

	// CollectNetwork, when non-nil, samples the active physical network
	// adapters' load and packet counts and returns them with the warnings it
	// produced; nil sends no network block.
	CollectNetwork func() ([]contract.HeartbeatNetworkAdapter, []string)

	interval atomic.Int64
}

// SetInterval stores the heartbeat interval in seconds: 0 (off) for s <= 0,
// MinIntervalSeconds for 1..59, and s otherwise. It is safe to call
// concurrently with Interval.
func (d *Deps) SetInterval(s int) {
	switch {
	case s <= 0:
		s = 0
	case s < MinIntervalSeconds:
		s = MinIntervalSeconds
	}
	if prev := d.interval.Swap(int64(s)); prev != int64(s) {
		d.info("heartbeat interval changed", logging.F("from", int(prev)), logging.F("to", s))
	}
}

// Interval returns the stored heartbeat interval in seconds; 0 means off.
func (d *Deps) Interval() int {
	return int(d.interval.Load())
}

// HeartbeatPath is the request path a device's heartbeat is posted to.
func HeartbeatPath(deviceID string) string {
	return "/api/v1/devices/" + url.PathEscape(deviceID) + "/heartbeat"
}

// RunOnce sends one heartbeat when the interval is above 0 and the agent is
// enrolled, and adopts the interval the backend answers with. Every failure is
// one warn line "heartbeat failed"; RunOnce always returns nil.
func RunOnce(ctx context.Context, deps *Deps) error {
	if deps == nil || deps.Interval() <= 0 {
		return nil
	}
	if deps.Store == nil || deps.Client == nil || deps.Collect == nil || deps.Clock == nil {
		return nil
	}

	st, err := deps.Store.Load()
	if err != nil || !st.Enrolled() {
		// An unenrolled agent sends nothing; the check-in loop enrolls it.
		return nil
	}

	performance, warnings := deps.Collect()
	var network []contract.HeartbeatNetworkAdapter
	if deps.CollectNetwork != nil {
		var networkWarnings []string
		network, networkWarnings = deps.CollectNetwork()
		warnings = append(warnings, networkWarnings...)
	}
	body, err := json.Marshal(contract.HeartbeatRequest{
		CollectedAt: deps.Clock.Now().UTC().Format(time.RFC3339),
		Performance: performance,
		Network:     network,
		Warnings:    warnings,
	})
	if err != nil {
		deps.warn(logging.F("error", err.Error()))
		return nil
	}

	resp, err := deps.Client.Do(http.MethodPost, HeartbeatPath(st.DeviceID), body)
	if err != nil {
		deps.warn(logging.F("error", err.Error()))
		return nil
	}
	defer func() {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fields := []logging.Field{logging.F("status", resp.StatusCode)}
		if code := errorCode(resp); code != "" {
			fields = append(fields, logging.F("error", code))
		}
		deps.warn(fields...)
		return nil
	}

	var data []byte
	if resp.Body != nil {
		data, err = io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		if err != nil {
			deps.warn(logging.F("error", err.Error()))
			return nil
		}
	}
	var out contract.HeartbeatResponse
	if err := json.Unmarshal(data, &out); err != nil {
		deps.warn(logging.F("error", err.Error()))
		return nil
	}
	deps.SetInterval(out.HeartbeatIntervalSeconds)
	return nil
}

// Run calls RunOnce, then waits Interval() seconds -- or IdlePoll while the
// heartbeat is off -- on deps.Clock.After, until ctx is cancelled. It returns
// ctx.Err().
func Run(ctx context.Context, deps *Deps) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		_ = RunOnce(ctx, deps)

		wait := IdlePoll
		if seconds := deps.Interval(); seconds > 0 {
			wait = time.Duration(seconds) * time.Second
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deps.Clock.After(wait):
		}
	}
}

// errorCode is the backend's `error` string from a rejected heartbeat's body
// (read up to maxResponseBytes), e.g. heartbeat_not_configured; "" when the
// body is not a JSON object with a non-empty string `error`.
func errorCode(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&payload); err != nil {
		return ""
	}
	return payload.Error
}

// info writes an informational heartbeat line, such as an interval change.
func (d *Deps) info(msg string, fields ...logging.Field) {
	if d.Logger == nil {
		return
	}
	_ = d.Logger.Log(logging.LevelInfo, msg, fields...)
}

// warn writes the one warn line a failed heartbeat costs.
func (d *Deps) warn(fields ...logging.Field) {
	if d.Logger == nil {
		return
	}
	_ = d.Logger.Log(logging.LevelWarn, "heartbeat failed", fields...)
}
