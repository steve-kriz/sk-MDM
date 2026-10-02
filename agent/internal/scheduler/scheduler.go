// Package scheduler runs the agent's periodic cycle: collect the inventory and
// the posture, fetch the device's policy bundle, evaluate it, post the check-in
// and wait however long the backend asked for before doing it again.
//
// Three rules shape the cycle:
//
//   - Nothing is lost to an outage. A check-in that cannot be posted is
//     written to the spool directory, and the next cycle that reaches the
//     backend drains the spool oldest first, before its own payload.
//   - A failure the backend caused is not a failure of the cycle. An
//     unreachable policy endpoint costs the check-in its compliance report and
//     one warning line, not the check-in itself.
//   - Cycles never overlap. Run waits for a cycle to finish before timing the
//     next one, and RunOnce refuses to start a second cycle while one is in
//     flight, so a slow collection cannot stack up behind itself.
//
// Everything that touches the operating system — the clock, the filesystem and
// the probe commands — arrives through agent/internal/platform, so the whole
// package runs in a test with no disk, no network and no wall clock.
package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"runtime"
	"sync"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/client"
	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/inventory"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/policy"
	"github.com/officehq/sk-mdm/agent/internal/posture"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

// Spool directory locations, beside the config and state files the installer
// creates.
const (
	// WindowsSpoolDir is the spool location on Windows.
	WindowsSpoolDir = `C:\ProgramData\OfficeHQ\MDM\spool`
	// DarwinSpoolDir is the spool location on macOS.
	DarwinSpoolDir = "/Library/Application Support/OfficeHQ/MDM/spool"
)

// DefaultIntervalSeconds is the wait used until a check-in has returned one.
const DefaultIntervalSeconds = config.DefaultCheckInIntervalSeconds

// JitterPercent is how much is added to the check-in interval, at most: an
// interval of 600 seconds is waited out somewhere in [600, 660]. A fleet that
// enrolled together must not check in together for ever.
const JitterPercent = 10

// maxResponseBytes caps what a response may feed the JSON decoder, so a
// misbehaving endpoint cannot exhaust the agent's memory.
const maxResponseBytes = 1 << 20 // 1 MB

// Transport is the part of the TASK-015 client the cycle uses: a signed
// request and the enrollment that makes signing possible. *client.Client
// satisfies it.
type Transport interface {
	Do(method, path string, body []byte) (*http.Response, error)
	Enroll(ctx context.Context) error
}

// Store is the part of the TASK-014 state store the cycle uses.
// *state.Store satisfies it.
type Store interface {
	Load() (state.State, error)
	Save(st state.State) error
}

// SpoolDir returns the spool location for a GOOS value: the Windows path for
// "windows" and the macOS path for anything else, the agent shipping for those
// two platforms only.
func SpoolDir(goos string) string {
	if goos == "windows" {
		return WindowsSpoolDir
	}
	return DarwinSpoolDir
}

// Deps is everything one cycle needs, and the little state that survives
// between cycles.
//
// It is passed by pointer because RunOnce writes to it: IntervalSeconds holds
// what the last check-in asked for and is what Run times the next cycle from.
//
// The four function fields are seams. Left nil they call the production
// collectors and agent/internal/policy; set, they are called instead, which is
// how a test runs a cycle without probing the host.
type Deps struct {
	// Client is the transport every request goes through.
	Client Transport

	// Store holds the device id the request paths are built from, and is
	// what a rejected credential is cleared through.
	Store Store

	// FS is where the spool lives.
	FS platform.FileSystem

	// Clock stamps the check-in, ages the OS update check, names spool files
	// and times the wait between cycles.
	Clock platform.Clock

	// Runner runs the inventory and posture probes. It may be nil when both
	// collectors are supplied.
	Runner platform.CommandRunner

	// Logger, when non-nil, records each cycle. Nothing written here carries
	// the device secret or the enrollment token.
	Logger *logging.Logger

	// GOOS selects the probe set and the default spool location; empty means
	// this build's GOOS.
	GOOS string

	// SpoolDir is where unposted payloads are kept; empty means
	// SpoolDir(GOOS).
	SpoolDir string

	// IntervalSeconds is what the last check-in asked for. RunOnce updates
	// it from the response; Run waits it out with jitter. Zero means
	// DefaultIntervalSeconds.
	IntervalSeconds int

	// CollectInventory overrides inventory.Collect.
	CollectInventory func() (contract.Inventory, error)

	// CollectPosture overrides posture.Collect.
	CollectPosture func() (contract.Posture, error)

	// Evaluate overrides policy.Evaluate. It is called once per cycle, and
	// not at all when the policy bundle could not be fetched.
	Evaluate func(bundle contract.PolicyBundleResponse, posture contract.Posture, now time.Time) []policy.Result

	// AfterCheckIn, when non-nil, is called with the decoded check-in
	// response at the end of a successful cycle. It is the seam the command
	// executor plugs into: PendingCommandCount is what tells it whether a
	// command poll would find work. An error it returns is the cycle's
	// error.
	AfterCheckIn func(ctx context.Context, resp contract.CheckInResponse) error

	// mu guards running, so the overlap check is one decision however many
	// goroutines ask at once.
	mu sync.Mutex
	// running reports whether a cycle is in flight.
	running bool
}

// CheckInPath is the check-in endpoint for a device.
func CheckInPath(deviceID string) string {
	return "/api/v1/devices/" + url.PathEscape(deviceID) + "/checkin"
}

// PoliciesPath is the policy bundle endpoint for a device.
func PoliciesPath(deviceID string) string {
	return "/api/v1/devices/" + url.PathEscape(deviceID) + "/policies"
}

// Run executes cycles until ctx is cancelled, waiting the interval the backend
// last asked for, plus jitter, between them.
//
// A cycle that fails is logged and the loop carries on: an agent that stops
// checking in because one check-in failed is an agent nobody hears from again.
// The wait is only timed once the cycle has returned, so two cycles never
// overlap however long one takes.
func Run(ctx context.Context, deps *Deps) error {
	if deps == nil {
		return errors.New("scheduler: nil deps")
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err := RunOnce(ctx, deps); err != nil {
			deps.log(logging.LevelError, "check-in cycle failed", logging.F("error", err.Error()))
		}

		wait := deps.nextWait()
		deps.log(logging.LevelDebug, "waiting for next check-in",
			logging.F("seconds", int(wait/time.Second)),
		)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deps.Clock.After(wait):
		}
	}
}

// RunOnce executes one cycle: collect, fetch the policy bundle, evaluate it,
// drain the spool and post the check-in.
//
// The error return is for what stopped the cycle from being attempted at all —
// an agent that cannot enroll, a collector that cannot run, a spool that cannot
// be written. A backend that was unreachable or that answered with an error is
// handled rather than reported: the payload is spooled, the credential is
// cleared or the compliance report is dropped, and nil comes back so Run keeps
// its rhythm.
//
// A call made while another cycle is in flight starts nothing and returns nil.
func RunOnce(ctx context.Context, deps *Deps) error {
	if deps == nil {
		return errors.New("scheduler: nil deps")
	}
	if !deps.acquire() {
		deps.log(logging.LevelDebug, "cycle already running")
		return nil
	}
	defer deps.release()

	return runCycle(ctx, deps)
}

// runCycle is one cycle, with the overlap guard already held.
func runCycle(ctx context.Context, deps *Deps) error {
	deviceID, err := deps.ensureEnrolled(ctx)
	if err != nil {
		return err
	}

	inv, err := deps.collectInventory()
	if err != nil {
		return fmt.Errorf("inventory: %w", err)
	}
	pst, err := deps.collectPosture()
	if err != nil {
		return fmt.Errorf("posture: %w", err)
	}

	// The bundle is fetched after collection and before the check-in, because
	// a policy is evaluated against the posture this cycle just collected.
	req := contract.CheckInRequest{
		CollectedAt: deps.Clock.Now().UTC().Format(time.RFC3339),
		Inventory:   inv,
		Posture:     pst,
	}
	if bundle, ok := deps.fetchBundle(deviceID); ok {
		req.PolicyCompliance = policy.Entries(deps.evaluate(bundle, pst, deps.Clock.Now()))
	}

	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	path := CheckInPath(deviceID)

	// Whatever the last outage left behind goes first, so the backend sees
	// the device's history in the order it happened.
	if err := deps.drainSpool(path); err != nil {
		if errors.Is(err, client.ErrUnauthorized) {
			return deps.clearCredential()
		}
		// The endpoint is answering badly or not at all; this cycle's
		// payload joins the queue rather than chasing it.
		return deps.spoolPayload(body)
	}

	return deps.postCheckIn(ctx, path, body)
}

// ensureEnrolled returns the device id to build request paths from, enrolling
// first when the state store holds no credential. It runs before any signed
// request, so a cycle that follows a cleared credential re-enrolls instead of
// signing with nothing.
func (d *Deps) ensureEnrolled(ctx context.Context) (string, error) {
	st, err := d.Store.Load()
	if err != nil {
		return "", err
	}
	if st.Enrolled() {
		return st.DeviceID, nil
	}

	d.log(logging.LevelInfo, "not enrolled, enrolling before check-in")
	if err := d.Client.Enroll(ctx); err != nil {
		return "", err
	}

	st, err = d.Store.Load()
	if err != nil {
		return "", err
	}
	if !st.Enrolled() {
		return "", client.ErrNotEnrolled
	}
	return st.DeviceID, nil
}

// fetchBundle gets the device's policy bundle. The second return is false when
// there is nothing to evaluate — the request failed, the status was not 200, or
// the body was not a bundle — and the caller then posts a check-in with no
// compliance report at all rather than an empty or a stale one.
//
// A failure here costs exactly one warning line and never the check-in.
func (d *Deps) fetchBundle(deviceID string) (contract.PolicyBundleResponse, bool) {
	var bundle contract.PolicyBundleResponse

	resp, err := d.Client.Do(http.MethodGet, PoliciesPath(deviceID), nil)
	if err != nil {
		d.log(logging.LevelWarn, "policy fetch failed", logging.F("error", err.Error()))
		return bundle, false
	}
	defer closeBody(resp)

	if resp.StatusCode != http.StatusOK {
		d.log(logging.LevelWarn, "policy fetch failed", logging.F("status", resp.StatusCode))
		return bundle, false
	}

	data, err := readBody(resp)
	if err != nil {
		d.log(logging.LevelWarn, "policy fetch failed", logging.F("error", err.Error()))
		return bundle, false
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		d.log(logging.LevelWarn, "policy fetch failed", logging.F("error", err.Error()))
		return bundle, false
	}
	return bundle, true
}

// drainSpool posts every payload an earlier cycle could not, oldest first.
//
// A payload the backend accepts is deleted. A payload it rejects with a 4xx is
// deleted too, with one warning naming the file: a body the backend has already
// refused will not be accepted on a later try, and retrying it for ever would
// block everything behind it. A transport failure or a 5xx stops the drain and
// comes back as an error, leaving the rest of the queue for the next cycle.
func (d *Deps) drainSpool(path string) error {
	spool := d.spool()

	paths, err := spool.List()
	if err != nil {
		d.log(logging.LevelWarn, "spool unreadable", logging.F("error", err.Error()))
		return nil
	}

	for _, file := range paths {
		payload, err := d.FS.ReadFile(file)
		if err != nil {
			d.log(logging.LevelWarn, "spooled check-in unreadable",
				logging.F("file", file),
				logging.F("error", err.Error()),
			)
			continue
		}

		resp, err := d.Client.Do(http.MethodPost, path, payload)
		if err != nil {
			d.log(logging.LevelWarn, "spooled check-in failed",
				logging.F("file", file),
				logging.F("error", err.Error()),
			)
			return err
		}

		status := resp.StatusCode
		closeBody(resp)

		switch {
		case status >= 200 && status < 300:
			if err := spool.Remove(file); err != nil {
				return err
			}
			d.log(logging.LevelInfo, "spooled check-in accepted", logging.F("file", file))
		case status >= 500:
			d.log(logging.LevelWarn, "spooled check-in failed",
				logging.F("file", file),
				logging.F("status", status),
			)
			return fmt.Errorf("spooled check-in failed with status %d", status)
		default:
			d.log(logging.LevelWarn, "spooled check-in rejected",
				logging.F("file", file),
				logging.F("status", status),
			)
			if err := spool.Remove(file); err != nil {
				return err
			}
		}
	}
	return nil
}

// postCheckIn posts this cycle's payload and acts on the answer.
func (d *Deps) postCheckIn(ctx context.Context, path string, body []byte) error {
	resp, err := d.Client.Do(http.MethodPost, path, body)
	if err != nil {
		if errors.Is(err, client.ErrUnauthorized) {
			return d.clearCredential()
		}
		d.log(logging.LevelWarn, "check-in failed", logging.F("error", err.Error()))
		return d.spoolPayload(body)
	}
	defer closeBody(resp)

	switch {
	case resp.StatusCode >= 500:
		d.log(logging.LevelWarn, "check-in failed", logging.F("status", resp.StatusCode))
		return d.spoolPayload(body)
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		// The backend understood the request and refused it; sending the
		// same bytes again later would be refused again.
		d.log(logging.LevelWarn, "check-in rejected", logging.F("status", resp.StatusCode))
		return nil
	}

	var out contract.CheckInResponse
	data, err := readBody(resp)
	if err != nil {
		d.log(logging.LevelWarn, "check-in response unreadable", logging.F("error", err.Error()))
	} else if err := json.Unmarshal(data, &out); err != nil {
		d.log(logging.LevelWarn, "check-in response unreadable", logging.F("error", err.Error()))
	}

	if out.CheckInIntervalSeconds > 0 {
		d.IntervalSeconds = out.CheckInIntervalSeconds
	}

	d.log(logging.LevelInfo, "checked in",
		logging.F("checkInIntervalSeconds", d.IntervalSeconds),
		logging.F("pendingCommandCount", out.PendingCommandCount),
	)

	if d.AfterCheckIn != nil {
		return d.AfterCheckIn(ctx, out)
	}
	return nil
}

// clearCredential discards a device identity the backend has rejected, so the
// next cycle enrolls again. Both halves are written empty: half an identity
// would be signed with and refused all over again.
func (d *Deps) clearCredential() error {
	d.log(logging.LevelWarn, "device credential rejected, clearing enrollment state")
	return d.Store.Save(state.State{})
}

// spoolPayload queues a payload the backend did not take.
func (d *Deps) spoolPayload(body []byte) error {
	file, err := d.spool().Add(body)
	if err != nil {
		return err
	}
	d.log(logging.LevelInfo, "check-in spooled", logging.F("file", file))
	return nil
}

// spool is the queue this agent spools to.
func (d *Deps) spool() *Spool {
	dir := d.SpoolDir
	if dir == "" {
		dir = SpoolDir(d.goos())
	}
	return NewSpool(d.FS, d.Clock, dir)
}

// nextWait is the interval the backend asked for plus up to JitterPercent of
// it, so a fleet that enrolled together spreads itself out.
func (d *Deps) nextWait() time.Duration {
	seconds := d.IntervalSeconds
	if seconds <= 0 {
		seconds = DefaultIntervalSeconds
	}

	base := time.Duration(seconds) * time.Second
	span := base / 100 * JitterPercent
	if span <= 0 {
		return base
	}
	return base + time.Duration(rand.Int64N(int64(span)+1))
}

// goos is the platform the collectors probe for.
func (d *Deps) goos() string {
	if d.GOOS != "" {
		return d.GOOS
	}
	return runtime.GOOS
}

// collectInventory runs the injected collector, or the real one.
func (d *Deps) collectInventory() (contract.Inventory, error) {
	if d.CollectInventory != nil {
		return d.CollectInventory()
	}
	return inventory.Collect(d.Runner, d.Clock, d.goos())
}

// collectPosture runs the injected collector, or the real one.
func (d *Deps) collectPosture() (contract.Posture, error) {
	if d.CollectPosture != nil {
		return d.CollectPosture()
	}
	return posture.Collect(d.Runner, d.Clock, d.goos())
}

// evaluate runs the injected evaluator, or agent/internal/policy.
func (d *Deps) evaluate(bundle contract.PolicyBundleResponse, pst contract.Posture, now time.Time) []policy.Result {
	if d.Evaluate != nil {
		return d.Evaluate(bundle, pst, now)
	}
	return policy.Evaluate(bundle, pst, now)
}

// acquire takes the overlap guard, reporting false when a cycle is already
// running.
func (d *Deps) acquire() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.running {
		return false
	}
	d.running = true
	return true
}

// release hands the overlap guard back.
func (d *Deps) release() {
	d.mu.Lock()
	d.running = false
	d.mu.Unlock()
}

// log writes one record when a logger was given. A failed write is dropped:
// the agent has nowhere better to report it, and a full disk must not stop a
// check-in.
func (d *Deps) log(level logging.Level, msg string, fields ...logging.Field) {
	if d.Logger == nil {
		return
	}
	_ = d.Logger.Log(level, msg, fields...)
}

// readBody reads at most maxResponseBytes of a response body.
func readBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
}

// closeBody closes a response body the cycle is done with.
func closeBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}
