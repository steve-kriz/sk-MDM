// Package scheduler runs the agent's periodic cycle: collect the inventory and
// the posture, fetch the device's policy bundle, evaluate it, post the check-in
// and wait however long the backend asked for before doing it again.
//
// Three rules shape the cycle:
//
//   - Nothing is lost to an outage. A check-in that cannot be posted is
//     written to the spool directory, and the next cycle that reaches the
//     backend drains the spool oldest first, before its own payload. While
//     the spool holds files, Run also re-sends it on a backoff between full
//     cycles, so it goes out soon after the backend is reachable again.
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
	"strings"
	"sync"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/antivirus"
	"github.com/officehq/sk-mdm/agent/internal/client"
	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/inventory"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/policy"
	"github.com/officehq/sk-mdm/agent/internal/posture"
	"github.com/officehq/sk-mdm/agent/internal/service"
	"github.com/officehq/sk-mdm/agent/internal/state"
	"github.com/officehq/sk-mdm/agent/internal/version"
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

// SignInPollInterval is how often an unenrolled agent with no enrollment token
// looks again for an enrollment token, the first look after a rejected token
// has been removed included.
const SignInPollInterval = 60 * time.Second

// msgWaitingForSignIn is logged once, at info, while enrollment waits for a
// user to sign in.
const msgWaitingForSignIn = "waiting for a user to sign in"

// JitterPercent is how much is added to the check-in interval, at most: an
// interval of 600 seconds is waited out somewhere in [600, 660]. A fleet that
// enrolled together must not check in together for ever.
const JitterPercent = 10

// DrainRetryBaseDelay is the wait before the first drain attempt after a cycle
// left files in the spool. Each failed attempt doubles it, plus up to
// JitterPercent, never past the next full cycle's due time.
const DrainRetryBaseDelay = 60 * time.Second

// maxDrainDoublings bounds the doubling so the shift cannot overflow; the
// next full cycle caps the delay long before it is reached.
const maxDrainDoublings = 20

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

	// BeforeEnroll, when non-nil, runs ahead of every enrollment attempt. It
	// is where the caller makes sure the device description Enroll sends is
	// complete: the first inventory collection only happens after enrollment.
	BeforeEnroll func()

	// CollectPosture overrides posture.Collect.
	CollectPosture func() (contract.Posture, error)

	// Evaluate overrides policy.Evaluate. It is called once per cycle, and
	// not at all when the policy bundle could not be fetched.
	Evaluate func(bundle contract.PolicyBundleResponse, posture contract.Posture, now time.Time) []policy.Result

	// ApplyUpdate, when non-nil, is called with the release a check-in
	// advertised, at most once per cycle and only when one was advertised.
	// It is the seam agent/internal/update plugs into: the call replaces
	// this binary and hands the restart to the service manager, so it is the
	// last thing a cycle may get to. An error matching
	// service.ErrRestartRequired means the new build is in place: the cycle
	// skips the command poll and Run returns that error so the process exits
	// and is restarted onto it. Any other error costs one warning line and
	// nothing else -- a failed update is retried by the next cycle, not by
	// this one.
	ApplyUpdate func(ctx context.Context, rel contract.AgentRelease) error

	// Enforce, when non-nil, is called once per cycle with the bundle's
	// effectiveSettings and the posture this cycle collected, after the
	// bundle has been evaluated and before the check-in is posted. It is the
	// seam agent/internal/enforce plugs into. It is not called when the
	// bundle could not be fetched, so a failed fetch changes nothing on the
	// device. The check-in reports the posture from before enforcement; the
	// next cycle reports the result. The one exception is the Defender
	// hardener: its block (CollectDefenderHardening, read right after Enforce)
	// and the violations derived from it ride on this same check-in.
	Enforce func(ctx context.Context, effective map[string]any, posture contract.Posture)

	// CollectAntivirusFindings overrides antivirus.CollectFindings. It runs
	// every cycle that posts a check-in, after enforcement, whether or not
	// the bundle was fetched. It returns the findings and the warnings to add
	// to the posture. When it and Runner are both nil, no findings are
	// collected.
	CollectAntivirusFindings func() ([]contract.AntivirusFinding, []string)

	// CollectAntivirusStatus overrides antivirus.CollectStatus. It runs once
	// every cycle that posts a check-in, right after the antivirus findings,
	// whether or not the bundle was fetched. It returns the status block, or
	// nil for no "antivirusStatus" key, and the warnings to add to the posture
	// after the findings warnings. When it and Runner are both nil, no status
	// is collected.
	CollectAntivirusStatus func() (*contract.AntivirusStatus, []string)

	// CollectAntivirusScan returns the last scheduled antivirus scan result
	// to report, or nil when there is none. It runs once every cycle that
	// posts a check-in, after the antivirus findings. Left nil, or returning
	// nil, the check-in carries no "antivirusScan" key.
	CollectAntivirusScan func() *contract.AntivirusScan

	// CollectDefenderHardening returns the Defender hardener's block from its
	// last Apply, or nil when there is none. When non-nil it is called exactly
	// once every cycle, after Enforce, whether or not the bundle was fetched.
	// Its value becomes the check-in's "defenderHardening" (no key when nil),
	// and when the bundle was fetched its failed items become violations via
	// policy.WithDefenderHardening.
	CollectDefenderHardening func() *contract.DefenderHardening

	// CollectAgentErrors returns the agent's buffered warn and error records,
	// already capped to what one check-in may carry, and empties the buffer.
	// It runs once every cycle that builds a check-in body, as the last step
	// before the body is encoded. Left nil, or returning nil or empty, the
	// check-in carries no "agentErrors" key.
	CollectAgentErrors func() []contract.AgentError

	// CollectAgentActions returns the actions the agent performed since the
	// last check-in body and empties its buffer. It runs once every cycle that
	// builds a check-in body, after Enforce and immediately before
	// CollectAgentErrors. Left nil, or returning nil or empty, the check-in
	// carries no "agentActions" key.
	CollectAgentActions func() []contract.AgentAction

	// CollectTimeZone overrides inventory.ResolveTimeZone. It runs every cycle
	// that posts a check-in and returns the device's IANA time zone in Zone,
	// or a Reason (and Detail) saying why none could be worked out, in which
	// case the check-in carries no timeZone but a "timezone:<reason>"
	// inventory warning. When it and Runner are both nil, the result is
	// Reason no_collector.
	CollectTimeZone func() inventory.TimeZoneResult

	// CollectAnalytics, when non-nil, collects the endpoint analytics block
	// every cycle that posts a check-in, after the antivirus findings. It is
	// given the crash watermark and returns the block and the new watermark
	// candidate. Left nil, the check-in carries no "analytics" key and the
	// watermark is never touched. An error or a panic costs the check-in its
	// analytics block and one warning line, never the check-in itself.
	CollectAnalytics func(since time.Time) (contract.Analytics, time.Time, error)

	// AnalyticsWatermark persists the crash watermark CollectAnalytics is
	// given. It is advanced only once a check-in carrying the crashes up to
	// the candidate has been accepted. Nil means every cycle starts from now
	// and nothing is saved.
	AnalyticsWatermark AnalyticsWatermark

	// AnalyticsDisabled is whether the admin has turned this device's
	// analytics collection off, as the last readable check-in response said
	// ("analyticsEnabled": false). RunOnce updates it after every 2xx whose
	// body decodes; the zero value means enabled, which holds until a
	// response says otherwise. It lives in memory only. While it is true no
	// analytics are collected, the watermark is not loaded, and it is saved
	// as now each cycle so re-enabling does not backfill the off period.
	AnalyticsDisabled bool

	// OnHeartbeatInterval, when non-nil, is called once after every 2xx
	// check-in whose body decodes, with the response's heartbeatIntervalSeconds
	// -- or 0 when the key is absent (the heartbeat is off). It is the seam
	// agent/internal/heartbeat plugs into. It is not called after a body that
	// does not decode, a rejection or a transport error.
	OnHeartbeatInterval func(seconds int)

	// AfterCheckIn, when non-nil, is called with the decoded check-in
	// response at the end of a successful cycle. It is the seam the command
	// executor plugs into: PendingCommandCount is what tells it whether a
	// command poll would find work. An error it returns is the cycle's
	// error.
	AfterCheckIn func(ctx context.Context, resp contract.CheckInResponse) error

	// SignInWake, when non-nil, ends a wait for a signed-in user early: the
	// brokered sign-in sends on it after every completed sign-in, so the
	// enrollment it makes possible happens at once rather than at the next
	// SignInPollInterval tick. It is only listened to while enrollment is
	// waiting for a user.
	SignInWake <-chan struct{}

	// ClearEnrollmentToken, when non-nil, removes the enrollment token from
	// the config. Run calls it when enrollment answers
	// client.ErrEnrollmentTokenRejected, so the brokered sign-in sees that a
	// sign-in is needed again.
	ClearEnrollmentToken func() error

	// awaitingSignIn records that msgWaitingForSignIn has been logged for the
	// current wait, so it is logged once rather than every tick. Only Run's
	// goroutine touches it.
	awaitingSignIn bool

	// timeZoneLogged and lastTimeZone record the time zone result last
	// logged, so the result is logged on the first cycle and again only when
	// it changes. Only the goroutine running the cycle touches them.
	timeZoneLogged bool
	lastTimeZone   inventory.TimeZoneResult

	// mu guards running, so the overlap check is one decision however many
	// goroutines ask at once.
	mu sync.Mutex
	// running reports whether a cycle is in flight.
	running bool
}

// AnalyticsWatermark is where the crash watermark is kept between cycles.
// Load returns the zero time and a nil error when none has been saved yet.
type AnalyticsWatermark interface {
	Load() (time.Time, error)
	Save(time.Time) error
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
//
// While the spool holds files, the wait before the next full cycle is broken
// up by drain attempts: lightweight wakes that only re-send the spool. The
// first comes DrainRetryBaseDelay (plus jitter) after a cycle that left files
// behind; each failed attempt doubles the delay, never past the next full
// cycle's due time, and every full cycle that leaves files behind starts the
// delay over. An attempt that empties the spool runs a full cycle at once.
func Run(ctx context.Context, deps *Deps) error {
	if deps == nil {
		return errors.New("scheduler: nil deps")
	}

	// full is whether the next wake runs a full cycle rather than a drain
	// attempt; fullDue is when the next full cycle is due; failures counts
	// the failed drain attempts since the last full cycle that left files.
	full := true
	var fullDue time.Time
	failures := 0

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		var wake <-chan struct{}
		var wait time.Duration
		drainNext := false

		if full {
			err := RunOnce(ctx, deps)
			if errors.Is(err, service.ErrRestartRequired) {
				// An update is in place: the process exits so the service
				// manager restarts it onto the new build.
				return err
			}

			// Enrollment that needs a signed-in user is looked at again
			// every SignInPollInterval, or as soon as the brokered sign-in
			// says someone signed in, instead of after a whole check-in
			// interval.
			enrolling := false
			wait = deps.nextWait()
			switch {
			case errors.Is(err, client.ErrAwaitingSignIn):
				if !deps.awaitingSignIn {
					deps.awaitingSignIn = true
					deps.log(logging.LevelInfo, msgWaitingForSignIn)
				}
				wait, wake = SignInPollInterval, deps.SignInWake
				enrolling = true
			case errors.Is(err, client.ErrEnrollmentTokenRejected):
				// The token is unknown, expired or used up: it is removed
				// so the sign-in asks for a new one, and the wait for that
				// sign-in starts over, waiting message included.
				deps.clearEnrollmentToken(err)
				deps.awaitingSignIn = false
				wait, wake = SignInPollInterval, deps.SignInWake
				enrolling = true
			case err != nil:
				deps.log(logging.LevelError, "check-in cycle failed", logging.F("error", err.Error()))
			default:
				deps.awaitingSignIn = false
			}

			// The next full cycle is timed from when this one returned.
			fullDue = deps.Clock.Now().Add(wait)

			// A cycle that left files in the spool restarts the drain
			// backoff at DrainRetryBaseDelay.
			if !enrolling && deps.spoolPending() {
				failures = 0
				drainNext = true
			}
		} else {
			switch deps.attemptDrain() {
			case drainEmptied, drainUnauthorized:
				// Connectivity is back, or the credential has to be
				// replaced: either way a full cycle runs now.
				full = true
				continue
			case drainFailed, drainSkipped:
				failures++
				drainNext = true
			}
			// Otherwise drain attempts end and the full cycle keeps its
			// schedule.
			wait = fullDue.Sub(deps.Clock.Now())
		}

		full = true
		if drainNext {
			remaining := fullDue.Sub(deps.Clock.Now())
			if delay := drainDelay(failures); delay < remaining {
				wait, full = delay, false
			} else {
				wait = remaining
			}
		}

		if wait <= 0 {
			// Already due: no wait at all.
			continue
		}

		msg := "waiting for next check-in"
		if !full {
			msg = "waiting for next spool drain attempt"
		}
		deps.log(logging.LevelDebug, msg,
			logging.F("seconds", int(wait/time.Second)),
		)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deps.Clock.After(wait):
		case <-wake:
		}
	}
}

// drainOutcome is how a drain attempt ended, which decides Run's next wake.
type drainOutcome int

const (
	// drainStopped ends drain attempts: the agent is not enrolled, or the
	// spool could not be listed. The full cycle keeps its schedule.
	drainStopped drainOutcome = iota
	// drainSkipped means a cycle held the overlap guard and nothing was
	// sent. Run counts it as a failed attempt.
	drainSkipped
	// drainFailed means the spool still holds files after the attempt.
	drainFailed
	// drainEmptied means the spool is empty after the attempt.
	drainEmptied
	// drainUnauthorized means the backend rejected the credential, which
	// has been cleared.
	drainUnauthorized
)

// attemptDrain is one drain attempt: it re-sends the spool, oldest first, and
// does nothing else -- no collection, no policy fetch, no new spool file. It
// takes the same overlap guard as RunOnce, so it never runs beside a cycle.
func (d *Deps) attemptDrain() drainOutcome {
	if !d.acquire() {
		d.log(logging.LevelDebug, "cycle already running")
		return drainSkipped
	}
	defer d.release()

	st, err := d.Store.Load()
	if err != nil || !st.Enrolled() {
		return drainStopped
	}

	removed, err := d.drainSpool(CheckInPath(st.DeviceID))
	switch {
	case errors.Is(err, client.ErrUnauthorized):
		if err := d.clearCredential(); err != nil {
			d.log(logging.LevelError, "enrollment state not cleared", logging.F("error", err.Error()))
		}
		return drainUnauthorized
	case errors.Is(err, client.ErrNotEnrolled):
		return drainStopped
	case err != nil:
		return drainFailed
	}

	files, err := d.spool().List()
	if err != nil {
		return drainStopped
	}
	if len(files) > 0 {
		// Only files that could not be read were left: the attempt did
		// not get through them, so it failed.
		return drainFailed
	}
	d.log(logging.LevelInfo, "spool drained, connectivity restored", logging.F("files", removed))
	return drainEmptied
}

// spoolPending reports whether a drain attempt should be scheduled: the agent
// is enrolled and the spool lists at least one file. A spool that does not
// exist or cannot be listed counts as empty.
func (d *Deps) spoolPending() bool {
	st, err := d.Store.Load()
	if err != nil || !st.Enrolled() {
		return false
	}
	files, err := d.spool().List()
	return err == nil && len(files) > 0
}

// drainDelay is the wait before a drain attempt after failures consecutive
// failed attempts: DrainRetryBaseDelay doubled once per failure, plus up to
// JitterPercent of it.
func drainDelay(failures int) time.Duration {
	if failures > maxDrainDoublings {
		failures = maxDrainDoublings
	}
	return jitter(DrainRetryBaseDelay << failures)
}

// clearEnrollmentToken removes a rejected enrollment token through
// ClearEnrollmentToken and logs the rejection. cause names the backend's error
// code, never the token.
func (d *Deps) clearEnrollmentToken(cause error) {
	if d.ClearEnrollmentToken == nil {
		d.log(logging.LevelWarn, "enrollment token rejected", logging.F("error", cause.Error()))
		return
	}
	if err := d.ClearEnrollmentToken(); err != nil {
		d.log(logging.LevelError, "enrollment token rejected and could not be removed",
			logging.F("error", cause.Error()),
			logging.F("clearError", err.Error()),
		)
		return
	}
	d.log(logging.LevelWarn, "enrollment token rejected, removed from the config; a new sign-in is needed",
		logging.F("error", cause.Error()))
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

	tz := deps.collectTimeZone()
	deps.logTimeZone(tz)

	// The bundle is fetched after collection and before the check-in, because
	// a policy is evaluated against the posture this cycle just collected.
	req := contract.CheckInRequest{
		CollectedAt: deps.Clock.Now().UTC().Format(time.RFC3339),
		Inventory:   inv,
		Posture:     pst,
		// What this agent is running, so the backend advertises a new build
		// only to the devices that are not on it yet.
		AgentVersion: version.Version,
		// The device's IANA zone, so the console shows its dates in it. ""
		// leaves the key off the wire.
		TimeZone: tz.Zone,
	}
	// Why no zone was collected rides on the inventory warnings, after the
	// inventory collector's own.
	if w := timeZoneWarning(tz); w != "" {
		req.Inventory.Warnings = append(req.Inventory.Warnings, w)
	}
	bundle, bundleOK := deps.fetchBundle(deviceID)
	var results []policy.Result
	if bundleOK {
		// Evaluation runs before Enforce, against the posture collected above.
		results = deps.evaluate(bundle, pst, deps.Clock.Now())
		if deps.Enforce != nil {
			deps.Enforce(ctx, bundle.EffectiveSettings, pst)
		}
	}
	// The Defender hardener's block from the Apply that just ran rides on this
	// check-in, and its failures become violations of the same check-in's
	// compliance report.
	var hardening *contract.DefenderHardening
	if deps.CollectDefenderHardening != nil {
		hardening = deps.CollectDefenderHardening()
	}
	req.DefenderHardening = hardening
	if bundleOK {
		req.PolicyCompliance = policy.Entries(policy.WithDefenderHardening(results, bundle, hardening))
	}

	// Threat detections travel on every check-in, policy or no policy. A
	// collection problem is a posture warning, never a lost check-in.
	findings, findingWarnings := deps.collectAntivirusFindings()
	req.AntivirusFindings = findings
	req.Posture.Warnings = append(req.Posture.Warnings, findingWarnings...)

	// The full antivirus status rides on every check-in as well. A failed
	// probe sends no block and costs only a posture warning.
	avStatus, statusWarnings := deps.collectAntivirusStatus()
	req.AntivirusStatus = avStatus
	req.Posture.Warnings = append(req.Posture.Warnings, statusWarnings...)

	// The last scheduled scan result, when there is one, rides along too.
	if deps.CollectAntivirusScan != nil {
		req.AntivirusScan = deps.CollectAntivirusScan()
	}

	// Endpoint analytics ride along when a collector is wired. The watermark
	// candidate is held back until the check-in carrying it is accepted.
	// While the admin has collection off nothing is collected, and the
	// watermark is pinned to now so re-enabling sends no crash from the off
	// period.
	var onAccepted func()
	if deps.CollectAnalytics != nil && deps.AnalyticsDisabled {
		if deps.AnalyticsWatermark != nil {
			deps.saveAnalyticsWatermark(deps.Clock.Now())
		}
	} else if deps.CollectAnalytics != nil {
		since := deps.analyticsSince()
		block, candidate, err := deps.collectAnalytics(since)
		if err != nil {
			deps.log(logging.LevelWarn, "analytics collection failed", logging.F("error", err.Error()))
		} else {
			req.Analytics = &block
			if deps.AnalyticsWatermark != nil && candidate.After(since) {
				onAccepted = func() { deps.saveAnalyticsWatermark(candidate) }
			}
		}
	}

	// The actions the agent performed (this cycle's Enforce included) ride in
	// this body. The collector empties its buffer, so what it hands over is
	// carried by this body or by the spool file, never by a later body.
	if deps.CollectAgentActions != nil {
		req.AgentActions = deps.CollectAgentActions()
	}

	// The agent's own warn and error records go last, so anything logged
	// earlier in this cycle rides in this body. The collector empties its
	// buffer: what it hands over is carried by this body, or by the spool file
	// should the post fail, and is never put in a later body again.
	if deps.CollectAgentErrors != nil {
		req.AgentErrors = deps.CollectAgentErrors()
	}

	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	path := CheckInPath(deviceID)

	// Whatever the last outage left behind goes first, so the backend sees
	// the device's history in the order it happened.
	if _, err := deps.drainSpool(path); err != nil {
		if errors.Is(err, client.ErrUnauthorized) {
			return deps.clearCredential()
		}
		// The endpoint is answering badly or not at all; this cycle's
		// payload joins the queue rather than chasing it.
		return deps.spoolPayload(body)
	}

	return deps.postCheckIn(ctx, path, body, onAccepted)
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

	// While enrollment waits for a user to sign in this runs every
	// SignInPollInterval; the waiting message has already said why.
	if !d.awaitingSignIn {
		d.log(logging.LevelInfo, "not enrolled, enrolling before check-in")
	}
	if d.BeforeEnroll != nil {
		d.BeforeEnroll()
	}
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
// block everything behind it. A transport failure or a retryable status (5xx,
// 408, 429) stops the drain and comes back as an error, leaving the rest of the
// queue for the next cycle.
//
// The count is how many files the drain removed: accepted with a 2xx plus
// deleted after a non-retryable 4xx. An unreadable file is skipped and not
// counted.
func (d *Deps) drainSpool(path string) (int, error) {
	spool := d.spool()
	removed := 0

	paths, err := spool.List()
	if err != nil {
		d.log(logging.LevelWarn, "spool unreadable", logging.F("error", err.Error()))
		return 0, nil
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
			return removed, err
		}

		status := resp.StatusCode
		closeBody(resp)

		switch {
		case status >= 200 && status < 300:
			if err := spool.Remove(file); err != nil {
				return removed, err
			}
			removed++
			d.log(logging.LevelInfo, "spooled check-in accepted", logging.F("file", file))
		case retryableStatus(status):
			d.log(logging.LevelWarn, "spooled check-in failed",
				logging.F("file", file),
				logging.F("status", status),
			)
			return removed, fmt.Errorf("spooled check-in failed with status %d", status)
		default:
			d.log(logging.LevelWarn, "spooled check-in rejected",
				logging.F("file", file),
				logging.F("status", status),
			)
			if err := spool.Remove(file); err != nil {
				return removed, err
			}
			removed++
		}
	}
	return removed, nil
}

// retryableStatus reports whether an upload answered with status should be
// kept and sent again: a 5xx, a 408 Request Timeout or a 429 Too Many
// Requests. Every other non-2xx is a refusal the same bytes would meet again.
func retryableStatus(status int) bool {
	return status >= 500 || status == http.StatusRequestTimeout || status == http.StatusTooManyRequests
}

// postCheckIn posts this cycle's payload and acts on the answer. onAccepted,
// when non-nil, is called once the backend has answered 2xx, and not
// otherwise.
func (d *Deps) postCheckIn(ctx context.Context, path string, body []byte, onAccepted func()) error {
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
	case retryableStatus(resp.StatusCode):
		d.log(logging.LevelWarn, "check-in failed", logging.F("status", resp.StatusCode))
		return d.spoolPayload(body)
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		// The backend understood the request and refused it; sending the
		// same bytes again later would be refused again.
		fields := []logging.Field{logging.F("status", resp.StatusCode)}
		fields = append(fields, rejectionFields(resp)...)
		d.log(logging.LevelWarn, "check-in rejected", fields...)
		return nil
	}

	if onAccepted != nil {
		onAccepted()
	}

	var out contract.CheckInResponse
	data, err := readBody(resp)
	if err != nil {
		d.log(logging.LevelWarn, "check-in response unreadable", logging.F("error", err.Error()))
	} else if err := json.Unmarshal(data, &out); err != nil {
		d.log(logging.LevelWarn, "check-in response unreadable", logging.F("error", err.Error()))
	} else {
		// Only a response that was read and decoded moves the switch.
		d.AnalyticsDisabled = out.AnalyticsEnabled != nil && !*out.AnalyticsEnabled
		// And the heartbeat frequency: present only while the heartbeat is on.
		if d.OnHeartbeatInterval != nil {
			seconds := 0
			if out.HeartbeatIntervalSeconds != nil {
				seconds = *out.HeartbeatIntervalSeconds
			}
			d.OnHeartbeatInterval(seconds)
		}
	}

	if out.CheckInIntervalSeconds > 0 {
		d.IntervalSeconds = out.CheckInIntervalSeconds
	}

	d.log(logging.LevelInfo, "checked in",
		logging.F("checkInIntervalSeconds", d.IntervalSeconds),
		logging.F("pendingCommandCount", out.PendingCommandCount),
	)

	// The update comes before the command poll: applying one restarts the
	// agent, and a command leased now would be interrupted by that restart.
	if err := d.applyUpdate(ctx, out.AgentRelease); err != nil {
		return err
	}

	if d.AfterCheckIn != nil {
		return d.AfterCheckIn(ctx, out)
	}
	return nil
}

// applyUpdate installs the build a check-in advertised, once.
//
// It is the only call site, and it is reached once per cycle, so an update is
// attempted at most once however the attempt goes. A failure is logged and the
// cycle carries on: the release is still published, so the next check-in
// advertises it again, and an agent that cannot update itself must still check
// in, report its inventory and run its commands.
//
// The one error it returns is service.ErrRestartRequired: the new build is in
// place and the agent must exit to be restarted onto it.
func (d *Deps) applyUpdate(ctx context.Context, rel *contract.AgentRelease) error {
	if rel == nil || d.ApplyUpdate == nil {
		return nil
	}

	d.log(logging.LevelInfo, "agent update advertised", logging.F("version", rel.Version))
	err := d.ApplyUpdate(ctx, *rel)
	switch {
	case err == nil:
	case errors.Is(err, service.ErrRestartRequired):
		d.log(logging.LevelInfo, "agent restarting to apply update", logging.F("version", rel.Version))
		return err
	default:
		d.log(logging.LevelWarn, "agent update failed",
			logging.F("version", rel.Version),
			logging.F("error", err.Error()),
		)
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

	return jitter(time.Duration(seconds) * time.Second)
}

// jitter is base plus up to JitterPercent of it.
func jitter(base time.Duration) time.Duration {
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

// collectAntivirusFindings runs the injected collector, or the real one when
// there is a runner to run it with. With neither, nothing is collected.
func (d *Deps) collectAntivirusFindings() ([]contract.AntivirusFinding, []string) {
	if d.CollectAntivirusFindings != nil {
		return d.CollectAntivirusFindings()
	}
	if d.Runner == nil {
		return nil, nil
	}
	return antivirus.CollectFindings(d.Runner, d.Clock, d.goos())
}

// collectAntivirusStatus runs the injected status collector, or the real one
// when there is a runner to run it with. With neither, nothing is collected.
func (d *Deps) collectAntivirusStatus() (*contract.AntivirusStatus, []string) {
	if d.CollectAntivirusStatus != nil {
		return d.CollectAntivirusStatus()
	}
	if d.Runner == nil {
		return nil, nil
	}
	return antivirus.CollectStatus(d.Runner, d.Clock, d.goos())
}

// analyticsSince returns the crash watermark this cycle's analytics are
// collected from. With no store it is now, every cycle. A store with no
// watermark yet, or an unreadable one, starts from now too, and now is saved
// at once whatever comes of the check-in, so no crash from before the first
// analytics cycle is ever sent.
func (d *Deps) analyticsSince() time.Time {
	now := d.Clock.Now()
	if d.AnalyticsWatermark == nil {
		return now
	}
	since, err := d.AnalyticsWatermark.Load()
	if err != nil {
		d.log(logging.LevelWarn, "analytics watermark unreadable", logging.F("error", err.Error()))
	} else if !since.IsZero() {
		return since
	}
	d.saveAnalyticsWatermark(now)
	return now
}

// saveAnalyticsWatermark saves t, logging a failure rather than returning it:
// a watermark that is not advanced only means crashes are sent again, and the
// backend deduplicates them.
func (d *Deps) saveAnalyticsWatermark(t time.Time) {
	if err := d.AnalyticsWatermark.Save(t); err != nil {
		d.log(logging.LevelWarn, "analytics watermark not saved", logging.F("error", err.Error()))
	}
}

// collectAnalytics runs the analytics collector, turning a panic inside it
// into an error so a broken collector cannot cost the check-in.
func (d *Deps) collectAnalytics(since time.Time) (block contract.Analytics, candidate time.Time, err error) {
	defer func() {
		if r := recover(); r != nil {
			block, candidate, err = contract.Analytics{}, since, fmt.Errorf("analytics collector panicked: %v", r)
		}
	}()
	return d.CollectAnalytics(since)
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
// maxRejectionBytes bounds what is read from a refused check-in's body.
const maxRejectionBytes = 64 << 10

// rejectionFields are the log fields naming why the backend refused a
// request: the contract's {"error": "...", "fields": [...]} body, or nothing
// when the body says nothing readable.
func rejectionFields(resp *http.Response) []logging.Field {
	if resp == nil || resp.Body == nil {
		return nil
	}
	var payload struct {
		Error  string   `json:"error"`
		Fields []string `json:"fields"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRejectionBytes)).Decode(&payload); err != nil || payload.Error == "" {
		return nil
	}
	out := []logging.Field{logging.F("error", payload.Error)}
	if len(payload.Fields) > 0 {
		out = append(out, logging.F("fields", strings.Join(payload.Fields, ", ")))
	}
	return out
}

func closeBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}

// collectTimeZone runs the injected collector, or the real one when there is
// a runner to run it with. With neither, the result is Reason no_collector.
func (d *Deps) collectTimeZone() inventory.TimeZoneResult {
	if d.CollectTimeZone != nil {
		return d.CollectTimeZone()
	}
	if d.Runner == nil {
		return inventory.TimeZoneResult{Reason: inventory.TimeZoneNoCollector}
	}
	return inventory.ResolveTimeZone(d.Runner, d.Clock, d.goos())
}

// logTimeZone logs the time zone result on the first cycle and again
// whenever it differs from the last one logged.
func (d *Deps) logTimeZone(tz inventory.TimeZoneResult) {
	if d.timeZoneLogged && tz == d.lastTimeZone {
		return
	}
	d.timeZoneLogged = true
	d.lastTimeZone = tz
	if tz.Reason == "" {
		d.log(logging.LevelInfo, "time zone collected", logging.F("zone", tz.Zone))
		return
	}
	fields := []logging.Field{logging.F("reason", tz.Reason)}
	if tz.Detail != "" {
		fields = append(fields, logging.F("detail", tz.Detail))
	}
	d.log(logging.LevelWarn, "time zone not collected", fields...)
}

// timeZoneWarning is the "timezone:<reason>[:<detail>]" inventory warning for
// a result with no zone, or "" when the zone resolved.
func timeZoneWarning(tz inventory.TimeZoneResult) string {
	if tz.Reason == "" {
		return ""
	}
	w := inventory.ProbeTimeZone + ":" + tz.Reason
	if tz.Detail != "" {
		w += ":" + tz.Detail
	}
	return w
}
