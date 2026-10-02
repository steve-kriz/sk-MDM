// Package service hosts the agent as a background service: the start, stop and
// shutdown state machine both platforms drive, the Windows service control
// manager adapter, the Windows service registration and the macOS LaunchDaemon
// plist the installer writes.
//
// The state machine in Run touches nothing outside this process. A control
// request arrives on a channel, every side effect is a plain function in Hooks,
// and the wait for the in-flight cycle is timed on an injected clock, so the
// whole of it runs in a test on a Windows or a macOS host, as a normal user,
// with no service control manager and no launchd. The operating system shows up
// in exactly two places next door: dispatch_windows.go, which hands the service
// control manager's requests to Run, and the sc.exe and launchctl calls in
// windows.go and launchd.go, which go through platform.CommandRunner so an
// install is exercised unprivileged.
package service

import (
	"context"
	"errors"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// The identity the agent is registered under on each platform.
const (
	// Name is the Windows service name, as `sc.exe` and the Services list
	// know it.
	Name = "OfficeHQMDMAgent"
	// DisplayName is what the Windows Services list shows.
	DisplayName = "OfficeHQ MDM Agent"
)

// StopGrace is how long a stop request waits for the in-flight check-in cycle
// to finish before the service reports itself stopped regardless.
//
// A cycle shells out to inventory and posture probes, so stopping is not
// instant; the service control manager, on the other hand, will not wait
// forever. Thirty seconds is long enough for a cycle that is nearly done and
// short enough that a stuck probe does not hold a shutdown up.
const StopGrace = 30 * time.Second

// ErrStopTimeout is returned when the work was still running after StopGrace.
// The service reports itself stopped either way: an agent that will not let go
// must not leave the service control manager waiting on it.
var ErrStopTimeout = errors.New("service: the agent did not stop within the grace period")

// Request is a control request delivered to a running service.
type Request int

// The control requests the service accepts. Anything else — a pause, a
// continue — is not accepted and never reaches Run.
const (
	// RequestStop is an operator or an installer stopping the service.
	RequestStop Request = iota
	// RequestShutdown is the machine going down.
	RequestShutdown
)

// String is the request's name, for a log line.
func (r Request) String() string {
	switch r {
	case RequestStop:
		return "stop"
	case RequestShutdown:
		return "shutdown"
	default:
		return "unknown"
	}
}

// State is a state Run reports through Hooks.Report. The four values are the
// states the Windows service control manager understands, which is what
// dispatch_windows.go forwards them as.
type State int

// The states, in the order one run passes through them.
const (
	// StateStartPending is reported before the work has been started.
	StateStartPending State = iota
	// StateRunning is reported once the work is under way.
	StateRunning
	// StateStopPending is reported once a stop request has been accepted and
	// the in-flight cycle is being waited out.
	StateStopPending
	// StateStopped is reported when the work has finished, or when it has
	// outlived StopGrace.
	StateStopped
)

// String is the state's name, for a log line.
func (s State) String() string {
	switch s {
	case StateStartPending:
		return "start pending"
	case StateRunning:
		return "running"
	case StateStopPending:
		return "stop pending"
	case StateStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

// Hooks is everything Run drives and everything it is driven by.
//
// Start, Stop and Shutdown are plain functions rather than an interface or a
// service control manager handle, which is what lets the state machine be
// tested with three counters.
type Hooks struct {
	// Start is the work the service exists to do — for the agent, the
	// scheduler loop. It is called once, on its own goroutine, and is
	// expected to return once the context it is given is cancelled. The
	// error it returns is Run's, except for a plain context cancellation,
	// which is what a clean stop looks like and is reported as success.
	Start func(ctx context.Context) error

	// Stop is called once, before the work's context is cancelled, when a
	// stop is requested. It is the agent's shutdown path: a second stop
	// request while the first is being honoured never reaches it.
	Stop func()

	// Shutdown is Stop's equivalent for the machine going down. Left nil,
	// a shutdown request calls Stop instead.
	Shutdown func()

	// Report, when non-nil, is called with each state the service passes
	// through, in order. It is how the service control manager is kept
	// informed, and how a test sees the transitions.
	Report func(state State)

	// Requests is where control requests arrive. Left nil, only a cancelled
	// context stops the service, which is what `mdmagent run` in a console
	// does.
	Requests <-chan Request

	// Clock times the wait for the in-flight cycle; nil means the real one.
	Clock platform.Clock

	// StopTimeout overrides StopGrace. Zero means StopGrace.
	StopTimeout time.Duration
}

// Run starts the work and drives it to a stop, returning when the work has
// finished.
//
// The service stops for one of three reasons: a request on Hooks.Requests, a
// cancellation of ctx — which is how a foreground `mdmagent run` turns a SIGINT
// or a CTRL_BREAK into a stop — or the work returning on its own. The first two
// call Stop (or Shutdown) exactly once and then wait up to StopGrace for the
// work to return; every further request that arrives while stopping is
// discarded, because the shutdown path is already running and running it twice
// would stop the agent twice.
//
// StateStopped is always reported, whether the work returned in time or not.
func Run(ctx context.Context, hooks Hooks) error {
	if hooks.Start == nil {
		return errors.New("service: no start hook")
	}

	hooks.report(StateStartPending)

	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- hooks.Start(workCtx) }()

	hooks.report(StateRunning)

	var request Request
	select {
	case err := <-done:
		// The work stopped of its own accord. Nothing requested it, so
		// neither Stop nor Shutdown is called.
		hooks.report(StateStopped)
		return stopError(err)
	case <-ctx.Done():
		request = RequestStop
	case request = <-hooks.Requests:
	}

	hooks.fire(request)
	hooks.report(StateStopPending)
	cancel()

	expiry := hooks.clock().After(hooks.stopTimeout())
	for {
		select {
		case err := <-done:
			hooks.report(StateStopped)
			return stopError(err)
		case <-expiry:
			hooks.report(StateStopped)
			return ErrStopTimeout
		case <-hooks.Requests:
			// A second stop while stopping is ignored: the shutdown path
			// has already run and the work is already being waited out.
		}
	}
}

// Restart asks the platform's service manager to stop the agent and start it
// again. It is what a self-update invokes once the new binary is in place, so
// the build that is running becomes the build that was just installed.
//
// It is a request, not a sequence this process sees through: the process making
// it is the one being stopped, so everything after the stop belongs to the
// service manager. On macOS that is launchd, which is asked to kick the job
// over; on Windows it is the service control manager, which is asked to stop
// the service and start it again.
func Restart(ctx context.Context, cfg Config) error {
	if cfg.Runner == nil {
		return errors.New("service: no command runner")
	}
	if cfg.goos() == "windows" {
		return restartWindows(ctx, cfg)
	}
	return restartDarwin(ctx, cfg)
}

// fire runs the hook a request asks for, once. A shutdown with no hook of its
// own is the stop path: the machine is going down, so the agent stops.
func (h Hooks) fire(request Request) {
	if request == RequestShutdown && h.Shutdown != nil {
		h.Shutdown()
		return
	}
	if h.Stop != nil {
		h.Stop()
	}
}

// report hands one state to the caller's reporter, when there is one.
func (h Hooks) report(state State) {
	if h.Report != nil {
		h.Report(state)
	}
}

// clock is the clock the stop is timed on.
func (h Hooks) clock() platform.Clock {
	if h.Clock != nil {
		return h.Clock
	}
	return platform.SystemClock{}
}

// stopTimeout is how long the in-flight cycle is waited out.
func (h Hooks) stopTimeout() time.Duration {
	if h.StopTimeout > 0 {
		return h.StopTimeout
	}
	return StopGrace
}

// stopError maps what the work returned onto what the service reports. A
// context cancellation is the stop that was just asked for, not a failure.
func stopError(err error) error {
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
