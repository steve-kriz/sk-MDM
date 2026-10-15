//go:build windows

package service

import (
	"context"
	"time"

	"golang.org/x/sys/windows/svc"
)

// accepted is what the service tells the service control manager it handles: a
// stop and a machine shutdown, and nothing else. A pause or a continue would
// leave the agent half-running, which is worse for the device than either
// state.
const accepted = svc.AcceptStop | svc.AcceptShutdown

// Managed reports whether this process was started by the Windows service
// control manager, as opposed to from a console. `mdmagent run` is the same
// verb either way — it is what the service is registered as — so it asks this
// to decide whether to talk to the control manager or to a terminal.
func Managed() bool {
	managed, err := svc.IsWindowsService()
	return err == nil && managed
}

// Dispatch hosts hooks under the Windows service control manager, returning
// when the service has stopped.
//
// Everything it does is translation: a control request becomes a Request, a
// state becomes a svc.Status, and the decisions stay in Run, where they are
// tested without a control manager at all.
func Dispatch(ctx context.Context, hooks Hooks) error {
	return svc.Run(Name, &handler{ctx: ctx, hooks: hooks})
}

// handler is the svc.Handler that bridges the control manager to Run.
type handler struct {
	ctx   context.Context
	hooks Hooks
}

// Execute runs one service lifetime.
func (h *handler) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	requests := make(chan Request, 1)

	hooks := h.hooks
	hooks.Requests = requests
	hooks.Report = func(state State) {
		// The final SERVICE_STOPPED is x/sys's, sent after Execute returns
		// with ExecuteExit's code; forwarding Run's StateStopped would
		// report a stop with exit code 0 ahead of it.
		if !forwardsToSCM(state) {
			return
		}
		s <- status(state)
	}

	done := make(chan error, 1)
	go func() { done <- Run(h.ctx, hooks) }()

	for {
		select {
		case err := <-done:
			return ExecuteExit(err)
		case change := <-r:
			switch change.Cmd {
			case svc.Stop:
				forward(requests, RequestStop)
			case svc.Shutdown:
				forward(requests, RequestShutdown)
			default:
				// Interrogate, and anything else the control manager
				// sends that is not accepted, is answered with the
				// status it already holds.
				s <- change.CurrentStatus
			}
		}
	}
}

// forward hands a request to Run, dropping it when one is already queued: a
// second stop while the first is being honoured changes nothing, and must not
// block the control manager's goroutine.
func forward(requests chan Request, request Request) {
	select {
	case requests <- request:
	default:
	}
}

// status is the control manager's view of one state.
func status(state State) svc.Status {
	switch state {
	case StateStartPending:
		return svc.Status{State: svc.StartPending, WaitHint: waitHint()}
	case StateRunning:
		return svc.Status{State: svc.Running, Accepts: accepted}
	case StateStopPending:
		return svc.Status{State: svc.StopPending, WaitHint: waitHint()}
	default:
		return svc.Status{State: svc.Stopped}
	}
}

// waitHint is how long the control manager is asked to wait before it decides
// the service is wedged: the same grace period the stop itself allows.
func waitHint() uint32 {
	return uint32(StopGrace / time.Millisecond)
}
