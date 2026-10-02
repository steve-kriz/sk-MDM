//go:build !windows

package service

import (
	"context"
	"errors"
)

// ErrNoServiceManager is returned by Dispatch off Windows. macOS has no
// equivalent handshake: a LaunchDaemon is an ordinary foreground process that
// launchd starts and signals, which is exactly what `mdmagent run` already is.
var ErrNoServiceManager = errors.New("service: no service control manager on this platform")

// Managed is false off Windows: there is no control manager to be started by,
// so `mdmagent run` always runs in the foreground.
func Managed() bool { return false }

// Dispatch is not available off Windows.
func Dispatch(_ context.Context, _ Hooks) error { return ErrNoServiceManager }
