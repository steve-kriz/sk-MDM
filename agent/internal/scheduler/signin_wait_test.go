package scheduler

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/client"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

// scriptedEnroll is a Transport whose Enroll answers come from a function and
// whose calls are signalled on a channel.
type scriptedEnroll struct {
	mockTransport
	mu     sync.Mutex
	calls  int
	answer func(call int) error
	called chan int
}

func (s *scriptedEnroll) Enroll(ctx context.Context) error {
	s.mu.Lock()
	s.calls++
	n := s.calls
	s.mu.Unlock()
	err := s.answer(n)
	s.called <- n
	return err
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func expectCall(t *testing.T, ch chan int, want int) {
	t.Helper()
	select {
	case got := <-ch:
		if got != want {
			t.Fatalf("enroll call = %d, want %d", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("enroll call %d never came", want)
	}
}

func signInDeps(t *testing.T, transport Transport, wake chan struct{}) (*Deps, *fake.Clock, *fake.FS) {
	t.Helper()
	clock := fake.NewClock(time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	return &Deps{
		Client:     transport,
		Store:      &fakeStore{},
		FS:         fsys,
		Clock:      clock,
		GOOS:       "darwin",
		Logger:     logging.New(fsys, clock, "agent.log", logging.LevelInfo, "scheduler"),
		SignInWake: wake,
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
	}, clock, fsys
}

// An unenrolled agent with no enrollment token looks again every 60 s,
// logs "waiting for a user to sign in" once, and does not check in.
func TestRun_WaitsForSignInEverySixtySeconds(t *testing.T) {
	transport := &scriptedEnroll{
		answer: func(int) error { return client.ErrAwaitingSignIn },
		called: make(chan int, 8),
	}
	deps, clock, fsys := signInDeps(t, transport, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, deps) }()

	expectCall(t, transport.called, 1)
	waitUntil(t, "first wait", func() bool { return len(clock.Waits()) == 1 })
	if w := clock.Waits()[0]; w != SignInPollInterval {
		t.Errorf("wait = %v, want %v", w, SignInPollInterval)
	}
	clock.Advance(SignInPollInterval)
	expectCall(t, transport.called, 2)
	waitUntil(t, "second wait", func() bool { return len(clock.Waits()) == 2 })
	clock.Advance(SignInPollInterval)
	expectCall(t, transport.called, 3)

	cancel()
	<-done

	logged, _ := fsys.Content("agent.log")
	if n := strings.Count(string(logged), "waiting for a user to sign in"); n != 1 {
		t.Errorf("waiting message logged %d times, want 1:\n%s", n, logged)
	}
	if strings.Contains(string(logged), "check-in cycle failed") {
		t.Errorf("waiting for sign-in must not be logged as a failure:\n%s", logged)
	}
	if len(transport.requests) != 0 {
		t.Errorf("no request may be made before enrollment, got %d", len(transport.requests))
	}
}

// A successful /callback wakes the loop at once, without waiting the 60 s.
func TestRun_SignInWakeRetriesAtOnce(t *testing.T) {
	transport := &scriptedEnroll{
		answer: func(int) error { return client.ErrAwaitingSignIn },
		called: make(chan int, 8),
	}
	wake := make(chan struct{}, 1)
	deps, clock, _ := signInDeps(t, transport, wake)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, deps) }()

	expectCall(t, transport.called, 1)
	waitUntil(t, "first wait", func() bool { return len(clock.Waits()) == 1 })
	wake <- struct{}{}
	expectCall(t, transport.called, 2)

	cancel()
	<-done
}

// An enrollment token the backend rejects is removed from the config through
// ClearEnrollmentToken, the rejection is logged, and the next look comes at
// the next 60 s tick (or at once on a sign-in wake) rather than after the
// check-in interval.
func TestRun_RejectedEnrollmentTokenIsCleared(t *testing.T) {
	transport := &scriptedEnroll{
		answer: func(n int) error {
			if n == 1 {
				return fmt.Errorf("%w: status 403 (enrollment_token_exhausted)", client.ErrEnrollmentTokenRejected)
			}
			return client.ErrAwaitingSignIn
		},
		called: make(chan int, 8),
	}
	deps, clock, fsys := signInDeps(t, transport, nil)
	cleared := 0
	deps.ClearEnrollmentToken = func() error { cleared++; return nil }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, deps) }()

	expectCall(t, transport.called, 1)
	waitUntil(t, "first wait", func() bool { return len(clock.Waits()) == 1 })
	if w := clock.Waits()[0]; w != SignInPollInterval {
		t.Errorf("wait = %v, want %v", w, SignInPollInterval)
	}
	if cleared != 1 {
		t.Errorf("ClearEnrollmentToken calls = %d, want 1", cleared)
	}
	clock.Advance(SignInPollInterval)
	expectCall(t, transport.called, 2)
	waitUntil(t, "second wait", func() bool { return len(clock.Waits()) == 2 })

	cancel()
	<-done

	if cleared != 1 {
		t.Errorf("ClearEnrollmentToken calls = %d, want 1", cleared)
	}
	logged, _ := fsys.Content("agent.log")
	if !strings.Contains(string(logged), "enrollment token rejected") || !strings.Contains(string(logged), "enrollment_token_exhausted") {
		t.Errorf("rejection not logged:\n%s", logged)
	}
	if !strings.Contains(string(logged), "waiting for a user to sign in") {
		t.Errorf("waiting message not logged after the token was cleared:\n%s", logged)
	}
}

// A token that cannot be removed is logged and the loop carries on.
func TestRun_RejectedEnrollmentTokenClearFailureLogged(t *testing.T) {
	transport := &scriptedEnroll{
		answer: func(int) error { return client.ErrEnrollmentTokenRejected },
		called: make(chan int, 8),
	}
	deps, clock, fsys := signInDeps(t, transport, nil)
	deps.ClearEnrollmentToken = func() error { return errors.New("disk full") }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, deps) }()
	expectCall(t, transport.called, 1)
	waitUntil(t, "first wait", func() bool { return len(clock.Waits()) == 1 })
	cancel()
	<-done

	logged, _ := fsys.Content("agent.log")
	if !strings.Contains(string(logged), "disk full") {
		t.Errorf("clear failure not logged:\n%s", logged)
	}
}

// Once a user has signed in, the next tick enrolls and the cycle checks in.
func TestRun_EnrollsAfterSignInThenChecksIn(t *testing.T) {
	store := &fakeStore{}
	transport := &scriptedEnroll{
		called: make(chan int, 8),
	}
	transport.answer = func(n int) error {
		if n == 1 {
			return client.ErrAwaitingSignIn
		}
		store.state = state.State{DeviceID: "d1", DeviceSecret: "s"}
		return nil
	}
	deps, clock, _ := signInDeps(t, transport, nil)
	deps.Store = store

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, deps) }()

	expectCall(t, transport.called, 1)
	waitUntil(t, "first wait", func() bool { return len(clock.Waits()) == 1 })
	clock.Advance(SignInPollInterval)
	expectCall(t, transport.called, 2)
	waitUntil(t, "post-enrollment wait", func() bool { return len(clock.Waits()) == 2 })

	cancel()
	<-done

	if w := clock.Waits()[1]; w < DefaultIntervalSeconds*time.Second {
		t.Errorf("after enrollment the normal interval applies, got %v", w)
	}
	checkedIn := false
	for _, r := range transport.requests {
		if strings.HasSuffix(r.path, "/checkin") {
			checkedIn = true
		}
	}
	if !checkedIn {
		t.Error("expected a check-in after enrollment")
	}
}
