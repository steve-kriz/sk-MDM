// E2E cucumber-style tests for TASK-044's agent wiring: the per-device
// heartbeat loop beside the scheduler (AC39).
package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

// TestE2E_NewAgentWiresHeartbeatInterval verifies that newAgent sets
// scheduler.Deps.OnHeartbeatInterval to the heartbeat deps' SetInterval, so a
// decoded check-in response reaches the heartbeat loop.
func TestE2E_NewAgentWiresHeartbeatInterval(t *testing.T) {
	// Given: a simulated agentEnv with fakes, assembled through newAgent
	fsys := fake.NewFS()
	runner := fake.NewCommandRunner()
	clock := fake.NewClock(time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC))
	doer := fake.NewHTTPDoer()

	cfg := config.Config{CollectionURL: "https://collect.example.com", EnrollmentToken: "tok"}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	fsys.Seed(config.Path("windows"), data)

	env := agentEnv{
		FS:         fsys,
		Runner:     runner,
		Clock:      clock,
		Doer:       doer,
		GOOS:       "windows",
		ConfigPath: config.Path("windows"),
		StatePath:  state.StatePath("windows"),
	}

	// When: newAgent is called
	a, err := newAgent(env)
	if err != nil {
		t.Fatalf("newAgent failed: %v", err)
	}

	// Then: deps.OnHeartbeatInterval is set, and the agent carries a non-nil
	// heartbeat loop with a Collect function wired.
	if a.deps.OnHeartbeatInterval == nil {
		t.Fatal("deps.OnHeartbeatInterval should be non-nil")
	}
	if a.heartbeat == nil {
		t.Fatal("agent.heartbeat should be non-nil")
	}
	if a.heartbeat.Collect == nil {
		t.Fatal("agent.heartbeat.Collect should be non-nil")
	}

	// And: calling it sets the heartbeat loop's own interval (the SetInterval
	// clamping rules apply: 1..59 raised to 60, 0 and below off).
	a.deps.OnHeartbeatInterval(300)
	if got := a.heartbeat.Interval(); got != 300 {
		t.Errorf("after OnHeartbeatInterval(300): Interval() = %d, want 300", got)
	}
	a.deps.OnHeartbeatInterval(0)
	if got := a.heartbeat.Interval(); got != 0 {
		t.Errorf("after OnHeartbeatInterval(0): Interval() = %d, want 0", got)
	}

	// And: Collect runs without panicking (the probe itself is exercised by
	// agent/internal/analytics tests).
	if _, _, err := func() (any, any, error) {
		perf, warnings := a.heartbeat.Collect()
		return perf, warnings, nil
	}(); err != nil {
		t.Errorf("heartbeat.Collect panicked or errored: %v", err)
	}

	// And: the network sample is wired too.
	if a.heartbeat.CollectNetwork == nil {
		t.Fatal("agent.heartbeat.CollectNetwork should be non-nil")
	}
	_, _ = a.heartbeat.CollectNetwork()
}

// TestE2E_HooksStartLaunchesHeartbeatBeforeScheduler verifies that
// hooks().Start starts the heartbeat loop on its own goroutine and does not
// panic, by driving it with an already-cancelled context: both the heartbeat
// loop and scheduler.Run check ctx.Err() first and return immediately, so a
// hang here would mean the wiring is broken.
func TestE2E_HooksStartLaunchesHeartbeatBeforeScheduler(t *testing.T) {
	fsys := fake.NewFS()
	runner := fake.NewCommandRunner()
	clock := fake.NewClock(time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC))
	doer := fake.NewHTTPDoer()

	cfg := config.Config{CollectionURL: "https://collect.example.com", EnrollmentToken: "tok"}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	fsys.Seed(config.Path("windows"), data)

	env := agentEnv{
		FS:         fsys,
		Runner:     runner,
		Clock:      clock,
		Doer:       doer,
		GOOS:       "windows",
		ConfigPath: config.Path("windows"),
		StatePath:  state.StatePath("windows"),
	}

	a, err := newAgent(env)
	if err != nil {
		t.Fatalf("newAgent failed: %v", err)
	}
	if a.heartbeat == nil {
		t.Fatal("agent.heartbeat should be non-nil so hooks().Start launches it")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: both loops must return immediately

	done := make(chan error, 1)
	go func() { done <- a.hooks().Start(ctx) }()

	select {
	case err := <-done:
		if err == nil {
			t.Error("hooks().Start should return ctx.Err() on an already-cancelled context")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hooks().Start did not return for an already-cancelled context")
	}
}
