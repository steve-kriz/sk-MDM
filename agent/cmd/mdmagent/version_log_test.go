// E2E cucumber-style test for TASK-054's AC15: the "agent started" info line
// written by hooks().Start carries a version field equal to version.Version.
//
// New file per TASK-054 instructions: run_test.go and heartbeat_wiring_test.go
// (AC16) must pass unchanged.
package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
	"github.com/officehq/sk-mdm/agent/internal/version"
)

// logRecords decodes every JSON line fsys holds at path.
func logRecords(fsys *fake.FS, path string) []map[string]any {
	data, ok := fsys.Content(path)
	if !ok {
		return nil
	}
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err == nil {
			records = append(records, record)
		}
	}
	return records
}

// TestScenario_AgentStartedLogsVersion verifies AC15: Given the agent is
// built with version.Version "1.2.3", when the service Start hook runs, the
// info line "agent started" carries field version "1.2.3".
func TestScenario_AgentStartedLogsVersion(t *testing.T) {
	// Given: the agent is built with version.Version "1.2.3".
	original := version.Version
	version.Version = "1.2.3"
	defer func() { version.Version = original }()

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

	// When: the service Start hook runs. An already-cancelled context makes
	// scheduler.Run and the heartbeat/sign-in loops return immediately, as
	// heartbeat_wiring_test.go's equivalent scenario does.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() { done <- a.hooks().Start(ctx) }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("hooks().Start did not return for an already-cancelled context")
	}

	// Then: the info line "agent started" carries field version "1.2.3".
	records := logRecords(fsys, agentLogPath(env.GOOS))
	var started []map[string]any
	for _, record := range records {
		if record["msg"] == "agent started" {
			started = append(started, record)
		}
	}
	if len(started) != 1 {
		t.Fatalf("\"agent started\" lines = %v, want exactly one", started)
	}
	if started[0]["level"] != "info" {
		t.Errorf("level = %v, want info", started[0]["level"])
	}
	if got := started[0]["version"]; got != "1.2.3" {
		t.Errorf("version = %v, want %q", got, "1.2.3")
	}
}

// TestScenario_AgentStartedWithNilLoggerDoesNotPanic exercises the nil-logger
// guard kept around the "agent started" line (a.logger != nil).
func TestScenario_AgentStartedWithNilLoggerDoesNotPanic(t *testing.T) {
	a := &agent{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() { done <- a.hooks().Start(ctx) }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("hooks().Start did not return for an already-cancelled context")
	}
}
