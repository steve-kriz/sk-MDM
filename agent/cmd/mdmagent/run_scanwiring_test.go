package main

// E2E/cucumber-style tests for TASK-055 AC23: newAgent wires one Scanner
// instance into both the Enforce seam (after the antivirus enforcer, which
// itself follows enforce.Defaults) and deps.CollectAntivirusScan, and a
// blocked scan command never blocks scheduler.RunOnce. Every command and
// HTTP call is faked; no real PowerShell, Defender or network call is made.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/antivirus"
	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/scheduler"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

// scanWiringTransport is a minimal scheduler.Transport that answers a policy
// fetch with the given effective settings and captures the check-in body.
type scanWiringTransport struct {
	mu                sync.Mutex
	effectiveSettings map[string]any
	checkinBody       []byte
}

func (tr *scanWiringTransport) Enroll(ctx context.Context) error { return nil }

func (tr *scanWiringTransport) Do(method, path string, body []byte) (*http.Response, error) {
	if method == http.MethodGet && strings.Contains(path, "policies") {
		bundle := contract.PolicyBundleResponse{EffectiveSettings: tr.effectiveSettings}
		data, _ := json.Marshal(bundle)
		return fake.Response(http.StatusOK, string(data)), nil
	}
	if method == http.MethodPost && strings.Contains(path, "checkin") {
		tr.mu.Lock()
		tr.checkinBody = append([]byte(nil), body...)
		tr.mu.Unlock()
		return fake.Response(http.StatusOK, "{}"), nil
	}
	return fake.Response(http.StatusOK, "{}"), nil
}

func (tr *scanWiringTransport) lastCheckinBody() []byte {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return tr.checkinBody
}

// blockOnScanRunner delegates to a fake.CommandRunner for every command
// except the Defender scan script, which it blocks on until released (or the
// command's context is cancelled), so a test can prove a blocked scan never
// holds up scheduler.RunOnce. The fake.CommandRunner alone cannot block.
type blockOnScanRunner struct {
	inner   *fake.CommandRunner
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func newBlockOnScanRunner(inner *fake.CommandRunner) *blockOnScanRunner {
	return &blockOnScanRunner{inner: inner, started: make(chan struct{}), release: make(chan struct{})}
}

func (r *blockOnScanRunner) Run(ctx context.Context, name string, args ...string) (platform.CommandResult, error) {
	if len(args) > 0 && args[len(args)-1] == antivirus.WindowsScanScript {
		r.once.Do(func() { close(r.started) })
		select {
		case <-r.release:
		case <-ctx.Done():
			return platform.CommandResult{}, ctx.Err()
		}
	}
	return r.inner.Run(ctx, name, args...)
}

// buildTestAgent assembles newAgent with a pre-enrolled state, so RunOnce
// never needs to enroll.
func buildTestAgent(t *testing.T, runner platform.CommandRunner, clock *fake.Clock) *agent {
	t.Helper()
	fsys := fake.NewFS()

	cfg := config.Config{CollectionURL: "https://collect.example.com", EnrollmentToken: "tok"}
	cfgData, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	fsys.Seed(config.Path("windows"), cfgData)

	st := state.State{DeviceID: "d1", DeviceSecret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	stData, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("failed to marshal state: %v", err)
	}
	fsys.Seed(state.StatePath("windows"), stData)

	a, err := newAgent(agentEnv{
		FS:         fsys,
		Runner:     runner,
		Clock:      clock,
		Doer:       fake.NewHTTPDoer(),
		GOOS:       "windows",
		ConfigPath: config.Path("windows"),
		StatePath:  state.StatePath("windows"),
	})
	if err != nil {
		t.Fatalf("newAgent failed: %v", err)
	}
	a.deps.CollectInventory = func() (contract.Inventory, error) { return contract.Inventory{}, nil }
	a.deps.CollectPosture = func() (contract.Posture, error) { return contract.Posture{}, nil }
	a.deps.CollectAntivirusFindings = func() ([]contract.AntivirusFinding, []string) { return nil, nil }
	a.deps.AfterCheckIn = nil
	return a
}

// TestE2E_AC23_EnforceRunsDefaultsThenAntivirusThenScanner covers the
// Enforce seam's order and that CollectAntivirusScan is wired to the very
// same Scanner instance the seam runs: once a scan it started has completed,
// deps.CollectAntivirusScan reports it, which only the instance that ran the
// scan could do.
func TestE2E_AC23_EnforceRunsDefaultsThenAntivirusThenScanner(t *testing.T) {
	runner := fake.NewCommandRunner()
	// The firewall command (enforce.Defaults) and the antivirus enable
	// command both succeed outright so the cycle moves straight to the
	// scanner.
	runner.Results["powershell.exe -NoProfile -NonInteractive -Command Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"] = platform.CommandResult{}
	runner.Results[fake.Command{Name: "powershell.exe", Args: []string{"-NoProfile", "-NonInteractive", "-Command", antivirus.WindowsEnableScript}}.String()] = platform.CommandResult{Stdout: "realTimeProtectionEnabled=True\nisTamperProtected=False\n"}
	runner.Results[fake.Command{Name: "powershell.exe", Args: []string{"-NoProfile", "-NonInteractive", "-Command", antivirus.WindowsScanScript}}.String()] = platform.CommandResult{Stdout: "threatsFound=0\n"}

	clock := fake.NewClock(time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC))
	a := buildTestAgent(t, runner, clock)

	if a.deps.CollectAntivirusScan == nil {
		t.Fatal("deps.CollectAntivirusScan should be wired")
	}

	effective := map[string]any{
		"firewallEnabled":                       true,
		antivirus.SettingAntivirusEnabled:       true,
		antivirus.SettingAntivirusScanFrequency: "daily",
	}
	posture := contract.Posture{
		Firewall:  contract.Firewall{Enabled: false},
		Antivirus: contract.Antivirus{Enabled: false},
	}

	a.deps.Enforce(context.Background(), effective, posture)

	// Wait for the scanner's goroutine to record its command and persist its
	// result; the scanner is not exposed here, so this polls the shared
	// runner rather than sleeping a fixed amount.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if len(runner.Calls()) >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected 3 commands (firewall, antivirus enable, scan), got %d: %v", len(runner.Calls()), runner.Calls())
		}
		time.Sleep(time.Millisecond)
	}

	calls := runner.Calls()
	if len(calls) != 3 {
		t.Fatalf("expected exactly 3 commands, got %d: %v", len(calls), calls)
	}
	wantOrder := []string{
		"Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
		antivirus.WindowsEnableScript,
		antivirus.WindowsScanScript,
	}
	for i, want := range wantOrder {
		got := calls[i].Args[len(calls[i].Args)-1]
		if got != want {
			t.Errorf("call %d script = %q, want %q", i, got, want)
		}
	}

	// Poll for the scanner to have persisted its result in memory (its
	// goroutine still needs a moment after the command returns).
	deadline = time.Now().Add(2 * time.Second)
	for {
		if rec := a.deps.CollectAntivirusScan(); rec != nil {
			if rec.Result != "clean" {
				t.Errorf("CollectAntivirusScan() = %+v, want result clean", rec)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("deps.CollectAntivirusScan never reported the scan the Enforce seam started")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestE2E_AC23_RunOnceDoesNotBlockOnAnInFlightScan covers the second half of
// AC23: with a scan command blocked in the runner, scheduler.RunOnce still
// posts its check-in and returns.
func TestE2E_AC23_RunOnceDoesNotBlockOnAnInFlightScan(t *testing.T) {
	inner := fake.NewCommandRunner()
	runner := newBlockOnScanRunner(inner)
	t.Cleanup(func() { close(runner.release) })

	clock := fake.NewClock(time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC))
	a := buildTestAgent(t, runner, clock)

	transport := &scanWiringTransport{effectiveSettings: map[string]any{antivirus.SettingAntivirusScanFrequency: "daily"}}
	a.deps.Client = transport

	done := make(chan error, 1)
	go func() {
		done <- scheduler.RunOnce(context.Background(), a.deps)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunOnce returned an error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunOnce did not return: a blocked scan command appears to have blocked check-in")
	}

	if transport.lastCheckinBody() == nil {
		t.Fatal("expected a check-in to have been posted")
	}
}
