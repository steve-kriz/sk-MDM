package antivirus

// E2E/cucumber-style and unit tests for TASK-055 Part B's agent scanner
// (AC12-AC21). This file is in package antivirus (white-box) because it needs
// the unexported wait() method to observe a background scan finishing without
// sleeping. Every command goes through agent/internal/platform/fake -- no
// real PowerShell or Defender is ever invoked, and no database is touched.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

const scanTestPath = "/ProgramData/OfficeHQ/MDM/antivirus-scan.json"

func scanArgs() []string {
	return []string{"-NoProfile", "-NonInteractive", "-Command", WindowsScanScript}
}

func scanCommandKey() string {
	return fake.Command{Name: "powershell.exe", Args: scanArgs()}.String()
}

func dailySettings() map[string]any {
	return map[string]any{SettingAntivirusScanFrequency: "daily"}
}

// scanRunnerResult is what a blockingScanRunner call unblocks to.
type scanRunnerResult struct {
	out platform.CommandResult
	err error
}

// blockingScanRunner blocks every Run call until release is sent to, or ctx is
// cancelled, so a test can observe a scan that is still running and control
// exactly when it finishes. The fake.CommandRunner cannot do this, since it
// always returns immediately.
type blockingScanRunner struct {
	calls   int32
	started chan struct{}
	release chan scanRunnerResult
	once    sync.Once
}

func newBlockingScanRunner() *blockingScanRunner {
	return &blockingScanRunner{started: make(chan struct{}), release: make(chan scanRunnerResult, 1)}
}

func (r *blockingScanRunner) Run(ctx context.Context, name string, args ...string) (platform.CommandResult, error) {
	atomic.AddInt32(&r.calls, 1)
	r.once.Do(func() { close(r.started) })
	select {
	case res := <-r.release:
		return res.out, res.err
	case <-ctx.Done():
		return platform.CommandResult{}, ctx.Err()
	}
}

func (r *blockingScanRunner) callCount() int32 { return atomic.LoadInt32(&r.calls) }

// TestScenario_AC12_DueScanStartsInBackground covers a due scan starting on a
// goroutine while Apply returns immediately.
func TestScenario_AC12_DueScanStartsInBackground(t *testing.T) {
	runner := newBlockingScanRunner()
	clock := fake.NewClock(time.Now())
	fsys := fake.NewFS()
	s := NewScanner(runner, clock, fsys, "windows", nil, scanTestPath)

	// When Scanner.Apply is called with {"antivirusScanFrequency": "daily"}
	if err := s.Apply(context.Background(), dailySettings(), contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	// Then Apply returns nil while the scan command is still running
	select {
	case <-runner.started:
	case <-time.After(2 * time.Second):
		t.Fatal("scan command was never started")
	}
	if n := runner.callCount(); n != 1 {
		t.Fatalf("expected exactly one scan command, got %d", n)
	}

	// Clean up: release the blocked command and let the scan finish.
	runner.release <- scanRunnerResult{out: platform.CommandResult{Stdout: "threatsFound=0\n"}}
	s.wait()
}

// TestScenario_AC13_ExactScanCommand covers the exact command text AC13
// requires.
func TestScenario_AC13_ExactScanCommand(t *testing.T) {
	want := `$start = Get-Date; ` +
		`Start-MpScan -ScanType QuickScan -ErrorAction Stop; ` +
		`$n = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -ge $start }).Count; ` +
		`"threatsFound=$n"`
	if WindowsScanScript != want {
		t.Fatalf("WindowsScanScript =\n%q\nwant\n%q", WindowsScanScript, want)
	}

	runner := fake.NewCommandRunner()
	runner.Results[scanCommandKey()] = platform.CommandResult{Stdout: "threatsFound=0\n"}
	clock := fake.NewClock(time.Now())
	fsys := fake.NewFS()
	s := NewScanner(runner, clock, fsys, "windows", nil, scanTestPath)

	if err := s.Apply(context.Background(), dailySettings(), contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	s.wait()

	calls := runner.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected exactly one runner call, got %d: %v", len(calls), calls)
	}
	if calls[0].Name != "powershell.exe" {
		t.Errorf("command name = %q, want powershell.exe", calls[0].Name)
	}
	if len(calls[0].Args) == 0 || calls[0].Args[len(calls[0].Args)-1] != want {
		t.Errorf("command script = %v, want it to end with the exact WindowsScanScript text", calls[0].Args)
	}
}

// TestScenario_AC14_ScanOutcomesMapToResults covers every outcome in AC14's
// table except timeout, which needs the injected clock to pass ScanTimeout
// and is covered separately below.
func TestScenario_AC14_ScanOutcomesMapToResults(t *testing.T) {
	cases := []struct {
		name       string
		result     platform.CommandResult
		runnerErr  error
		wantResult string
		wantCount  int
		wantDetail string
	}{
		{name: "clean", result: platform.CommandResult{Stdout: "threatsFound=0\n"}, wantResult: ScanResultClean, wantCount: 0},
		{name: "threats found", result: platform.CommandResult{Stdout: "threatsFound=3\n"}, wantResult: ScanResultThreatsFound, wantCount: 3},
		{name: "exit code 2", result: platform.CommandResult{ExitCode: 2}, wantResult: ScanResultFailed, wantDetail: "exit code 2"},
		{name: "unparseable output", result: platform.CommandResult{Stdout: "garbage\n"}, wantResult: ScanResultFailed, wantDetail: "unparseable output"},
		{name: "runner error", runnerErr: errors.New("access denied"), wantResult: ScanResultFailed, wantDetail: "access denied"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := fake.NewCommandRunner()
			if tc.runnerErr != nil {
				runner.Errors[scanCommandKey()] = tc.runnerErr
			} else {
				runner.Results[scanCommandKey()] = tc.result
			}
			start := time.Date(2026, 10, 11, 1, 0, 0, 0, time.UTC)
			clock := fake.NewClock(start)
			fsys := fake.NewFS()
			s := NewScanner(runner, clock, fsys, "windows", nil, scanTestPath)

			if err := s.Apply(context.Background(), dailySettings(), contract.Posture{}); err != nil {
				t.Fatalf("Apply returned an error: %v", err)
			}
			s.wait()

			last := s.Last()
			if last == nil {
				t.Fatal("Last() returned nil")
			}
			if last.Result != tc.wantResult {
				t.Errorf("result = %q, want %q", last.Result, tc.wantResult)
			}
			if last.ThreatsFound != tc.wantCount {
				t.Errorf("threatsFound = %d, want %d", last.ThreatsFound, tc.wantCount)
			}
			if last.Detail != tc.wantDetail {
				t.Errorf("detail = %q, want %q", last.Detail, tc.wantDetail)
			}
			if last.ScanType != ScanTypeQuick {
				t.Errorf("scanType = %q, want %q", last.ScanType, ScanTypeQuick)
			}
			if last.StartedAt == nil || *last.StartedAt != start.Format(time.RFC3339) {
				t.Errorf("startedAt = %v, want %s", last.StartedAt, start.Format(time.RFC3339))
			}
			if last.CompletedAt == nil {
				t.Error("completedAt should not be nil")
			}
		})
	}
}

// TestScenario_AC14_ScanTimesOutPastTwoHours covers a scan that runs past
// ScanTimeout on the injected clock: result timeout, and the command's
// context is cancelled (observed by the blocking runner unblocking on its
// own ctx, with no result ever sent to it).
func TestScenario_AC14_ScanTimesOutPastTwoHours(t *testing.T) {
	runner := newBlockingScanRunner()
	clock := fake.NewClock(time.Now())
	fsys := fake.NewFS()
	s := NewScanner(runner, clock, fsys, "windows", nil, scanTestPath)

	if err := s.Apply(context.Background(), dailySettings(), contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	select {
	case <-runner.started:
	case <-time.After(2 * time.Second):
		t.Fatal("scan command was never started")
	}

	// When the scan runs past ScanTimeout (2 hours) on the injected clock
	clock.Advance(ScanTimeout)
	s.wait()

	last := s.Last()
	if last == nil {
		t.Fatal("Last() returned nil")
	}
	if last.Result != ScanResultTimeout {
		t.Errorf("result = %q, want %q", last.Result, ScanResultTimeout)
	}
}

// TestScenario_AC15_ResultPersistedAtomically covers the state file's path
// and mode.
func TestScenario_AC15_ResultPersistedAtomically(t *testing.T) {
	runner := fake.NewCommandRunner()
	runner.Results[scanCommandKey()] = platform.CommandResult{Stdout: "threatsFound=0\n"}
	clock := fake.NewClock(time.Now())
	fsys := fake.NewFS()
	s := NewScanner(runner, clock, fsys, "windows", nil, scanTestPath)

	if err := s.Apply(context.Background(), dailySettings(), contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	s.wait()

	data, ok := fsys.Content(scanTestPath)
	if !ok {
		t.Fatalf("expected a record at %s", scanTestPath)
	}
	var record contract.AntivirusScan
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("failed to decode persisted record: %v", err)
	}
	if record.Result != ScanResultClean {
		t.Errorf("persisted result = %q, want clean", record.Result)
	}
	mode, ok := fsys.Mode(scanTestPath)
	if !ok || mode != ScanStateFileMode {
		t.Errorf("mode = %v, ok=%v, want %v", mode, ok, ScanStateFileMode)
	}

	// ScanStatePath documents the real paths for windows and darwin.
	if ScanStatePath("windows") != WindowsScanStatePath {
		t.Errorf("ScanStatePath(windows) = %q, want %q", ScanStatePath("windows"), WindowsScanStatePath)
	}
	if ScanStatePath("darwin") != DarwinScanStatePath {
		t.Errorf("ScanStatePath(darwin) = %q, want %q", ScanStatePath("darwin"), DarwinScanStatePath)
	}
}

// TestScenario_AC15_ShutdownMidScanWritesNothing covers the agent context
// being cancelled (service stop) while a scan is in flight.
func TestScenario_AC15_ShutdownMidScanWritesNothing(t *testing.T) {
	runner := newBlockingScanRunner()
	clock := fake.NewClock(time.Now())
	fsys := fake.NewFS()
	s := NewScanner(runner, clock, fsys, "windows", nil, scanTestPath)

	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Apply(ctx, dailySettings(), contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	select {
	case <-runner.started:
	case <-time.After(2 * time.Second):
		t.Fatal("scan command was never started")
	}

	// When the agent context is cancelled before the command returns
	cancel()
	s.wait()

	// Then no scan state file is written
	if _, ok := fsys.Content(scanTestPath); ok {
		t.Error("expected no scan state file to be written")
	}
	if s.Last() != nil {
		t.Error("Last() should still be nil: no record was ever persisted")
	}
}

// seedRecord writes a record whose startedAt is age before now, directly to
// fsys at scanTestPath, simulating a restart.
func seedRecord(t *testing.T, fsys *fake.FS, now time.Time, age time.Duration, result string) {
	t.Helper()
	started := now.Add(-age).Format(time.RFC3339)
	completed := now.Add(-age + time.Minute).Format(time.RFC3339)
	record := contract.AntivirusScan{ScanType: ScanTypeQuick, Result: result, StartedAt: &started, CompletedAt: &completed}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("failed to marshal seed record: %v", err)
	}
	fsys.Seed(scanTestPath, data)
}

// TestScenario_AC16_RestartDoesNotRescanWithinInterval covers a persisted
// failed scan whose interval has not yet elapsed.
func TestScenario_AC16_RestartDoesNotRescanWithinInterval(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	fsys := fake.NewFS()
	seedRecord(t, fsys, now, 23*time.Hour, ScanResultFailed)

	runner := fake.NewCommandRunner()
	clock := fake.NewClock(now)
	s := NewScanner(runner, clock, fsys, "windows", nil, scanTestPath)

	if err := s.Apply(context.Background(), dailySettings(), contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if calls := runner.Calls(); len(calls) != 0 {
		t.Errorf("expected no scan command, got %v", calls)
	}
}

// TestScenario_AC16_ScanIsDueOnceIntervalHasElapsed covers daily, weekly and
// monthly intervals, including a failed prior attempt.
func TestScenario_AC16_ScanIsDueOnceIntervalHasElapsed(t *testing.T) {
	cases := []struct {
		frequency string
		age       time.Duration
	}{
		{"daily", 24 * time.Hour},
		{"weekly", 168 * time.Hour},
		{"monthly", 720 * time.Hour},
	}

	for _, tc := range cases {
		t.Run(tc.frequency, func(t *testing.T) {
			now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
			fsys := fake.NewFS()
			seedRecord(t, fsys, now, tc.age, ScanResultTimeout)

			runner := fake.NewCommandRunner()
			runner.Results[scanCommandKey()] = platform.CommandResult{Stdout: "threatsFound=0\n"}
			clock := fake.NewClock(now)
			s := NewScanner(runner, clock, fsys, "windows", nil, scanTestPath)

			if err := s.Apply(context.Background(), map[string]any{SettingAntivirusScanFrequency: tc.frequency}, contract.Posture{}); err != nil {
				t.Fatalf("Apply returned an error: %v", err)
			}
			s.wait()

			if calls := runner.Calls(); len(calls) != 1 {
				t.Errorf("expected exactly one scan command, got %d: %v", len(calls), calls)
			}
		})
	}
}

// TestScenario_AC17_NoScanWhenFrequencyOffOrUnknown covers every value that
// must not start a scan.
func TestScenario_AC17_NoScanWhenFrequencyOffOrUnknown(t *testing.T) {
	cases := []struct {
		name     string
		settings map[string]any
	}{
		{"off", map[string]any{SettingAntivirusScanFrequency: "off"}},
		{"absent", map[string]any{}},
		{"non-string", map[string]any{SettingAntivirusScanFrequency: 7}},
		{"unknown string", map[string]any{SettingAntivirusScanFrequency: "hourly"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := fake.NewCommandRunner()
			clock := fake.NewClock(time.Now())
			fsys := fake.NewFS()
			s := NewScanner(runner, clock, fsys, "windows", nil, scanTestPath)

			if err := s.Apply(context.Background(), tc.settings, contract.Posture{}); err != nil {
				t.Fatalf("Apply returned an error: %v", err)
			}
			if calls := runner.Calls(); len(calls) != 0 {
				t.Errorf("expected no scan command, got %v", calls)
			}
		})
	}
}

// TestScenario_AC18_AtMostOneScanAtATime covers the in-flight guard across
// repeated Apply calls.
func TestScenario_AC18_AtMostOneScanAtATime(t *testing.T) {
	runner := newBlockingScanRunner()
	clock := fake.NewClock(time.Now())
	fsys := fake.NewFS()
	s := NewScanner(runner, clock, fsys, "windows", nil, scanTestPath)

	if err := s.Apply(context.Background(), dailySettings(), contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	select {
	case <-runner.started:
	case <-time.After(2 * time.Second):
		t.Fatal("scan command was never started")
	}

	// When Apply is called twice more while a scan is in flight
	if err := s.Apply(context.Background(), dailySettings(), contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if err := s.Apply(context.Background(), dailySettings(), contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	// Then the runner received exactly one scan command
	if n := runner.callCount(); n != 1 {
		t.Errorf("expected exactly one scan command, got %d", n)
	}

	runner.release <- scanRunnerResult{out: platform.CommandResult{Stdout: "threatsFound=0\n"}}
	s.wait()
}

// TestScenario_AC19_CorruptStateFileMeansNoRecord covers the exactly-one
// warning line and that a scan is still due.
func TestScenario_AC19_CorruptStateFileMeansNoRecord(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed(scanTestPath, []byte("not json"))

	logFS := fake.NewFS()
	clock := fake.NewClock(time.Now())
	logger := logging.New(logFS, clock, "/agent.log", logging.LevelDebug, "scan")

	runner := fake.NewCommandRunner()
	runner.Results[scanCommandKey()] = platform.CommandResult{Stdout: "threatsFound=0\n"}
	s := NewScanner(runner, clock, fsys, "windows", logger, scanTestPath)

	// Then exactly one warning line is logged about the scan state, at
	// construction.
	data, ok := logFS.Content("/agent.log")
	if !ok {
		t.Fatal("expected a log line to have been written")
	}
	var warnCount int
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("failed to decode log line %q: %v", line, err)
		}
		if rec["level"] == "warn" {
			warnCount++
		}
	}
	if warnCount != 1 {
		t.Errorf("expected exactly one warning line, got %d", warnCount)
	}

	// And exactly one scan command is run, since a corrupt file is no record.
	if err := s.Apply(context.Background(), dailySettings(), contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	s.wait()
	if calls := runner.Calls(); len(calls) != 1 {
		t.Errorf("expected exactly one scan command, got %d: %v", len(calls), calls)
	}
}

// TestScenario_AC20_MacOSReportsScansAsUnsupported covers the "unsupported"
// Last() record while scanning is nominally on, and nil once it is off with
// no record.
func TestScenario_AC20_MacOSReportsScansAsUnsupported(t *testing.T) {
	runner := fake.NewCommandRunner()
	clock := fake.NewClock(time.Now())
	fsys := fake.NewFS()
	s := NewScanner(runner, clock, fsys, "darwin", nil, scanTestPath)

	// When Scanner.Apply is called with {"antivirusScanFrequency": "weekly"}
	if err := s.Apply(context.Background(), map[string]any{SettingAntivirusScanFrequency: "weekly"}, contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	// Then no command is run
	if calls := runner.Calls(); len(calls) != 0 {
		t.Errorf("expected no command on darwin, got %v", calls)
	}
	// And Scanner.Last() is the unsupported record
	last := s.Last()
	if last == nil {
		t.Fatal("expected a non-nil unsupported record")
	}
	if last.ScanType != ScanTypeQuick || last.Result != ScanResultUnsupported || last.StartedAt != nil ||
		last.CompletedAt != nil || last.ThreatsFound != 0 {
		t.Errorf("Last() = %+v, want {quick unsupported nil nil 0}", last)
	}

	// When Scanner.Apply is called with {"antivirusScanFrequency": "off"}
	if err := s.Apply(context.Background(), map[string]any{SettingAntivirusScanFrequency: "off"}, contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	// Then Scanner.Last() is nil
	if s.Last() != nil {
		t.Errorf("Last() = %+v, want nil", s.Last())
	}
}

// TestScenario_AC21_LastRecordReportedAfterFrequencyOff covers reporting the
// persisted record on Windows regardless of the current frequency, and a
// concurrent read against a running scan. go test -race cannot run in this
// environment (no cgo), so this only exercises the concurrent access path
// without the race detector attached.
func TestScenario_AC21_LastRecordReportedAfterFrequencyOff(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	fsys := fake.NewFS()
	seedRecord(t, fsys, now, 1*time.Hour, ScanResultThreatsFound)

	runner := newBlockingScanRunner()
	clock := fake.NewClock(now)
	s := NewScanner(runner, clock, fsys, "windows", nil, scanTestPath)

	// When Scanner.Apply is called with {"antivirusScanFrequency": "off"}
	if err := s.Apply(context.Background(), map[string]any{SettingAntivirusScanFrequency: "off"}, contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	// Then Scanner.Last() returns that record
	last := s.Last()
	if last == nil || last.Result != ScanResultThreatsFound {
		t.Fatalf("Last() = %+v, want result %q", last, ScanResultThreatsFound)
	}

	// Start a new scan (interval has elapsed: seeded 1h ago, daily due at 24h
	// would not be due, so force due with a weekly-eligible record age via a
	// fresh seed that is due).
	seedRecord(t, fsys, now.Add(-25*time.Hour), 25*time.Hour, ScanResultClean)
	s2 := NewScanner(runner, clock, fsys, "windows", nil, scanTestPath)
	if err := s2.Apply(context.Background(), dailySettings(), contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	select {
	case <-runner.started:
	case <-time.After(2 * time.Second):
		t.Fatal("scan command was never started")
	}

	// And reading Last() concurrently with a running scan does not panic or
	// deadlock (the race detector itself could not be run in this
	// environment).
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = s2.Last()
			}
		}
	}()
	time.Sleep(20 * time.Millisecond)
	close(stop)
	wg.Wait()

	runner.release <- scanRunnerResult{out: platform.CommandResult{Stdout: "threatsFound=0\n"}}
	s2.wait()
}

// TestName covers Scanner.Name().
func TestScenario_ScannerNameIsAntivirusScan(t *testing.T) {
	s := NewScanner(fake.NewCommandRunner(), fake.NewClock(time.Now()), fake.NewFS(), "windows", nil, scanTestPath)
	if s.Name() != "antivirus-scan" {
		t.Errorf("Name() = %q, want antivirus-scan", s.Name())
	}
}
