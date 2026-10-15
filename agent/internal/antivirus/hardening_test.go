package antivirus_test

// E2E/cucumber-style and unit tests for TASK-060, the Defender protections
// hardener (agent/internal/antivirus/hardening.go) and its six policy keys.
// Every scenario name below mirrors a Gherkin scenario in
// tasks/testing/TASK-060-defender-policy-set-to-on.md. No real PowerShell or
// Defender is ever invoked and no database is touched anywhere in this file:
// every command goes through a hand-rolled platform.CommandRunner and every
// deadline through agent/internal/platform/fake.Clock.
//
// A custom stepRunner is used instead of fake.CommandRunner because the
// hardener's read and write scripts share a command prefix
// ("powershell.exe -NoProfile -NonInteractive -Command ...") but differ in
// their full text, which fake.CommandRunner keys results by exactly; ordering
// the canned responses is simpler and mirrors the fixed sequence Apply runs
// its processes in (read, then write, then signature update).

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/antivirus"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// ----------------------------------------------------------------------------
// stepRunner: a platform.CommandRunner that replays one canned step per call,
// in order, and records every call for assertions on the exact script text.
// ----------------------------------------------------------------------------

type stepFunc func(ctx context.Context) (platform.CommandResult, error)

type stepRunner struct {
	mu    sync.Mutex
	calls []fake.Command
	steps []stepFunc
}

func newStepRunner(steps ...stepFunc) *stepRunner {
	return &stepRunner{steps: steps}
}

func (r *stepRunner) Run(ctx context.Context, name string, args ...string) (platform.CommandResult, error) {
	r.mu.Lock()
	idx := len(r.calls)
	r.calls = append(r.calls, fake.Command{Name: name, Args: append([]string(nil), args...)})
	r.mu.Unlock()

	if idx < len(r.steps) {
		return r.steps[idx](ctx)
	}
	return platform.CommandResult{}, nil
}

func (r *stepRunner) Calls() []fake.Command {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]fake.Command(nil), r.calls...)
}

// script returns the full script text of call i (the last argument).
func (r *stepRunner) script(i int) string {
	calls := r.Calls()
	if i >= len(calls) || len(calls[i].Args) == 0 {
		return ""
	}
	return calls[i].Args[len(calls[i].Args)-1]
}

// immediate returns a step that answers at once.
func immediate(out platform.CommandResult, err error) stepFunc {
	return func(context.Context) (platform.CommandResult, error) { return out, err }
}

// blocking returns a step that never answers on its own: it signals started
// once invoked and then waits for ctx to be cancelled, which runBounded does
// once the injected clock's deadline fires. This is the same shape as
// blockingScanRunner in scan_test.go.
func blocking(started chan struct{}) stepFunc {
	var once sync.Once
	return func(ctx context.Context) (platform.CommandResult, error) {
		once.Do(func() { close(started) })
		<-ctx.Done()
		return platform.CommandResult{}, ctx.Err()
	}
}

// ----------------------------------------------------------------------------
// Read-body JSON fixtures
// ----------------------------------------------------------------------------

// readOpts builds one HardeningReadScript-shaped JSON reply.
type readOpts struct {
	available   bool
	runningMode string
	tamper      bool
	age         any // nil, an int, or a non-numeric string
	prefs       map[string]any
	smart       map[string]any
	errs        map[string]any
}

// satisfiedPrefs is a Get-MpPreference reply where every predicate in the
// Description's table already holds, so nothing needs writing.
func satisfiedPrefs() map[string]any {
	return map[string]any{
		"DisableRealtimeMonitoring":    false,
		"DisableBehaviorMonitoring":    false,
		"DisableIOAVProtection":        false,
		"DisableScriptScanning":        false,
		"MAPSReporting":                2,
		"SubmitSamplesConsent":         1,
		"EnableNetworkProtection":      1,
		"EnableControlledFolderAccess": 1,
		"PUAProtection":                1,
		"SignatureUpdateInterval":      24,
		"SignatureScheduleDay":         0,
	}
}

// satisfiedSmart is a SmartScreen reply where both items already hold.
func satisfiedSmart() map[string]any {
	return map[string]any{
		"enableSmartScreen":         1,
		"shellSmartScreenLevel":     "Warn",
		"edgeSmartScreenEnabled":    1,
		"edgeSmartScreenPuaEnabled": 1,
	}
}

func defaultRead() readOpts {
	return readOpts{available: true, runningMode: "Normal", prefs: satisfiedPrefs(), smart: satisfiedSmart(), errs: map[string]any{}}
}

func (o readOpts) withPrefs(overrides map[string]any) readOpts {
	prefs := map[string]any{}
	for k, v := range o.prefs {
		prefs[k] = v
	}
	for k, v := range overrides {
		prefs[k] = v
	}
	o.prefs = prefs
	return o
}

func (o readOpts) withSmart(overrides map[string]any) readOpts {
	smart := map[string]any{}
	for k, v := range o.smart {
		smart[k] = v
	}
	for k, v := range overrides {
		smart[k] = v
	}
	o.smart = smart
	return o
}

func (o readOpts) withErrors(overrides map[string]any) readOpts {
	errs := map[string]any{}
	for k, v := range o.errs {
		errs[k] = v
	}
	for k, v := range overrides {
		errs[k] = v
	}
	o.errs = errs
	return o
}

func readStdout(t *testing.T, o readOpts) string {
	t.Helper()
	obj := map[string]any{
		"defenderAvailable":     o.available,
		"runningMode":           o.runningMode,
		"tamperProtected":       o.tamper,
		"antivirusSignatureAge": o.age,
		"preferences":           o.prefs,
		"smartScreen":           o.smart,
		"errors":                o.errs,
	}
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal read fixture: %v", err)
	}
	return string(b)
}

func readResult(t *testing.T, o readOpts) platform.CommandResult {
	return platform.CommandResult{Stdout: readStdout(t, o)}
}

// settings builds an effective-settings map with each of keys set to true.
func settings(keys ...string) map[string]any {
	m := map[string]any{}
	for _, k := range keys {
		m[k] = true
	}
	return m
}

func withRansomware(m map[string]any, mode string) map[string]any {
	m[antivirus.SettingDefenderRansomwareProtection] = mode
	return m
}

func item(t *testing.T, block *contract.DefenderHardening, name string) *contract.DefenderHardeningItem {
	t.Helper()
	if block == nil {
		t.Fatalf("Last() returned nil")
	}
	for i := range block.Items {
		if block.Items[i].Item == name {
			return &block.Items[i]
		}
	}
	t.Fatalf("item %q not found in block.Items %+v", name, block.Items)
	return nil
}

// ----------------------------------------------------------------------------
// AC: On a goos other than windows, Apply runs nothing and Last() stays nil.
// ----------------------------------------------------------------------------

func TestScenario_MacOSRunsNothing(t *testing.T) {
	runner := newStepRunner()
	clock := fake.NewClock(time.Now())
	h := antivirus.NewHardener(runner, clock, "darwin")

	effective := settings(
		antivirus.SettingDefenderRealTimeProtection,
		antivirus.SettingDefenderCloudProtection,
		antivirus.SettingDefenderNetworkProtection,
		antivirus.SettingDefenderReputationProtection,
		antivirus.SettingDefenderDailySignatureUpdate,
	)
	effective = withRansomware(effective, "block")

	if err := h.Apply(context.Background(), effective, contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if n := len(runner.Calls()); n != 0 {
		t.Fatalf("expected no command, got %d", n)
	}
	if h.Last() != nil {
		t.Fatalf("Last() = %+v, want nil", h.Last())
	}
}

// ----------------------------------------------------------------------------
// AC: Nothing required on Windows.
// ----------------------------------------------------------------------------

func TestScenario_NothingRequiredOnWindows(t *testing.T) {
	runner := newStepRunner()
	start := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	clock := fake.NewClock(start)
	h := antivirus.NewHardener(runner, clock, "windows")

	// defenderCloudProtection "true" as a string is wrong-typed: not required.
	effective := map[string]any{antivirus.SettingDefenderCloudProtection: "true"}

	if err := h.Apply(context.Background(), effective, contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if n := len(runner.Calls()); n != 0 {
		t.Fatalf("expected no command, got %d", n)
	}
	last := h.Last()
	if last == nil {
		t.Fatal("Last() returned nil")
	}
	if len(last.Items) != 0 {
		t.Errorf("items = %+v, want []", last.Items)
	}
	if last.EvaluatedAt != start.UTC().Format(time.RFC3339) {
		t.Errorf("evaluatedAt = %q, want %q", last.EvaluatedAt, start.UTC().Format(time.RFC3339))
	}
}

// ----------------------------------------------------------------------------
// AC: Everything already on runs only the read.
// ----------------------------------------------------------------------------

func TestScenario_EverythingAlreadyOnRunsOnlyRead(t *testing.T) {
	read := defaultRead()
	runner := newStepRunner(immediate(readResult(t, read), nil))
	clock := fake.NewClock(time.Now())
	h := antivirus.NewHardener(runner, clock, "windows")

	effective := settings(antivirus.SettingDefenderRealTimeProtection, antivirus.SettingDefenderCloudProtection)

	if err := h.Apply(context.Background(), effective, contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	calls := runner.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected exactly one command, got %d", len(calls))
	}
	if got := runner.script(0); got != antivirus.HardeningReadScript {
		t.Errorf("first command script = %q, want HardeningReadScript", got)
	}

	last := h.Last()
	for _, name := range []string{
		antivirus.ItemRealTimeMonitoring, antivirus.ItemBehaviorMonitoring, antivirus.ItemIOAVProtection,
		antivirus.ItemScriptScanning, antivirus.ItemMAPSReporting, antivirus.ItemSubmitSamplesConsent,
	} {
		if got := item(t, last, name).State; got != antivirus.HardeningStateOK {
			t.Errorf("%s state = %q, want ok", name, got)
		}
	}
}

// ----------------------------------------------------------------------------
// AC: Only the unsatisfied items are written and confirmed.
// ----------------------------------------------------------------------------

func TestScenario_OnlyUnsatisfiedItemsWrittenAndConfirmed(t *testing.T) {
	firstRead := defaultRead().withPrefs(map[string]any{
		"DisableScriptScanning":   true,
		"EnableNetworkProtection": 0,
	})
	writeBack := defaultRead().withPrefs(map[string]any{
		"DisableScriptScanning":   false,
		"EnableNetworkProtection": 1,
	})
	runner := newStepRunner(
		immediate(readResult(t, firstRead), nil),
		immediate(readResult(t, writeBack), nil),
	)
	clock := fake.NewClock(time.Now())
	h := antivirus.NewHardener(runner, clock, "windows")

	effective := settings(antivirus.SettingDefenderRealTimeProtection, antivirus.SettingDefenderNetworkProtection)

	if err := h.Apply(context.Background(), effective, contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	calls := runner.Calls()
	if len(calls) != 2 {
		t.Fatalf("expected exactly one write process (two calls total), got %d", len(calls))
	}
	script := runner.script(1)
	if !strings.Contains(script, "try { Set-MpPreference -DisableScriptScanning $false -ErrorAction Stop } catch { $errors['scriptScanning']") {
		t.Errorf("write script missing scriptScanning try/catch: %s", script)
	}
	if !strings.Contains(script, "try { Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop } catch { $errors['networkProtection']") {
		t.Errorf("write script missing networkProtection try/catch: %s", script)
	}
	if strings.Contains(script, "-DisableRealtimeMonitoring") {
		t.Errorf("write script should not touch a satisfied item: %s", script)
	}

	last := h.Last()
	if got := item(t, last, antivirus.ItemScriptScanning).State; got != antivirus.HardeningStateApplied {
		t.Errorf("scriptScanning state = %q, want applied", got)
	}
	if got := item(t, last, antivirus.ItemNetworkProtection).State; got != antivirus.HardeningStateApplied {
		t.Errorf("networkProtection state = %q, want applied", got)
	}
	if got := item(t, last, antivirus.ItemRealTimeMonitoring).State; got != antivirus.HardeningStateOK {
		t.Errorf("realTimeMonitoring state = %q, want ok", got)
	}
}

// ----------------------------------------------------------------------------
// AC: Tamper Protection blocks a change.
// ----------------------------------------------------------------------------

func TestScenario_TamperProtectionBlocksAChange(t *testing.T) {
	firstRead := defaultRead().withPrefs(map[string]any{"DisableRealtimeMonitoring": true})
	firstRead.tamper = true
	writeBack := defaultRead().withPrefs(map[string]any{"DisableRealtimeMonitoring": true})
	writeBack.tamper = true

	runner := newStepRunner(
		immediate(readResult(t, firstRead), nil),
		immediate(readResult(t, writeBack), nil),
	)
	clock := fake.NewClock(time.Now())
	h := antivirus.NewHardener(runner, clock, "windows")

	// Apply returns a non-nil error naming the blocked item -- tamper_blocked
	// is one of the two states AC "Apply returns a non-nil error..." names.
	err := h.Apply(context.Background(), settings(antivirus.SettingDefenderRealTimeProtection), contract.Posture{})
	if err == nil || !strings.Contains(err.Error(), "realTimeMonitoring tamper_blocked") {
		t.Fatalf("Apply error = %v, want it to name realTimeMonitoring tamper_blocked", err)
	}

	if n := len(runner.Calls()); n != 2 {
		t.Fatalf("expected exactly one write process (two calls total), got %d", n)
	}
	rtm := item(t, h.Last(), antivirus.ItemRealTimeMonitoring)
	if rtm.State != antivirus.HardeningStateTamperBlocked {
		t.Errorf("state = %q, want tamper_blocked", rtm.State)
	}
	if rtm.Detail != antivirus.HardeningDetailUnchanged {
		t.Errorf("detail = %q, want %q", rtm.Detail, antivirus.HardeningDetailUnchanged)
	}
}

// ----------------------------------------------------------------------------
// AC: A local override without Tamper Protection fails with the error text.
// ----------------------------------------------------------------------------

func TestScenario_LocalOverrideFailsWithErrorText(t *testing.T) {
	firstRead := defaultRead().withPrefs(map[string]any{"MAPSReporting": 0})
	writeBack := defaultRead().
		withPrefs(map[string]any{"MAPSReporting": 0}).
		withErrors(map[string]any{"mapsReporting": "Operation failed with 0x800106ba"})

	runner := newStepRunner(
		immediate(readResult(t, firstRead), nil),
		immediate(readResult(t, writeBack), nil),
	)
	clock := fake.NewClock(time.Now())
	h := antivirus.NewHardener(runner, clock, "windows")

	if err := h.Apply(context.Background(), settings(antivirus.SettingDefenderCloudProtection), contract.Posture{}); err == nil {
		t.Fatal("expected Apply to return an error")
	}

	mr := item(t, h.Last(), antivirus.ItemMAPSReporting)
	if mr.State != antivirus.HardeningStateFailed {
		t.Errorf("state = %q, want failed", mr.State)
	}
	if mr.Detail != "Operation failed with 0x800106ba" {
		t.Errorf("detail = %q, want the caught error text", mr.Detail)
	}
}

// ----------------------------------------------------------------------------
// AC: Stronger existing values are never weakened.
// ----------------------------------------------------------------------------

func TestScenario_StrongerExistingValuesNeverWeakened(t *testing.T) {
	firstRead := defaultRead().
		withPrefs(map[string]any{"SubmitSamplesConsent": 3, "SignatureUpdateInterval": 4}).
		withSmart(map[string]any{"shellSmartScreenLevel": "Block", "enableSmartScreen": 0})
	firstRead.age = 0 // signatures already fresh: defenderDailySignatureUpdate's signatureUpdate item is "ok" and runs no process
	writeBack := firstRead.withSmart(map[string]any{"enableSmartScreen": 1})

	runner := newStepRunner(
		immediate(readResult(t, firstRead), nil),
		immediate(readResult(t, writeBack), nil),
	)
	clock := fake.NewClock(time.Now())
	h := antivirus.NewHardener(runner, clock, "windows")

	effective := settings(
		antivirus.SettingDefenderCloudProtection,
		antivirus.SettingDefenderReputationProtection,
		antivirus.SettingDefenderDailySignatureUpdate,
	)
	if err := h.Apply(context.Background(), effective, contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	last := h.Last()
	if got := item(t, last, antivirus.ItemSubmitSamplesConsent).State; got != antivirus.HardeningStateOK {
		t.Errorf("submitSamplesConsent state = %q, want ok", got)
	}
	if got := item(t, last, antivirus.ItemSignatureUpdateInterval).State; got != antivirus.HardeningStateOK {
		t.Errorf("signatureUpdateInterval state = %q, want ok", got)
	}

	script := runner.script(1)
	if !strings.Contains(script, "Set-ItemProperty -Path $sysKey -Name EnableSmartScreen -Type DWord -Value 1") {
		t.Errorf("write script should set EnableSmartScreen to 1: %s", script)
	}
	// The read body (re-run after the writes) always mentions
	// ShellSmartScreenLevel as a read; only the write fragment matters here.
	if strings.Contains(script, "-Name ShellSmartScreenLevel") {
		t.Errorf("write script should not set ShellSmartScreenLevel when it is already Block: %s", script)
	}
	for _, forbidden := range []string{"$true", "Disabled"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("write script must never contain %q: %s", forbidden, script)
		}
	}
	if strings.Contains(script, "-Value 0") {
		t.Errorf("write script must never write a registry value of 0: %s", script)
	}
}

// ----------------------------------------------------------------------------
// AC: Controlled Folder Access mode (Scenario Outline).
// ----------------------------------------------------------------------------

func TestScenario_ControlledFolderAccessMode(t *testing.T) {
	cases := []struct {
		mode     string
		current  int
		state    string
		runs     bool
		contains string
	}{
		{"block", 1, antivirus.HardeningStateOK, false, ""},
		{"block", 2, antivirus.HardeningStateApplied, true, "-EnableControlledFolderAccess Enabled"},
		{"block", 3, antivirus.HardeningStateApplied, true, "-EnableControlledFolderAccess Enabled"},
		{"block", 4, antivirus.HardeningStateApplied, true, "-EnableControlledFolderAccess Enabled"},
		{"audit", 1, antivirus.HardeningStateOK, false, ""},
		{"audit", 2, antivirus.HardeningStateOK, false, ""},
		{"audit", 3, antivirus.HardeningStateOK, false, ""},
		{"audit", 4, antivirus.HardeningStateApplied, true, "-EnableControlledFolderAccess AuditMode"},
	}

	for _, tc := range cases {
		t.Run(tc.mode+"_"+string(rune('0'+tc.current)), func(t *testing.T) {
			firstRead := defaultRead().withPrefs(map[string]any{"EnableControlledFolderAccess": tc.current})
			writeBack := defaultRead().withPrefs(map[string]any{"EnableControlledFolderAccess": 1})
			var runner *stepRunner
			if tc.runs {
				runner = newStepRunner(immediate(readResult(t, firstRead), nil), immediate(readResult(t, writeBack), nil))
			} else {
				runner = newStepRunner(immediate(readResult(t, firstRead), nil))
			}
			clock := fake.NewClock(time.Now())
			h := antivirus.NewHardener(runner, clock, "windows")

			effective := withRansomware(map[string]any{}, tc.mode)
			if err := h.Apply(context.Background(), effective, contract.Posture{}); err != nil && tc.state != antivirus.HardeningStateFailed {
				t.Fatalf("Apply returned an error: %v", err)
			}

			cfa := item(t, h.Last(), antivirus.ItemControlledFolderAccess)
			if cfa.State != tc.state {
				t.Errorf("state = %q, want %q", cfa.State, tc.state)
			}
			calls := runner.Calls()
			if tc.runs {
				if len(calls) != 2 {
					t.Fatalf("expected a write process, got %d calls", len(calls))
				}
				if !strings.Contains(runner.script(1), tc.contains) {
					t.Errorf("write script = %q, want it to contain %q", runner.script(1), tc.contains)
				}
			} else if len(calls) != 1 {
				t.Fatalf("expected no write process, got %d calls", len(calls))
			}
		})
	}
}

// ----------------------------------------------------------------------------
// AC: Defender in passive mode skips Defender items but applies SmartScreen.
// ----------------------------------------------------------------------------

func TestScenario_PassiveModeSkipsDefenderButAppliesSmartScreen(t *testing.T) {
	firstRead := defaultRead()
	firstRead.runningMode = "Passive Mode"
	firstRead = firstRead.withSmart(map[string]any{"enableSmartScreen": nil})
	writeBack := firstRead.withSmart(map[string]any{"enableSmartScreen": 1})

	runner := newStepRunner(
		immediate(readResult(t, firstRead), nil),
		immediate(readResult(t, writeBack), nil),
	)
	clock := fake.NewClock(time.Now())
	h := antivirus.NewHardener(runner, clock, "windows")

	effective := settings(antivirus.SettingDefenderRealTimeProtection, antivirus.SettingDefenderReputationProtection)
	if err := h.Apply(context.Background(), effective, contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	last := h.Last()
	rtm := item(t, last, antivirus.ItemRealTimeMonitoring)
	if rtm.State != antivirus.HardeningStateNotApplicable || rtm.Detail != antivirus.HardeningDetailDefenderPassive {
		t.Errorf("realTimeMonitoring = %+v, want not_applicable/defender_passive", rtm)
	}
	pua := item(t, last, antivirus.ItemPUAProtection)
	if pua.State != antivirus.HardeningStateNotApplicable || pua.Detail != antivirus.HardeningDetailDefenderPassive {
		t.Errorf("puaProtection = %+v, want not_applicable/defender_passive", pua)
	}
	for _, call := range runner.Calls() {
		script := call.Args[len(call.Args)-1]
		if strings.Contains(script, "Set-MpPreference") || strings.Contains(script, "Update-MpSignature") {
			t.Errorf("no command should touch Set-MpPreference/Update-MpSignature in passive mode: %s", script)
		}
	}
	sw := item(t, last, antivirus.ItemSmartScreenWindows)
	if sw.State != antivirus.HardeningStateApplied {
		t.Errorf("smartScreenWindows = %+v, want applied", sw)
	}
}

// ----------------------------------------------------------------------------
// AC: Defender unavailable.
// ----------------------------------------------------------------------------

func TestScenario_DefenderUnavailable(t *testing.T) {
	read := defaultRead()
	read.available = false
	runner := newStepRunner(immediate(readResult(t, read), nil))
	clock := fake.NewClock(time.Now())
	h := antivirus.NewHardener(runner, clock, "windows")

	err := h.Apply(context.Background(), settings(antivirus.SettingDefenderDailySignatureUpdate), contract.Posture{})
	if err != nil {
		t.Fatalf("Apply returned an error, want nil: %v", err)
	}

	last := h.Last()
	for _, name := range []string{antivirus.ItemSignatureUpdateInterval, antivirus.ItemSignatureScheduleDay, antivirus.ItemSignatureUpdate} {
		it := item(t, last, name)
		if it.State != antivirus.HardeningStateNotApplicable || it.Detail != antivirus.HardeningDetailDefenderUnavailable {
			t.Errorf("%s = %+v, want not_applicable/defender_unavailable", name, it)
		}
	}
}

// ----------------------------------------------------------------------------
// AC: Read process failure (Scenario Outline).
// ----------------------------------------------------------------------------

func TestScenario_ReadProcessFailure(t *testing.T) {
	cases := []struct {
		name   string
		step   stepFunc
		detail string
	}{
		{"fails to start", immediate(platform.CommandResult{}, errors.New("exec: not found")), antivirus.HardeningDetailReadFailed},
		{"exits with code 1", immediate(platform.CommandResult{ExitCode: 1}, nil), antivirus.HardeningDetailReadFailed},
		{"prints not json", immediate(platform.CommandResult{Stdout: "not json"}, nil), antivirus.HardeningDetailUnparseable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := newStepRunner(tc.step)
			clock := fake.NewClock(time.Now())
			h := antivirus.NewHardener(runner, clock, "windows")

			err := h.Apply(context.Background(), settings(antivirus.SettingDefenderNetworkProtection), contract.Posture{})
			if err == nil {
				t.Fatal("expected Apply to return an error")
			}
			if !strings.Contains(err.Error(), "networkProtection") {
				t.Errorf("error = %q, want it to name networkProtection", err.Error())
			}
			if n := len(runner.Calls()); n != 1 {
				t.Errorf("expected no further command, got %d calls", n)
			}
			np := item(t, h.Last(), antivirus.ItemNetworkProtection)
			if np.State != antivirus.HardeningStateFailed || np.Detail != tc.detail {
				t.Errorf("networkProtection = %+v, want failed/%s", np, tc.detail)
			}
		})
	}
}

// TestScenario_ReadProcessTimeout covers "does not answer within 60s" (its own
// test since it needs the injected clock to pass HardeningTimeout, like
// scan_test.go's AC14 timeout case).
func TestScenario_ReadProcessTimeout(t *testing.T) {
	started := make(chan struct{})
	runner := newStepRunner(blocking(started))
	clock := fake.NewClock(time.Now())
	h := antivirus.NewHardener(runner, clock, "windows")

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Apply(context.Background(), settings(antivirus.SettingDefenderNetworkProtection), contract.Posture{})
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("read command was never started")
	}
	clock.Advance(antivirus.HardeningTimeout)

	var err error
	select {
	case err = <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Apply never returned")
	}
	if err == nil || !strings.Contains(err.Error(), "networkProtection") {
		t.Fatalf("Apply error = %v, want it to name networkProtection", err)
	}
	np := item(t, h.Last(), antivirus.ItemNetworkProtection)
	if np.State != antivirus.HardeningStateFailed || np.Detail != antivirus.HardeningDetailTimeout {
		t.Errorf("networkProtection = %+v, want failed/timeout", np)
	}
	if n := len(runner.Calls()); n != 1 {
		t.Errorf("expected no further command, got %d calls", n)
	}
}

// ----------------------------------------------------------------------------
// AC: Write process failure (fails to start / exits non-zero / unparseable).
// The timeout case is covered separately below since it needs the injected
// clock to pass HardeningTimeout.
// ----------------------------------------------------------------------------

func TestScenario_WriteProcessFailure(t *testing.T) {
	cases := []struct {
		name   string
		step   stepFunc
		detail string
	}{
		{"fails to start", immediate(platform.CommandResult{}, errors.New("exec: not found")), antivirus.HardeningDetailWriteFailed},
		{"exits with code 1", immediate(platform.CommandResult{ExitCode: 1}, nil), antivirus.HardeningDetailWriteFailed},
		{"prints not json", immediate(platform.CommandResult{Stdout: "not json"}, nil), antivirus.HardeningDetailUnparseable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			firstRead := defaultRead().withPrefs(map[string]any{"EnableNetworkProtection": 0})
			runner := newStepRunner(immediate(readResult(t, firstRead), nil), tc.step)
			clock := fake.NewClock(time.Now())
			h := antivirus.NewHardener(runner, clock, "windows")

			effective := settings(antivirus.SettingDefenderNetworkProtection, antivirus.SettingDefenderCloudProtection)
			err := h.Apply(context.Background(), effective, contract.Posture{})
			if err == nil {
				t.Fatal("expected Apply to return an error")
			}
			np := item(t, h.Last(), antivirus.ItemNetworkProtection)
			if np.State != antivirus.HardeningStateFailed || np.Detail != tc.detail {
				t.Errorf("networkProtection = %+v, want failed/%s", np, tc.detail)
			}
			// Items satisfied in the first read stay ok (mapsReporting and
			// submitSamplesConsent were already satisfied by defaultRead()).
			if got := item(t, h.Last(), antivirus.ItemMAPSReporting).State; got != antivirus.HardeningStateOK {
				t.Errorf("mapsReporting state = %q, want ok", got)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// AC: Write process times out.
// ----------------------------------------------------------------------------

func TestScenario_WriteProcessTimesOut(t *testing.T) {
	firstRead := defaultRead().withPrefs(map[string]any{"EnableNetworkProtection": 0})
	started := make(chan struct{})
	runner := newStepRunner(immediate(readResult(t, firstRead), nil), blocking(started))
	clock := fake.NewClock(time.Now())
	h := antivirus.NewHardener(runner, clock, "windows")

	effective := settings(antivirus.SettingDefenderNetworkProtection, antivirus.SettingDefenderCloudProtection)

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Apply(context.Background(), effective, contract.Posture{})
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("write command was never started")
	}
	clock.Advance(antivirus.HardeningTimeout)

	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Apply never returned")
	}

	last := h.Last()
	np := item(t, last, antivirus.ItemNetworkProtection)
	if np.State != antivirus.HardeningStateFailed || np.Detail != antivirus.HardeningDetailTimeout {
		t.Errorf("networkProtection = %+v, want failed/timeout", np)
	}
	if got := item(t, last, antivirus.ItemMAPSReporting).State; got != antivirus.HardeningStateOK {
		t.Errorf("mapsReporting state = %q, want ok", got)
	}
	if got := item(t, last, antivirus.ItemSubmitSamplesConsent).State; got != antivirus.HardeningStateOK {
		t.Errorf("submitSamplesConsent state = %q, want ok", got)
	}
}

// ----------------------------------------------------------------------------
// AC: Signature updates.
// ----------------------------------------------------------------------------

func TestScenario_FreshSignaturesNeedNoUpdate(t *testing.T) {
	read := defaultRead()
	read.age = 0
	runner := newStepRunner(immediate(readResult(t, read), nil))
	clock := fake.NewClock(time.Now())
	h := antivirus.NewHardener(runner, clock, "windows")

	if err := h.Apply(context.Background(), settings(antivirus.SettingDefenderDailySignatureUpdate), contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if n := len(runner.Calls()); n != 1 {
		t.Fatalf("expected no Update-MpSignature command, got %d calls", n)
	}
	if got := item(t, h.Last(), antivirus.ItemSignatureUpdate).State; got != antivirus.HardeningStateOK {
		t.Errorf("signatureUpdate state = %q, want ok", got)
	}
}

func TestScenario_StaleSignaturesAreUpdated(t *testing.T) {
	read := defaultRead()
	read.age = 2
	runner := newStepRunner(
		immediate(readResult(t, read), nil),
		immediate(platform.CommandResult{Stdout: "antivirusSignatureAge=0\n"}, nil),
	)
	clock := fake.NewClock(time.Now())
	h := antivirus.NewHardener(runner, clock, "windows")

	if err := h.Apply(context.Background(), settings(antivirus.SettingDefenderDailySignatureUpdate), contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if n := len(runner.Calls()); n != 2 {
		t.Fatalf("expected exactly one Update-MpSignature process, got %d calls", n)
	}
	if got := runner.script(1); got != antivirus.SignatureUpdateScript {
		t.Errorf("second command script = %q, want SignatureUpdateScript", got)
	}
	if got := item(t, h.Last(), antivirus.ItemSignatureUpdate).State; got != antivirus.HardeningStateApplied {
		t.Errorf("signatureUpdate state = %q, want applied", got)
	}
}

func TestScenario_SignatureUpdateTimesOut(t *testing.T) {
	read := defaultRead()
	read.age = 1
	started := make(chan struct{})
	runner := newStepRunner(immediate(readResult(t, read), nil), blocking(started))
	clock := fake.NewClock(time.Now())
	h := antivirus.NewHardener(runner, clock, "windows")

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Apply(context.Background(), settings(antivirus.SettingDefenderDailySignatureUpdate), contract.Posture{})
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("update command was never started")
	}
	clock.Advance(antivirus.SignatureUpdateTimeout)

	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Apply never returned")
	}

	su := item(t, h.Last(), antivirus.ItemSignatureUpdate)
	if su.State != antivirus.HardeningStateFailed || su.Detail != antivirus.HardeningDetailTimeout {
		t.Errorf("signatureUpdate = %+v, want failed/timeout", su)
	}
}

func TestScenario_MissingOrNonNumericSignatureAgeTriggersUpdate(t *testing.T) {
	cases := []struct {
		name string
		age  any
	}{
		{"missing", nil},
		{"unknown", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			read := defaultRead()
			read.age = tc.age
			runner := newStepRunner(
				immediate(readResult(t, read), nil),
				immediate(platform.CommandResult{Stdout: "antivirusSignatureAge=0\n"}, nil),
			)
			clock := fake.NewClock(time.Now())
			h := antivirus.NewHardener(runner, clock, "windows")

			if err := h.Apply(context.Background(), settings(antivirus.SettingDefenderDailySignatureUpdate), contract.Posture{}); err != nil {
				t.Fatalf("Apply returned an error: %v", err)
			}
			if n := len(runner.Calls()); n != 2 {
				t.Fatalf("expected exactly one Update-MpSignature process, got %d calls", n)
			}
			if got := item(t, h.Last(), antivirus.ItemSignatureUpdate).State; got != antivirus.HardeningStateApplied {
				t.Errorf("signatureUpdate state = %q, want applied", got)
			}
		})
	}
}

func TestScenario_SignatureUpdateOutputWithoutParseableAge(t *testing.T) {
	read := defaultRead()
	read.age = 2
	runner := newStepRunner(
		immediate(readResult(t, read), nil),
		immediate(platform.CommandResult{Stdout: "done\n"}, nil),
	)
	clock := fake.NewClock(time.Now())
	h := antivirus.NewHardener(runner, clock, "windows")

	if err := h.Apply(context.Background(), settings(antivirus.SettingDefenderDailySignatureUpdate), contract.Posture{}); err == nil {
		t.Fatal("expected Apply to return an error")
	}
	su := item(t, h.Last(), antivirus.ItemSignatureUpdate)
	if su.State != antivirus.HardeningStateFailed || su.Detail != antivirus.HardeningDetailUnparseable {
		t.Errorf("signatureUpdate = %+v, want failed/unparseable", su)
	}
}

// ----------------------------------------------------------------------------
// AC: Failed signature update waits four hours.
// ----------------------------------------------------------------------------

func TestScenario_FailedSignatureUpdateWaitsFourHours(t *testing.T) {
	start := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
	clock := fake.NewClock(start)
	read := defaultRead()
	read.age = 1

	runner := newStepRunner(
		immediate(readResult(t, read), nil),
		immediate(platform.CommandResult{ExitCode: 1}, nil), // the failed update at 10:00:00Z
	)
	h := antivirus.NewHardener(runner, clock, "windows")

	if err := h.Apply(context.Background(), settings(antivirus.SettingDefenderDailySignatureUpdate), contract.Posture{}); err == nil {
		t.Fatal("expected the first Apply to return an error (the update failed)")
	}
	if n := len(runner.Calls()); n != 2 {
		t.Fatalf("expected the read and the failed update, got %d calls", n)
	}

	// When Apply runs at 12:00:00Z with antivirusSignatureAge still 1. Apply
	// returns nil here: "waiting" is not one of the two states ("failed",
	// "tamper_blocked") that make Apply return a non-nil error.
	clock.Advance(2 * time.Hour)
	runner.steps = append(runner.steps, immediate(readResult(t, read), nil))
	if err := h.Apply(context.Background(), settings(antivirus.SettingDefenderDailySignatureUpdate), contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error while waiting, want nil: %v", err)
	}
	if n := len(runner.Calls()); n != 3 {
		t.Fatalf("expected no Update-MpSignature command while waiting, got %d calls", n)
	}
	su := item(t, h.Last(), antivirus.ItemSignatureUpdate)
	if su.State != antivirus.HardeningStateWaiting {
		t.Errorf("state = %q, want waiting", su.State)
	}
	wantDetail := "next attempt after " + start.Add(4*time.Hour).UTC().Format(time.RFC3339)
	if su.Detail != wantDetail {
		t.Errorf("detail = %q, want %q", su.Detail, wantDetail)
	}

	// The first Apply at or after 4 hours runs it again.
	clock.Advance(2 * time.Hour)
	runner.steps = append(runner.steps,
		immediate(readResult(t, read), nil),
		immediate(platform.CommandResult{Stdout: "antivirusSignatureAge=0\n"}, nil),
	)
	if err := h.Apply(context.Background(), settings(antivirus.SettingDefenderDailySignatureUpdate), contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if n := len(runner.Calls()); n != 5 {
		t.Fatalf("expected one Update-MpSignature command to have run, got %d calls", n)
	}
}

// ----------------------------------------------------------------------------
// AC: Apply error names failed and blocked items only.
// ----------------------------------------------------------------------------

// TestScenario_ApplyErrorNamesFailedAndBlockedItemsOnly covers the AC
// "Apply returns a non-nil error whose message names every item in state
// failed or tamper_blocked ... It returns nil when all items are ok, applied,
// not_applicable or waiting." tamperProtected is false throughout, since
// IsTamperProtected is one computer-wide flag the read reports once: when it
// is true every unsatisfied Defender-preference item in that same Apply
// becomes tamper_blocked (covered by TestScenario_TamperProtectionBlocksAChange),
// so a single read cannot itself produce one item tamper_blocked and a
// different Defender-preference item failed. This scenario instead checks the
// other half of the same naming rule: a failed item is named together with its
// state and caught error text, while ok and applied items in the very same
// Apply are not mentioned at all.
func TestScenario_ApplyErrorNamesFailedAndBlockedItemsOnly(t *testing.T) {
	firstRead := defaultRead().withPrefs(map[string]any{
		"EnableNetworkProtection": 0,
		"MAPSReporting":           0,
	})
	writeBack := defaultRead().
		withPrefs(map[string]any{
			"EnableNetworkProtection": 0, // still 0: failed
			"MAPSReporting":           2, // now satisfied: applied
		}).
		withErrors(map[string]any{"networkProtection": "boom"})

	runner := newStepRunner(immediate(readResult(t, firstRead), nil), immediate(readResult(t, writeBack), nil))
	clock := fake.NewClock(time.Now())
	h := antivirus.NewHardener(runner, clock, "windows")

	// realTimeMonitoring is already satisfied (ok) by the default prefs, so
	// its item should never appear in the error either.
	effective := settings(
		antivirus.SettingDefenderRealTimeProtection,
		antivirus.SettingDefenderNetworkProtection,
		antivirus.SettingDefenderCloudProtection,
	)
	err := h.Apply(context.Background(), effective, contract.Posture{})
	if err == nil {
		t.Fatal("expected Apply to return an error")
	}
	if !strings.Contains(err.Error(), "networkProtection failed") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "networkProtection failed")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("error = %q, want it to contain the caught error text", err.Error())
	}
	for _, excluded := range []string{"mapsReporting", "realTimeMonitoring", "behaviorMonitoring"} {
		if strings.Contains(err.Error(), excluded) {
			t.Errorf("error = %q, should not mention ok/applied item %q", err.Error(), excluded)
		}
	}

	if got := item(t, h.Last(), antivirus.ItemMAPSReporting).State; got != antivirus.HardeningStateApplied {
		t.Errorf("mapsReporting state = %q, want applied", got)
	}
}

// ----------------------------------------------------------------------------
// AC: Idempotent next cycle.
// ----------------------------------------------------------------------------

func TestScenario_IdempotentNextCycle(t *testing.T) {
	firstRead := defaultRead().withPrefs(map[string]any{"EnableNetworkProtection": 0})
	writeBack := defaultRead().withPrefs(map[string]any{"EnableNetworkProtection": 1})
	secondRead := defaultRead().withPrefs(map[string]any{"EnableNetworkProtection": 1})

	runner := newStepRunner(immediate(readResult(t, firstRead), nil), immediate(readResult(t, writeBack), nil))
	clock := fake.NewClock(time.Now())
	h := antivirus.NewHardener(runner, clock, "windows")

	effective := settings(antivirus.SettingDefenderNetworkProtection)
	if err := h.Apply(context.Background(), effective, contract.Posture{}); err != nil {
		t.Fatalf("first Apply returned an error: %v", err)
	}
	if got := item(t, h.Last(), antivirus.ItemNetworkProtection).State; got != antivirus.HardeningStateApplied {
		t.Fatalf("first Apply networkProtection = %q, want applied", got)
	}

	runner.steps = append(runner.steps, immediate(readResult(t, secondRead), nil))
	if err := h.Apply(context.Background(), effective, contract.Posture{}); err != nil {
		t.Fatalf("second Apply returned an error: %v", err)
	}
	if n := len(runner.Calls()); n != 3 {
		t.Fatalf("expected exactly one command on the second Apply, got %d total calls", n)
	}
	if got := item(t, h.Last(), antivirus.ItemNetworkProtection).State; got != antivirus.HardeningStateOK {
		t.Errorf("second Apply networkProtection = %q, want ok", got)
	}
}

// ----------------------------------------------------------------------------
// AC: Last() block in fixed order.
// ----------------------------------------------------------------------------

func TestScenario_LastBlockFixedOrder(t *testing.T) {
	runner := newStepRunner()
	clock := fake.NewClock(time.Now())
	h := antivirus.NewHardener(runner, clock, "windows")
	if h.Last() != nil {
		t.Fatal("Last() before any Apply should be nil")
	}

	read := defaultRead()
	read.age = 0
	runner.steps = append(runner.steps, immediate(readResult(t, read), nil))

	effective := settings(
		antivirus.SettingDefenderRealTimeProtection,
		antivirus.SettingDefenderCloudProtection,
		antivirus.SettingDefenderNetworkProtection,
		antivirus.SettingDefenderReputationProtection,
		antivirus.SettingDefenderDailySignatureUpdate,
	)
	effective = withRansomware(effective, "block")

	if err := h.Apply(context.Background(), effective, contract.Posture{}); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	want := []string{
		"realTimeMonitoring", "behaviorMonitoring", "ioavProtection", "scriptScanning",
		"mapsReporting", "submitSamplesConsent", "networkProtection", "controlledFolderAccess",
		"puaProtection", "smartScreenWindows", "smartScreenEdge",
		"signatureUpdateInterval", "signatureScheduleDay", "signatureUpdate",
	}
	last := h.Last()
	if len(last.Items) != len(want) {
		t.Fatalf("items = %+v, want %d entries", last.Items, len(want))
	}
	for i, name := range want {
		if last.Items[i].Item != name {
			t.Errorf("items[%d] = %q, want %q", i, last.Items[i].Item, name)
		}
	}
}
