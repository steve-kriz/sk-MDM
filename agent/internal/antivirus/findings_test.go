package antivirus_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/antivirus"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// loadFixture reads one of this package's testdata files.
func loadFixture(t *testing.T, goos, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", goos, name))
	if err != nil {
		t.Fatalf("failed to load fixture %s/%s: %v", goos, name, err)
	}
	return string(data)
}

func findingsCommandKey() string {
	return fake.Command{
		Name: "powershell.exe",
		Args: []string{"-NoProfile", "-NonInteractive", "-Command", antivirus.WindowsFindingsScript},
	}.String()
}

func darwinCommandKey() string {
	return fake.Command{
		Name: antivirus.DarwinLogCommand,
		Args: []string{"show", "--style", "ndjson", "--last", antivirus.DarwinFindingsWindow, "--predicate", antivirus.DarwinFindingsPredicate},
	}.String()
}

// blockingFindingsRunner never returns, for the findings timeout path.
type blockingFindingsRunner struct {
	started chan struct{}
}

func newBlockingFindingsRunner() *blockingFindingsRunner {
	return &blockingFindingsRunner{started: make(chan struct{})}
}

func (b *blockingFindingsRunner) Run(ctx context.Context, name string, args ...string) (platform.CommandResult, error) {
	close(b.started)
	select {}
}

// TestScenario_WindowsFindingsAreParsedFromTheFixture covers the fixture, the
// command shape and the field mapping.
func TestScenario_WindowsFindingsAreParsedFromTheFixture(t *testing.T) {
	runner := fake.NewCommandRunner()
	runner.Results[findingsCommandKey()] = platform.CommandResult{
		Stdout:   loadFixture(t, "windows", "findings.txt"),
		ExitCode: 0,
	}
	clock := fake.NewClock(time.Now())

	findings, warnings := antivirus.CollectFindings(runner, clock, "windows")
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}

	calls := runner.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected exactly one runner call, got %d", len(calls))
	}
	if calls[0].String() != findingsCommandKey() {
		t.Errorf("runner call = %q, want %q", calls[0].String(), findingsCommandKey())
	}

	first := findings[0]
	if first.FindingID != "{3F2A1B4C-5D6E-4F70-8192-A3B4C5D6E7F8}" {
		t.Errorf("findingId = %q", first.FindingID)
	}
	if first.ThreatName != "Trojan:Win32/Wacatac.B!ml" {
		t.Errorf("threatName = %q", first.ThreatName)
	}
	if first.Severity != "severe" {
		t.Errorf("severity = %q, want severe", first.Severity)
	}
	if first.DetectedAt != "2026-10-02T07:15:00Z" {
		t.Errorf("detectedAt = %q", first.DetectedAt)
	}
	if len(first.Resources) != 1 || first.Resources[0] != `file:_C:\Users\a\Downloads\invoice.exe` {
		t.Errorf("resources = %v", first.Resources)
	}
	if !first.Remediated {
		t.Error("remediated should be true")
	}

	second := findings[1]
	if second.Severity != "moderate" {
		t.Errorf("second severity = %q, want moderate", second.Severity)
	}
	if second.Remediated {
		t.Error("second remediated should be false")
	}
	if len(second.Resources) != 2 {
		t.Errorf("second resources = %v", second.Resources)
	}
}

// TestScenario_WindowsFindingsScriptUsesSilentlyContinue covers the script text.
func TestScenario_WindowsFindingsScriptUsesSilentlyContinue(t *testing.T) {
	if !strings.Contains(antivirus.WindowsFindingsScript, "Get-MpThreatDetection -ErrorAction SilentlyContinue") {
		t.Errorf("WindowsFindingsScript should contain Get-MpThreatDetection -ErrorAction SilentlyContinue")
	}
	if !strings.Contains(antivirus.WindowsFindingsScript, "Get-MpThreat -ThreatID $_.ThreatID -ErrorAction SilentlyContinue") {
		t.Errorf("WindowsFindingsScript should contain Get-MpThreat -ThreatID $_.ThreatID -ErrorAction SilentlyContinue")
	}
}

// TestScenario_ThirdPartyActiveWithDefenderStoppedYieldsNoFindings covers the
// empty-stdout, exit-0 edge case the stopped Defender service produces.
func TestScenario_ThirdPartyActiveWithDefenderStoppedYieldsNoFindings(t *testing.T) {
	runner := fake.NewCommandRunner()
	runner.Results[findingsCommandKey()] = platform.CommandResult{Stdout: "", ExitCode: 0}
	clock := fake.NewClock(time.Now())

	findings, warnings := antivirus.CollectFindings(runner, clock, "windows")
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d", len(findings))
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}
}

// TestScenario_SeverityMappingAndTimestampNormalisation covers the SeverityID
// map and the UTC conversion.
func TestScenario_SeverityMappingAndTimestampNormalisation(t *testing.T) {
	cases := []struct {
		id       int
		severity string
	}{
		{1, "low"},
		{2, "moderate"},
		{4, "high"},
		{5, "severe"},
		{3, "unknown"},
		{0, "unknown"},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("severityId=%d", tc.id), func(t *testing.T) {
			line := fmt.Sprintf(`{"detectionId":"id-1","threatName":"T","severityId":%d,"detectedAt":"2026-10-02T17:15:00+10:00","resources":[],"actionSuccess":false}`, tc.id)
			runner := fake.NewCommandRunner()
			runner.Results[findingsCommandKey()] = platform.CommandResult{Stdout: line, ExitCode: 0}
			clock := fake.NewClock(time.Now())

			findings, _ := antivirus.CollectFindings(runner, clock, "windows")
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(findings))
			}
			if findings[0].Severity != tc.severity {
				t.Errorf("severity = %q, want %q", findings[0].Severity, tc.severity)
			}
			if findings[0].DetectedAt != "2026-10-02T07:15:00Z" {
				t.Errorf("detectedAt = %q, want 2026-10-02T07:15:00Z", findings[0].DetectedAt)
			}
		})
	}
}

// TestScenario_MacOSFindingsCommand covers the exact command shape.
func TestScenario_MacOSFindingsCommand(t *testing.T) {
	runner := fake.NewCommandRunner()
	clock := fake.NewClock(time.Now())

	antivirus.CollectFindings(runner, clock, "darwin")

	calls := runner.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected exactly one runner call, got %d: %v", len(calls), calls)
	}
	if calls[0].Name != antivirus.DarwinLogCommand {
		t.Errorf("command name = %q, want %q", calls[0].Name, antivirus.DarwinLogCommand)
	}
	want := []string{"show", "--style", "ndjson", "--last", "24h", "--predicate",
		`subsystem == "com.apple.XProtectFramework.PluginAPI" AND category == "XPEvent.structured"`}
	if len(calls[0].Args) != len(want) {
		t.Fatalf("args = %v, want %v", calls[0].Args, want)
	}
	for i, arg := range want {
		if calls[0].Args[i] != arg {
			t.Errorf("args[%d] = %q, want %q", i, calls[0].Args[i], arg)
		}
	}
	if antivirus.DarwinFindingsWindow != "24h" {
		t.Errorf("DarwinFindingsWindow = %q, want 24h", antivirus.DarwinFindingsWindow)
	}
}

// TestScenario_MacOSFindingsAreParsedFromTheFixture covers the fixture, the
// ordering and the field mapping, including the derived findingId.
func TestScenario_MacOSFindingsAreParsedFromTheFixture(t *testing.T) {
	runner := fake.NewCommandRunner()
	runner.Results[darwinCommandKey()] = platform.CommandResult{
		Stdout:   loadFixture(t, "darwin", "findings.ndjson"),
		ExitCode: 0,
	}
	clock := fake.NewClock(time.Now())

	findings, warnings := antivirus.CollectFindings(runner, clock, "darwin")
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}

	keysteal, sheepswap := findings[0], findings[1]
	if keysteal.ThreatName != "Keysteal" {
		t.Errorf("findings[0].ThreatName = %q, want Keysteal first", keysteal.ThreatName)
	}
	if sheepswap.ThreatName != "SheepSwap" {
		t.Errorf("findings[1].ThreatName = %q, want SheepSwap second", sheepswap.ThreatName)
	}

	sum := sha256.Sum256([]byte("2026-10-02 17:15:00.123456+1000|SheepSwap|30"))
	wantID := "xprotect-" + hex.EncodeToString(sum[:])[:32]
	if sheepswap.FindingID != wantID {
		t.Errorf("SheepSwap findingId = %q, want %q", sheepswap.FindingID, wantID)
	}
	if sheepswap.Severity != "unknown" {
		t.Errorf("SheepSwap severity = %q, want unknown", sheepswap.Severity)
	}
	if sheepswap.DetectedAt != "2026-10-02T07:15:00Z" {
		t.Errorf("SheepSwap detectedAt = %q", sheepswap.DetectedAt)
	}
	if len(sheepswap.Resources) != 1 || sheepswap.Resources[0] != "/Users/a/Library/x.app" {
		t.Errorf("SheepSwap resources = %v", sheepswap.Resources)
	}
	if !sheepswap.Remediated {
		t.Error("SheepSwap remediated should be true")
	}

	if keysteal.Remediated {
		t.Error("Keysteal remediated should be false")
	}
	if len(keysteal.Resources) != 0 {
		t.Errorf("Keysteal resources = %v, want []", keysteal.Resources)
	}
}

// TestScenario_MacOSFindingIdsAreStableAndDeduplicated covers id stability
// across collections and deduplication within one.
func TestScenario_MacOSFindingIdsAreStableAndDeduplicated(t *testing.T) {
	line := `{"timestamp":"2026-10-02 17:15:00.123456+1000","eventMessage":"{\"plugin\":\"SheepSwap\",\"status_code\":30,\"status_message\":\"Threat remediated\",\"caused_by\":[\"/a\"]}","subsystem":"com.apple.XProtectFramework.PluginAPI","category":"XPEvent.structured"}`
	stdout := line + "\n" + line

	runner1 := fake.NewCommandRunner()
	runner1.Results[darwinCommandKey()] = platform.CommandResult{Stdout: stdout, ExitCode: 0}
	clock1 := fake.NewClock(time.Now())
	findings1, _ := antivirus.CollectFindings(runner1, clock1, "darwin")
	if len(findings1) != 1 {
		t.Fatalf("expected 1 deduplicated finding, got %d", len(findings1))
	}

	runner2 := fake.NewCommandRunner()
	runner2.Results[darwinCommandKey()] = platform.CommandResult{Stdout: stdout, ExitCode: 0}
	clock2 := fake.NewClock(time.Now())
	findings2, _ := antivirus.CollectFindings(runner2, clock2, "darwin")
	if len(findings2) != 1 {
		t.Fatalf("expected 1 deduplicated finding on the second run, got %d", len(findings2))
	}

	if findings1[0].FindingID != findings2[0].FindingID {
		t.Errorf("findingId changed between runs: %q vs %q", findings1[0].FindingID, findings2[0].FindingID)
	}
}

// TestScenario_MalformedMacOSLinesAreDroppedWithOneWarning covers every drop
// reason in one collection.
func TestScenario_MalformedMacOSLinesAreDroppedWithOneWarning(t *testing.T) {
	lines := []string{
		// valid detection
		`{"timestamp":"2026-10-02 17:15:00.123456+1000","eventMessage":"{\"plugin\":\"SheepSwap\",\"status_code\":30,\"status_message\":\"Threat remediated\",\"caused_by\":[]}"}`,
		// not JSON
		`not json at all`,
		// no eventMessage
		`{"timestamp":"2026-10-02 17:16:00.000000+1000"}`,
		// eventMessage is not JSON
		`{"timestamp":"2026-10-02 17:17:00.000000+1000","eventMessage":"not json"}`,
		// event has no plugin
		`{"timestamp":"2026-10-02 17:18:00.000000+1000","eventMessage":"{\"status_code\":30}"}`,
		// status_code is a string, not an integer
		`{"timestamp":"2026-10-02 17:19:00.000000+1000","eventMessage":"{\"plugin\":\"X\",\"status_code\":\"30\"}"}`,
		// timestamp does not parse
		`{"timestamp":"yesterday","eventMessage":"{\"plugin\":\"X\",\"status_code\":30}"}`,
	}

	runner := fake.NewCommandRunner()
	runner.Results[darwinCommandKey()] = platform.CommandResult{Stdout: strings.Join(lines, "\n"), ExitCode: 0}
	clock := fake.NewClock(time.Now())

	findings, warnings := antivirus.CollectFindings(runner, clock, "darwin")
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	if len(warnings) != 1 || warnings[0] != antivirus.WarningFindingsUnparseable {
		t.Fatalf("warnings = %v, want exactly [%q]", warnings, antivirus.WarningFindingsUnparseable)
	}
}

// TestScenario_CleanXProtectScansAddNothing covers the status_code 0 path.
func TestScenario_CleanXProtectScansAddNothing(t *testing.T) {
	line := `{"timestamp":"2026-10-02 16:00:00.000000+1000","eventMessage":"{\"plugin\":\"Adload\",\"status_code\":0,\"status_message\":\"No threat detected\",\"caused_by\":[]}"}`
	runner := fake.NewCommandRunner()
	runner.Results[darwinCommandKey()] = platform.CommandResult{Stdout: line, ExitCode: 0}
	clock := fake.NewClock(time.Now())

	findings, warnings := antivirus.CollectFindings(runner, clock, "darwin")
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d", len(findings))
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}
}

// TestScenario_EmptyOutputYieldsNoFindingsKey covers both OSes: empty or
// whitespace-only stdout costs nothing, and the marshalled request has no
// antivirusFindings key.
func TestScenario_EmptyOutputYieldsNoFindingsKey(t *testing.T) {
	for _, goos := range []string{"windows", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			runner := fake.NewCommandRunner()
			key := findingsCommandKey()
			if goos == "darwin" {
				key = darwinCommandKey()
			}
			runner.Results[key] = platform.CommandResult{Stdout: "   \n  ", ExitCode: 0}
			clock := fake.NewClock(time.Now())

			findings, warnings := antivirus.CollectFindings(runner, clock, goos)
			if len(findings) != 0 {
				t.Errorf("expected zero findings, got %d", len(findings))
			}
			if len(warnings) != 0 {
				t.Errorf("expected no warnings, got %v", warnings)
			}

			req := contract.CheckInRequest{AntivirusFindings: findings}
			data, err := json.Marshal(req)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}
			if strings.Contains(string(data), "antivirusFindings") {
				t.Errorf("marshalled request should have no antivirusFindings key, got %s", data)
			}
		})
	}
}

// TestScenario_MalformedWindowsLinesAreDroppedWithOneWarning covers every drop
// reason in one collection.
func TestScenario_MalformedWindowsLinesAreDroppedWithOneWarning(t *testing.T) {
	lines := []string{
		`{"detectionId":"id-1","threatName":"T","severityId":1,"detectedAt":"2026-10-02T07:15:00Z","resources":[],"actionSuccess":true}`,
		`not json`,
		`{"detectionId":"","threatName":"T","severityId":1,"detectedAt":"2026-10-02T07:15:00Z","resources":[],"actionSuccess":true}`,
		`{"detectionId":"id-2","threatName":"T","severityId":1,"detectedAt":"yesterday","resources":[],"actionSuccess":true}`,
	}
	runner := fake.NewCommandRunner()
	runner.Results[findingsCommandKey()] = platform.CommandResult{Stdout: strings.Join(lines, "\n"), ExitCode: 0}
	clock := fake.NewClock(time.Now())

	findings, warnings := antivirus.CollectFindings(runner, clock, "windows")
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	if len(warnings) != 1 || warnings[0] != antivirus.WarningFindingsUnparseable {
		t.Fatalf("warnings = %v, want exactly [%q]", warnings, antivirus.WarningFindingsUnparseable)
	}
}

// TestScenario_FindingsProbeFailureDoesNotCostTheCheckIn covers the three
// probe-failure modes on both OSes.
func TestScenario_FindingsProbeFailureDoesNotCostTheCheckIn(t *testing.T) {
	cases := []struct {
		name    string
		goos    string
		failure string
		warning string
	}{
		{"windows cannot be started", "windows", "start", antivirus.WarningFindings},
		{"windows exits with code 1", "windows", "exit1", antivirus.WarningFindings},
		{"windows never answers", "windows", "timeout", antivirus.WarningFindingsTimeout},
		{"darwin cannot be started", "darwin", "start", antivirus.WarningFindings},
		{"darwin exits with code 1", "darwin", "exit1", antivirus.WarningFindings},
		{"darwin never answers", "darwin", "timeout", antivirus.WarningFindingsTimeout},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := findingsCommandKey()
			if tc.goos == "darwin" {
				key = darwinCommandKey()
			}

			var findings []contract.AntivirusFinding
			var warnings []string

			switch tc.failure {
			case "start":
				runner := fake.NewCommandRunner()
				runner.Errors[key] = errors.New("boom: cannot start")
				clock := fake.NewClock(time.Now())
				findings, warnings = antivirus.CollectFindings(runner, clock, tc.goos)
			case "exit1":
				runner := fake.NewCommandRunner()
				runner.Results[key] = platform.CommandResult{ExitCode: 1}
				clock := fake.NewClock(time.Now())
				findings, warnings = antivirus.CollectFindings(runner, clock, tc.goos)
			case "timeout":
				runner := newBlockingFindingsRunner()
				clock := fake.NewClock(time.Now())
				go func() {
					<-runner.started
					clock.Advance(antivirus.FindingsTimeout)
				}()
				findings, warnings = antivirus.CollectFindings(runner, clock, tc.goos)
			}

			if len(findings) != 0 {
				t.Errorf("expected zero findings, got %d", len(findings))
			}
			if len(warnings) != 1 || warnings[0] != tc.warning {
				t.Errorf("warnings = %v, want exactly [%q]", warnings, tc.warning)
			}
		})
	}
}

// longRunes returns a string of n repeated runes.
func longRunes(n int) string { return strings.Repeat("r", n) }

// TestScenario_WindowsFindingsAreBounded covers the 20-finding cap, the
// 3-resource cap, the 260-rune resource cut, the 256-rune threatName cut and
// every resources shape.
func TestScenario_WindowsFindingsAreBounded(t *testing.T) {
	type rawFinding struct {
		DetectionID   string `json:"detectionId"`
		ThreatName    string `json:"threatName"`
		SeverityID    int    `json:"severityId"`
		DetectedAt    string `json:"detectedAt"`
		Resources     any    `json:"resources"`
		ActionSuccess bool   `json:"actionSuccess"`
	}

	base := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	var lines []string
	for i := 0; i < 25; i++ {
		f := rawFinding{
			DetectionID: fmt.Sprintf("id-%02d", i),
			ThreatName:  "T",
			SeverityID:  1,
			DetectedAt:  base.Add(time.Duration(i) * time.Second).Format(time.RFC3339),
			Resources:   []string{"r"},
		}
		switch i {
		case 0:
			f.ThreatName = longRunes(300)
			f.Resources = []any{longRunes(300), "a", "b", "c", "d"}
		case 1:
			f.Resources = nil
		case 2:
			f.Resources = `C:\x.exe`
		case 3:
			f.Resources = []any{"a", 7}
		}
		data, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("marshal fixture line: %v", err)
		}
		lines = append(lines, string(data))
	}

	runner := fake.NewCommandRunner()
	runner.Results[findingsCommandKey()] = platform.CommandResult{Stdout: strings.Join(lines, "\n"), ExitCode: 0}
	clock := fake.NewClock(time.Now())

	findings, _ := antivirus.CollectFindings(runner, clock, "windows")
	if len(findings) != 20 {
		t.Fatalf("expected 20 findings, got %d", len(findings))
	}

	if len(findings[0].ThreatName) != 256 {
		t.Errorf("findings[0].ThreatName length = %d, want 256", len(findings[0].ThreatName))
	}
	if len(findings[0].Resources) != 3 {
		t.Fatalf("findings[0].Resources = %v, want 3 entries", findings[0].Resources)
	}
	if len([]rune(findings[0].Resources[0])) != 260 {
		t.Errorf("findings[0].Resources[0] rune length = %d, want 260", len([]rune(findings[0].Resources[0])))
	}

	if len(findings[1].Resources) != 0 {
		t.Errorf("findings[1].Resources = %v, want []", findings[1].Resources)
	}
	if len(findings[2].Resources) != 1 || findings[2].Resources[0] != `C:\x.exe` {
		t.Errorf(`findings[2].Resources = %v, want ["C:\x.exe"]`, findings[2].Resources)
	}
	if len(findings[3].Resources) != 1 || findings[3].Resources[0] != "a" {
		t.Errorf(`findings[3].Resources = %v, want ["a"]`, findings[3].Resources)
	}
}

// TestScenario_MacOSFindingsAreBoundedAndNewestFirst covers the darwin cap,
// ordering and resources shapes.
func TestScenario_MacOSFindingsAreBoundedAndNewestFirst(t *testing.T) {
	type event struct {
		Plugin        string `json:"plugin"`
		StatusCode    int    `json:"status_code"`
		StatusMessage string `json:"status_message"`
		CausedBy      any    `json:"caused_by"`
	}
	type entry struct {
		Timestamp    string `json:"timestamp"`
		EventMessage string `json:"eventMessage"`
	}

	base := time.Date(2026, 10, 2, 0, 0, 0, 0, time.FixedZone("+1000", 10*3600))
	marshalEvent := func(e event) string {
		data, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal event: %v", err)
		}
		return string(data)
	}

	var lines []string
	for i := 0; i < 20; i++ {
		ts := base.Add(time.Duration(i) * time.Second).Format(antivirus.DarwinTimestampLayout)
		ev := event{Plugin: fmt.Sprintf("Ordinary%02d", i), StatusCode: 10, StatusMessage: "Threat remediated", CausedBy: []string{"/ordinary"}}
		data, err := json.Marshal(entry{Timestamp: ts, EventMessage: marshalEvent(ev)})
		if err != nil {
			t.Fatalf("marshal entry: %v", err)
		}
		lines = append(lines, string(data))
	}

	special := []event{
		{Plugin: "CausedByLong", StatusCode: 10, StatusMessage: "Threat remediated", CausedBy: []any{longRunes(300), "/a", "/b", "/c", "/d"}},
		{Plugin: longRunes(300), StatusCode: 10, StatusMessage: "Threat remediated", CausedBy: []any{"/normal"}},
		{Plugin: "CausedByNull", StatusCode: 10, StatusMessage: "Threat remediated", CausedBy: nil},
		{Plugin: "CausedByString", StatusCode: 10, StatusMessage: "Threat remediated", CausedBy: "/x"},
		{Plugin: "CausedByArray", StatusCode: 10, StatusMessage: "Threat remediated", CausedBy: []any{"/a", 7}},
	}
	for i, ev := range special {
		ts := base.Add(time.Duration(20+i) * time.Second).Format(antivirus.DarwinTimestampLayout)
		data, err := json.Marshal(entry{Timestamp: ts, EventMessage: marshalEvent(ev)})
		if err != nil {
			t.Fatalf("marshal special entry: %v", err)
		}
		lines = append(lines, string(data))
	}

	runner := fake.NewCommandRunner()
	runner.Results[darwinCommandKey()] = platform.CommandResult{Stdout: strings.Join(lines, "\n"), ExitCode: 0}
	clock := fake.NewClock(time.Now())

	findings, _ := antivirus.CollectFindings(runner, clock, "darwin")
	if len(findings) != 20 {
		t.Fatalf("expected 20 findings, got %d", len(findings))
	}

	byName := make(map[string]contract.AntivirusFinding, len(findings))
	for _, f := range findings {
		byName[f.ThreatName] = f
	}

	// Newest first: the five special entries, posted last, are the first five
	// returned, in reverse order of being posted.
	wantOrder := []string{"CausedByArray", "CausedByString", "CausedByNull", longRunes(256), "CausedByLong"}
	for i, name := range wantOrder {
		if findings[i].ThreatName != name {
			t.Errorf("findings[%d].ThreatName = %q, want %q", i, findings[i].ThreatName, name)
		}
	}

	longPlugin, ok := byName[longRunes(256)]
	if !ok {
		t.Fatal("expected a finding with the truncated 300-rune plugin name")
	}
	if len(longPlugin.ThreatName) != 256 {
		t.Errorf("long plugin threatName length = %d, want 256", len(longPlugin.ThreatName))
	}

	causedByLong, ok := byName["CausedByLong"]
	if !ok {
		t.Fatal("expected the CausedByLong finding")
	}
	if len(causedByLong.Resources) != 3 {
		t.Fatalf("CausedByLong resources = %v, want 3 entries", causedByLong.Resources)
	}
	if len([]rune(causedByLong.Resources[0])) != 260 {
		t.Errorf("CausedByLong resources[0] rune length = %d, want 260", len([]rune(causedByLong.Resources[0])))
	}

	if n, ok := byName["CausedByNull"]; !ok || len(n.Resources) != 0 {
		t.Errorf("CausedByNull resources = %v, want []", n.Resources)
	}
	if s, ok := byName["CausedByString"]; !ok || len(s.Resources) != 1 || s.Resources[0] != "/x" {
		t.Errorf("CausedByString resources = %v, want [/x]", s.Resources)
	}
	if a, ok := byName["CausedByArray"]; !ok || len(a.Resources) != 1 || a.Resources[0] != "/a" {
		t.Errorf("CausedByArray resources = %v, want [/a]", a.Resources)
	}
}

// TestScenario_UnsupportedGoosCollectsNothing covers the default branch.
func TestScenario_UnsupportedGoosCollectsNothing(t *testing.T) {
	runner := fake.NewCommandRunner()
	clock := fake.NewClock(time.Now())

	findings, warnings := antivirus.CollectFindings(runner, clock, "linux")
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d", len(findings))
	}
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}
	if calls := runner.Calls(); len(calls) != 0 {
		t.Errorf("expected no runner calls, got %v", calls)
	}
}

// ----------------------------------------------------------------------------
// AC12: Windows findings carry status, action and category.
// ----------------------------------------------------------------------------

// TestScenario_AC12_WindowsFindingsCarryStatusActionAndCategory covers the
// main scenario.
func TestScenario_AC12_WindowsFindingsCarryStatusActionAndCategory(t *testing.T) {
	line := `{"detectionId":"id-1","threatName":"T","severityId":5,"detectedAt":"2026-10-02T07:15:00Z",` +
		`"resources":[],"actionSuccess":true,"categoryId":8,"statusId":3,"actionId":2,"active":true,` +
		`"lastStatusChangeAt":"2026-10-02T07:00:00Z","remediatedAt":null,"processName":"C:\\x.exe","user":"CONTOSO\\a"}`

	runner := fake.NewCommandRunner()
	runner.Results[findingsCommandKey()] = platform.CommandResult{Stdout: line, ExitCode: 0}
	clock := fake.NewClock(time.Now())

	findings, warnings := antivirus.CollectFindings(runner, clock, "windows")
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Status != "quarantined" {
		t.Errorf("status = %q, want quarantined", f.Status)
	}
	if f.Action != "quarantine" {
		t.Errorf("action = %q, want quarantine", f.Action)
	}
	if f.Category != "Trojan" {
		t.Errorf("category = %q, want Trojan", f.Category)
	}
	if f.Active == nil || !*f.Active {
		t.Errorf("active = %v, want true", f.Active)
	}
	if f.LastStatusChangeAt != "2026-10-02T07:00:00Z" {
		t.Errorf("lastStatusChangeAt = %q, want 2026-10-02T07:00:00Z", f.LastStatusChangeAt)
	}
	if f.ProcessName != "C:\\x.exe" {
		t.Errorf("processName = %q, want C:\\x.exe", f.ProcessName)
	}
	if f.User != "CONTOSO\\a" {
		t.Errorf("user = %q, want CONTOSO\\a", f.User)
	}
}

// TestScenario_AC12Edge_UnknownIdsAndOldOutput covers the unmapped-id and
// old-output-shape edge scenario.
func TestScenario_AC12Edge_UnknownIdsAndOldOutput(t *testing.T) {
	line := `{"detectionId":"id-1","threatName":"T","severityId":1,"detectedAt":"2026-10-02T07:15:00Z",` +
		`"resources":[],"actionSuccess":false,"categoryId":777,"statusId":999,"actionId":999}`

	runner := fake.NewCommandRunner()
	runner.Results[findingsCommandKey()] = platform.CommandResult{Stdout: line, ExitCode: 0}
	clock := fake.NewClock(time.Now())

	findings, warnings := antivirus.CollectFindings(runner, clock, "windows")
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Status != "unknown" {
		t.Errorf("status = %q, want unknown", f.Status)
	}
	if f.Action != "unknown" {
		t.Errorf("action = %q, want unknown", f.Action)
	}
	if f.Category != "Category 777" {
		t.Errorf("category = %q, want 'Category 777'", f.Category)
	}

	// A line without the new keys at all marshals with exactly the six
	// original keys.
	oldLine := `{"detectionId":"id-2","threatName":"T","severityId":1,"detectedAt":"2026-10-02T07:15:00Z",` +
		`"resources":[],"actionSuccess":false}`
	runner2 := fake.NewCommandRunner()
	runner2.Results[findingsCommandKey()] = platform.CommandResult{Stdout: oldLine, ExitCode: 0}
	findings2, warnings2 := antivirus.CollectFindings(runner2, clock, "windows")
	if len(warnings2) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings2)
	}
	if len(findings2) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings2))
	}
	data, err := json.Marshal(findings2[0])
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	wantKeys := []string{"findingId", "threatName", "severity", "detectedAt", "resources", "remediated"}
	if len(fields) != len(wantKeys) {
		t.Fatalf("marshalled finding has keys %v, want exactly %v", keysOf(fields), wantKeys)
	}
	for _, key := range wantKeys {
		if _, ok := fields[key]; !ok {
			t.Errorf("marshalled finding is missing key %q", key)
		}
	}
}

// TestScenario_AC12Edge_ThreatRecordGone covers the missing-$t edge scenario:
// a categoryId/active of null must never surface as 0/false.
func TestScenario_AC12Edge_ThreatRecordGone(t *testing.T) {
	if !strings.Contains(antivirus.WindowsFindingsScript, "if ($null -ne $t)") {
		t.Fatal("WindowsFindingsScript should guard categoryId/active with 'if ($null -ne $t)'")
	}

	line := `{"detectionId":"id-1","threatName":"T","severityId":1,"detectedAt":"2026-10-02T07:15:00Z",` +
		`"resources":[],"actionSuccess":false,"categoryId":null,"statusId":3,"actionId":2,"active":null}`

	runner := fake.NewCommandRunner()
	runner.Results[findingsCommandKey()] = platform.CommandResult{Stdout: line, ExitCode: 0}
	clock := fake.NewClock(time.Now())

	findings, warnings := antivirus.CollectFindings(runner, clock, "windows")
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Status != "quarantined" {
		t.Errorf("status = %q, want quarantined", f.Status)
	}
	if f.Action != "quarantine" {
		t.Errorf("action = %q, want quarantine", f.Action)
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if _, ok := fields["category"]; ok {
		t.Error("marshalled finding should have no category key")
	}
	if _, ok := fields["active"]; ok {
		t.Error("marshalled finding should have no active key")
	}

	// categoryId 0 also yields no category key (0 is absent, never "Category 0").
	zeroLine := `{"detectionId":"id-2","threatName":"T","severityId":1,"detectedAt":"2026-10-02T07:15:00Z",` +
		`"resources":[],"actionSuccess":false,"categoryId":0}`
	runner2 := fake.NewCommandRunner()
	runner2.Results[findingsCommandKey()] = platform.CommandResult{Stdout: zeroLine, ExitCode: 0}
	findings2, _ := antivirus.CollectFindings(runner2, clock, "windows")
	if len(findings2) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings2))
	}
	data2, err := json.Marshal(findings2[0])
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var fields2 map[string]any
	if err := json.Unmarshal(data2, &fields2); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if _, ok := fields2["category"]; ok {
		t.Error("categoryId 0 should yield no category key")
	}
}

// keysOf returns the keys of m, for readable failure messages.
func keysOf(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// ----------------------------------------------------------------------------
// AC13: macOS findings keep the original six keys.
// ----------------------------------------------------------------------------

// TestScenario_AC13_MacOSFindingsKeepTheOriginalSixKeys covers the scenario,
// using the existing darwin findings fixture.
func TestScenario_AC13_MacOSFindingsKeepTheOriginalSixKeys(t *testing.T) {
	runner := fake.NewCommandRunner()
	runner.Results[darwinCommandKey()] = platform.CommandResult{
		Stdout:   loadFixture(t, "darwin", "findings.ndjson"),
		ExitCode: 0,
	}
	clock := fake.NewClock(time.Now())

	findings, warnings := antivirus.CollectFindings(runner, clock, "darwin")
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding from the darwin fixture")
	}
	wantKeys := []string{"findingId", "threatName", "severity", "detectedAt", "resources", "remediated"}
	for _, finding := range findings {
		data, err := json.Marshal(finding)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}
		var fields map[string]any
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}
		if len(fields) != len(wantKeys) {
			t.Fatalf("macOS finding has keys %v, want exactly %v", keysOf(fields), wantKeys)
		}
		for _, forbidden := range []string{"category", "status", "action", "active", "lastStatusChangeAt", "remediatedAt", "processName", "user"} {
			if _, ok := fields[forbidden]; ok {
				t.Errorf("macOS finding should not have key %q", forbidden)
			}
		}
	}
}
