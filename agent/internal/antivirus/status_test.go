package antivirus_test

import (
	"context"
	"encoding/json"
	"errors"
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

// loadStatusFixture reads one of this package's status testdata files.
func loadStatusFixture(t *testing.T, goos, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", goos, name))
	if err != nil {
		t.Fatalf("failed to load fixture %s/%s: %v", goos, name, err)
	}
	return string(data)
}

func windowsStatusCommandKey() string {
	return fake.Command{
		Name: "powershell.exe",
		Args: []string{"-NoProfile", "-NonInteractive", "-Command", antivirus.WindowsStatusScript},
	}.String()
}

func darwinStatusCommandKey() string {
	return fake.Command{Name: "/bin/sh", Args: []string{"-c", antivirus.DarwinStatusScript}}.String()
}

// blockingStatusRunner never returns, for the status timeout path.
type blockingStatusRunner struct {
	started chan struct{}
}

func newBlockingStatusRunner() *blockingStatusRunner {
	return &blockingStatusRunner{started: make(chan struct{})}
}

func (b *blockingStatusRunner) Run(ctx context.Context, name string, args ...string) (platform.CommandResult, error) {
	close(b.started)
	select {}
}

func strPtr(s string) *string { return &s }
func intPtr(n int) *int       { return &n }
func boolVal(b bool) *bool    { return &b }

// ----------------------------------------------------------------------------
// AC1: the Windows status script shape, run exactly once, read-only.
// ----------------------------------------------------------------------------

// TestScenario_AC1_WindowsStatusRunsOneReadOnlyPowerShellCommand covers the
// Background + "Windows status runs one read-only PowerShell command" scenario.
func TestScenario_AC1_WindowsStatusRunsOneReadOnlyPowerShellCommand(t *testing.T) {
	runner := fake.NewCommandRunner()
	runner.Results[windowsStatusCommandKey()] = platform.CommandResult{Stdout: `{"defenderAvailable":false,"status":null,"products":[]}`, ExitCode: 0}
	clock := fake.NewClock(time.Now())

	_, warnings := antivirus.CollectStatus(runner, clock, "windows")
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}

	calls := runner.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected exactly one runner call, got %d: %+v", len(calls), calls)
	}
	if calls[0].Name != "powershell.exe" {
		t.Errorf("command name = %q, want powershell.exe", calls[0].Name)
	}
	wantArgs := []string{"-NoProfile", "-NonInteractive", "-Command", antivirus.WindowsStatusScript}
	if len(calls[0].Args) != len(wantArgs) || calls[0].Args[len(calls[0].Args)-1] != antivirus.WindowsStatusScript {
		t.Errorf("args = %v, want %v", calls[0].Args, wantArgs)
	}

	script := antivirus.WindowsStatusScript
	if n := strings.Count(script, "Get-MpComputerStatus"); n != 1 {
		t.Errorf("WindowsStatusScript contains Get-MpComputerStatus %d times, want exactly 1", n)
	}
	if !strings.Contains(script, "root/SecurityCenter2") {
		t.Error("WindowsStatusScript should contain root/SecurityCenter2")
	}
	if !strings.Contains(script, "ConvertTo-Json -Compress -Depth 4") {
		t.Error("WindowsStatusScript should contain ConvertTo-Json -Compress -Depth 4")
	}
	for _, forbidden := range []string{"Start-MpScan", "Set-MpPreference", "Update-MpSignature"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("WindowsStatusScript should not contain %q", forbidden)
		}
	}
}

// ----------------------------------------------------------------------------
// AC2: an active Defender maps every field.
// ----------------------------------------------------------------------------

// TestScenario_AC2_ActiveDefenderMapsEveryField covers "An active Defender
// maps every field".
func TestScenario_AC2_ActiveDefenderMapsEveryField(t *testing.T) {
	runner := fake.NewCommandRunner()
	runner.Results[windowsStatusCommandKey()] = platform.CommandResult{
		Stdout:   loadStatusFixture(t, "windows", "status-active.json"),
		ExitCode: 0,
	}
	clock := fake.NewClock(time.Now())

	status, warnings := antivirus.CollectStatus(runner, clock, "windows")
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if status == nil {
		t.Fatal("expected a non-nil status block")
	}
	if status.Product != "Microsoft Defender" {
		t.Errorf("product = %q, want Microsoft Defender", status.Product)
	}
	if !status.DefenderAvailable {
		t.Error("defenderAvailable should be true")
	}
	if status.Protection.RealTimeProtectionEnabled == nil || !*status.Protection.RealTimeProtectionEnabled {
		t.Error("protection.realTimeProtectionEnabled should be true")
	}
	if status.Protection.TamperProtected == nil || !*status.Protection.TamperProtected {
		t.Error("protection.tamperProtected should be true")
	}
	if status.Versions.Engine == nil || *status.Versions.Engine != "1.1.24090.11" {
		t.Errorf("versions.engine = %v, want 1.1.24090.11", status.Versions.Engine)
	}
	if status.Signatures.AntivirusAgeDays == nil || *status.Signatures.AntivirusAgeDays != 1 {
		t.Errorf("signatures.antivirusAgeDays = %v, want 1", status.Signatures.AntivirusAgeDays)
	}
	if status.Scans.QuickEndedAt == nil || *status.Scans.QuickEndedAt != "2026-10-01T02:06:31Z" {
		t.Errorf("scans.quickEndedAt = %v, want 2026-10-01T02:06:31Z", status.Scans.QuickEndedAt)
	}
	if status.RunningMode == nil || *status.RunningMode != "Normal" {
		t.Errorf("runningMode = %v, want Normal", status.RunningMode)
	}
	if status.ComputerState == nil || *status.ComputerState != 0 {
		t.Errorf("computerState = %v, want 0", status.ComputerState)
	}
	if status.RebootRequired == nil || *status.RebootRequired {
		t.Errorf("rebootRequired = %v, want false", status.RebootRequired)
	}
}

// ----------------------------------------------------------------------------
// AC3: dates are normalised to RFC3339 UTC.
// ----------------------------------------------------------------------------

func windowsStatusWithQuickEndTime(raw string) string {
	return `{"defenderAvailable":true,"status":{"QuickScanEndTime":` + raw + `},"products":[]}`
}

// TestScenario_AC3_DatesAreNormalisedToRFC3339UTC covers the date Scenario
// Outline.
func TestScenario_AC3_DatesAreNormalisedToRFC3339UTC(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		expected *string
	}{
		{"PS7 offset string", `"2024-10-02T17:00:00.123+10:00"`, strPtr("2024-10-02T07:00:00Z")},
		{"PS5.1 /Date(ms)/", `"/Date(1727852400000)/"`, strPtr("2024-10-02T07:00:00Z")},
		{"PS5.1 /Date(ms+offset)/", `"/Date(1727852400000+1000)/"`, strPtr("2024-10-02T07:00:00Z")},
		{"wrapped value object", `{"value":"/Date(1727852400000)/"}`, strPtr("2024-10-02T07:00:00Z")},
		{"ms <= 0", `"/Date(0)/"`, nil},
		{"1601 never date", `"1601-01-01T00:00:00Z"`, nil},
		{"garbage string", `"garbage"`, nil},
		{"a number", `12345`, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := fake.NewCommandRunner()
			runner.Results[windowsStatusCommandKey()] = platform.CommandResult{
				Stdout:   windowsStatusWithQuickEndTime(tc.raw),
				ExitCode: 0,
			}
			clock := fake.NewClock(time.Now())

			status, warnings := antivirus.CollectStatus(runner, clock, "windows")
			if len(warnings) != 0 {
				t.Fatalf("expected no warnings, got %v", warnings)
			}
			got := status.Scans.QuickEndedAt
			if tc.expected == nil {
				if got != nil {
					t.Errorf("quickEndedAt = %q, want null", *got)
				}
				return
			}
			if got == nil || *got != *tc.expected {
				t.Errorf("quickEndedAt = %v, want %q", got, *tc.expected)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// AC4: ages and computer state are bounded.
// ----------------------------------------------------------------------------

func windowsStatusWithAgeAndState(age, state string) string {
	return `{"defenderAvailable":true,"status":{"AntivirusSignatureAge":` + age + `,"ComputerState":` + state + `},"products":[]}`
}

// TestScenario_AC4_AgesAndComputerStateAreBounded covers the Scenario Outline.
func TestScenario_AC4_AgesAndComputerStateAreBounded(t *testing.T) {
	cases := []struct {
		name     string
		age      string
		state    string
		ageOut   *int
		stateOut *int
	}{
		{"in range", "2", "0", intPtr(2), intPtr(0)},
		{"sentinel 65535 / state too big", "65535", "70000", nil, nil},
		{"sentinel 4294967295 / negative state", "4294967295", "-1", nil, nil},
		{"fraction / string state", "1.5", `"2"`, nil, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := fake.NewCommandRunner()
			runner.Results[windowsStatusCommandKey()] = platform.CommandResult{
				Stdout:   windowsStatusWithAgeAndState(tc.age, tc.state),
				ExitCode: 0,
			}
			clock := fake.NewClock(time.Now())

			status, warnings := antivirus.CollectStatus(runner, clock, "windows")
			if len(warnings) != 0 {
				t.Fatalf("expected no warnings, got %v", warnings)
			}
			if (status.Signatures.AntivirusAgeDays == nil) != (tc.ageOut == nil) ||
				(tc.ageOut != nil && *status.Signatures.AntivirusAgeDays != *tc.ageOut) {
				t.Errorf("antivirusAgeDays = %v, want %v", status.Signatures.AntivirusAgeDays, tc.ageOut)
			}
			if (status.ComputerState == nil) != (tc.stateOut == nil) ||
				(tc.stateOut != nil && *status.ComputerState != *tc.stateOut) {
				t.Errorf("computerState = %v, want %v", status.ComputerState, tc.stateOut)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// AC5: Defender stopped by a third-party product.
// ----------------------------------------------------------------------------

// TestScenario_AC5_DefenderStoppedByThirdPartyProduct covers the fixture
// scenario.
func TestScenario_AC5_DefenderStoppedByThirdPartyProduct(t *testing.T) {
	runner := fake.NewCommandRunner()
	runner.Results[windowsStatusCommandKey()] = platform.CommandResult{
		Stdout:   loadStatusFixture(t, "windows", "status-unavailable.json"),
		ExitCode: 0,
	}
	clock := fake.NewClock(time.Now())

	status, warnings := antivirus.CollectStatus(runner, clock, "windows")
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if status.DefenderAvailable {
		t.Error("defenderAvailable should be false")
	}
	if status.RunningMode != nil {
		t.Errorf("runningMode = %v, want nil", status.RunningMode)
	}
	if status.ComputerState != nil {
		t.Errorf("computerState = %v, want nil", status.ComputerState)
	}
	if status.RebootRequired != nil {
		t.Errorf("rebootRequired = %v, want nil", status.RebootRequired)
	}
	protection := status.Protection
	for name, value := range map[string]*bool{
		"amServiceEnabled":          protection.AMServiceEnabled,
		"antispywareEnabled":        protection.AntispywareEnabled,
		"antivirusEnabled":          protection.AntivirusEnabled,
		"behaviorMonitorEnabled":    protection.BehaviorMonitorEnabled,
		"ioavProtectionEnabled":     protection.IoavProtectionEnabled,
		"onAccessProtectionEnabled": protection.OnAccessProtectionEnabled,
		"realTimeProtectionEnabled": protection.RealTimeProtectionEnabled,
		"nisEnabled":                protection.NISEnabled,
		"tamperProtected":           protection.TamperProtected,
	} {
		if value != nil {
			t.Errorf("protection.%s = %v, want nil", name, *value)
		}
	}
	versions := status.Versions
	for name, value := range map[string]*string{
		"engine":               versions.Engine,
		"product":              versions.Product,
		"service":              versions.Service,
		"nisEngine":            versions.NISEngine,
		"antivirusSignature":   versions.AntivirusSignature,
		"antispywareSignature": versions.AntispywareSignature,
		"nisSignature":         versions.NISSignature,
	} {
		if value != nil {
			t.Errorf("versions.%s = %v, want nil", name, *value)
		}
	}
	if status.Signatures.AntivirusAgeDays != nil || status.Signatures.AntivirusLastUpdatedAt != nil || status.Signatures.OutOfDate != nil {
		t.Errorf("signatures should be entirely null, got %+v", status.Signatures)
	}
	if status.Scans.QuickEndedAt != nil || status.Scans.QuickAgeDays != nil || status.Scans.QuickOverdue != nil {
		t.Errorf("scans should be entirely null, got %+v", status.Scans)
	}
	if len(status.SecurityCenterProducts) != 1 {
		t.Fatalf("expected 1 security center product, got %d", len(status.SecurityCenterProducts))
	}
	product := status.SecurityCenterProducts[0]
	if product.Name != "Contoso Endpoint Security" || product.State != "on" || product.DefinitionsUpToDate == nil || !*product.DefinitionsUpToDate {
		t.Errorf("product = %+v, want Contoso Endpoint Security/on/true", product)
	}
}

// ----------------------------------------------------------------------------
// AC6: Security Center product state decoding, bounds and shapes.
// ----------------------------------------------------------------------------

func windowsStatusWithOneProduct(productState string) string {
	return `{"defenderAvailable":false,"status":null,"products":[{"name":"AV","productState":` + productState + `}]}`
}

// TestScenario_AC6_SecurityCenterProductStateDecoding covers the Scenario
// Outline.
func TestScenario_AC6_SecurityCenterProductStateDecoding(t *testing.T) {
	cases := []struct {
		productState string
		state        string
		upToDate     *bool
	}{
		{"266240", "on", boolVal(true)},
		{"262144", "off", boolVal(true)},
		{"270336", "snoozed", boolVal(true)},
		{"274432", "expired", boolVal(true)},
		{"266256", "on", boolVal(false)},
		{`"x"`, "unknown", nil},
	}

	for _, tc := range cases {
		t.Run(tc.productState, func(t *testing.T) {
			runner := fake.NewCommandRunner()
			runner.Results[windowsStatusCommandKey()] = platform.CommandResult{
				Stdout:   windowsStatusWithOneProduct(tc.productState),
				ExitCode: 0,
			}
			clock := fake.NewClock(time.Now())

			status, warnings := antivirus.CollectStatus(runner, clock, "windows")
			if len(warnings) != 0 {
				t.Fatalf("expected no warnings, got %v", warnings)
			}
			if len(status.SecurityCenterProducts) != 1 {
				t.Fatalf("expected 1 product, got %d", len(status.SecurityCenterProducts))
			}
			product := status.SecurityCenterProducts[0]
			if product.State != tc.state {
				t.Errorf("state = %q, want %q", product.State, tc.state)
			}
			if (product.DefinitionsUpToDate == nil) != (tc.upToDate == nil) ||
				(tc.upToDate != nil && *product.DefinitionsUpToDate != *tc.upToDate) {
				t.Errorf("definitionsUpToDate = %v, want %v", product.DefinitionsUpToDate, tc.upToDate)
			}
		})
	}
}

// TestScenario_AC6Edge_ProductListBoundsAndShapes covers the "Product list
// bounds and shapes" edge scenario.
func TestScenario_AC6Edge_ProductListBoundsAndShapes(t *testing.T) {
	// 12 entries, one with an empty name, as a JSON array.
	var products strings.Builder
	products.WriteString("[")
	for i := 0; i < 12; i++ {
		if i > 0 {
			products.WriteString(",")
		}
		name := "AV"
		if i == 5 {
			name = ""
		}
		products.WriteString(`{"name":"` + name + `","productState":266240}`)
	}
	products.WriteString("]")

	runner := fake.NewCommandRunner()
	runner.Results[windowsStatusCommandKey()] = platform.CommandResult{
		Stdout:   `{"defenderAvailable":false,"status":null,"products":` + products.String() + `}`,
		ExitCode: 0,
	}
	clock := fake.NewClock(time.Now())

	status, warnings := antivirus.CollectStatus(runner, clock, "windows")
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	// 11 valid entries (one dropped for an empty name), capped at 10.
	if len(status.SecurityCenterProducts) != 10 {
		t.Fatalf("expected 10 products, got %d", len(status.SecurityCenterProducts))
	}
	for _, p := range status.SecurityCenterProducts {
		if p.Name == "" {
			t.Error("no product should have an empty name")
		}
	}

	// A single object is read as a one-element list.
	runner2 := fake.NewCommandRunner()
	runner2.Results[windowsStatusCommandKey()] = platform.CommandResult{
		Stdout:   `{"defenderAvailable":false,"status":null,"products":{"name":"Solo","productState":266240}}`,
		ExitCode: 0,
	}
	status2, _ := antivirus.CollectStatus(runner2, clock, "windows")
	if len(status2.SecurityCenterProducts) != 1 || status2.SecurityCenterProducts[0].Name != "Solo" {
		t.Errorf("expected a one-element list with Solo, got %+v", status2.SecurityCenterProducts)
	}

	// Absent products gives [].
	runner3 := fake.NewCommandRunner()
	runner3.Results[windowsStatusCommandKey()] = platform.CommandResult{
		Stdout:   `{"defenderAvailable":false,"status":null}`,
		ExitCode: 0,
	}
	status3, _ := antivirus.CollectStatus(runner3, clock, "windows")
	if status3.SecurityCenterProducts == nil || len(status3.SecurityCenterProducts) != 0 {
		t.Errorf("expected an empty (non-nil) slice, got %+v", status3.SecurityCenterProducts)
	}
}

// ----------------------------------------------------------------------------
// AC7: strings are bounded and wrong types become null.
// ----------------------------------------------------------------------------

// TestScenario_AC7_StringsAreBoundedAndWrongTypesBecomeNull covers the
// scenario.
func TestScenario_AC7_StringsAreBoundedAndWrongTypesBecomeNull(t *testing.T) {
	longEngine := strings.Repeat("e", 100)
	longMode := strings.Repeat("m", 80)
	longName := strings.Repeat("n", 200)

	stdout := `{"defenderAvailable":true,"status":{"AMEngineVersion":"` + longEngine + `","AMRunningMode":"` + longMode +
		`","RealTimeProtectionEnabled":"yes"},"products":[{"name":"` + longName + `","productState":266240}]}`

	runner := fake.NewCommandRunner()
	runner.Results[windowsStatusCommandKey()] = platform.CommandResult{Stdout: stdout, ExitCode: 0}
	clock := fake.NewClock(time.Now())

	status, warnings := antivirus.CollectStatus(runner, clock, "windows")
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
	if status.Versions.Engine == nil || len([]rune(*status.Versions.Engine)) != 64 {
		t.Errorf("versions.engine length = %v, want 64", status.Versions.Engine)
	}
	if status.RunningMode == nil || len([]rune(*status.RunningMode)) != 64 {
		t.Errorf("runningMode length = %v, want 64", status.RunningMode)
	}
	if len(status.SecurityCenterProducts) != 1 || len([]rune(status.SecurityCenterProducts[0].Name)) != 128 {
		t.Errorf("product name length = %v, want 128", status.SecurityCenterProducts)
	}
	if status.Protection.RealTimeProtectionEnabled != nil {
		t.Errorf("protection.realTimeProtectionEnabled = %v, want nil", *status.Protection.RealTimeProtectionEnabled)
	}
}

// ----------------------------------------------------------------------------
// AC8: a failing status probe costs a warning, not the check-in.
// ----------------------------------------------------------------------------

// TestScenario_AC8_FailingStatusProbeCostsAWarningNotTheCheckIn covers the
// Scenario Outline.
func TestScenario_AC8_FailingStatusProbeCostsAWarningNotTheCheckIn(t *testing.T) {
	cases := []struct {
		name    string
		arrange func() (platform.CommandRunner, platform.Clock)
		warning string
	}{
		{
			name: "fails to start",
			arrange: func() (platform.CommandRunner, platform.Clock) {
				runner := fake.NewCommandRunner()
				runner.Errors[windowsStatusCommandKey()] = errors.New("boom: cannot start")
				return runner, fake.NewClock(time.Now())
			},
			warning: antivirus.WarningStatus,
		},
		{
			name: "exits with code 1",
			arrange: func() (platform.CommandRunner, platform.Clock) {
				runner := fake.NewCommandRunner()
				runner.Results[windowsStatusCommandKey()] = platform.CommandResult{ExitCode: 1}
				return runner, fake.NewClock(time.Now())
			},
			warning: antivirus.WarningStatus,
		},
		{
			name: "does not answer within 30 seconds",
			arrange: func() (platform.CommandRunner, platform.Clock) {
				runner := newBlockingStatusRunner()
				clock := fake.NewClock(time.Now())
				go func() {
					<-runner.started
					clock.Advance(antivirus.StatusTimeout)
				}()
				return runner, clock
			},
			warning: antivirus.WarningStatusTimeout,
		},
		{
			name: "prints nothing",
			arrange: func() (platform.CommandRunner, platform.Clock) {
				runner := fake.NewCommandRunner()
				runner.Results[windowsStatusCommandKey()] = platform.CommandResult{Stdout: "", ExitCode: 0}
				return runner, fake.NewClock(time.Now())
			},
			warning: antivirus.WarningStatusUnparseable,
		},
		{
			name: `prints "not json"`,
			arrange: func() (platform.CommandRunner, platform.Clock) {
				runner := fake.NewCommandRunner()
				runner.Results[windowsStatusCommandKey()] = platform.CommandResult{Stdout: "not json", ExitCode: 0}
				return runner, fake.NewClock(time.Now())
			},
			warning: antivirus.WarningStatusUnparseable,
		},
		{
			name: "prints two JSON objects",
			arrange: func() (platform.CommandRunner, platform.Clock) {
				runner := fake.NewCommandRunner()
				runner.Results[windowsStatusCommandKey()] = platform.CommandResult{
					Stdout:   `{"defenderAvailable":false}{"defenderAvailable":true}`,
					ExitCode: 0,
				}
				return runner, fake.NewClock(time.Now())
			},
			warning: antivirus.WarningStatusUnparseable,
		},
		{
			name: "prints a 70000-byte JSON object",
			arrange: func() (platform.CommandRunner, platform.Clock) {
				padding := strings.Repeat("x", 70000)
				runner := fake.NewCommandRunner()
				runner.Results[windowsStatusCommandKey()] = platform.CommandResult{
					Stdout:   `{"defenderAvailable":false,"pad":"` + padding + `"}`,
					ExitCode: 0,
				}
				return runner, fake.NewClock(time.Now())
			},
			warning: antivirus.WarningStatusUnparseable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner, clock := tc.arrange()
			status, warnings := antivirus.CollectStatus(runner, clock, "windows")
			if status != nil {
				t.Errorf("expected a nil block, got %+v", status)
			}
			if len(warnings) != 1 || warnings[0] != tc.warning {
				t.Errorf("warnings = %v, want exactly [%q]", warnings, tc.warning)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// AC9: macOS reports XProtect versions and definition age.
// ----------------------------------------------------------------------------

// TestScenario_AC9_MacOSReportsXProtectVersionsAndDefinitionAge covers the
// main darwin scenario.
func TestScenario_AC9_MacOSReportsXProtectVersionsAndDefinitionAge(t *testing.T) {
	runner := fake.NewCommandRunner()
	runner.Results[darwinStatusCommandKey()] = platform.CommandResult{
		Stdout:   loadStatusFixture(t, "darwin", "status.txt"),
		ExitCode: 0,
	}
	clock := fake.NewClock(time.Date(2024, 10, 4, 0, 0, 0, 0, time.UTC))

	status, warnings := antivirus.CollectStatus(runner, clock, "darwin")
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}

	calls := runner.Calls()
	if len(calls) != 1 || calls[0].Name != "/bin/sh" || len(calls[0].Args) != 2 || calls[0].Args[0] != "-c" || calls[0].Args[1] != antivirus.DarwinStatusScript {
		t.Fatalf("expected exactly one /bin/sh -c <DarwinStatusScript> call, got %+v", calls)
	}

	if status.Product != "XProtect" {
		t.Errorf("product = %q, want XProtect", status.Product)
	}
	if status.DefenderAvailable {
		t.Error("defenderAvailable should be false")
	}
	if status.Versions.XProtectDefinitions == nil || *status.Versions.XProtectDefinitions != "5272" {
		t.Errorf("versions.xprotectDefinitions = %v, want 5272", status.Versions.XProtectDefinitions)
	}
	if status.Versions.XProtectRemediator == nil || *status.Versions.XProtectRemediator != "145" {
		t.Errorf("versions.xprotectRemediator = %v, want 145", status.Versions.XProtectRemediator)
	}
	if status.Signatures.AntivirusLastUpdatedAt == nil || *status.Signatures.AntivirusLastUpdatedAt != "2024-10-02T00:00:00Z" {
		t.Errorf("signatures.antivirusLastUpdatedAt = %v, want 2024-10-02T00:00:00Z", status.Signatures.AntivirusLastUpdatedAt)
	}
	if status.Signatures.AntivirusAgeDays == nil || *status.Signatures.AntivirusAgeDays != 2 {
		t.Errorf("signatures.antivirusAgeDays = %v, want 2", status.Signatures.AntivirusAgeDays)
	}
	if status.RunningMode != nil {
		t.Errorf("runningMode = %v, want nil", status.RunningMode)
	}
	if status.ComputerState != nil || status.RebootRequired != nil {
		t.Errorf("computerState/rebootRequired should be nil, got %v/%v", status.ComputerState, status.RebootRequired)
	}
	if len(status.SecurityCenterProducts) != 0 {
		t.Errorf("securityCenterProducts = %v, want []", status.SecurityCenterProducts)
	}
}

// TestScenario_AC9Edge_MacOSOutputWithNothingUsable covers the edge scenario.
func TestScenario_AC9Edge_MacOSOutputWithNothingUsable(t *testing.T) {
	runner := fake.NewCommandRunner()
	runner.Results[darwinStatusCommandKey()] = platform.CommandResult{
		Stdout:   "definitionsVersion=\ndefinitionsModified=\nremediatorVersion=\n",
		ExitCode: 0,
	}
	clock := fake.NewClock(time.Date(2024, 10, 4, 0, 0, 0, 0, time.UTC))

	status, warnings := antivirus.CollectStatus(runner, clock, "darwin")
	if status != nil {
		t.Errorf("expected a nil block, got %+v", status)
	}
	if len(warnings) != 1 || warnings[0] != antivirus.WarningStatusUnparseable {
		t.Errorf("warnings = %v, want exactly [%q]", warnings, antivirus.WarningStatusUnparseable)
	}

	// definitionsModified after the clock gives antivirusAgeDays null.
	runner2 := fake.NewCommandRunner()
	runner2.Results[darwinStatusCommandKey()] = platform.CommandResult{
		Stdout:   "definitionsVersion=5272\ndefinitionsModified=1727913600\nremediatorVersion=145\n", // 2024-10-03T00:00:00Z
		ExitCode: 0,
	}
	clock2 := fake.NewClock(time.Date(2024, 10, 2, 0, 0, 0, 0, time.UTC)) // clock before modified time
	status2, warnings2 := antivirus.CollectStatus(runner2, clock2, "darwin")
	if len(warnings2) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings2)
	}
	if status2.Signatures.AntivirusAgeDays != nil {
		t.Errorf("antivirusAgeDays = %v, want nil when modified is after the clock", status2.Signatures.AntivirusAgeDays)
	}
}

// ----------------------------------------------------------------------------
// AC10: other platforms collect nothing.
// ----------------------------------------------------------------------------

// TestScenario_AC10_OtherPlatformsCollectNothing covers the scenario.
func TestScenario_AC10_OtherPlatformsCollectNothing(t *testing.T) {
	runner := fake.NewCommandRunner()
	clock := fake.NewClock(time.Now())

	status, warnings := antivirus.CollectStatus(runner, clock, "linux")
	if status != nil {
		t.Errorf("expected a nil block, got %+v", status)
	}
	if warnings != nil {
		t.Errorf("expected no warnings, got %v", warnings)
	}
	if calls := runner.Calls(); len(calls) != 0 {
		t.Errorf("expected no command to run, got %+v", calls)
	}
}

// ----------------------------------------------------------------------------
// AC14: posture.antivirus keeps exactly its three fields.
// ----------------------------------------------------------------------------

// TestScenario_AC14_PostureAntivirusIsUntouched covers
// contract.Antivirus's shape, separate from contract.AntivirusStatus.
func TestScenario_AC14_PostureAntivirusIsUntouched(t *testing.T) {
	av := contract.Antivirus{Name: "n", Enabled: true, DefinitionsAgeDays: 1}
	_ = av
	// A compile-time check: contract.Antivirus must have exactly these three
	// fields. Adding or removing one breaks this test at compile time via the
	// struct literal above and the JSON round trip below.
	data, err := json.Marshal(av)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	want := `{"name":"n","enabled":true,"definitionsAgeDays":1}`
	if string(data) != want {
		t.Errorf("marshalled Antivirus = %s, want %s", data, want)
	}
}
