// Tests for analytics.CollectNetwork: the heartbeat's network saturation and
// packet sample.
package analytics_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/analytics"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

func i64(v int64) *int64     { return &v }
func f64(v float64) *float64 { return &v }

// runNetwork seeds the network probe of goos with stdout and collects.
func runNetwork(t *testing.T, goos, stdout string, exitCode int) ([]contract.HeartbeatNetworkAdapter, []string) {
	t.Helper()
	probe, ok := analytics.NetworkProbe(goos)
	if !ok {
		t.Fatalf("no network probe for %s", goos)
	}
	runner := fake.NewCommandRunner()
	runner.Results[probe.String()] = platform.CommandResult{Stdout: stdout, ExitCode: exitCode}
	clock := fake.NewClock(time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC))
	return analytics.CollectNetwork(runner, clock, goos)
}

func fixture(t *testing.T, goos string) string {
	t.Helper()
	out, err := loadFixture(goos, analytics.ProbeNetwork)
	if err != nil {
		t.Fatalf("loadFixture: %v", err)
	}
	return out
}

func assertAdapters(t *testing.T, got, want []contract.HeartbeatNetworkAdapter) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		g, _ := json.MarshalIndent(got, "", "  ")
		w, _ := json.MarshalIndent(want, "", "  ")
		t.Errorf("adapters =\n%s\nwant\n%s", g, w)
	}
}

func TestCollectNetworkWindowsFixture(t *testing.T) {
	got, warnings := runNetwork(t, "windows", fixture(t, "windows"), 0)
	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}
	assertAdapters(t, got, []contract.HeartbeatNetworkAdapter{
		{
			Name:                     "Ethernet",
			LinkSpeedBitsPerSecond:   i64(1_000_000_000),
			ReceiveBitsPerSecond:     i64(200_000_000),
			SendBitsPerSecond:        i64(20_000_000),
			UtilizationPercent:       f64(20),
			PacketsReceivedPerSecond: f64(20000),
			PacketsSentPerSecond:     f64(5000),
			ReceiveErrors:            i64(0),
			SendErrors:               i64(405),
			ReceiveDiscards:          i64(12),
			SendDiscards:             i64(0),
		},
		// No matching performance counter instance: link speed only.
		{Name: "Wi-Fi", LinkSpeedBitsPerSecond: i64(1_081_000_000)},
	})
}

func TestCollectNetworkDarwinFixture(t *testing.T) {
	got, warnings := runNetwork(t, "darwin", fixture(t, "darwin"), 0)
	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}
	assertAdapters(t, got, []contract.HeartbeatNetworkAdapter{
		{
			Name:                     "en0",
			LinkSpeedBitsPerSecond:   i64(1_000_000_000),
			ReceiveBitsPerSecond:     i64(200_000_000),
			SendBitsPerSecond:        i64(10_000_000),
			UtilizationPercent:       f64(20),
			PacketsReceivedPerSecond: f64(8000),
			PacketsSentPerSecond:     f64(2000),
			ReceiveErrors:            i64(3),
			SendErrors:               i64(1),
			ReceiveDiscards:          i64(9),
		},
		{
			// Wi-Fi media names no rate, so there is no utilisation.
			Name:                     "en1",
			ReceiveBitsPerSecond:     i64(1_200_000),
			SendBitsPerSecond:        i64(80_000),
			PacketsReceivedPerSecond: f64(100),
			PacketsSentPerSecond:     f64(50),
			ReceiveErrors:            i64(0),
			SendErrors:               i64(0),
			ReceiveDiscards:          i64(0),
		},
	})
}

func TestCollectNetworkDarwinTenGigMedia(t *testing.T) {
	out := "adapter=en5 10Gbase-T <full-duplex>\n--- sample\n--- sample\n"
	got, warnings := runNetwork(t, "darwin", out, 0)
	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}
	assertAdapters(t, got, []contract.HeartbeatNetworkAdapter{
		{Name: "en5", LinkSpeedBitsPerSecond: i64(10_000_000_000)},
	})
}

func TestCollectNetworkCounterResetGivesNullRate(t *testing.T) {
	out := `{"name":"Ethernet","linkSpeed":100000000,"freq":10000000,"t1":0,"t2":10000000,` +
		`"rxBytes1":5000,"rxBytes2":1000,"txBytes1":0,"txBytes2":25000000}`
	got, _ := runNetwork(t, "windows", out, 0)
	assertAdapters(t, got, []contract.HeartbeatNetworkAdapter{
		{
			Name:                   "Ethernet",
			LinkSpeedBitsPerSecond: i64(100_000_000),
			SendBitsPerSecond:      i64(200_000_000),
			// Above the link speed (a timing artefact): capped at 100.
			UtilizationPercent: f64(100),
		},
	})
}

func TestCollectNetworkNoAdaptersUp(t *testing.T) {
	got, warnings := runNetwork(t, "windows", "", 0)
	if got != nil || len(warnings) != 0 {
		t.Errorf("got %v, %v; want no adapters and no warnings", got, warnings)
	}
}

func TestCollectNetworkCapsAdapters(t *testing.T) {
	var lines []string
	for i := 0; i < analytics.MaxNetworkAdapters+3; i++ {
		lines = append(lines, `{"name":"nic`+string(rune('a'+i))+`"}`)
	}
	got, _ := runNetwork(t, "windows", strings.Join(lines, "\n"), 0)
	if len(got) != analytics.MaxNetworkAdapters {
		t.Errorf("len = %d, want %d", len(got), analytics.MaxNetworkAdapters)
	}
}

func TestCollectNetworkUnparseable(t *testing.T) {
	for goos, out := range map[string]string{"windows": "garbage\n", "darwin": "garbage\n"} {
		got, warnings := runNetwork(t, goos, out, 0)
		if got != nil || !reflect.DeepEqual(warnings, []string{"network:unparseable"}) {
			t.Errorf("%s: got %v, %v; want nil and [network:unparseable]", goos, got, warnings)
		}
	}
}

func TestCollectNetworkProbeFails(t *testing.T) {
	got, warnings := runNetwork(t, "windows", "", 1)
	if got != nil || !reflect.DeepEqual(warnings, []string{"network"}) {
		t.Errorf("got %v, %v; want nil and [network]", got, warnings)
	}
}

func TestCollectNetworkUnsupportedOS(t *testing.T) {
	got, warnings := analytics.CollectNetwork(fake.NewCommandRunner(), fake.NewClock(time.Now()), "linux")
	if got != nil || !reflect.DeepEqual(warnings, []string{"network"}) {
		t.Errorf("got %v, %v; want nil and [network]", got, warnings)
	}
}

// The check-in's analytics probes stay unchanged: the network probe is the
// heartbeat's alone.
func TestNetworkProbeNotInCheckInProbes(t *testing.T) {
	for _, goos := range []string{"windows", "darwin"} {
		for _, p := range analytics.Probes(goos) {
			if p.Name == analytics.ProbeNetwork {
				t.Errorf("%s: Probes includes %q", goos, analytics.ProbeNetwork)
			}
		}
	}
}
