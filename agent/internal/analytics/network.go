package analytics

import (
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// ProbeNetwork samples the active physical network adapters for the
// heartbeat. It is not one of Probes: the check-in's analytics block carries
// no network data, so only CollectNetwork runs it.
const ProbeNetwork = "network"

// MaxNetworkAdapters is the most adapters one heartbeat carries.
const MaxNetworkAdapters = 8

// darwinNetworkSampleSeconds is the gap between the two netstat samples the
// darwin probe prints; the script sleeps exactly this long.
const darwinNetworkSampleSeconds = 1.0

// NetworkProbe is the network probe for goos; false for a goos without one.
func NetworkProbe(goos string) (Probe, bool) {
	switch goos {
	case "windows":
		return Probe{Name: ProbeNetwork, Cmd: windowsShell, Args: windowsArgs(windowsNetworkScript)}, true
	case "darwin":
		return Probe{Name: ProbeNetwork, Cmd: darwinShell, Args: []string{"-c", darwinNetworkScript}}, true
	default:
		return Probe{}, false
	}
}

// CollectNetwork runs the network probe for goos and returns one entry per
// active physical adapter (at most MaxNetworkAdapters) with the warnings it
// produced. A goos with no network probe yields no adapters and the warning
// ProbeNetwork, as a failing probe does; output that cannot be understood
// yields "network:unparseable".
func CollectNetwork(runner platform.CommandRunner, clock platform.Clock, goos string) ([]contract.HeartbeatNetworkAdapter, []string) {
	probe, ok := NetworkProbe(goos)
	if !ok {
		return nil, []string{ProbeNetwork}
	}

	stdout, warnings := runProbes(runner, clock, []Probe{probe})
	out, ran := stdout[ProbeNetwork]
	if !ran {
		return nil, warnings
	}

	var adapters []contract.HeartbeatNetworkAdapter
	if goos == "windows" {
		adapters, ok = parseWindowsNetwork(out)
	} else {
		adapters, ok = parseDarwinNetwork(out)
	}
	if !ok {
		return nil, append(warnings, unparseable(ProbeNetwork))
	}
	if len(adapters) > MaxNetworkAdapters {
		adapters = adapters[:MaxNetworkAdapters]
	}
	return adapters, warnings
}

// counterSample is one adapter's cumulative counters at two instants
// elapsedSeconds apart. A nil pointer is a counter the OS did not report.
type counterSample struct {
	name           string
	linkSpeed      *int64
	elapsedSeconds float64
	rxBytes        [2]*int64
	txBytes        [2]*int64
	rxPackets      [2]*int64
	txPackets      [2]*int64
	rxErrors       *int64
	txErrors       *int64
	rxDiscards     *int64
	txDiscards     *int64
}

// adapter turns the two samples into rates. A rate whose counter is missing,
// went backwards (a reset or wrap) or whose window is not positive is nil.
func (s counterSample) adapter() contract.HeartbeatNetworkAdapter {
	a := contract.HeartbeatNetworkAdapter{
		Name:                   s.name,
		LinkSpeedBitsPerSecond: s.linkSpeed,
		ReceiveErrors:          s.rxErrors,
		SendErrors:             s.txErrors,
		ReceiveDiscards:        s.rxDiscards,
		SendDiscards:           s.txDiscards,
	}

	rate := func(pair [2]*int64) *float64 {
		if pair[0] == nil || pair[1] == nil || s.elapsedSeconds <= 0 || *pair[1] < *pair[0] {
			return nil
		}
		r := float64(*pair[1]-*pair[0]) / s.elapsedSeconds
		return &r
	}
	bits := func(pair [2]*int64) *int64 {
		r := rate(pair)
		if r == nil {
			return nil
		}
		b := int64(math.Round(*r * 8))
		return &b
	}

	a.ReceiveBitsPerSecond = bits(s.rxBytes)
	a.SendBitsPerSecond = bits(s.txBytes)
	a.PacketsReceivedPerSecond = roundedPtr(rate(s.rxPackets))
	a.PacketsSentPerSecond = roundedPtr(rate(s.txPackets))

	if a.LinkSpeedBitsPerSecond != nil && (a.ReceiveBitsPerSecond != nil || a.SendBitsPerSecond != nil) {
		var busiest int64
		for _, v := range []*int64{a.ReceiveBitsPerSecond, a.SendBitsPerSecond} {
			if v != nil && *v > busiest {
				busiest = *v
			}
		}
		u := math.Min(100, float64(busiest)/float64(*a.LinkSpeedBitsPerSecond)*100)
		a.UtilizationPercent = roundedPtr(&u)
	}
	return a
}

// roundedPtr rounds a rate to two decimal places.
func roundedPtr(v *float64) *float64 {
	if v == nil {
		return nil
	}
	r := math.Round(*v*100) / 100
	return &r
}

// parseWindowsNetwork reads the JSON line the Windows probe prints per
// adapter. No lines means no adapter is up; ok is false only when lines were
// printed and none of them could be read.
func parseWindowsNetwork(out string) ([]contract.HeartbeatNetworkAdapter, bool) {
	lines := splitLines(out)
	var adapters []contract.HeartbeatNetworkAdapter
	for _, line := range lines {
		fields, err := decodeObject(line)
		if err != nil {
			continue
		}
		name, _ := fields["name"].(string)
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		s := counterSample{
			name:       name,
			linkSpeed:  positiveField(fields, "linkSpeed"),
			rxBytes:    [2]*int64{counterField(fields, "rxBytes1"), counterField(fields, "rxBytes2")},
			txBytes:    [2]*int64{counterField(fields, "txBytes1"), counterField(fields, "txBytes2")},
			rxPackets:  [2]*int64{counterField(fields, "rxPackets1"), counterField(fields, "rxPackets2")},
			txPackets:  [2]*int64{counterField(fields, "txPackets1"), counterField(fields, "txPackets2")},
			rxErrors:   counterField(fields, "rxErrors"),
			txErrors:   counterField(fields, "txErrors"),
			rxDiscards: counterField(fields, "rxDiscards"),
			txDiscards: counterField(fields, "txDiscards"),
		}
		freq, t1, t2 := positiveField(fields, "freq"), counterField(fields, "t1"), counterField(fields, "t2")
		if freq != nil && t1 != nil && t2 != nil {
			s.elapsedSeconds = float64(*t2-*t1) / float64(*freq)
		}
		adapters = append(adapters, s.adapter())
	}
	return adapters, len(lines) == 0 || len(adapters) > 0
}

// counterField is fields[key] as a non-negative integer; nil otherwise.
func counterField(fields map[string]any, key string) *int64 {
	n, ok := fields[key].(json.Number)
	if !ok {
		return nil
	}
	v, err := n.Int64()
	if err != nil || v < 0 {
		return nil
	}
	return &v
}

// positiveField is fields[key] as an integer above zero; nil otherwise.
func positiveField(fields map[string]any, key string) *int64 {
	v := counterField(fields, key)
	if v == nil || *v == 0 {
		return nil
	}
	return v
}

// darwinSampleMarker separates the darwin probe's adapter list and its two
// netstat samples.
const darwinSampleMarker = "--- sample"

// darwinMediaSpeed finds the link rate in an ifconfig media line such as
// "autoselect (1000baseT <full-duplex>)" or "10Gbase-T <full-duplex>".
var darwinMediaSpeed = regexp.MustCompile(`(?i)\b(\d+)(G?)base`)

// parseDarwinNetwork reads the darwin probe: one "adapter=<name> <media>"
// line per active en* interface, then two netstat -ibdn tables, each after a
// darwinSampleMarker line, darwinNetworkSampleSeconds apart. ok is false when
// the two samples are not both there.
func parseDarwinNetwork(out string) ([]contract.HeartbeatNetworkAdapter, bool) {
	sections := strings.Split(strings.ReplaceAll(out, "\r", ""), darwinSampleMarker)
	if len(sections) != 3 {
		return nil, false
	}
	first, second := parseNetstat(sections[1]), parseNetstat(sections[2])

	var adapters []contract.HeartbeatNetworkAdapter
	for _, line := range splitLines(sections[0]) {
		rest, ok := strings.CutPrefix(line, "adapter=")
		if !ok {
			continue
		}
		name, media, _ := strings.Cut(strings.TrimSpace(rest), " ")
		if name == "" {
			continue
		}
		a, b := first[name], second[name]
		adapters = append(adapters, counterSample{
			name:           name,
			linkSpeed:      darwinLinkSpeed(media),
			elapsedSeconds: darwinNetworkSampleSeconds,
			rxBytes:        [2]*int64{a["Ibytes"], b["Ibytes"]},
			txBytes:        [2]*int64{a["Obytes"], b["Obytes"]},
			rxPackets:      [2]*int64{a["Ipkts"], b["Ipkts"]},
			txPackets:      [2]*int64{a["Opkts"], b["Opkts"]},
			rxErrors:       b["Ierrs"],
			txErrors:       b["Oerrs"],
			rxDiscards:     b["Drop"],
		}.adapter())
	}
	return adapters, true
}

// darwinLinkSpeed is the bits per second an ifconfig media line names; nil
// when it names none (Wi-Fi reports only "autoselect").
func darwinLinkSpeed(media string) *int64 {
	m := darwinMediaSpeed.FindStringSubmatch(media)
	if m == nil {
		return nil
	}
	v, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || v <= 0 {
		return nil
	}
	unit := int64(1_000_000)
	if m[2] != "" {
		unit = 1_000_000_000
	}
	speed := v * unit
	return &speed
}

// parseNetstat reads a netstat -ibdn table into each interface's link-layer
// counters, keyed by interface then by column heading. Columns are located by
// the heading row, and only <Link#n> rows with one value per heading count.
func parseNetstat(table string) map[string]map[string]*int64 {
	rows := map[string]map[string]*int64{}
	var headings []string
	for _, line := range splitLines(table) {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "Name" {
			headings = fields
			continue
		}
		if headings == nil || len(fields) != len(headings) {
			continue
		}
		counters := map[string]*int64{}
		for i, heading := range headings {
			if heading == "Network" && !strings.HasPrefix(fields[i], "<Link#") {
				counters = nil
				break
			}
			if v, err := strconv.ParseInt(fields[i], 10, 64); err == nil && v >= 0 {
				counters[heading] = &v
			}
		}
		if counters != nil {
			rows[strings.TrimSuffix(fields[0], "*")] = counters
		}
	}
	return rows
}
