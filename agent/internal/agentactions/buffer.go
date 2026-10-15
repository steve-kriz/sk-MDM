// Package agentactions collects the actions the agent performs on the device
// (firewall or antivirus turned on, blocked domains rewritten, an agent update
// rolled back) so they can travel to the backend on the next check-in and
// appear in the device History.
//
// The buffer is in memory only and bounded to MaxActions entries: actions
// still buffered when the process exits are lost.
package agentactions

import (
	"sort"
	"sync"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
)

// The bounds on what the buffer holds.
const (
	// MaxActions is the most actions the buffer holds.
	MaxActions = 20
	// MaxDetails is the most details one action keeps, in sorted key order.
	MaxDetails = 8
	// MaxKeyRunes is the longest a detail key may be.
	MaxKeyRunes = 64
	// MaxValueRunes is the longest a detail value may be.
	MaxValueRunes = 256
)

// timeFormat is the wire format of occurredAt: ISO-8601 UTC to the second.
const timeFormat = "2006-01-02T15:04:05Z"

type entry struct {
	actionType string
	details    map[string]string
	at         time.Time
	seq        uint64
}

// Buffer is the bounded, goroutine-safe store of agent actions. Its zero
// value is not usable; call New.
type Buffer struct {
	clock   platform.Clock
	mu      sync.Mutex
	entries []entry
	seq     uint64
}

// New returns an empty buffer that stamps Record calls with clock. A nil
// clock means the system time.
func New(clock platform.Clock) *Buffer {
	if clock == nil {
		clock = platform.SystemClock{}
	}
	return &Buffer{clock: clock}
}

// Record buffers one action that happened now.
func (b *Buffer) Record(actionType string, details map[string]string) {
	b.RecordAt(actionType, details, b.clock.Now())
}

// RecordAt buffers one action that happened at at. When the buffer already
// holds MaxActions, the entry with the oldest occurredAt is removed first.
func (b *Buffer) RecordAt(actionType string, details map[string]string, at time.Time) {
	e := entry{
		actionType: actionType,
		details:    normaliseDetails(details),
		at:         at.UTC().Truncate(time.Second),
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.entries) >= MaxActions {
		oldest := 0
		for i := 1; i < len(b.entries); i++ {
			if b.entries[i].at.Before(b.entries[oldest].at) {
				oldest = i
			}
		}
		b.entries = append(b.entries[:oldest], b.entries[oldest+1:]...)
	}
	b.seq++
	e.seq = b.seq
	b.entries = append(b.entries, e)
}

// Collect returns every buffered action ordered by occurredAt ascending
// (equal times in record order) and empties the buffer. It returns nil when
// the buffer is empty.
func (b *Buffer) Collect() []contract.AgentAction {
	b.mu.Lock()
	taken := b.entries
	b.entries = nil
	b.mu.Unlock()

	if len(taken) == 0 {
		return nil
	}
	sort.SliceStable(taken, func(i, j int) bool {
		if !taken[i].at.Equal(taken[j].at) {
			return taken[i].at.Before(taken[j].at)
		}
		return taken[i].seq < taken[j].seq
	})

	out := make([]contract.AgentAction, 0, len(taken))
	for _, e := range taken {
		out = append(out, contract.AgentAction{
			Type:       e.actionType,
			OccurredAt: e.at.Format(timeFormat),
			Details:    e.details,
		})
	}
	return out
}

// normaliseDetails keeps at most MaxDetails entries in sorted key order, with
// keys cut to MaxKeyRunes and values to MaxValueRunes. The result is never
// nil.
func normaliseDetails(details map[string]string) map[string]string {
	keys := make([]string, 0, len(details))
	for k := range details {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make(map[string]string, MaxDetails)
	for _, k := range keys {
		if len(out) >= MaxDetails {
			break
		}
		cut := truncate(k, MaxKeyRunes)
		if _, dup := out[cut]; dup {
			continue
		}
		out[cut] = truncate(details[k], MaxValueRunes)
	}
	return out
}

// truncate cuts s to at most max runes.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max])
}
