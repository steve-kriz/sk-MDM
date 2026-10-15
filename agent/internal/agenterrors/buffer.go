// Package agenterrors collects the warn and error records the agent logs so
// they can travel to the backend on the next check-in.
//
// The buffer is in memory only, bounded to MaxEntries distinct records, and
// collapses repeats of the same (level, component, message) into one entry
// with a count: an agent that fails the same way every cycle while offline
// reports a handful of entries, not thousands of lines.
package agenterrors

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
)

// The bounds on what the buffer holds and what one check-in carries.
const (
	// MaxEntries is the most distinct entries the buffer holds.
	MaxEntries = 50
	// MaxFields is the most fields one entry keeps, in call order.
	MaxFields = 8
	// MaxValueRunes is the longest a field value or the message may be.
	MaxValueRunes = 256
	// MaxKeyRunes is the longest a field key or the component may be.
	MaxKeyRunes = 64
	// MaxEncodedBytes is the largest the JSON-encoded agentErrors array of one
	// check-in body may be.
	MaxEncodedBytes = 32768
)

// Redacted replaces the value of a field whose key looks secret.
const Redacted = "[redacted]"

// timeFormat is the logger's own timestamp format: ISO-8601 UTC with
// milliseconds.
const timeFormat = "2006-01-02T15:04:05.000Z07:00"

// secretKeyParts mark a field key whose value must never leave the device.
var secretKeyParts = []string{"token", "secret", "password", "authorization", "signature", "cookie"}

type key struct {
	level, component, message string
}

type entry struct {
	key     key
	fields  map[string]string
	count   int
	firstAt time.Time
	lastAt  time.Time
}

// Buffer is the bounded, deduplicating, goroutine-safe store of warn and
// error records. Its zero value is not usable; call New.
type Buffer struct {
	mu      sync.Mutex
	entries map[key]*entry
}

// New returns an empty buffer.
func New() *Buffer {
	return &Buffer{entries: map[key]*entry{}}
}

// Record makes the buffer a logging.Sink. Records below LevelWarn are
// ignored.
func (b *Buffer) Record(level logging.Level, component, msg string, fields []logging.Field, at time.Time) {
	if level < logging.LevelWarn {
		return
	}
	b.Add(level.String(), component, msg, fields, at)
}

// Add records one warn or error record logged at at. A record with the same
// (level, component, message) as a buffered entry adds to its count, moves its
// lastAt to the later of the two times and replaces its fields; any other
// record becomes a new entry, evicting the entry with the oldest lastAt when
// the buffer already holds MaxEntries.
func (b *Buffer) Add(level, component, message string, fields []logging.Field, at time.Time) {
	k := key{
		level:     level,
		component: truncate(component, MaxKeyRunes),
		message:   truncate(message, MaxValueRunes),
	}
	normalised := normaliseFields(fields)
	at = at.UTC()

	b.mu.Lock()
	defer b.mu.Unlock()

	if e, ok := b.entries[k]; ok {
		e.count++
		if at.Before(e.firstAt) {
			e.firstAt = at
		}
		if !at.Before(e.lastAt) {
			e.lastAt = at
			e.fields = normalised
		}
		return
	}

	if len(b.entries) >= MaxEntries {
		var oldest *entry
		for _, e := range b.entries {
			if oldest == nil || e.lastAt.Before(oldest.lastAt) {
				oldest = e
			}
		}
		delete(b.entries, oldest.key)
	}
	b.entries[k] = &entry{key: k, fields: normalised, count: 1, firstAt: at, lastAt: at}
}

// Len is the number of distinct entries buffered.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.entries)
}

// Drain returns every buffered entry, newest lastAt first, and empties the
// buffer. It returns nil when the buffer is empty.
func (b *Buffer) Drain() []contract.AgentError {
	b.mu.Lock()
	taken := make([]*entry, 0, len(b.entries))
	for _, e := range b.entries {
		taken = append(taken, e)
	}
	b.entries = map[key]*entry{}
	b.mu.Unlock()

	if len(taken) == 0 {
		return nil
	}
	sort.SliceStable(taken, func(i, j int) bool {
		if !taken[i].lastAt.Equal(taken[j].lastAt) {
			return taken[i].lastAt.After(taken[j].lastAt)
		}
		return taken[i].firstAt.After(taken[j].firstAt)
	})

	out := make([]contract.AgentError, 0, len(taken))
	for _, e := range taken {
		out = append(out, contract.AgentError{
			Level:     e.key.level,
			Component: e.key.component,
			Message:   e.key.message,
			Fields:    e.fields,
			Count:     e.count,
			FirstAt:   e.firstAt.Format(timeFormat),
			LastAt:    e.lastAt.Format(timeFormat),
		})
	}
	return out
}

// Collect drains the buffer and caps the result to MaxEncodedBytes: what one
// check-in body carries. Entries left out by the cap are discarded.
func (b *Buffer) Collect() []contract.AgentError {
	return Fit(b.Drain(), MaxEncodedBytes)
}

// Fit returns the entries whose JSON-encoded array is at most maxBytes,
// leaving out the entries with the oldest lastAt until it fits. The result is
// ordered newest lastAt first, and is nil when nothing fits.
func Fit(entries []contract.AgentError, maxBytes int) []contract.AgentError {
	if len(entries) == 0 {
		return nil
	}
	sorted := append([]contract.AgentError(nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return parseTime(sorted[i].LastAt).After(parseTime(sorted[j].LastAt))
	})

	// json.Marshal of a slice is "[" + the elements joined by "," + "]", so
	// the array's size is the sum of its elements' sizes plus the punctuation.
	size := 2
	kept := 0
	for i, e := range sorted {
		encoded, err := json.Marshal(e)
		if err != nil {
			break
		}
		next := size + len(encoded)
		if i > 0 {
			next++
		}
		if next > maxBytes {
			break
		}
		size = next
		kept++
	}
	if kept == 0 {
		return nil
	}
	return sorted[:kept]
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// normaliseFields keeps the first MaxFields fields, encodes non-string values
// as JSON, cuts keys and values to their limits and redacts secret-looking
// keys. The result is never nil.
func normaliseFields(fields []logging.Field) map[string]string {
	out := make(map[string]string, MaxFields)
	for _, f := range fields {
		if len(out) >= MaxFields {
			break
		}
		k := truncate(f.Key, MaxKeyRunes)
		if k == "" {
			continue
		}
		if _, dup := out[k]; dup {
			continue
		}
		if isSecretKey(f.Key) {
			out[k] = Redacted
			continue
		}
		out[k] = truncate(stringValue(f.Value), MaxValueRunes)
	}
	return out
}

func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	encoded, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(encoded)
}

func isSecretKey(k string) bool {
	lower := strings.ToLower(k)
	for _, part := range secretKeyParts {
		if strings.Contains(lower, part) {
			return true
		}
	}
	return false
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
