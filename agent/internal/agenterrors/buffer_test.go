package agenterrors

import (
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// ============================================================================
// AC1: warn/error captured, info/debug and below-level records are not.
// ============================================================================

// TestScenario_AC1_WarnAndErrorRecordsAreCapturedInfoAndDebugAreNot covers:
//
//	Given an agent logger at level info with an error buffer attached
//	When the "enforce" component logs warn "policy enforcement failed" and
//	     the "client" component logs debug "request sent" and info "checked in"
//	Then the buffer holds exactly one entry with level "warn", component
//	     "enforce", message "policy enforcement failed"
func TestScenario_AC1_WarnAndErrorRecordsAreCapturedInfoAndDebugAreNot(t *testing.T) {
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC))
	root := logging.New(fsys, clock, "/agent.log", logging.LevelInfo, "agent")

	buf := New()
	root.SetSink(buf)

	enforce := root.With("enforce")
	client := root.With("client")

	enforce.Warn("policy enforcement failed")
	client.Debug("request sent")
	client.Info("checked in")

	if got := buf.Len(); got != 1 {
		t.Fatalf("buffer len = %d, want 1", got)
	}
	entries := buf.Drain()
	if len(entries) != 1 {
		t.Fatalf("drained %d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Level != "warn" || e.Component != "enforce" || e.Message != "policy enforcement failed" {
		t.Errorf("entry = %+v, want level=warn component=enforce message=%q", e, "policy enforcement failed")
	}
}

// TestScenario_AC1_RecordsBelowConfiguredLevelAreNotCaptured covers:
//
//	Given an agent logger at level error with an error buffer attached
//	When a warn record "agent update failed" is logged
//	Then the buffer is empty
func TestScenario_AC1_RecordsBelowConfiguredLevelAreNotCaptured(t *testing.T) {
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Now())
	root := logging.New(fsys, clock, "/agent.log", logging.LevelError, "agent")

	buf := New()
	root.SetSink(buf)

	root.Warn("agent update failed")

	if got := buf.Len(); got != 0 {
		t.Fatalf("buffer len = %d, want 0", got)
	}
}

// Error-level records are captured the same way as warn.
func TestScenario_AC1_ErrorRecordsAreCaptured(t *testing.T) {
	fsys := fake.NewFS()
	clock := fake.NewClock(time.Now())
	root := logging.New(fsys, clock, "/agent.log", logging.LevelInfo, "agent")
	buf := New()
	root.SetSink(buf)

	root.Error("check-in failed")

	if got := buf.Len(); got != 1 {
		t.Fatalf("buffer len = %d, want 1", got)
	}
}

// ============================================================================
// AC2: a failed log write still captures the record.
// ============================================================================

// TestScenario_AC2_AFailedLogWriteStillCapturesTheRecord covers:
//
//	Given the log file append always fails
//	When a warn record "signed-in user could not be read" is logged
//	Then the buffer holds that entry
func TestScenario_AC2_AFailedLogWriteStillCapturesTheRecord(t *testing.T) {
	fsys := fake.NewFS()
	fsys.WriteErr = func(string) error { return errAlwaysFails }
	clock := fake.NewClock(time.Now())
	root := logging.New(fsys, clock, "/agent.log", logging.LevelInfo, "agent")

	buf := New()
	root.SetSink(buf)

	err := root.Warn("signed-in user could not be read")
	if err == nil {
		t.Fatal("expected the write to fail")
	}

	entries := buf.Drain()
	if len(entries) != 1 || entries[0].Message != "signed-in user could not be read" {
		t.Fatalf("entries = %+v, want one entry with that message", entries)
	}
}

// ============================================================================
// AC3: repeats collapse into one entry with a count.
// ============================================================================

// TestScenario_AC3_RepeatsCollapseIntoOneEntryWithACount covers:
//
//	Given the clock reads 10:00, 10:15 and 10:30 for three warn records
//	     "policy enforcement failed" from "enforce" with error fields "a","b","c"
//	Then the buffer holds one entry with count 3, firstAt 10:00, lastAt 10:30
//	     and fields error "c"
func TestScenario_AC3_RepeatsCollapseIntoOneEntryWithACount(t *testing.T) {
	buf := New()
	base := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)

	buf.Add("warn", "enforce", "policy enforcement failed", []logging.Field{logging.F("error", "a")}, base)
	buf.Add("warn", "enforce", "policy enforcement failed", []logging.Field{logging.F("error", "b")}, base.Add(15*time.Minute))
	buf.Add("warn", "enforce", "policy enforcement failed", []logging.Field{logging.F("error", "c")}, base.Add(30*time.Minute))

	entries := buf.Drain()
	if len(entries) != 1 {
		t.Fatalf("drained %d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Count != 3 {
		t.Errorf("count = %d, want 3", e.Count)
	}
	if e.FirstAt != base.Format(wireTimeFormat) {
		t.Errorf("firstAt = %s, want %s", e.FirstAt, base.Format(wireTimeFormat))
	}
	if e.LastAt != base.Add(30*time.Minute).Format(wireTimeFormat) {
		t.Errorf("lastAt = %s, want %s", e.LastAt, base.Add(30*time.Minute).Format(wireTimeFormat))
	}
	if e.Fields["error"] != "c" {
		t.Errorf("fields[error] = %q, want %q (the latest record's fields)", e.Fields["error"], "c")
	}
}

// wireTimeFormat mirrors the unexported timeFormat constant in buffer.go: the
// logger's own ISO-8601-with-milliseconds layout.
const wireTimeFormat = "2006-01-02T15:04:05.000Z07:00"

// ============================================================================
// AC4: the buffer evicts the oldest entry beyond 50.
// ============================================================================

// TestScenario_AC4_TheBufferEvictsTheOldestEntryBeyond50 covers:
//
//	Given the buffer holds 50 distinct entries
//	When a 51st distinct warn message is logged
//	Then the buffer holds 50 entries, including the new one, and the entry
//	     with the oldest lastAt is gone
func TestScenario_AC4_TheBufferEvictsTheOldestEntryBeyond50(t *testing.T) {
	buf := New()
	base := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

	for i := 0; i < MaxEntries; i++ {
		buf.Add("warn", "comp", messageFor(i), nil, base.Add(time.Duration(i)*time.Minute))
	}
	if got := buf.Len(); got != MaxEntries {
		t.Fatalf("buffer len = %d, want %d", got, MaxEntries)
	}

	// The 51st distinct message, with the newest lastAt of all.
	buf.Add("warn", "comp", messageFor(MaxEntries), nil, base.Add(time.Duration(MaxEntries)*time.Minute))

	if got := buf.Len(); got != MaxEntries {
		t.Fatalf("buffer len after 51st = %d, want %d", got, MaxEntries)
	}

	entries := buf.Drain()
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Message] = true
	}
	if !seen[messageFor(MaxEntries)] {
		t.Error("expected the new (51st) entry to be present")
	}
	if seen[messageFor(0)] {
		t.Error("expected the entry with the oldest lastAt (the first one added) to be evicted")
	}
}

func messageFor(i int) string {
	return "distinct message " + strconv.Itoa(i)
}

// ============================================================================
// AC5: entry values are normalised.
// ============================================================================

// TestScenario_AC5_LongAndNonStringFieldsAreNormalised covers:
//
//	When a warn record is logged with 10 fields, a 1000-character value, an
//	     integer status 503 and a 400-character message
//	Then the entry keeps the first 8 fields, the long value is 256 characters,
//	     status is "503" and the message is 256 characters
func TestScenario_AC5_LongAndNonStringFieldsAreNormalised(t *testing.T) {
	buf := New()

	longValue := strings.Repeat("x", 1000)
	longMessage := strings.Repeat("m", 400)

	fields := []logging.Field{
		logging.F("f0", "v0"),
		logging.F("long", longValue),
		logging.F("status", 503),
		logging.F("f3", "v3"),
		logging.F("f4", "v4"),
		logging.F("f5", "v5"),
		logging.F("f6", "v6"),
		logging.F("f7", "v7"),
		logging.F("f8", "v8"), // beyond the first 8: dropped
		logging.F("f9", "v9"), // beyond the first 8: dropped
	}

	buf.Add("warn", "comp", longMessage, fields, time.Now())
	entries := buf.Drain()
	if len(entries) != 1 {
		t.Fatalf("drained %d entries, want 1", len(entries))
	}
	e := entries[0]

	if len(e.Fields) != MaxFields {
		t.Errorf("kept %d fields, want %d: %+v", len(e.Fields), MaxFields, e.Fields)
	}
	if _, ok := e.Fields["f8"]; ok {
		t.Error("field beyond the first 8 (f8) should have been dropped")
	}
	if _, ok := e.Fields["f9"]; ok {
		t.Error("field beyond the first 8 (f9) should have been dropped")
	}
	if got := len([]rune(e.Fields["long"])); got != MaxValueRunes {
		t.Errorf("long value length = %d, want %d", got, MaxValueRunes)
	}
	if e.Fields["status"] != "503" {
		t.Errorf("status = %q, want %q (JSON encoding of the integer)", e.Fields["status"], "503")
	}
	if got := len([]rune(e.Message)); got != MaxValueRunes {
		t.Errorf("message length = %d, want %d", got, MaxValueRunes)
	}
}

// AC5 also bounds component and key length; covered directly against the
// constants so a future change to either is caught here.
func TestScenario_AC5_ComponentAndKeysAreTruncated(t *testing.T) {
	buf := New()
	longComponent := strings.Repeat("c", 100)
	longKey := strings.Repeat("k", 100)

	buf.Add("warn", longComponent, "msg", []logging.Field{logging.F(longKey, "v")}, time.Now())
	entries := buf.Drain()
	e := entries[0]

	if got := len([]rune(e.Component)); got != MaxKeyRunes {
		t.Errorf("component length = %d, want %d", got, MaxKeyRunes)
	}
	for key := range e.Fields {
		if got := len([]rune(key)); got != MaxKeyRunes {
			t.Errorf("field key length = %d, want %d", got, MaxKeyRunes)
		}
	}
}

// ============================================================================
// AC6: secret-looking fields are redacted.
// ============================================================================

// TestScenario_AC6_SecretLookingFieldsAreRedacted is the AC6 scenario outline.
func TestScenario_AC6_SecretLookingFieldsAreRedacted(t *testing.T) {
	keys := []string{"enrollmentToken", "deviceSecret", "Authorization", "X-MDM-Signature", "cookie", "password"}
	for _, key := range keys {
		key := key
		t.Run(key, func(t *testing.T) {
			buf := New()
			buf.Add("warn", "comp", "msg-"+key, []logging.Field{logging.F(key, "abc123")}, time.Now())
			entries := buf.Drain()
			if len(entries) != 1 {
				t.Fatalf("drained %d entries, want 1", len(entries))
			}
			got, ok := entries[0].Fields[key]
			if !ok {
				t.Fatalf("expected field %q to be present, fields = %+v", key, entries[0].Fields)
			}
			if got != Redacted {
				t.Errorf("field %q = %q, want %q", key, got, Redacted)
			}
		})
	}
}

// A field whose key does not look secret is never redacted.
func TestScenario_AC6_NonSecretFieldsAreNotRedacted(t *testing.T) {
	buf := New()
	buf.Add("warn", "comp", "msg", []logging.Field{logging.F("status", "503")}, time.Now())
	entries := buf.Drain()
	if entries[0].Fields["status"] != "503" {
		t.Errorf("status = %q, want unredacted %q", entries[0].Fields["status"], "503")
	}
}

// ============================================================================
// AC8: agentErrors is capped at 32 KB.
// ============================================================================

// TestScenario_AC8_AgentErrorsIsCappedAt32KB covers:
//
//	Given the buffer holds 50 entries, each with 8 fields of 256 characters
//	When a cycle builds its check-in
//	Then the encoded agentErrors is at most 32768 bytes
//	And every entry left out has an older lastAt than every entry sent
//	And the buffer is empty after the build
// bigMessage is a distinct, exactly-256-rune message for index i: the index
// goes first so it survives AC5's 256-rune truncation and keeps every
// message in the test distinct.
func bigMessage(i int) string {
	prefix := strconv.Itoa(i)
	return prefix + strings.Repeat("m", MaxValueRunes-len(prefix))
}

func TestScenario_AC8_AgentErrorsIsCappedAt32KB(t *testing.T) {
	buf := New()
	base := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

	longValue := strings.Repeat("v", MaxValueRunes)
	fields := make([]logging.Field, 0, MaxFields)
	for i := 0; i < MaxFields; i++ {
		fields = append(fields, logging.F("field"+strconv.Itoa(i), longValue))
	}

	for i := 0; i < MaxEntries; i++ {
		buf.Add("warn", "comp", bigMessage(i), fields, base.Add(time.Duration(i)*time.Minute))
	}

	collected := buf.Collect()

	encoded, err := json.Marshal(collected)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(encoded) > MaxEncodedBytes {
		t.Fatalf("encoded agentErrors is %d bytes, want <= %d", len(encoded), MaxEncodedBytes)
	}
	if len(collected) == 0 {
		t.Fatal("expected at least one entry to fit")
	}
	if len(collected) >= MaxEntries {
		t.Fatalf("expected some entries to be left out, kept %d of %d", len(collected), MaxEntries)
	}

	// Every kept entry's lastAt must be >= every left-out entry's lastAt:
	// since entries were added with strictly increasing lastAt by index, the
	// kept set must be the newest-lastAt suffix of entries added, i.e. the
	// highest-indexed messages.
	messageIndex := map[string]int{}
	for i := 0; i < MaxEntries; i++ {
		messageIndex[bigMessage(i)] = i
	}
	minKeptIndex := MaxEntries
	for _, e := range collected {
		i, ok := messageIndex[e.Message]
		if !ok {
			t.Fatalf("collected entry with unrecognised message %q", e.Message)
		}
		if i < minKeptIndex {
			minKeptIndex = i
		}
	}
	if len(collected) != MaxEntries-minKeptIndex {
		t.Errorf("kept entries are not exactly the newest-lastAt suffix: kept %d, minKeptIndex %d", len(collected), minKeptIndex)
	}

	if got := buf.Len(); got != 0 {
		t.Errorf("buffer len after Collect = %d, want 0 (drained)", got)
	}
}

// Fit in isolation: nil in, nil out; everything fits under a large cap.
func TestScenario_AC8_FitReturnsNilForEmptyInput(t *testing.T) {
	if got := Fit(nil, MaxEncodedBytes); got != nil {
		t.Errorf("Fit(nil, ...) = %v, want nil", got)
	}
}

// ============================================================================
// Edge case: concurrent Add from multiple goroutines on the same key sums to
// the right count (the repo runs tests without -race, so this is checked by
// count rather than the race detector).
// ============================================================================

func TestScenario_Edge_ConcurrentAddOnSameKeyIsSafe(t *testing.T) {
	buf := New()
	var wg sync.WaitGroup
	const perGoroutine = 500
	now := time.Now()

	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				buf.Add("warn", "heartbeat", "request failed", nil, now)
			}
		}()
	}
	wg.Wait()

	entries := buf.Drain()
	if len(entries) != 1 {
		t.Fatalf("drained %d entries, want 1", len(entries))
	}
	if entries[0].Count != 2*perGoroutine {
		t.Errorf("count = %d, want %d", entries[0].Count, 2*perGoroutine)
	}
}

var errAlwaysFails = &alwaysFailErr{}

type alwaysFailErr struct{}

func (*alwaysFailErr) Error() string { return "always fails" }
