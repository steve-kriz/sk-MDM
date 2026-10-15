// E2E cucumber-style and unit tests for TASK-054's heartbeat diagnostics:
// the agent logs the backend's error code on a failed heartbeat (AC13) and
// logs each change to the stored heartbeat interval (AC14).
//
// New file per TASK-054 instructions: heartbeat_test.go (AC16) must pass
// unchanged. This file reuses its package-private helpers (mockTransport,
// enrolledStore, newLogger, warnLines, noopCollect), since it lives in the
// same package.
package heartbeat

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// allLines decodes every JSON record the fake file system holds for path,
// regardless of level.
func allLines(fsys *fake.FS, path string) []map[string]any {
	data, ok := fsys.Content(path)
	if !ok {
		return nil
	}
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err == nil {
			records = append(records, record)
		}
	}
	return records
}

func infoLines(fsys *fake.FS) []map[string]any {
	var out []map[string]any
	for _, record := range allLines(fsys, logPath) {
		if record["level"] == "info" {
			out = append(out, record)
		}
	}
	return out
}

// ============================================================================
// Scenario Outline: The agent logs the backend's error code on a failed
// heartbeat (AC13)
// ============================================================================

func TestScenario_RunOnceLogsBackendErrorCode(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		body      string
		wantError string // "" means no error field expected
	}{
		{"heartbeat_not_configured", http.StatusServiceUnavailable, `{"error":"heartbeat_not_configured"}`, "heartbeat_not_configured"},
		{"heartbeat_store_unavailable", http.StatusServiceUnavailable, `{"error":"heartbeat_store_unavailable"}`, "heartbeat_store_unavailable"},
		{"invalid_signature", http.StatusUnauthorized, `{"error":"invalid_signature"}`, "invalid_signature"},
		{"non-JSON body", http.StatusBadGateway, `<html>Bad Gateway</html>`, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given: the heartbeat interval is 300 and the device is enrolled.
			fsys := fake.NewFS()
			clock := fake.NewClock(time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC))
			deps := &Deps{
				Client: &mockTransport{doFunc: func(string, string, []byte) (*http.Response, error) {
					return fake.Response(tc.status, tc.body), nil
				}},
				Store:   enrolledStore(),
				Clock:   clock,
				Logger:  newLogger(fsys, clock),
				Collect: noopCollect,
			}
			deps.SetInterval(300)

			// When: RunOnce runs.
			err := RunOnce(context.Background(), deps)

			// Then: RunOnce returns nil and the interval is unchanged.
			if err != nil {
				t.Fatalf("RunOnce returned %v, want nil", err)
			}
			if got := deps.Interval(); got != 300 {
				t.Errorf("Interval() = %d, want unchanged 300", got)
			}

			// And: exactly one warn line "heartbeat failed" was written with
			// status <status>, and the error field only when expected.
			warns := warnLines(fsys)
			if len(warns) != 1 {
				t.Fatalf("warn lines = %v, want exactly one", warns)
			}
			var record map[string]any
			if err := json.Unmarshal([]byte(warns[0]), &record); err != nil {
				t.Fatalf("warn line did not decode as JSON: %v", err)
			}
			if record["msg"] != "heartbeat failed" {
				t.Errorf("msg = %v, want %q", record["msg"], "heartbeat failed")
			}
			if status, ok := record["status"].(float64); !ok || int(status) != tc.status {
				t.Errorf("status = %v, want %d", record["status"], tc.status)
			}
			if tc.wantError == "" {
				if _, present := record["error"]; present {
					t.Errorf("error field = %v, want absent", record["error"])
				}
			} else if record["error"] != tc.wantError {
				t.Errorf("error = %v, want %q", record["error"], tc.wantError)
			}
		})
	}
}

// ============================================================================
// Scenario Outline: The agent logs each heartbeat interval change once (AC14)
// ============================================================================

func TestScenario_SetIntervalLogsEachChangeOnce(t *testing.T) {
	cases := []struct {
		name       string
		before     int
		input      int
		wantLine   bool
		wantFrom   int
		wantTo     int
	}{
		{"0 to 300", 0, 300, true, 0, 300},
		{"300 to 0", 300, 0, true, 300, 0},
		{"300 unchanged", 300, 300, false, 0, 0},
		{"60 stored, 30 clamped to 60: unchanged", 60, 30, false, 0, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fake.NewFS()
			clock := fake.NewClock(time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC))
			deps := &Deps{Logger: newLogger(fsys, clock)}
			// Given: the stored heartbeat interval is <before>, set directly so
			// the setup itself writes no "heartbeat interval changed" line.
			deps.interval.Store(int64(tc.before))

			// When: SetInterval(<input>) is called.
			deps.SetInterval(tc.input)

			lines := infoLines(fsys)
			if !tc.wantLine {
				if len(lines) != 0 {
					t.Fatalf("info lines = %v, want none", lines)
				}
				return
			}
			if len(lines) != 1 {
				t.Fatalf("info lines = %v, want exactly one", lines)
			}
			record := lines[0]
			if record["msg"] != "heartbeat interval changed" {
				t.Errorf("msg = %v, want %q", record["msg"], "heartbeat interval changed")
			}
			if from, ok := record["from"].(float64); !ok || int(from) != tc.wantFrom {
				t.Errorf("from = %v, want %d", record["from"], tc.wantFrom)
			}
			if to, ok := record["to"].(float64); !ok || int(to) != tc.wantTo {
				t.Errorf("to = %v, want %d", record["to"], tc.wantTo)
			}
		})
	}
}

// ============================================================================
// Scenario: SetInterval with no logger does not panic and is race-free (AC14
// edge)
// ============================================================================

func TestScenario_SetIntervalNilLoggerNoPanicConcurrent(t *testing.T) {
	// Given: heartbeat.Deps with a nil Logger.
	var d Deps // Logger is nil

	// When: SetInterval and Interval are called concurrently.
	// Note: `go test -race` could not be run in this environment (no cgo/C
	// toolchain available), so this exercises the concurrent call pattern
	// without the race detector attached; it still proves no panic occurs.
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			d.SetInterval(n)
		}(i)
		go func() {
			defer wg.Done()
			_ = d.Interval()
		}()
	}
	wg.Wait()
	// Then: no panic (reaching here is the assertion).
}
