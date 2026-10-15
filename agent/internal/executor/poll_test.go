package executor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// fakeTransport stands in for the TASK-015 client: it answers a canned lease
// body on GET and records every posted result on POST, so a test can assert
// on exactly which commands were reported -- and, just as importantly, which
// were not. No network call is ever made.
type fakeTransport struct {
	mu sync.Mutex

	leaseBody   []byte
	leaseStatus int

	posted       []postedResult
	resultStatus int
}

type postedResult struct {
	path string
	body []byte
}

func newFakeTransport(leaseBody []byte) *fakeTransport {
	return &fakeTransport{leaseBody: leaseBody, leaseStatus: http.StatusOK, resultStatus: http.StatusOK}
}

func (f *fakeTransport) Do(method, path string, body []byte) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if method == http.MethodGet {
		return &http.Response{
			StatusCode: f.leaseStatus,
			Body:       io.NopCloser(bytes.NewReader(f.leaseBody)),
		}, nil
	}

	f.posted = append(f.posted, postedResult{path: path, body: append([]byte(nil), body...)})
	return &http.Response{
		StatusCode: f.resultStatus,
		Body:       io.NopCloser(bytes.NewReader([]byte(`{"ok":true}`))),
	}, nil
}

// postedCommandIDs is the command id named by each posted result's path, in
// posting order: ".../commands/dev-1/<commandId>/result".
func (f *fakeTransport) postedCommandIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	ids := make([]string, 0, len(f.posted))
	for _, p := range f.posted {
		parts := strings.Split(p.path, "/")
		if len(parts) >= 2 {
			ids = append(ids, parts[len(parts)-2])
		}
	}
	return ids
}

// commandJSON builds one lease item: a "lock" command (no required payload
// field of its own, and a fixed argv per platform), so its outcome is
// controlled entirely through the fake runner's canned exit code.
func commandJSON(id string, payload string) string {
	return fmt.Sprintf(`{"commandId":%q,"type":%q,"payload":%s,"issuedAt":1000,"expiresAt":2000}`, id, TypeLock, payload)
}

func leaseJSON(commands ...string) []byte {
	return []byte(`{"commands":[` + strings.Join(commands, ",") + `]}`)
}

// lockCommandLine is the fixed argv runPower issues for "lock" on Windows --
// the one line every leased "lock" command in this file runs through.
const lockCommandLine = "rundll32.exe user32.dll,LockWorkStation"

func TestScenario_OF6_StopsBatchAfterFlaggedFailure(t *testing.T) {
	runner := fake.NewCommandRunner()
	runner.Results[lockCommandLine] = platform.CommandResult{ExitCode: 1}

	transport := newFakeTransport(leaseJSON(
		commandJSON("A", `{"stopOnFailure":true}`),
		commandJSON("B", `{}`),
		commandJSON("C", `{}`),
	))

	fs := fake.NewFS()
	store := NewStore(fs, "/store.json")

	deps := &Deps{
		Runner:   runner,
		FS:       fs,
		Clock:    fake.NewClock(time.Unix(1000, 0)),
		GOOS:     "windows",
		Client:   transport,
		DeviceID: "dev-1",
		Store:    store,
	}

	if err := Poll(context.Background(), deps); err != nil {
		t.Fatalf("Poll returned an error: %v", err)
	}

	// A is run and its failed result is recorded and posted.
	calls := runner.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected exactly one command run (A), got %d: %v", len(calls), calls)
	}

	record, found, err := store.Lookup("A")
	if err != nil {
		t.Fatalf("store.Lookup(A) failed: %v", err)
	}
	if !found || record.Result.Status != StatusFailed {
		t.Fatalf("expected A recorded as failed, got found=%v result=%+v", found, record.Result)
	}

	posted := transport.postedCommandIDs()
	if len(posted) != 1 || posted[0] != "A" {
		t.Fatalf("expected only A to be posted, got %v", posted)
	}

	// B and C are not run, not recorded and not reported.
	if _, found, _ := store.Lookup("B"); found {
		t.Errorf("B must not be recorded")
	}
	if _, found, _ := store.Lookup("C"); found {
		t.Errorf("C must not be recorded")
	}
}

func TestScenario_OF6_ReplayedFailedResultAlsoStopsBatch(t *testing.T) {
	runner := fake.NewCommandRunner()
	// If B or A were actually run, this would make them "succeed"; the
	// assertion is on the call count, not the exit code.
	fs := fake.NewFS()
	store := NewStore(fs, "/store.json")

	// The store already holds a failed result for A from an earlier cycle
	// that could not report it.
	if err := store.Record("A", contract.CommandResultRequest{
		Status:     StatusFailed,
		ExitCode:   -1,
		Output:     "error: execution_failed",
		FinishedAt: 999,
	}); err != nil {
		t.Fatalf("seeding the store failed: %v", err)
	}

	transport := newFakeTransport(leaseJSON(
		commandJSON("A", `{"stopOnFailure":true}`),
		commandJSON("B", `{}`),
	))

	deps := &Deps{
		Runner:   runner,
		FS:       fs,
		Clock:    fake.NewClock(time.Unix(1000, 0)),
		GOOS:     "windows",
		Client:   transport,
		DeviceID: "dev-1",
		Store:    store,
	}

	if err := Poll(context.Background(), deps); err != nil {
		t.Fatalf("Poll returned an error: %v", err)
	}

	// A was never actually executed: its result came straight from the store.
	if calls := runner.Calls(); len(calls) != 0 {
		t.Fatalf("expected no command to be run, got %d: %v", len(calls), calls)
	}

	posted := transport.postedCommandIDs()
	foundA := false
	for _, id := range posted {
		if id == "A" {
			foundA = true
		}
		if id == "B" {
			t.Errorf("B must not be posted")
		}
	}
	if !foundA {
		t.Errorf("expected A's stored result to be posted, posted=%v", posted)
	}

	if _, found, _ := store.Lookup("B"); found {
		t.Errorf("B must not be recorded")
	}
}

func TestScenario_OF6_ContinuesWhenFailureNotFlagged(t *testing.T) {
	runner := fake.NewCommandRunner()
	runner.Results[lockCommandLine] = platform.CommandResult{ExitCode: 1}

	transport := newFakeTransport(leaseJSON(
		commandJSON("A", `{}`),
		commandJSON("B", `{}`),
	))

	fs := fake.NewFS()
	store := NewStore(fs, "/store.json")

	deps := &Deps{
		Runner:   runner,
		FS:       fs,
		Clock:    fake.NewClock(time.Unix(1000, 0)),
		GOOS:     "windows",
		Client:   transport,
		DeviceID: "dev-1",
		Store:    store,
	}

	if err := Poll(context.Background(), deps); err != nil {
		t.Fatalf("Poll returned an error: %v", err)
	}

	if calls := runner.Calls(); len(calls) != 2 {
		t.Fatalf("expected both A and B to run, got %d calls", len(calls))
	}
	posted := transport.postedCommandIDs()
	if len(posted) != 2 {
		t.Fatalf("expected both A and B to be posted, got %v", posted)
	}
	if _, found, _ := store.Lookup("B"); !found {
		t.Errorf("B should have been recorded")
	}
}

func TestScenario_OF6_ContinuesWhenFlaggedButSucceeded(t *testing.T) {
	runner := fake.NewCommandRunner()
	// No canned result: the default zero-value CommandResult has ExitCode 0,
	// which Execute reports as succeeded.

	transport := newFakeTransport(leaseJSON(
		commandJSON("A", `{"stopOnFailure":true}`),
		commandJSON("B", `{}`),
	))

	fs := fake.NewFS()
	store := NewStore(fs, "/store.json")

	deps := &Deps{
		Runner:   runner,
		FS:       fs,
		Clock:    fake.NewClock(time.Unix(1000, 0)),
		GOOS:     "windows",
		Client:   transport,
		DeviceID: "dev-1",
		Store:    store,
	}

	if err := Poll(context.Background(), deps); err != nil {
		t.Fatalf("Poll returned an error: %v", err)
	}

	if calls := runner.Calls(); len(calls) != 2 {
		t.Fatalf("expected both A and B to run, got %d calls", len(calls))
	}
	posted := transport.postedCommandIDs()
	if len(posted) != 2 {
		t.Fatalf("expected both A and B to be posted, got %v", posted)
	}
	if _, found, _ := store.Lookup("B"); !found {
		t.Errorf("B should have been recorded")
	}
}
