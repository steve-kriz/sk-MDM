// E2E cucumber-style tests for TASK-064's AC9 and AC10: a command result
// answered 408 or 429 is not marked posted and is retried by retryResults at
// the next Poll, the same as a 5xx; every other 4xx keeps today's behaviour
// of marking the result posted. Client, FS and Clock are fakes (see
// poll_test.go's fakeTransport); no real network, filesystem or database is
// used anywhere in this file.
package executor

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/platform"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// Scenario Outline: 408 and 429 keep a command result for retry (AC9)
func TestScenario_CommandResult408And429RetriedAtNextPoll_AC9(t *testing.T) {
	for _, status := range []int{http.StatusRequestTimeout, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			// Given a leased command whose result POST is answered <status>
			runner := fake.NewCommandRunner()
			runner.Results[lockCommandLine] = platform.CommandResult{ExitCode: 0}

			transport := newFakeTransport(leaseJSON(commandJSON("A", `{}`)))
			transport.resultStatus = status

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

			// When Poll runs
			if err := Poll(context.Background(), deps); err != nil {
				t.Fatalf("first Poll returned an error: %v", err)
			}

			// Then the store marks the result unposted after the first Poll
			record, found, err := store.Lookup("A")
			if err != nil {
				t.Fatalf("store.Lookup(A) failed: %v", err)
			}
			if !found {
				t.Fatalf("expected A to be recorded")
			}
			if record.Posted {
				t.Fatalf("expected A to be unposted after a %d response, got posted", status)
			}
			if calls := runner.Calls(); len(calls) != 1 {
				t.Fatalf("expected A to have run exactly once, got %d calls", len(calls))
			}

			// And then Poll runs again with the backend answering 200, with
			// nothing left to lease (so only the retry path is exercised)
			transport.leaseBody = leaseJSON()
			transport.resultStatus = http.StatusOK

			if err := Poll(context.Background(), deps); err != nil {
				t.Fatalf("second Poll returned an error: %v", err)
			}

			// Then the second Poll posts the stored result and marks it
			// posted, without running the command again
			record, found, err = store.Lookup("A")
			if err != nil {
				t.Fatalf("store.Lookup(A) failed: %v", err)
			}
			if !found || !record.Posted {
				t.Fatalf("expected A to be marked posted after the second Poll, got found=%v posted=%v", found, record.Posted)
			}
			if calls := runner.Calls(); len(calls) != 1 {
				t.Fatalf("expected the command to still have run exactly once, got %d calls", len(calls))
			}
		})
	}
}

// Scenario Outline: Other 4xx statuses keep today's behaviour (AC10) -- the
// executor's share of it: a command result is marked posted.
func TestScenario_OtherFourXXStatusesMarkResultPosted_AC10(t *testing.T) {
	for _, status := range []int{400, 404, 409, 413} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			runner := fake.NewCommandRunner()
			runner.Results[lockCommandLine] = platform.CommandResult{ExitCode: 0}

			transport := newFakeTransport(leaseJSON(commandJSON("A", `{}`)))
			transport.resultStatus = status

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

			record, found, err := store.Lookup("A")
			if err != nil {
				t.Fatalf("store.Lookup(A) failed: %v", err)
			}
			if !found || !record.Posted {
				t.Fatalf("expected A marked posted for status %d, got found=%v posted=%v", status, found, record.Posted)
			}
		})
	}
}

// Edge path: a transport error (no response at all) behaves like a 5xx/408/
// 429 -- the result is kept for retry, never marked posted.
func TestScenario_TransportErrorKeepsResultForRetry_Edge(t *testing.T) {
	runner := fake.NewCommandRunner()
	runner.Results[lockCommandLine] = platform.CommandResult{ExitCode: 0}

	transport := newFakeTransport(leaseJSON(commandJSON("A", `{}`)))
	transport.leaseStatus = http.StatusOK

	fs := fake.NewFS()
	store := NewStore(fs, "/store.json")

	failing := &errorAfterLeaseTransport{fakeTransport: transport}

	deps := &Deps{
		Runner:   runner,
		FS:       fs,
		Clock:    fake.NewClock(time.Unix(1000, 0)),
		GOOS:     "windows",
		Client:   failing,
		DeviceID: "dev-1",
		Store:    store,
	}

	if err := Poll(context.Background(), deps); err != nil {
		t.Fatalf("Poll returned an error: %v", err)
	}

	record, found, err := store.Lookup("A")
	if err != nil {
		t.Fatalf("store.Lookup(A) failed: %v", err)
	}
	if !found || record.Posted {
		t.Fatalf("expected A recorded and unposted after a transport error, got found=%v posted=%v", found, record.Posted)
	}
}

// errorAfterLeaseTransport answers the lease GET normally but fails every
// result POST with a transport error.
type errorAfterLeaseTransport struct {
	*fakeTransport
}

func (e *errorAfterLeaseTransport) Do(method, path string, body []byte) (*http.Response, error) {
	if method == http.MethodPost {
		return nil, errTransport
	}
	return e.fakeTransport.Do(method, path, body)
}

var errTransport = &transportError{"simulated network failure"}

type transportError struct{ msg string }

func (e *transportError) Error() string { return e.msg }
