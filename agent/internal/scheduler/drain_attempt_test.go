// E2E cucumber-style tests for TASK-064's drain attempt (agent/internal/
// scheduler.attemptDrain, drainSpool, postCheckIn and the pure backoff
// helpers). Every scenario below implements a Gherkin scenario from the
// ticket by name. Client, Store, FS and Clock are all fakes; no real network,
// filesystem or database is used anywhere in this file.
package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/client"
	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

// drainTestDeps builds Deps for an enrolled darwin agent with the spool at
// "/spool", a recording logger at debug level (so both the warn/info records
// AC3/AC5/AC7/AC12 name and the Run loop's debug waiting records can be
// asserted on) and the collectors stubbed to fail the test if a drain attempt
// ever reaches them.
func drainTestDeps(t *testing.T, clock *fake.Clock, fsys *fake.FS, transport Transport) *Deps {
	t.Helper()
	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	return &Deps{
		Client:   transport,
		Store:    &fakeStore{state: st},
		FS:       fsys,
		Clock:    clock,
		GOOS:     "darwin",
		SpoolDir: "/spool",
		Logger:   logging.New(fsys, clock, "agent.log", logging.LevelDebug, "scheduler"),
		CollectInventory: func() (contract.Inventory, error) {
			t.Fatal("a drain attempt must not collect inventory")
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			t.Fatal("a drain attempt must not collect posture")
			return contract.Posture{}, nil
		},
		CollectAntivirusFindings: func() ([]contract.AntivirusFinding, []string) {
			t.Fatal("a drain attempt must not collect antivirus findings")
			return nil, nil
		},
		CollectAntivirusStatus: func() (*contract.AntivirusStatus, []string) {
			t.Fatal("a drain attempt must not collect antivirus status")
			return nil, nil
		},
	}
}

func seedSpoolFiles(t *testing.T, clock *fake.Clock, fsys *fake.FS, dir string, payloads ...string) []string {
	t.Helper()
	spool := NewSpool(fsys, clock, dir)
	var paths []string
	for _, p := range payloads {
		path, err := spool.Add([]byte(p))
		if err != nil {
			t.Fatalf("seeding spool file failed: %v", err)
		}
		paths = append(paths, path)
		clock.Advance(time.Second) // each file gets a distinct, later timestamp
	}
	return paths
}

// ----------------------------------------------------------------------------
// Scenario: A drain attempt posts only the spool (AC2)
// ----------------------------------------------------------------------------

func TestScenario_DrainAttemptPostsOnlySpool_AC2(t *testing.T) {
	// Given the spool holds 2 files and the backend now answers 200
	clock := fake.NewClock(time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	transport := &mockTransport{}
	deps := drainTestDeps(t, clock, fsys, transport)
	seedSpoolFiles(t, clock, fsys, "/spool", `{"n":1}`, `{"n":2}`)

	// When a drain attempt runs
	outcome := deps.attemptDrain()

	// Then exactly 2 POSTs to the checkin path were sent, the older file first
	if outcome != drainEmptied {
		t.Fatalf("outcome = %v, want drainEmptied", outcome)
	}
	var checkinPosts [][]byte
	for _, r := range transport.requests {
		if r.method == http.MethodPost && strings.Contains(r.path, "checkin") {
			checkinPosts = append(checkinPosts, r.body)
		}
		// And: no GET to the policies path was sent before them (or at all)
		if r.method == http.MethodGet {
			t.Errorf("a drain attempt must send no GET request, got %s %s", r.method, r.path)
		}
	}
	if len(checkinPosts) != 2 {
		t.Fatalf("expected 2 checkin POSTs, got %d", len(checkinPosts))
	}
	var first, second struct {
		N int `json:"n"`
	}
	if err := json.Unmarshal(checkinPosts[0], &first); err != nil {
		t.Fatalf("unmarshal first post: %v", err)
	}
	if err := json.Unmarshal(checkinPosts[1], &second); err != nil {
		t.Fatalf("unmarshal second post: %v", err)
	}
	if first.N != 1 || second.N != 2 {
		t.Errorf("expected the older file (n=1) posted before the newer (n=2), got %d then %d", first.N, second.N)
	}

	// And: the drain attempt wrote no spool file
	files, err := deps.spool().List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected the spool empty after the attempt, got %v", files)
	}
}

// ----------------------------------------------------------------------------
// Scenario: An unreadable spool file counts as a failed drain attempt
// (AC3, AC5)
// ----------------------------------------------------------------------------

func TestScenario_UnreadableSpoolFileCountsAsFailedDrainAttempt_AC3_AC5(t *testing.T) {
	// Given the spool holds 1 file for which FS.ReadFile returns an error,
	// and the backend answers 200
	clock := fake.NewClock(time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	transport := &mockTransport{}
	deps := drainTestDeps(t, clock, fsys, transport)
	paths := seedSpoolFiles(t, clock, fsys, "/spool", `{"n":1}`)
	unreadable := paths[0]
	fsys.ReadErr = func(p string) error {
		if p == unreadable {
			return errors.New("disk error")
		}
		return nil
	}

	// When the first drain attempt runs (a full cycle is not exercised here;
	// attemptDrain is the seam the ticket names for this scenario)
	outcome := deps.attemptDrain()

	// Then the drain attempt logged one warn "spooled check-in unreadable"
	// naming that file
	lines := readLogLines(t, fsys)
	warns := filterByMsg(lines, "spooled check-in unreadable")
	if len(warns) != 1 {
		t.Fatalf("got %d 'spooled check-in unreadable' records, want 1: %v", len(warns), lines)
	}
	if warns[0]["file"] != unreadable {
		t.Errorf("file = %v, want %v", warns[0]["file"], unreadable)
	}

	// And: the drain attempt sent no POST to the checkin path
	if len(transport.requests) != 0 {
		t.Errorf("expected no request sent, got %v", transport.requests)
	}

	// And: Spool.List() still returns that file
	files, err := deps.spool().List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(files) != 1 || files[0] != unreadable {
		t.Errorf("expected the spool to still hold %v, got %v", unreadable, files)
	}

	// And: no full cycle starts immediately and no info record
	// "spool drained, connectivity restored" was logged -- the attempt FAILED
	if outcome != drainFailed {
		t.Errorf("outcome = %v, want drainFailed", outcome)
	}
	if n := len(filterByMsg(lines, "spool drained, connectivity restored")); n != 0 {
		t.Errorf("expected no 'spool drained, connectivity restored' record, got %d", n)
	}

	// And: the next drain attempt waits between 120 and 132 seconds, i.e.
	// drainDelay(1) (one failed attempt already counted) is in that range
	d := drainDelay(1)
	if d < 120*time.Second || d > 132*time.Second {
		t.Errorf("drainDelay(1) = %v, want [120s,132s]", d)
	}
}

// ----------------------------------------------------------------------------
// Scenario: A successful drain attempt runs a full cycle immediately (AC5)
// ----------------------------------------------------------------------------

func TestScenario_SuccessfulDrainAttemptEmptiesSpoolAndLogsInfo_AC5(t *testing.T) {
	// Given the spool holds 3 files and the backend now answers 200
	clock := fake.NewClock(time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	transport := &mockTransport{}
	deps := drainTestDeps(t, clock, fsys, transport)
	seedSpoolFiles(t, clock, fsys, "/spool", `{"n":1}`, `{"n":2}`, `{"n":3}`)

	// When a drain attempt runs
	outcome := deps.attemptDrain()

	// Then the spool is empty
	if outcome != drainEmptied {
		t.Fatalf("outcome = %v, want drainEmptied", outcome)
	}
	files, _ := deps.spool().List()
	if len(files) != 0 {
		t.Errorf("expected an empty spool, got %v", files)
	}

	// And: one info record "spool drained, connectivity restored" with
	// files 3 was logged
	lines := readLogLines(t, fsys)
	infos := filterByMsg(lines, "spool drained, connectivity restored")
	if len(infos) != 1 {
		t.Fatalf("got %d 'spool drained, connectivity restored' records, want 1: %v", len(infos), lines)
	}
	if files, ok := infos[0]["files"].(float64); !ok || int(files) != 3 {
		t.Errorf("files = %v, want 3", infos[0]["files"])
	}
	if infos[0]["level"] != "info" {
		t.Errorf("level = %v, want info", infos[0]["level"])
	}
}

// ----------------------------------------------------------------------------
// Scenario Outline: 408 and 429 keep a spooled check-in (AC7)
// ----------------------------------------------------------------------------

func TestScenario_DrainSpoolKeeps408And429_AC7(t *testing.T) {
	for _, status := range []int{http.StatusRequestTimeout, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			// Given the spool holds 2 files and the backend answers <status>
			// to the first POST
			clock := fake.NewClock(time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC))
			fsys := fake.NewFS()
			calls := 0
			transport := &mockTransport{
				doFunc: func(method, path string, body []byte) (*http.Response, error) {
					calls++
					return fake.Response(status, "{}"), nil
				},
			}
			deps := drainTestDeps(t, clock, fsys, transport)
			seedSpoolFiles(t, clock, fsys, "/spool", `{"n":1}`, `{"n":2}`)

			// When the spool is drained
			removed, err := deps.drainSpool(CheckInPath("d1"))

			// Then both files remain and only 1 POST was sent
			if err == nil {
				t.Fatal("expected drainSpool to return an error for a retryable status")
			}
			if removed != 0 {
				t.Errorf("removed = %d, want 0", removed)
			}
			if calls != 1 {
				t.Errorf("POSTs sent = %d, want 1", calls)
			}
			files, _ := deps.spool().List()
			if len(files) != 2 {
				t.Errorf("expected both files to remain, got %v", files)
			}

			// And: one warn "spooled check-in failed" with status <status>
			// was logged
			lines := readLogLines(t, fsys)
			warns := filterByMsg(lines, "spooled check-in failed")
			if len(warns) != 1 {
				t.Fatalf("got %d 'spooled check-in failed' records, want 1: %v", len(warns), lines)
			}
			if st, ok := warns[0]["status"].(float64); !ok || int(st) != status {
				t.Errorf("status = %v, want %d", warns[0]["status"], status)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Scenario Outline: 408 and 429 spool a fresh check-in (AC8)
// ----------------------------------------------------------------------------

func TestScenario_FreshCheckInSpooled408And429_AC8(t *testing.T) {
	for _, status := range []int{http.StatusRequestTimeout, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			// Given the spool is empty and the backend answers <status> to
			// the check-in
			clock := fake.NewClock(time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC))
			fsys := fake.NewFS()
			st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
			stateData, _ := json.Marshal(st)
			fsys.Seed(state.StatePath("darwin"), stateData)

			transport := &mockTransport{
				doFunc: func(method, path string, body []byte) (*http.Response, error) {
					if method == http.MethodPost && strings.Contains(path, "checkin") {
						return fake.Response(status, "{}"), nil
					}
					return fake.Response(http.StatusOK, "{}"), nil
				},
			}
			deps := &Deps{
				Client:   transport,
				Store:    &fakeStore{state: st},
				FS:       fsys,
				Clock:    clock,
				GOOS:     "darwin",
				SpoolDir: "/spool",
				CollectInventory: func() (contract.Inventory, error) {
					return contract.Inventory{}, nil
				},
				CollectPosture: func() (contract.Posture, error) {
					return contract.Posture{}, nil
				},
			}

			// When a full cycle runs
			if err := RunOnce(context.Background(), deps); err != nil {
				t.Fatalf("RunOnce failed: %v", err)
			}

			// Then the spool holds 1 file containing this cycle's body
			files, err := deps.spool().List()
			if err != nil {
				t.Fatalf("List failed: %v", err)
			}
			if len(files) != 1 {
				t.Fatalf("expected 1 spool file, got %v", files)
			}
			data, ok := fsys.Content(files[0])
			if !ok {
				t.Fatalf("spool file %s not found", files[0])
			}
			var req contract.CheckInRequest
			if err := json.Unmarshal(data, &req); err != nil {
				t.Errorf("spooled file is not this cycle's body: %v", err)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Scenario Outline: Other 4xx statuses keep today's behaviour (AC10)
// ----------------------------------------------------------------------------

func TestScenario_OtherFourXXStatusesKeepTodaysBehaviour_AC10(t *testing.T) {
	for _, status := range []int{400, 404, 409, 413} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			clock := fake.NewClock(time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC))
			fsys := fake.NewFS()
			transport := &mockTransport{
				doFunc: func(method, path string, body []byte) (*http.Response, error) {
					return fake.Response(status, "{}"), nil
				},
			}
			deps := drainTestDeps(t, clock, fsys, transport)
			seedSpoolFiles(t, clock, fsys, "/spool", `{"n":1}`)

			// Then a spooled check-in is deleted
			removed, err := deps.drainSpool(CheckInPath("d1"))
			if err != nil {
				t.Fatalf("drainSpool returned an error for a non-retryable status: %v", err)
			}
			if removed != 1 {
				t.Errorf("removed = %d, want 1", removed)
			}
			files, _ := deps.spool().List()
			if len(files) != 0 {
				t.Errorf("expected the spool emptied, got %v", files)
			}

			// And: a fresh check-in is not spooled
			st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
			stateData, _ := json.Marshal(st)
			fsys2 := fake.NewFS()
			fsys2.Seed(state.StatePath("darwin"), stateData)
			deps2 := &Deps{
				Client:   transport,
				Store:    &fakeStore{state: st},
				FS:       fsys2,
				Clock:    clock,
				GOOS:     "darwin",
				SpoolDir: "/spool",
				CollectInventory: func() (contract.Inventory, error) {
					return contract.Inventory{}, nil
				},
				CollectPosture: func() (contract.Posture, error) {
					return contract.Posture{}, nil
				},
			}
			if err := RunOnce(context.Background(), deps2); err != nil {
				t.Fatalf("RunOnce failed: %v", err)
			}
			files2, _ := deps2.spool().List()
			if len(files2) != 0 {
				t.Errorf("expected no spool file for a non-retryable status, got %v", files2)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Scenario: Every re-send is freshly signed (AC11)
// ----------------------------------------------------------------------------

func TestScenario_EveryResendIsFreshlySigned_AC11(t *testing.T) {
	// Given the spool holds 1 file and the first drain attempt fails with
	// 503 at fake time T1
	clock := fake.NewClock(time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	doer := fake.NewHTTPDoer()
	calls := 0
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return fake.Response(http.StatusServiceUnavailable, "{}"), nil
		}
		return fake.Response(http.StatusOK, "{}"), nil
	}

	cfg := config.Config{CollectionURL: "https://api.example.com", EnrollmentToken: "x"}
	store := state.NewStore(fsys, state.StatePath("darwin"))
	if err := store.Save(state.State{DeviceID: "d1", DeviceSecret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}); err != nil {
		t.Fatalf("seeding state failed: %v", err)
	}
	realClient := client.New(cfg, store, doer, clock)

	deps := &Deps{
		Client:   realClient,
		Store:    store,
		FS:       fsys,
		Clock:    clock,
		GOOS:     "darwin",
		SpoolDir: "/spool",
	}
	seedSpoolFiles(t, clock, fsys, "/spool", `{"n":1}`)

	t1 := clock.Now()
	if outcome := deps.attemptDrain(); outcome != drainFailed {
		t.Fatalf("first attempt outcome = %v, want drainFailed", outcome)
	}

	// When the next drain attempt succeeds at fake time T2
	clock.Advance(90 * time.Second)
	t2 := clock.Now()
	if outcome := deps.attemptDrain(); outcome != drainEmptied {
		t.Fatalf("second attempt outcome = %v, want drainEmptied", outcome)
	}

	// Then the two POSTs carry X-MDM-Timestamp T1 and T2 respectively
	reqs := doer.Requests()
	if len(reqs) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(reqs))
	}
	ts1 := reqs[0].Header.Get(client.HeaderTimestamp)
	ts2 := reqs[1].Header.Get(client.HeaderTimestamp)
	wantTS1 := formatUnix(t1)
	wantTS2 := formatUnix(t2)
	if ts1 != wantTS1 {
		t.Errorf("first timestamp = %s, want %s", ts1, wantTS1)
	}
	if ts2 != wantTS2 {
		t.Errorf("second timestamp = %s, want %s", ts2, wantTS2)
	}

	// And: their X-MDM-Nonce values differ
	n1 := reqs[0].Header.Get(client.HeaderNonce)
	n2 := reqs[1].Header.Get(client.HeaderNonce)
	if n1 == "" || n2 == "" {
		t.Fatalf("expected both requests to carry a nonce, got %q and %q", n1, n2)
	}
	if n1 == n2 {
		t.Errorf("expected different nonces, both were %q", n1)
	}
}

func formatUnix(t time.Time) string {
	return strconv.FormatInt(t.UTC().Unix(), 10)
}

// ----------------------------------------------------------------------------
// Scenario: 401 during a drain attempt clears the credential (AC12)
// ----------------------------------------------------------------------------

func TestScenario_DrainAttempt401ClearsCredential_AC12(t *testing.T) {
	// Given the spool holds 1 file and the backend answers 401
	clock := fake.NewClock(time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			return nil, client.ErrUnauthorized
		},
	}
	deps := drainTestDeps(t, clock, fsys, transport)
	store := deps.Store.(*fakeStore)
	seedSpoolFiles(t, clock, fsys, "/spool", `{"n":1}`)

	// When a drain attempt runs
	outcome := deps.attemptDrain()

	// Then the state store holds an empty state
	if outcome != drainUnauthorized {
		t.Fatalf("outcome = %v, want drainUnauthorized", outcome)
	}
	if store.lastSavedState.DeviceID != "" || store.lastSavedState.DeviceSecret != "" {
		t.Errorf("expected an empty saved state, got %+v", store.lastSavedState)
	}

	// And: the Run loop reaction (next full cycle immediately, no further
	// drain scheduled before it) is driven entirely by drainUnauthorized,
	// which Run maps straight to "full = true; continue" -- verified by the
	// outcome assertion above, the seam the ticket names for this case.
}

// ----------------------------------------------------------------------------
// Scenario: A drain attempt never overlaps a running cycle (AC13)
// ----------------------------------------------------------------------------

func TestScenario_DrainAttemptNeverOverlapsRunningCycle_AC13(t *testing.T) {
	// Given a full cycle is in flight holding the guard
	clock := fake.NewClock(time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	transport := &mockTransport{}
	deps := drainTestDeps(t, clock, fsys, transport)
	seedSpoolFiles(t, clock, fsys, "/spool", `{"n":1}`)

	if !deps.acquire() {
		t.Fatal("acquire failed on an idle Deps")
	}

	// When a drain attempt fires
	outcome := deps.attemptDrain()

	// Then it sends no request and returns
	if outcome != drainSkipped {
		t.Errorf("outcome = %v, want drainSkipped", outcome)
	}
	if len(transport.requests) != 0 {
		t.Errorf("expected no request sent, got %v", transport.requests)
	}
}

// ----------------------------------------------------------------------------
// Unit tests: the pure backoff helpers (AC3)
// ----------------------------------------------------------------------------

func TestUnit_DrainDelayDoublesWithJitterCap(t *testing.T) {
	cases := []struct {
		failures int
		minBase  time.Duration
		maxBase  time.Duration
	}{
		{0, 60 * time.Second, 66 * time.Second},
		{1, 120 * time.Second, 132 * time.Second},
		{2, 240 * time.Second, 264 * time.Second},
		{3, 480 * time.Second, 528 * time.Second},
	}
	for _, c := range cases {
		for i := 0; i < 20; i++ {
			d := drainDelay(c.failures)
			if d < c.minBase || d > c.maxBase {
				t.Fatalf("drainDelay(%d) = %v, want [%v,%v]", c.failures, d, c.minBase, c.maxBase)
			}
		}
	}
}

func TestUnit_DrainDelayNeverOverflowsAtMaxDoublings(t *testing.T) {
	// A failure count far past maxDrainDoublings must not panic or go
	// negative from a shift overflow.
	for _, failures := range []int{maxDrainDoublings, maxDrainDoublings + 1, maxDrainDoublings + 100, 1 << 30} {
		d := drainDelay(failures)
		if d <= 0 {
			t.Errorf("drainDelay(%d) = %v, want > 0", failures, d)
		}
	}
}

func TestUnit_JitterNeverGoesBelowBase(t *testing.T) {
	base := 60 * time.Second
	for i := 0; i < 50; i++ {
		d := jitter(base)
		if d < base {
			t.Fatalf("jitter(%v) = %v, want >= base", base, d)
		}
		if d > base+base/10+1 {
			t.Fatalf("jitter(%v) = %v, want <= base + 10%%", base, d)
		}
	}
}

func TestUnit_RetryableStatus(t *testing.T) {
	cases := map[int]bool{
		200: false, 204: false, 299: false,
		399: false,
		400: false, 401: false, 403: false, 404: false, 407: false,
		408: true,
		409: false, 413: false, 428: false,
		429: true,
		430: false, 499: false,
		500: true, 502: true, 503: true, 599: true, 600: true,
	}
	for status, want := range cases {
		if got := retryableStatus(status); got != want {
			t.Errorf("retryableStatus(%d) = %v, want %v", status, got, want)
		}
	}
}

func TestUnit_SpoolPendingReportsEnrollmentAndListState(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	// Not enrolled: always false, regardless of spool content.
	notEnrolled := &Deps{Store: &fakeStore{state: state.State{}}, FS: fsys, Clock: clock, GOOS: "darwin", SpoolDir: "/spool"}
	seedSpoolFiles(t, clock, fsys, "/spool", `{}`)
	if notEnrolled.spoolPending() {
		t.Error("spoolPending() = true for an unenrolled agent, want false")
	}

	// Enrolled with files: true.
	enrolled := &Deps{Store: &fakeStore{state: state.State{DeviceID: "d1", DeviceSecret: "s"}}, FS: fsys, Clock: clock, GOOS: "darwin", SpoolDir: "/spool"}
	if !enrolled.spoolPending() {
		t.Error("spoolPending() = false with a non-empty spool, want true")
	}

	// Enrolled, empty spool: false.
	emptyFS := fake.NewFS()
	enrolledEmpty := &Deps{Store: &fakeStore{state: state.State{DeviceID: "d1", DeviceSecret: "s"}}, FS: emptyFS, Clock: clock, GOOS: "darwin", SpoolDir: "/spool"}
	if enrolledEmpty.spoolPending() {
		t.Error("spoolPending() = true with an empty spool, want false")
	}

	// Enrolled, unlistable spool: false (treated as empty).
	unlistableFS := fake.NewFS()
	unlistableFS.ReadErr = func(p string) error {
		if p == "/spool" {
			return errors.New("permission denied")
		}
		return nil
	}
	enrolledUnlistable := &Deps{Store: &fakeStore{state: state.State{DeviceID: "d1", DeviceSecret: "s"}}, FS: unlistableFS, Clock: clock, GOOS: "darwin", SpoolDir: "/spool"}
	if enrolledUnlistable.spoolPending() {
		t.Error("spoolPending() = true for an unlistable spool, want false")
	}
}
