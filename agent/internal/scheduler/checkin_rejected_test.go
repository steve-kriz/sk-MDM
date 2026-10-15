package scheduler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

// A refused check-in names the backend's reason and offending fields in the
// log: a bare status left a device reporting nothing with no clue why.
func TestScenario_RejectedCheckInLogsTheReason(t *testing.T) {
	clock := fake.NewClock(time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	data, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), data)

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "POST" && strings.Contains(path, "checkin") {
				return fake.Response(http.StatusBadRequest,
					`{"error":"invalid_request","fields":["inventory.software[3].version"]}`), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}
	deps := &Deps{
		Client: transport,
		Store:  &fakeStore{state: st},
		FS:     fsys,
		Clock:  clock,
		GOOS:   "darwin",
		Logger: logging.New(fsys, clock, "agent.log", logging.LevelInfo, "scheduler"),
		CollectInventory: func() (contract.Inventory, error) {
			return contract.Inventory{}, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return contract.Posture{}, nil
		},
	}

	if err := RunOnce(context.Background(), deps); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	logged, _ := fsys.Content("agent.log")
	for _, want := range []string{"check-in rejected", "invalid_request", "inventory.software[3].version"} {
		if !strings.Contains(string(logged), want) {
			t.Errorf("log lacks %q:\n%s", want, logged)
		}
	}
}
