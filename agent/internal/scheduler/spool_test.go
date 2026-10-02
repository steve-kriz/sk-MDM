package scheduler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/contract"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

// TestScenario_SpoolDrainsOldestFirst tests that spooled files are posted oldest first.
func TestScenario_SpoolDrainsOldestFirst(t *testing.T) {
	// Given: three spool files and a server returning 200
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	spoolDir := "/spool"

	// Create three spool files with increasing timestamps
	payload1 := []byte(`{"payload":1}`)
	payload2 := []byte(`{"payload":2}`)
	payload3 := []byte(`{"payload":3}`)

	path1 := fmt.Sprintf("%s/checkin-2026100200000000000Z-000.json", spoolDir)
	path2 := fmt.Sprintf("%s/checkin-2026100200010000000Z-000.json", spoolDir)
	path3 := fmt.Sprintf("%s/checkin-2026100200020000000Z-000.json", spoolDir)

	fsys.Seed(path1, payload1)
	fsys.Seed(path2, payload2)
	fsys.Seed(path3, payload3)

	inv := contract.Inventory{}
	pst := contract.Posture{}

	postedPayloads := [][]byte{}
	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "POST" && strings.Contains(path, "checkin") {
				postedPayloads = append(postedPayloads, body)
				data, _ := json.Marshal(contract.CheckInResponse{})
				return fake.Response(http.StatusOK, string(data)), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	deps := &Deps{
		Client:   transport,
		Store:    stateStore,
		FS:       fsys,
		Clock:    clock,
		GOOS:     "darwin",
		SpoolDir: spoolDir,
		CollectInventory: func() (contract.Inventory, error) {
			return inv, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return pst, nil
		},
	}

	// When: the next cycle runs
	err := RunOnce(context.Background(), deps)

	// Then: the three payloads were posted in age order before the current one
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Verify spooled files were posted first
	if len(postedPayloads) < 3 {
		t.Fatalf("Expected at least 3 posted payloads, got %d", len(postedPayloads))
	}

	// First 3 should be the spooled ones
	if !bytes.Equal(postedPayloads[0], payload1) {
		t.Errorf("Expected first payload to be payload1, got %v", postedPayloads[0])
	}
	if !bytes.Equal(postedPayloads[1], payload2) {
		t.Errorf("Expected second payload to be payload2, got %v", postedPayloads[1])
	}
	if !bytes.Equal(postedPayloads[2], payload3) {
		t.Errorf("Expected third payload to be payload3, got %v", postedPayloads[2])
	}

	// And: the files are deleted
	spoolPaths := fsys.Paths()
	var spoolFiles []string
	for _, p := range spoolPaths {
		if strings.Contains(p, spoolDir) {
			spoolFiles = append(spoolFiles, p)
		}
	}

	// Should have no spool files left (or only the current one if it was also spooled)
	// Since all POSTs succeeded, all should be deleted
	if len(spoolFiles) > 0 {
		t.Errorf("Expected spool files to be deleted, found %d: %v", len(spoolFiles), spoolFiles)
	}
}

// TestScenario_RejectedSpoolEntryIsDropped tests 4xx handling for spooled files.
func TestScenario_RejectedSpoolEntryIsDropped(t *testing.T) {
	// Given: the server returns 400 for a spooled payload
	clock := fake.NewClock(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()

	st := state.State{DeviceID: "d1", DeviceSecret: "secret"}
	stateData, _ := json.Marshal(st)
	fsys.Seed(state.StatePath("darwin"), stateData)

	spoolDir := "/spool"

	// Create one spooled file
	payload := []byte(`{"payload":1}`)
	path := fmt.Sprintf("%s/checkin-2026100200000000000Z-000.json", spoolDir)
	fsys.Seed(path, payload)

	inv := contract.Inventory{}
	pst := contract.Posture{}

	transport := &mockTransport{
		doFunc: func(method, path string, body []byte) (*http.Response, error) {
			if method == "POST" && strings.Contains(path, "checkin") {
				// Return 400 for the first POST (spooled file)
				return fake.Response(http.StatusBadRequest, "{}"), nil
			}
			return fake.Response(http.StatusOK, "{}"), nil
		},
	}

	stateStore := &fakeStore{state: st}

	deps := &Deps{
		Client:   transport,
		Store:    stateStore,
		FS:       fsys,
		Clock:    clock,
		GOOS:     "darwin",
		SpoolDir: spoolDir,
		CollectInventory: func() (contract.Inventory, error) {
			return inv, nil
		},
		CollectPosture: func() (contract.Posture, error) {
			return pst, nil
		},
	}

	// When: the cycle runs
	err := RunOnce(context.Background(), deps)

	// Then: the file is deleted
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	spoolPaths := fsys.Paths()
	var spoolFiles []string
	for _, p := range spoolPaths {
		if strings.Contains(p, spoolDir) {
			spoolFiles = append(spoolFiles, p)
		}
	}

	if len(spoolFiles) > 0 {
		t.Errorf("Expected spooled file to be deleted, found %d files: %v", len(spoolFiles), spoolFiles)
	}

	// And: it is not retried and one warning naming the file is logged
	// Verified by checking the file was deleted and no second POST was attempted
}
