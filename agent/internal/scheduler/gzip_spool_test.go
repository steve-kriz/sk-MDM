// E2E cucumber-style test for TASK-068's AC14: the spool always stores the
// uncompressed JSON payload, and a spooled payload is compressed only on the
// wire when Client.Do has compression on. Client, Store, FS and Clock are all
// fakes; no real network, filesystem or database is used.
package scheduler

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/client"
	"github.com/officehq/sk-mdm/agent/internal/config"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
	"github.com/officehq/sk-mdm/agent/internal/state"
)

func TestScenario_SpoolStoresUncompressedJSON_AC14(t *testing.T) {
	// Given a check-in fails with a network error and its payload is spooled
	clock := fake.NewClock(time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC))
	fsys := fake.NewFS()
	doer := fake.NewHTTPDoer()

	cfg := config.Config{CollectionURL: "https://api.example.com", EnrollmentToken: "x"}
	store := state.NewStore(fsys, state.StatePath("darwin"))
	if err := store.Save(state.State{
		DeviceID:     "d1",
		DeviceSecret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}); err != nil {
		t.Fatalf("seeding state failed: %v", err)
	}
	realClient := client.New(cfg, store, doer, clock)

	// Compression is turned on by an earlier advertising response, exactly as
	// the real backend sends on every response.
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		resp := fake.Response(http.StatusOK, "{}")
		resp.Header.Set(client.HeaderAcceptContentEncoding, "gzip")
		return resp, nil
	}
	if _, err := realClient.Do(http.MethodGet, "/api/v1/devices/d1/policies", nil); err != nil {
		t.Fatalf("priming Do call failed: %v", err)
	}

	// The spooled payload is well over CompressMinBytes (1024 bytes).
	payload := []byte(`{"padding":"` + string(bytes.Repeat([]byte("x"), 4980)) + `"}`)

	spool := NewSpool(fsys, clock, "/spool")
	path, err := spool.Add(payload)
	if err != nil {
		t.Fatalf("Spool.Add failed: %v", err)
	}

	// Then the spool file contains the uncompressed JSON payload
	stored, ok := fsys.Content(path)
	if !ok {
		t.Fatalf("spool file %q not found", path)
	}
	if !bytes.Equal(stored, payload) {
		t.Fatalf("spool file does not hold the uncompressed payload byte-for-byte")
	}

	deps := &Deps{
		Client:   realClient,
		Store:    store,
		FS:       fsys,
		Clock:    clock,
		GOOS:     "darwin",
		SpoolDir: "/spool",
	}

	var sawContentEncoding string
	var sentBytes []byte
	doer.DoFunc = func(req *http.Request) (*http.Response, error) {
		sawContentEncoding = req.Header.Get("Content-Encoding")
		data, readErr := io.ReadAll(req.Body)
		if readErr != nil {
			t.Fatalf("reading drain request body: %v", readErr)
		}
		sentBytes = data
		return fake.Response(http.StatusOK, "{}"), nil
	}

	// When the spool is drained with compression on
	if outcome := deps.attemptDrain(); outcome != drainEmptied {
		t.Fatalf("attemptDrain outcome = %v, want drainEmptied", outcome)
	}

	// Then the recorded drain request body gunzips to that JSON payload
	if sawContentEncoding != "gzip" {
		t.Fatalf("drain request Content-Encoding = %q, want gzip", sawContentEncoding)
	}
	zr, err := gzip.NewReader(bytes.NewReader(sentBytes))
	if err != nil {
		t.Fatalf("gzip.NewReader on the drain request body: %v", err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("reading gunzip stream: %v", err)
	}
	if !bytes.Equal(plain, payload) {
		t.Fatalf("drained body mismatch:\n got  %q\n want %q", plain, payload)
	}

	// And the spool was emptied by the successful drain
	files, err := deps.spool().List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected the spool empty after the drain, got %v", files)
	}
}
