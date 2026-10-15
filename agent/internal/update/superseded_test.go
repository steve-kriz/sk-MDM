package update

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/officehq/sk-mdm/agent/internal/logging"
	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

// A failed self-update leaves its marker and the replaced binary behind. When
// an installer then puts a newer build in place, the next start must not roll
// the replaced (older) binary back over it -- seen in production: marker 1.0.7,
// <path>.old 1.0.6, MSI-installed 1.0.8 running.
func TestScenario_RollbackSupersededByNewerInstall(t *testing.T) {
	// Given "<path>.update-pending" contains "1.0.7", "<path>.old" holds the
	// 1.0.6 build, and the running build (installed by the MSI) is 1.0.8
	fsys := fake.NewFS()
	installed := []byte("1.0.8 binary")
	fsys.Seed("/usr/local/bin/mdmagent", installed)
	fsys.Seed("/usr/local/bin/mdmagent.old", []byte("1.0.6 binary"))
	fsys.Seed("/usr/local/bin/mdmagent.update-pending", []byte("1.0.7"))
	logger := logging.New(fsys, fake.NewClock(time.Now()), "/agent.log", logging.LevelDebug, "update")

	restartCalled := false
	deps := &Deps{
		FS:             fsys,
		Path:           "/usr/local/bin/mdmagent",
		CurrentVersion: "1.0.8",
		Logger:         logger,
		Restart: func(ctx context.Context) error {
			restartCalled = true
			return nil
		},
	}

	// When RollbackIfUnhealthy runs at start
	err := RollbackIfUnhealthy(deps)

	// Then it succeeds without restarting
	if err != nil {
		t.Fatalf("RollbackIfUnhealthy returned %v, want nil", err)
	}
	if restartCalled {
		t.Error("Restart should not be called when the update was superseded")
	}
	// And the running binary is untouched
	content, ok := fsys.Content("/usr/local/bin/mdmagent")
	if !ok || !bytes.Equal(content, installed) {
		t.Errorf("binary = %q (exists=%v), want the 1.0.8 build untouched", content, ok)
	}
	// And the marker and the replaced binary are deleted
	if fsys.Exists("/usr/local/bin/mdmagent.update-pending") {
		t.Error("the pending marker should be deleted")
	}
	if fsys.Exists("/usr/local/bin/mdmagent.old") {
		t.Error("the replaced binary should be deleted")
	}
	// And one info line records the superseded update, with no rollback warning
	log, _ := fsys.Content("/agent.log")
	text := string(log)
	if strings.Count(text, "update superseded by a newer install") != 1 {
		t.Errorf("log = %q, want one superseded line", text)
	}
	if !strings.Contains(text, `"installedVersion":"1.0.7"`) || !strings.Contains(text, `"runningVersion":"1.0.8"`) {
		t.Errorf("log = %q, want both versions recorded", text)
	}
	if strings.Contains(text, "update rollback") {
		t.Errorf("log = %q, want no rollback line", text)
	}
}

// Edge: with no "<path>.old" left behind, a superseded update still settles.
func TestScenario_RollbackSupersededWithoutReplacedBinary(t *testing.T) {
	fsys := fake.NewFS()
	fsys.Seed("/usr/local/bin/mdmagent", []byte("1.1.0 binary"))
	fsys.Seed("/usr/local/bin/mdmagent.update-pending", []byte("1.0.7"))

	err := RollbackIfUnhealthy(&Deps{FS: fsys, Path: "/usr/local/bin/mdmagent", CurrentVersion: "1.1.0"})

	if err != nil {
		t.Fatalf("RollbackIfUnhealthy returned %v, want nil", err)
	}
	if fsys.Exists("/usr/local/bin/mdmagent.update-pending") {
		t.Error("the pending marker should be deleted")
	}
}

// Edge: a marker that is not a readable version is never treated as
// superseded -- the existing rollback path still runs.
func TestScenario_UnreadableMarkerStillRollsBack(t *testing.T) {
	fsys := fake.NewFS()
	old := []byte("replaced binary")
	fsys.Seed("/usr/local/bin/mdmagent", []byte("running binary"))
	fsys.Seed("/usr/local/bin/mdmagent.old", old)
	fsys.Seed("/usr/local/bin/mdmagent.update-pending", []byte("garbage"))

	err := RollbackIfUnhealthy(&Deps{FS: fsys, Path: "/usr/local/bin/mdmagent", CurrentVersion: "1.0.8"})

	if err != nil {
		t.Fatalf("RollbackIfUnhealthy returned %v, want nil", err)
	}
	content, _ := fsys.Content("/usr/local/bin/mdmagent")
	if !bytes.Equal(content, old) {
		t.Errorf("binary = %q, want the replaced build restored", content)
	}
}
