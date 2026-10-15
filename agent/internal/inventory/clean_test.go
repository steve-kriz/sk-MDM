package inventory

import (
	"testing"

	"github.com/officehq/sk-mdm/agent/internal/contract"
)

// The backend refuses a whole check-in over one software entry with an empty
// version, so an entry the OS lists without one is sent as UnknownVersion.
func TestCleanSoftware_BlankVersionBecomesUnknown(t *testing.T) {
	got := cleanSoftware([]contract.SoftwareEntry{
		{Name: "IIS Express Application Compatibility Database for x64", Version: ""},
		{Name: "Spaces", Version: "   "},
		{Name: "Git", Version: "2.45.1"},
		{Name: "", Version: "1.0"},
	})
	want := []contract.SoftwareEntry{
		{Name: "IIS Express Application Compatibility Database for x64", Version: UnknownVersion},
		{Name: "Spaces", Version: UnknownVersion},
		{Name: "Git", Version: "2.45.1"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Name != want[i].Name || got[i].Version != want[i].Version {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
