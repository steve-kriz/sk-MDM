package config

import (
	"encoding/json"
	"errors"
	"io/fs"
	"testing"

	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

func readFields(t *testing.T, fsys *fake.FS, path string) map[string]any {
	t.Helper()
	data, ok := fsys.Content(path)
	if !ok {
		t.Fatalf("%s not written", path)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("config is not JSON: %v", err)
	}
	return fields
}

func TestSetEnrollmentToken_RewritesOnlyThatField(t *testing.T) {
	fsys := fake.NewFS()
	path := Path("windows")
	fsys.Seed(path, []byte(`{"collectionUrl":"https://mdm.example","ownership":"byoc","unknownKey":7}`))

	if err := SetEnrollmentToken(fsys, path, "abcd.ef01"); err != nil {
		t.Fatalf("SetEnrollmentToken: %v", err)
	}

	fields := readFields(t, fsys, path)
	if fields["enrollmentToken"] != "abcd.ef01" {
		t.Errorf("enrollmentToken = %v", fields["enrollmentToken"])
	}
	if fields["collectionUrl"] != "https://mdm.example" || fields["ownership"] != "byoc" || fields["unknownKey"] != float64(7) {
		t.Errorf("other fields changed: %v", fields)
	}
	if _, ok := fields["checkInIntervalSeconds"]; ok {
		t.Errorf("defaults were materialised: %v", fields)
	}
	if mode, _ := fsys.Mode(path); mode != FileMode {
		t.Errorf("mode = %v, want %v", mode, FileMode)
	}
	if fsys.Exists(path + ".tmp") {
		t.Error("temporary file left behind")
	}
}

func TestSetEnrollmentToken_EmptyRemovesKey(t *testing.T) {
	fsys := fake.NewFS()
	path := Path("darwin")
	fsys.Seed(path, []byte(`{"collectionUrl":"https://mdm.example","enrollmentToken":"old"}`))

	if err := SetEnrollmentToken(fsys, path, ""); err != nil {
		t.Fatalf("SetEnrollmentToken: %v", err)
	}
	fields := readFields(t, fsys, path)
	if _, ok := fields["enrollmentToken"]; ok {
		t.Errorf("enrollmentToken still present: %v", fields)
	}
	if fields["collectionUrl"] != "https://mdm.example" {
		t.Errorf("collectionUrl changed: %v", fields)
	}

	// ClearEnrollmentToken is the same thing by name.
	fsys.Seed(path, []byte(`{"collectionUrl":"https://mdm.example","enrollmentToken":"old"}`))
	if err := ClearEnrollmentToken(fsys, path); err != nil {
		t.Fatalf("ClearEnrollmentToken: %v", err)
	}
	if _, ok := readFields(t, fsys, path)["enrollmentToken"]; ok {
		t.Error("ClearEnrollmentToken left the key")
	}
}

func TestSetEnrollmentToken_MissingFileAndBadJSON(t *testing.T) {
	fsys := fake.NewFS()
	path := Path("darwin")
	if err := SetEnrollmentToken(fsys, path, "tok"); err != nil {
		t.Fatalf("SetEnrollmentToken on a missing file: %v", err)
	}
	if readFields(t, fsys, path)["enrollmentToken"] != "tok" {
		t.Error("token not written to a new file")
	}

	fsys.Seed(path, []byte(`not json`))
	if err := SetEnrollmentToken(fsys, path, "tok"); err == nil {
		t.Error("malformed config accepted")
	}
	if data, _ := fsys.Content(path); string(data) != "not json" {
		t.Error("malformed config was rewritten")
	}
}

func TestReadEnrollmentToken(t *testing.T) {
	fsys := fake.NewFS()
	path := Path("darwin")

	if _, err := ReadEnrollmentToken(fsys, path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: err = %v", err)
	}

	fsys.Seed(path, []byte(`{"collectionUrl":"https://mdm.example"}`))
	if tok, err := ReadEnrollmentToken(fsys, path); err != nil || tok != "" {
		t.Errorf("no token: got %q, %v", tok, err)
	}

	fsys.Seed(path, []byte(`{"collectionUrl":"https://mdm.example","enrollmentToken":"  tok  "}`))
	if tok, err := ReadEnrollmentToken(fsys, path); err != nil || tok != "tok" {
		t.Errorf("token: got %q, %v", tok, err)
	}

	fsys.Seed(path, []byte(`{`))
	if _, err := ReadEnrollmentToken(fsys, path); err == nil {
		t.Error("malformed config accepted")
	}
}
