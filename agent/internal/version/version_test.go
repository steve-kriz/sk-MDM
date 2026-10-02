// Package version
package version

import (
	"testing"
)

func TestVersionDefaultValue(t *testing.T) {
	// The version should default to "0.0.0-dev"
	expected := "0.0.0-dev"
	if Version != expected {
		t.Errorf("Expected Version %q, got %q", expected, Version)
	}
}
