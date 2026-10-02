//go:build windows

package platform

import (
	"testing"
)

// TestScenario_DPAPIMachineScope_RoundTrip validates that DPAPI round-trips plaintext
// and that the protected bytes differ from the original.
func TestScenario_DPAPIMachineScope_RoundTrip(t *testing.T) {
	// Given the system SecretProtector on Windows
	protector := NewSecretProtector()

	// When I protect "abc" and unprotect the result
	plaintext := []byte("abc")
	protected, err := protector.Protect(plaintext)
	if err != nil {
		t.Fatalf("Protect failed: %v", err)
	}

	unprotected, err := protector.Unprotect(protected)
	if err != nil {
		t.Fatalf("Unprotect failed: %v", err)
	}

	// Then the protected bytes differ from "abc"
	if string(protected) == string(plaintext) {
		t.Error("protected bytes should differ from plaintext")
	}

	// And the unprotected bytes equal "abc"
	if string(unprotected) != string(plaintext) {
		t.Errorf("unprotected bytes should equal plaintext, got %q", string(unprotected))
	}
}
