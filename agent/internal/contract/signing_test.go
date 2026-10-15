package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// SigningVector holds one test vector from the golden file
type SigningVector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	SecretHex   string `json:"secretHex"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	Query       string `json:"query"`
	Body        string `json:"body"`
	Timestamp   int64  `json:"timestamp"`
	Nonce       string `json:"nonce"`
	DeviceID    string `json:"deviceId"`
	Canonical   string `json:"canonical"`
	Signature   string `json:"signature"`
}

func loadVectors(t *testing.T) []SigningVector {
	// Load signing vectors from the test data file
	// Resolve path relative to this test file
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("Could not determine test file location")
	}

	vectorPath := filepath.Join(filepath.Dir(thisFile), "../../../contract/testdata/signing-vectors.json")

	data, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("Failed to read signing vectors: %v", err)
	}

	var vectors []SigningVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("Failed to parse signing vectors: %v", err)
	}

	return vectors
}

func TestCanonicalStringBasic(t *testing.T) {
	// Test: Canonical string is built from the seven parts
	parts := SigningParts{
		Method:    "get",
		Path:      "/api/v1/devices/d1/commands",
		Query:     "max=5",
		Body:      []byte{},
		Timestamp: 1760000000,
		Nonce:     "nonce-value",
		DeviceID:  "d1",
	}

	canonical := CanonicalString(parts)

	lines := make([]string, 0)
	start := 0
	for i := 0; i < len(canonical); i++ {
		if canonical[i] == '\n' {
			lines = append(lines, canonical[start:i])
			start = i + 1
		}
	}
	lines = append(lines, canonical[start:])

	if len(lines) != 7 {
		t.Fatalf("Expected 7 lines, got %d", len(lines))
	}

	// METHOD should be upper-cased
	if lines[0] != "GET" {
		t.Errorf("METHOD should be upper-cased: got %s", lines[0])
	}

	// Path should be exact
	if lines[1] != "/api/v1/devices/d1/commands" {
		t.Errorf("Path mismatch: got %s", lines[1])
	}

	// Query should be canonicalized
	if lines[2] != "max=5" {
		t.Errorf("Query mismatch: got %s", lines[2])
	}

	// Body hash should be SHA-256 of zero bytes
	expectedBodyHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if lines[3] != expectedBodyHash {
		t.Errorf("Body hash mismatch: expected %s, got %s", expectedBodyHash, lines[3])
	}

	// Timestamp
	if lines[4] != "1760000000" {
		t.Errorf("Timestamp mismatch: got %s", lines[4])
	}

	// Nonce
	if lines[5] != "nonce-value" {
		t.Errorf("Nonce mismatch: got %s", lines[5])
	}

	// DeviceID
	if lines[6] != "d1" {
		t.Errorf("DeviceID mismatch: got %s", lines[6])
	}
}

func TestQueryOrdering(t *testing.T) {
	// Test: Query pairs are ordered
	parts := SigningParts{
		Method:    "POST",
		Path:      "/api/v1/devices/dev-001/checkin",
		Query:     "b=2&a=1&a=0",
		Body:      []byte{},
		Timestamp: 1760000000,
		Nonce:     "nonce-value",
		DeviceID:  "dev-001",
	}

	canonical := CanonicalString(parts)

	// Extract the canonicalQuery line (line 3, 0-indexed)
	lines := make([]string, 0)
	start := 0
	for i := 0; i < len(canonical); i++ {
		if canonical[i] == '\n' {
			lines = append(lines, canonical[start:i])
			start = i + 1
		}
	}
	lines = append(lines, canonical[start:])

	expected := "a=0&a=1&b=2"
	if lines[2] != expected {
		t.Errorf("Query ordering mismatch: expected %s, got %s", expected, lines[2])
	}
}

func TestSignRequestPrefix(t *testing.T) {
	// Test: Signature carries the v1 prefix
	secretHex := "deadbeefcafef00dfeedfacebadc0ffee1d0c0de5afe1dea0123456789abcdef"
	parts := SigningParts{
		Method:    "GET",
		Path:      "/api/v1/devices/dev-001/commands",
		Query:     "",
		Body:      []byte{},
		Timestamp: 1760000000,
		Nonce:     "nonce-value",
		DeviceID:  "dev-001",
	}

	signature, err := SignRequest(secretHex, parts)
	if err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	// Should start with v1=
	if len(signature) < 3 || signature[:3] != "v1=" {
		t.Errorf("Signature should start with v1=: got %s", signature)
	}

	// Should have 64 hex characters after v1=
	hexPart := signature[3:]
	if len(hexPart) != 64 {
		t.Errorf("Signature hex part should be 64 chars: got %d", len(hexPart))
	}

	// All should be lowercase hex
	for _, c := range hexPart {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("Signature contains non-hex character: %c", c)
		}
	}
}

func TestGoAndNodeAgree(t *testing.T) {
	// Test: Go and Node agree on every vector
	vectors := loadVectors(t)

	if len(vectors) == 0 {
		t.Fatal("No signing vectors loaded")
	}

	for _, vector := range vectors {
		parts := SigningParts{
			Method:    vector.Method,
			Path:      vector.Path,
			Query:     vector.Query,
			Body:      []byte(vector.Body),
			Timestamp: vector.Timestamp,
			Nonce:     vector.Nonce,
			DeviceID:  vector.DeviceID,
		}

		canonical := CanonicalString(parts)
		if canonical != vector.Canonical {
			t.Errorf("Vector %s: canonical mismatch\nExpected:\n%s\nGot:\n%s",
				vector.Name, vector.Canonical, canonical)
		}

		signature, err := SignRequest(vector.SecretHex, parts)
		if err != nil {
			t.Errorf("Vector %s: SignRequest failed: %v", vector.Name, err)
		}

		if signature != vector.Signature {
			t.Errorf("Vector %s: signature mismatch\nExpected: %s\nGot: %s",
				vector.Name, vector.Signature, signature)
		}
	}
}

func TestVectorsCoverDeviceOpsOnly(t *testing.T) {
	// Test: Vectors cover only signed device operations
	vectors := loadVectors(t)

	for _, vector := range vectors {
		// Path should start with /api/v1/devices/
		if len(vector.Path) < len("/api/v1/devices/") ||
			vector.Path[:len("/api/v1/devices/")] != "/api/v1/devices/" {
			t.Errorf("Vector %s: path should start with /api/v1/devices/", vector.Name)
		}

		// Path should not be /api/v1/enroll
		if vector.Path == "/api/v1/enroll" {
			t.Errorf("Vector %s: path should not be /api/v1/enroll", vector.Name)
		}
	}
}

func TestUnicodeBodyHandling(t *testing.T) {
	// Test: Unicode body hashes as UTF-8
	vectors := loadVectors(t)

	// Find the vector with unicode content (looking for "naïve-日本")
	var unicodeVector *SigningVector
	for i := range vectors {
		if strings.Contains(vectors[i].Body, "naïve") || strings.Contains(vectors[i].Body, "日本") {
			unicodeVector = &vectors[i]
			break
		}
	}

	if unicodeVector == nil {
		t.Fatal("No unicode vector found")
	}

	parts := SigningParts{
		Method:    unicodeVector.Method,
		Path:      unicodeVector.Path,
		Query:     unicodeVector.Query,
		Body:      []byte(unicodeVector.Body),
		Timestamp: unicodeVector.Timestamp,
		Nonce:     unicodeVector.Nonce,
		DeviceID:  unicodeVector.DeviceID,
	}

	signature, err := SignRequest(unicodeVector.SecretHex, parts)
	if err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	if signature != unicodeVector.Signature {
		t.Errorf("Unicode vector signature mismatch\nExpected: %s\nGot: %s",
			unicodeVector.Signature, signature)
	}
}

func TestVerifySignatureWrongSecret(t *testing.T) {
	// Test: Wrong secret fails verification
	secretA := "deadbeefcafef00dfeedfacebadc0ffee1d0c0de5afe1dea0123456789abcdef"
	secretB := "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"

	parts := SigningParts{
		Method:    "GET",
		Path:      "/api/v1/devices/dev-001/commands",
		Query:     "",
		Body:      []byte{},
		Timestamp: 1760000000,
		Nonce:     "nonce-value",
		DeviceID:  "dev-001",
	}

	signatureWithA, err := SignRequest(secretA, parts)
	if err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	// Verify with wrong secret should fail
	verified := VerifySignature(secretB, parts, signatureWithA)
	if verified {
		t.Error("Verification with wrong secret should fail")
	}

	// Verify with correct secret should succeed
	verified = VerifySignature(secretA, parts, signatureWithA)
	if !verified {
		t.Error("Verification with correct secret should succeed")
	}
}

func TestVerifySignatureWrongPrefix(t *testing.T) {
	// Test: Signature without the v1 prefix is refused
	secretHex := "deadbeefcafef00dfeedfacebadc0ffee1d0c0de5afe1dea0123456789abcdef"
	parts := SigningParts{
		Method:    "GET",
		Path:      "/api/v1/devices/dev-001/commands",
		Query:     "",
		Body:      []byte{},
		Timestamp: 1760000000,
		Nonce:     "nonce-value",
		DeviceID:  "dev-001",
	}

	// Test with wrong prefix
	header := "v2=00112233"
	result := VerifySignature(secretHex, parts, header)

	if result {
		t.Error("Verification should return false for wrong prefix")
	}

	// Test with no prefix
	header = "00112233"
	result = VerifySignature(secretHex, parts, header)

	if result {
		t.Error("Verification should return false for missing prefix")
	}
}

func TestEmptyBodyEdgeCase(t *testing.T) {
	// Test: Empty body edge case
	vectors := loadVectors(t)

	// Find a vector with empty body
	var emptyBodyVector *SigningVector
	for i := range vectors {
		if vectors[i].Body == "" {
			emptyBodyVector = &vectors[i]
			break
		}
	}

	if emptyBodyVector == nil {
		t.Fatal("No empty body vector found")
	}

	parts := SigningParts{
		Method:    emptyBodyVector.Method,
		Path:      emptyBodyVector.Path,
		Query:     emptyBodyVector.Query,
		Body:      []byte{},
		Timestamp: emptyBodyVector.Timestamp,
		Nonce:     emptyBodyVector.Nonce,
		DeviceID:  emptyBodyVector.DeviceID,
	}

	canonical := CanonicalString(parts)

	// Body hash should be SHA-256 of zero bytes
	expectedBodyHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	lines := make([]string, 0)
	start := 0
	for i := 0; i < len(canonical); i++ {
		if canonical[i] == '\n' {
			lines = append(lines, canonical[start:i])
			start = i + 1
		}
	}
	lines = append(lines, canonical[start:])

	if lines[3] != expectedBodyHash {
		t.Errorf("Empty body hash mismatch: expected %s, got %s", expectedBodyHash, lines[3])
	}
}
