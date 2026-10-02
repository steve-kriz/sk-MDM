package contract

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// SignaturePrefix is the version marker every X-MDM-Signature value carries.
const SignaturePrefix = "v1="

// SigningParts holds the request facts that go into the canonical string.
type SigningParts struct {
	// Method is the HTTP method; it is upper-cased before signing.
	Method string
	// Path is the request path, e.g. "/api/v1/devices/dev-001/commands".
	Path string
	// Query is the raw query string, with or without a leading "?".
	Query string
	// Body is the raw request body. A nil or empty body hashes as zero bytes.
	Body []byte
	// Timestamp is epoch seconds, as sent in X-MDM-Timestamp.
	Timestamp int64
	// Nonce is the X-MDM-Nonce value.
	Nonce string
	// DeviceID is the X-MDM-Device-Id value.
	DeviceID string
}

// canonicalQuery decodes the query string into pairs, sorts them by key then
// value and renders them as "k=v&k=v". Repeated keys are kept, so "a=1&a=0"
// canonicalises to "a=0&a=1".
//
// A malformed escape leaves url.ParseQuery's partial result in place: the
// canonical string must stay total, and a request whose query the backend
// parses differently simply fails signature verification.
func canonicalQuery(raw string) string {
	raw = strings.TrimPrefix(raw, "?")
	if raw == "" {
		return ""
	}

	values, _ := url.ParseQuery(raw)

	type pair struct{ key, value string }
	pairs := make([]pair, 0, len(values))
	for key, items := range values {
		for _, item := range items {
			pairs = append(pairs, pair{key: key, value: item})
		}
	}

	// Go compares strings byte-wise; the TypeScript side compares UTF-8 bytes
	// explicitly so the two orderings agree.
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].key != pairs[j].key {
			return pairs[i].key < pairs[j].key
		}
		return pairs[i].value < pairs[j].value
	})

	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, p.key+"="+p.value)
	}
	return strings.Join(parts, "&")
}

// bodyHash is the lower-case SHA-256 hex of the body bytes. An empty body
// hashes the zero-byte input, never the string "null".
func bodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// CanonicalString builds the seven-line string that is actually signed:
//
//	METHOD\npath\ncanonicalQuery\nsha256hex(body)\ntimestamp\nnonce\ndeviceId
//
// It is byte-identical to canonicalString() in
// backend/src/contract/signing.ts for every vector in
// contract/testdata/signing-vectors.json.
func CanonicalString(parts SigningParts) string {
	return strings.Join([]string{
		strings.ToUpper(parts.Method),
		parts.Path,
		canonicalQuery(parts.Query),
		bodyHash(parts.Body),
		strconv.FormatInt(parts.Timestamp, 10),
		parts.Nonce,
		parts.DeviceID,
	}, "\n")
}

// SignRequest signs the canonical string with the device secret and returns
// the X-MDM-Signature value: "v1=" followed by 64 lower-case hex characters.
//
// secretHex is the lower-case hex device secret issued by enrollment; a value
// that is not valid hex is reported as an error rather than silently signed
// with a truncated key.
func SignRequest(secretHex string, parts SigningParts) (string, error) {
	key, err := hex.DecodeString(secretHex)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(CanonicalString(parts)))
	return SignaturePrefix + hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifySignature reports whether header is the signature this device secret
// produces for these parts. It returns false — never an error — for a header
// with the wrong prefix, the wrong length, non-hex characters or a signature
// made with a different secret.
func VerifySignature(secretHex string, parts SigningParts, header string) bool {
	if !strings.HasPrefix(header, SignaturePrefix) {
		return false
	}

	expected, err := SignRequest(secretHex, parts)
	if err != nil {
		return false
	}

	presented := strings.TrimPrefix(header, SignaturePrefix)
	want := strings.TrimPrefix(expected, SignaturePrefix)
	return subtle.ConstantTimeCompare([]byte(presented), []byte(want)) == 1
}
