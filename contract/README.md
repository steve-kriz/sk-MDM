# Agent-to-backend contract

This folder is the single source of truth for the wire between the Go agent and
the backend Lambda. Everything here is frozen: the agent tickets and the backend
tickets are built in parallel against it.

| Artefact | What it pins |
| --- | --- |
| `openapi.yaml` | The five operations, their auth headers and their body schemas |
| `testdata/signing-vectors.json` | The canonical string and signature both implementations must produce |
| `testdata/messages/*.json` | The exact field names of every message |

The same shapes are expressed in code twice, and the two must stay identical:

- TypeScript — `backend/src/contract/types.ts`, `backend/src/contract/signing.ts`
- Go — `agent/internal/contract/types.go`, `agent/internal/contract/signing.go`

## The two authentication schemes

This API has two, and which one applies depends entirely on the operation.

**`POST /api/v1/enroll` — enrollment token only.** The agent presents
`X-MDM-Enrollment-Token` over TLS and nothing else. At enroll time it has no
`deviceId` and no device secret, so the HMAC scheme below cannot be applied and
is deliberately *not* declared on that operation.

The token is presented as `<tokenId>.<secret>`, matching
`^[0-9a-f]{16}\.[0-9a-f]{64}$`. `tokenId` locates the stored token record; the
**full presented string** is what the backend hashes for comparison. A token
that does not match the pattern is a contract violation — the document declares
the pattern, the enrollment endpoint owns the runtime rejection.

**The four `/api/v1/devices/...` operations — device HMAC.** Each requires all
four of `X-MDM-Device-Id`, `X-MDM-Timestamp` (integer epoch seconds),
`X-MDM-Nonce` and `X-MDM-Signature`. The device secret is the lower-case hex
key returned once by `EnrollResponse.deviceSecret`.

## The canonical string

Seven lines joined by `\n`:

```
METHOD
path
canonicalQuery
sha256hex(body)
timestamp
nonce
deviceId
```

- `METHOD` is upper-cased.
- `path` is the request path exactly as sent, e.g.
  `/api/v1/devices/dev-001/commands`.
- `canonicalQuery` is the decoded query pairs sorted by key, then by value, each
  rendered `key=value` and joined with `&`. Repeated keys are kept, so
  `b=2&a=1&a=0` canonicalises to `a=0&a=1&b=2`. An absent query is an empty
  line.
- `sha256hex(body)` is the lower-case SHA-256 of the body's **UTF-8 bytes** — a
  non-ASCII body is hashed as the bytes on the wire, never a re-encoded or
  escaped form. An empty body hashes the zero-byte input, which is always
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- `timestamp` is decimal epoch seconds with no padding and no sign.

Sorting compares UTF-8 bytes in both languages: Go compares strings byte-wise
natively and the TypeScript side compares `Buffer`s explicitly so the two
orderings cannot drift.

## The signature

`signRequest` / `SignRequest` HMAC-SHA256 the canonical string with the device
secret and return

```
v1=<64 lower-case hex characters>
```

`verifySignature` / `VerifySignature` return **false** — never throwing, never
erroring — for a header whose prefix is not `v1=`, whose remainder is the wrong
length or is not hex, or which was made with a different secret. The hex
remainder is compared in constant time.

## Golden signing vectors

`testdata/signing-vectors.json` is a JSON **array** of vectors. Each object
carries the inputs plus the two expected outputs:

| Field | Meaning |
| --- | --- |
| `name`, `description` | Human labels for the case |
| `secretHex` | 64-character lower-case hex device secret |
| `method`, `path`, `query`, `body` | Request facts; `query` is the raw query string, `body` is the raw UTF-8 body |
| `timestamp` | Epoch seconds, a JSON **integer** |
| `nonce`, `deviceId` | Header values |
| `canonical` | The expected canonical string |
| `signature` | The expected `X-MDM-Signature` value |

Both the Node test and the Go test read this one file. Every vector signs a
device operation: each `path` begins with `/api/v1/devices/` and none is
`/api/v1/enroll`, because enroll is not signed. The set covers an empty body, a
query with repeated keys, no query at all, and a body containing the non-ASCII
string `naïve-日本`.

The values are real: they were produced by the TypeScript implementation and
then checked byte-for-byte against the Go implementation.

## Golden messages

`testdata/messages/` holds one file per message type, plus the variants that pin
the optional fields:

| File | Pins |
| --- | --- |
| `enroll-request.json`, `enroll-response.json` | `EnrollRequest`, `EnrollResponse` |
| `checkin-request.json` | Every `Inventory` and `Posture` field populated, warnings on both, no `policyCompliance` |
| `checkin-request-no-warnings.json` | The same message with both `warnings` keys absent |
| `checkin-request-with-compliance.json` | The same message with a `policyCompliance` array: one compliant entry with `violations: []`, one non-compliant entry with `["firewall_disabled"]` |
| `checkin-response.json` | `CheckInResponse` |
| `command-lease-response.json` | `CommandLeaseResponse` |
| `command-result-request.json` | `CommandResultRequest` |
| `policy-bundle-response.json` | Two policies, populated `effectiveSettings`, one conflict with one loser |
| `policy-bundle-response-no-conflicts.json` | `"conflicts": []` |

Rules these files exist to enforce:

- **Absent, not null.** `warnings` and `policyCompliance` are `omitempty` in Go:
  with nothing to report the key is not on the wire at all, and the backend must
  accept it being absent.
- **Empty, not absent.** `conflicts` is always present — an uncontested bundle
  emits `[]`. So is `violations` inside a compliance entry — a compliant entry
  still carries `[]`. No consumer should ever have to tell absent from empty for
  these two.
- **Names are law.** A collector that renames a field (`memoryBytes` for
  `ramBytes`) or adds one (`profiles` under `firewall`) breaks ingest silently.
  These files are the one place the names are pinned, and the Go decoder reads
  them with `DisallowUnknownFields` so a stray field fails loudly.
- `diskEncryption.method` is `bitlocker` or `filevault`; anything else is a
  contract violation.
- A `conflicts` entry always names at least one loser, and its
  `winningPolicyId` also appears in `policies`.
