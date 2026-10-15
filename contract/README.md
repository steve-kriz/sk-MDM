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
`X-MDM-Enrollment-Token` over TLS: admin-minted for silent installs, or minted
by `POST /api/v1/agent-auth/enrollment-token` after the user signs in (see
below). An `Authorization` header is ignored. At enroll time the agent has no
`deviceId` and no device secret, so the HMAC scheme below cannot be applied
and is deliberately *not* declared on that operation. The body's optional
`ownership` (`officehq` | `byoc`, default `officehq`) is recorded on the
device; a sign-in-minted token's `enrolledBy` is copied onto the device and
`enrolledByUpn` into the audit entry.

The token is presented as `<tokenId>.<secret>`, matching
`^[0-9a-f]{16}\.[0-9a-f]{64}$`. `tokenId` locates the stored token record; the
**full presented string** is what the backend hashes for comparison. A token
that does not match the pattern is a contract violation — the document declares
the pattern, the enrollment endpoint owns the runtime rejection.

**The four `/api/v1/devices/...` operations — device HMAC.** Each requires all
four of `X-MDM-Device-Id`, `X-MDM-Timestamp` (integer epoch seconds),
`X-MDM-Nonce` and `X-MDM-Signature`. The device secret is the lower-case hex
key returned once by `EnrollResponse.deviceSecret`.

## Agent sign-in brokered by the MDM site

Four **unauthenticated** routes let an unenrolled agent obtain the user's Entra
token without a localhost listener (spec Amendment A). `<host>` is
`PUBLIC_HOST` when set, otherwise the request's `Host` header. Entra not
configured answers `500 not_configured` on all four.

| Route | Answer |
| --- | --- |
| `POST /api/v1/agent-auth/sessions` `{"codeChallenge":"<43 base64url>","codeChallengeMethod":"S256"}` | `201 {"sessionId":"<64 hex>","signInUrl":"https://<host>/agent/signin/<sessionId>","expiresAt":"<ISO>"}`; bad body → `400 invalid_request` |
| `GET /agent/signin/{sessionId}` | `302` to the Entra authorize endpoint (`redirect_uri=https://<host>/agent/callback`, `state=<sessionId>`, the stored challenge, `code_challenge_method=S256`, `prompt=select_account`); unknown/expired → `404` HTML |
| `GET /agent/callback?code=&state=` | stores the code → `200` HTML "Signed in"; `error=access_denied` → `failed/access_denied`; other `error` → `failed/sign_in_failed`; unknown/expired/already-completed state or no code → `400` HTML |
| `GET /api/v1/agent-auth/sessions/{sessionId}` | `{"status":"pending"}`; `{"status":"complete","code":"…","redirectUri":"https://<host>/agent/callback"}` or `{"status":"failed","error":"access_denied"\|"sign_in_failed"}`, and the session is deleted on that read; unknown/expired → `404 {"error":"not_found"}` |

The session lives 24 h (`AGENTSIGNIN#<sessionId>`, DynamoDB `ttl`). The first
callback wins; the code is handed to the poller at most once, is never logged
or audited, and is useless without the PKCE verifier, which never leaves the
device. The agent redeems it at Entra itself as a public client.

## Entra token used once, to mint an enrollment token (Amendment B)

The access token from the sign-in is used for exactly one call and never
stored. "Signed-in user" reporting carries no Entra token: the agent reports
the user logged in to the operating system.

| Route | Answer |
| --- | --- |
| `POST /api/v1/agent-auth/enrollment-token` (public, `Authorization: Bearer <access token>`, scope `MDM.Agent`), body `{}` | `201 {"tokenId","token","expiresAt"}`; no/blank bearer → `401 user_token_missing`; JWKS outage → `503 jwks_unavailable`; other rejection → `401 invalid_user_token`; Entra not configured → `500 not_configured` |
| `POST /api/v1/enroll` | enrollment token only, as above |
| `POST /api/v1/devices/{deviceId}/user-session` (device HMAC only) body `{"username": "<string ≤256>" \| null}` | `200 {"user":{"username": …}}`; stored as `SIGNEDINUSER` `{deviceId, username, source:"os", reportedAt}`; a non-empty trimmed username also upserts `DEVICE#<id>` / `LOGINUSER#<sha256 of trimmed lower-cased username>` = `{deviceId, username, firstSeenAt, lastSeenAt, loginCount}`, capped at 100 per device; bad body → `400 invalid_request` with `fields: ["username"]`; device checks as on every device route |

The minted token has the admin token's format and hashing
(`<16 hex>.<64 hex>`, stored only as `tokenHash`), `maxUses: 1`, a one-hour
expiry, `label: "sign-in <upn>"`, `createdBy: "user:<upn or oid>"` and
`enrolledBy: {oid, upn, name}`. It is audited as `enrollment_token.created`
with `detail.source: "agent-sign-in"`, returned once and never logged.
`GET /api/v1/agent-auth/config` is unchanged.

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

## Payload compression

Device-signed agent requests (`Client.Do`) and `/api/v1/*` responses may be
gzip-compressed. Enroll and the public routes always send uncompressed bodies.

- **The signature covers the uncompressed body.** The agent signs the JSON
  bytes first and compresses them afterwards; the backend inflates the body
  before routing, so `verifyDeviceRequest` and every route see the uncompressed
  JSON. Body-size caps apply to the inflated body.
- **`X-MDM-Accept-Content-Encoding: gzip`** is on every backend response. The
  agent compresses a request body only while the most recent response it
  received carried it; a new agent process starts with compression off.
- **`Content-Encoding: gzip`** marks a compressed request body. The agent
  compresses only bodies of **1024 bytes** or more; shorter and empty bodies go
  out uncompressed. No header, an empty one or `identity` means uncompressed.
- **`Accept-Encoding: gzip`** is on every `Client.Do` request. The backend gzips
  an `/api/v1/*` response body of 1024 bytes or more when the request accepts
  gzip (not `q=0`) and answers with `Content-Encoding: gzip`, base64 with
  `isBase64Encoded: true` at the Function URL, and **`Vary: accept-encoding`**.
  The agent decompresses the response itself.

A compressed request the backend cannot take is refused before any route runs,
so no nonce is burned:

| Status | Body | When |
|---|---|---|
| 400 | `{"error":"invalid_gzip_body"}` | `Content-Encoding: gzip` but the body is not a valid gzip stream |
| 413 | `{"error":"payload_too_large"}` | the body inflates beyond 1048576 bytes (inflation stops at the cap) |
| 415 | `{"error":"unsupported_content_encoding"}` | any other `Content-Encoding` (`br`, `deflate`, `gzip, deflate`, ...) |

**One-retry fallback.** When a compressed request is answered 401, 415 or 400
`invalid_gzip_body`, the agent retries it exactly once uncompressed, with a
fresh nonce and signature, and sends no compressed body for the rest of the
process. An uncompressed request answered 401 is never retried. This keeps an
older backend, which would hash the compressed bytes, from making the agent
discard its credential.

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
| `checkin-request-with-analytics.json` | The same message with an `analytics` block: every `boot` / `performance` value non-null, one `crash` entry with a string `appVersion`, one `hang` entry with `appVersion: null`, and `warnings` |
| `checkin-request-with-analytics-nulls.json` | The same message with an `analytics` block whose every `boot` / `performance` value is `null` and `"crashes": []` |
| `checkin-request-with-defender-hardening.json` | The same message with a `defenderHardening` block: six items covering every state, with and without `detail` |
| `checkin-response.json` | `CheckInResponse` |
| `checkin-response-analytics-disabled.json` | `CheckInResponse` for a device whose analytics collection is off: `"analyticsEnabled": false` |
| `checkin-response-heartbeat-enabled.json` | `CheckInResponse` for a device whose heartbeat is on: `"heartbeatIntervalSeconds": 300` (absent when off) |
| `heartbeat-request.json` | `HeartbeatRequest`: every `performance` value non-null and one warning |
| `heartbeat-request-with-network.json` | `HeartbeatRequest` with a `network` block: a wired adapter at 20% utilisation, and a Wi-Fi adapter whose link speed (so utilisation) and send discards are null |
| `heartbeat-response.json` | `HeartbeatResponse` for a device whose heartbeat is on: `"heartbeatIntervalSeconds": 300` |
| `heartbeat-response-disabled.json` | `HeartbeatResponse` for a device whose heartbeat is off: `"heartbeatIntervalSeconds": 0` |
| `command-lease-response.json` | `CommandLeaseResponse` |
| `command-result-request.json` | `CommandResultRequest` |
| `policy-bundle-response.json` | Two policies, populated `effectiveSettings`, one conflict with one loser |
| `policy-bundle-response-no-conflicts.json` | `"conflicts": []` |

Rules these files exist to enforce:

- **Absent, not null.** `warnings` and `policyCompliance` are `omitempty` in Go:
  with nothing to report the key is not on the wire at all, and the backend must
  accept it being absent.
  The same holds for `analytics`: an agent that collects no endpoint
  analytics sends no `analytics` key at all (never `null`), and inside the
  block `warnings` is omitted when empty.
  The same holds for `analyticsEnabled` in `CheckInResponse`: it is absent when
  the device's analytics collection is on (the default), and present only as
  `false` when an admin has turned it off. It is never sent as `true`.
- **Empty, not absent.** `conflicts` is always present — an uncontested bundle
  emits `[]`. So is `violations` inside a compliance entry — a compliant entry
  still carries `[]`. No consumer should ever have to tell absent from empty for
  these two.
- **Analytics shape.** When `analytics` is sent, `boot`, `performance` and
  `crashes` are always present. `crashes` is `[]` when there are none — never
  absent or null — and holds at most 50 entries (events since the previous
  successful check-in). Every `boot` / `performance` scalar is always present
  and is `null` when the OS did not report it; `appVersion` is the only
  nullable crash field. The backend sanitises the block (bad values are nulled
  or dropped) and never fails a check-in over it.
- **Names are law.** A collector that renames a field (`memoryBytes` for
  `ramBytes`) or adds one (`profiles` under `firewall`) breaks ingest silently.
  These files are the one place the names are pinned, and the Go decoder reads
  them with `DisallowUnknownFields` so a stray field fails loudly.
- `diskEncryption.method` is `bitlocker` or `filevault`; anything else is a
  contract violation.
- A `conflicts` entry always names at least one loser, and its
  `winningPolicyId` also appears in `policies`.
