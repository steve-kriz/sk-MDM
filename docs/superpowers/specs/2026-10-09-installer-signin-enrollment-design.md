# Installer sign-in, ownership and Entra-based enrollment — design

Date: 2026-10-09
Status: approved in conversation, awaiting spec review

## Goal

Installing the agent should need no hand-entered values and no enrollment
token. The installer:

1. shows the collection URL (pre-filled at packaging, editable),
2. asks whether the machine is an **OfficeHQ device** or **BYOC**,
3. signs the user in to Entra ID in their browser,

and the device enrolls itself with the signed-in user's token. Packaging pulls
every value it needs from the deployed AWS stack. Both installers carry the
OfficeHQ logo.

## Non-goals

- Removing the legacy enrollment-token path from the backend or the admin
  enrollment-token screen (follow-up ticket).
- Any policy, posture or collector difference between BYOC and OfficeHQ
  devices — ownership is recorded and displayed only.
- Letting an admin change ownership after enrollment.
- Replacing device HMAC: after enrollment every call is still signed with the
  device secret. The user token proves *who enrolled* the device; it is not
  the device's ongoing credential.

## Decisions taken

| Question | Decision |
|---|---|
| Where do the installer values come from? | Packaging reads them from AWS and bakes them in; the installer shows them pre-filled. |
| Platforms | Windows MSI and macOS pkg. |
| Sign-in UX | Browser sign-in (authorization code + PKCE, loopback redirect) at the end of the install. A cancelled sign-in leaves a working but unenrolled agent. |
| What ownership does | Stored on the device, shown in the admin UI. No behaviour change. |
| Enrollment credential | The user's Entra access token (`MDM.Agent` scope) replaces the enrollment token. |
| Ongoing device credential | Unchanged: device id + device secret (HMAC), issued by `/enroll`. |
| Client secret | None. The agent is an Entra **public client**; a secret embedded in a distributed installer would protect nothing. |

## 1. Agent

### 1.1 Config

`config.json` (`agent/internal/config`) changes:

| Field | Change |
|---|---|
| `collectionUrl` | unchanged |
| `enrollmentToken` | optional; still honoured when present (legacy silent installs), never written by the new installers |
| `ownership` | **new**, `"officehq"` or `"byoc"`; absent or any other value → `"officehq"` |
| `tenantId`, `clientId` | **new**, optional; baked in at packaging |
| `checkInIntervalSeconds`, `logLevel` | unchanged |

When `tenantId`/`clientId` are absent the agent fetches them, and the scopes,
from `GET /api/v1/agent-auth/config` as `mdmagent login` does today. Scopes are
always derived as `api://<clientId>/MDM.Agent offline_access openid profile`
(the same list the backend publishes).

### 1.2 Loopback sign-in served by the service

The vault (`usertoken.bin` / `usertoken.json`) is SYSTEM/root-owned, so the
sign-in is completed by the service, not by a process running as the desktop
user. The installer's only user-context action is opening a URL.

New package `agent/internal/signin`, started by `mdmagent run`:

- Listens on **`127.0.0.1:47615`** only (never `0.0.0.0`, never `::`). If the
  port is taken, the service logs a warning and carries on without it;
  `mdmagent login` remains available.
- `GET /signin` — generates a PKCE verifier/challenge (S256) and a random
  `state`, keeps them in memory for 10 minutes (one pending sign-in at a time;
  a new `/signin` replaces the previous one), and answers `302` to
  `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize` with
  `response_type=code`, `client_id`, `redirect_uri=http://localhost:47615/callback`,
  `scope`, `state`, `code_challenge`, `code_challenge_method=S256`,
  `prompt=select_account`.
- `GET /callback` — rejects a missing/mismatched/expired `state` (400 page,
  nothing stored), an `error` parameter (page naming "sign-in was declined" or
  "sign-in failed"), then redeems the code at the token endpoint
  (`grant_type=authorization_code`, `code_verifier`, same `redirect_uri`, no
  secret). On success it writes the vault record exactly as `runLogin` does
  (`userauth.Record`) and answers a small HTML page with the OfficeHQ logo:
  "Signed in as <upn>. You can close this tab."
- Pages are static, embedded with `go:embed`, and contain no token, code or
  verifier. No token, code or verifier is ever logged.
- `Host` header must be `localhost:47615` or `127.0.0.1:47615`, otherwise 400
  (DNS-rebinding guard).

The redirect URI uses `localhost` (Entra requires it for loopback on the
"Mobile and desktop applications" platform and ignores the port), while the
listener binds `127.0.0.1`.

`userauth.Entra` gains `AuthorizeURL(...)` and `RedeemCode(ctx, tenant, client,
code, verifier, redirectURI, scopes) (Token, error)` alongside the existing
device-code functions; errors follow the existing sentinel style
(`ErrSignInDeclined`, `ErrSignInFailed`).

### 1.3 Enrollment waits for a signed-in user

In `mdmagent run`, when the state file has no device id:

- If the config carries an `enrollmentToken`, enroll as today (legacy path).
- Otherwise wait until the vault holds a usable record (checked on start, after
  every successful `/callback`, and every 60 s). The service logs once,
  at info, "waiting for a user to sign in", and does not check in.
- Enroll with `Authorization: Bearer <access token>` (refreshed through the
  existing `userauth.Session` first if expired) and no
  `X-MDM-Enrollment-Token` header. The enroll body gains `ownership`.
- Retry/backoff and the 4xx-is-final rule are unchanged. A `401`/`403` from
  enroll with a bearer token means the user's token was refused: the agent logs
  it, keeps the vault (refresh may fix it), and tries again at the next 60 s
  tick rather than giving up permanently.

After enrollment nothing changes: check-ins are HMAC-signed with the device
secret, and user-session reporting (TASK-031) keeps attaching the user token.

### 1.4 `mdmagent signin-url`

New verb that prints `http://localhost:47615/signin` and exits 0, so installers
and docs refer to one source of truth for the URL.

## 2. Backend

### 2.1 `POST /api/v1/enroll`

Two accepted credentials, checked in this order:

1. `Authorization: Bearer <token>` present → verify with
   `createUserTokenVerifier` (`MDM.Agent` scope, configured tenant/audience).
   - verifier 503 → `503 jwks_unavailable`
   - any other rejection → `401 invalid_user_token`
   - success → continue with `enrolledBy = { oid, upn, name }` from the claims.
2. Otherwise the existing `X-MDM-Enrollment-Token` checks, unchanged (steps 1–4
   and 6 of the current route). `enrolledBy` is absent.
3. Neither header → `401 invalid_enrollment_token` (unchanged).

The bearer path does not touch any enrollment-token record or use count.

Body: `ownership` is a new **optional** field; `"officehq"` or `"byoc"`, absent
→ `"officehq"`, any other value → `400 invalid_request` naming `ownership`.

Device profile gains `ownership` and (bearer path only) `enrolledBy`. On a
re-bind both are overwritten with the new enrollment's values. The
`device.enrolled` audit entry's `detail` gains `ownership` and, when present,
`enrolledBy.upn`. Tokens are never stored, logged or audited.

`contract/types.ts` and `agent/internal/contract` gain `ownership` on the
enroll request.

### 2.2 Admin UI and API

- Device list API returns `ownership` and `enrolledBy.upn`; devices enrolled
  before this change read as `ownership: "officehq"`.
- Device list gains an **Ownership** column ("OfficeHQ" / "BYOC") and an
  ownership filter (All / OfficeHQ / BYOC).
- Device detail shows ownership and "Enrolled by".

### 2.3 Stack

No new outputs needed: packaging uses the existing `CollectionUrl` output and
the public agent-auth config route.

### 2.4 Manual Entra step

On the existing app registration, add platform **Mobile and desktop
applications** with redirect URI `http://localhost`, and set "Allow public
client flows" to Yes (already required by the device-code flow). Documented in
the packaging README section.

## 3. Windows MSI (`installers/windows`)

- Uses the WixToolset.UI extension, `WixUI_Minimal`-style flow with one custom
  dialog inserted after the licence/welcome page:
  - **Collection URL** edit control bound to `COLLECTIONURL`, pre-filled with
    the baked default.
  - **Device type** radio group bound to `OWNERSHIP`: "OfficeHQ device"
    (`officehq`, default) / "BYOC (personal device)" (`byoc`).
  - Next is disabled while the URL does not start with `https://`.
- `WixUIBannerBmp` (493×58) and `WixUIDialogBmp` (493×312) are the OfficeHQ
  branded bitmaps.
- Baked values arrive as preprocessor variables from `build-plan.mjs`
  (`DefaultCollectionUrl`, `TenantId`, `ClientId`) and set the default property
  values; `COLLECTIONURL` and `OWNERSHIP` remain public, secure properties so
  `msiexec /qn COLLECTIONURL=… OWNERSHIP=byoc` still works. The `Launch`
  condition still refuses an empty `COLLECTIONURL`, and now also an
  `OWNERSHIP` other than `officehq`/`byoc`.
- `ENROLLTOKEN` stays an optional property; written to config only when set.
- `write-config.js` writes `collectionUrl`, `ownership`, `tenantId`,
  `clientId`, the defaults, and `enrollmentToken` only when non-empty.
  CustomActionData grows to
  `<dir>|<url>|<ownership>|<tenant>|<client>|<enrollToken>`.
- Exit dialog: checkbox "Sign in to OfficeHQ MDM now" (checked by default);
  when checked, `WixShellExec` opens `http://localhost:47615/signin` as the
  user. Not shown on silent installs.
- Start-menu shortcut **"Sign in to OfficeHQ MDM"** (an `.url` internet
  shortcut to the same address), removed on uninstall.
- Silent install with no `OWNERSHIP` → `officehq`.

## 4. macOS pkg (`installers/macos`)

- `distribution.xml` gains `<background>` (branded PNG, scaled to fit, left
  aligned) and a `<welcome>` HTML page with the logo.
- `build.sh` drops `--enroll-token` and takes `--collection-url`,
  `--tenant-id`, `--client-id`; `postinstall` placeholders change accordingly.
- `postinstall`, running as root:
  1. Finds the console user (`stat -f%Su /dev/console`; `root` or
     `loginwindow` means none).
  2. With a console user: asks, via
     `launchctl asuser <uid> sudo -u <user> osascript`,
     a `display dialog` for the collection URL (default answer = baked URL,
     re-asked while not `https://`) and a `choose from list`
     ("OfficeHQ device", "BYOC (personal device)"; default OfficeHQ).
     Cancel on either dialog keeps the baked defaults rather than failing the
     install.
  3. With no console user: baked URL and `officehq`.
  4. Writes `config.json` (same fields as Windows), locks it down and
     bootstraps the daemon exactly as today.
  5. With a console user, opens `http://localhost:47615/signin` with
     `launchctl asuser <uid> sudo -u <user> open <url>` after the daemon is
     bootstrapped. Failure to open is ignored (the install has succeeded).
- A `Sign in to OfficeHQ MDM.webloc` is installed in `/Applications/OfficeHQ/`
  and removed by `uninstall.sh`.

## 5. Packaging — `scripts/deploy/package-installers.sh`

```
scripts/deploy/package-installers.sh [--version] 1.2.3 [--platform windows|macos|auto]
                                     [--arch x64|arm64] [--stack MdmStack]
                                     [--profile P] [--region R] [--dry-run]
```

1. `aws cloudformation describe-stacks` → `CollectionUrl` output. Missing →
   exit 1 with "stack <name> has no CollectionUrl output; deploy the backend first".
2. `curl -fsS <CollectionUrl>/api/v1/agent-auth/config` → `tenantId`,
   `clientId`. Non-200 or incomplete → exit 1 naming the problem.
3. `--platform auto` (default) picks Windows under Git Bash/MSYS, macOS on
   Darwin. Windows: `node installers/windows/build-plan.mjs --version … --arch …
   --collection-url … --tenant-id … --client-id …`. macOS: `installers/macos/build.sh`
   with the same values (`MDM_SIGN_IDENTITY` still required).
4. `--dry-run` prints the resolved values and the build command, runs nothing
   after the two reads.

Output lands in `dist/` as today, so `publish-installers.sh` is unchanged. The
Node half (argument parsing, value validation, command construction) lives in
`scripts/package-installers.mjs` so it is covered by `node --test`; the shell
script is a thin wrapper, mirroring `publish-installers.sh`.

`build-plan.mjs` (both platforms) gains `--collection-url`, `--tenant-id`,
`--client-id` and refuses (exit 2) a non-https URL or an empty tenant/client.
`build.ps1` passes them through.

## 6. Branding

- `installers/branding/logo-au.svg` — committed copy of
  `https://www.officehq.com.au/wp-content/themes/thevariousartists/dist/images/logo-au.svg`.
- `installers/branding/render.mjs` — renders the SVG with `@resvg/resvg-js`
  (dev dependency) into committed `banner.bmp` (493×58, logo right-aligned on
  white), `dialog.bmp` (493×312, logo in the left panel), `macos-background.png`
  (620×418 @2x-ready) and `logo.png` (for the sign-in pages and welcome HTML).
  BMP is written as 24-bit uncompressed by a small encoder in the script.
- Builds use the committed files; they never fetch the website.

## 7. Error handling summary

| Situation | Result |
|---|---|
| User cancels / closes the sign-in tab | Agent installed, waits; Start-menu / webloc shortcut signs in later. |
| Port 47615 taken | Warning logged; `mdmagent login` (device code) still works. |
| Entra redirect URI not registered | Entra shows its own error; documented in README. |
| User token refused by `/enroll` | Logged; retried every 60 s; a fresh sign-in replaces the vault record. |
| Silent install | Baked URL, `officehq` (unless overridden); no sign-in until someone uses the shortcut. |
| Packaging cannot read stack / config route | Exit 1 before building anything. |

## 8. Testing

- **Agent (Go, fakes only):** `signin` handler — bind address, Host guard,
  state mismatch/expiry, error callback, successful redeem writes vault, no
  secrets in responses/logs; `userauth` authorize URL and code redemption;
  config `ownership` defaulting; run loop waits for vault, enrolls with bearer
  and without the token header, legacy token still used when configured,
  401 retried at the next tick.
- **Backend (`node --test`, mocked table and verifier):** bearer enroll success
  stores `ownership`/`enrolledBy` and audits them; bearer 503/invalid;
  bearer path leaves token records untouched; `ownership` validation; legacy
  token path unchanged; device list/detail include ownership; old devices read
  as `officehq`.
- **Installers:** `windows-msi.test.js` asserts the dialog, properties,
  bitmaps, exit-dialog shell exec, shortcut and the new CustomActionData;
  `windows-config-writer.test.js` covers the new fields and optional token;
  `macos-pkg.test.js` covers placeholders, the console-user branch and the
  no-console-user branch; build-plan tests cover the new arguments and refusals.
- **Packaging:** `package-installers.test.js` with stubbed `aws`/`fetch`/spawn:
  values resolved and passed through, missing output, bad config response,
  dry run spawns nothing.

## 9. Delivery order

1. Backend: bearer enroll + ownership (agents and installers depend on it).
2. Agent: config, `userauth` code flow, `signin` listener, run-loop enrollment.
3. Branding assets.
4. Windows MSI.
5. macOS pkg.
6. Packaging script.
7. Admin UI ownership column/filter/detail.
