# SK-MDM

Cross-platform device management: a TypeScript backend behind a Lambda Function
URL, a Go device agent, and the Windows/macOS installers that deploy it.

See [FEATURES.md](FEATURES.md) for what the product does today: enrollment,
data collected, policies, commands, the admin console, and known limits.

## Layout

| Path         | Contents                                                      |
| ------------ | ------------------------------------------------------------- |
| `backend/`   | TypeScript Lambda backend (`src/`), compiled to `dist/`        |
| `agent/`     | Go device agent (`cmd/mdmagent`, `internal/`)                  |
| `scripts/`   | Repo tooling, including the agent cross-compile script         |
| `installers/`| Installer packaging and its tests                              |

## Prerequisites

- Node.js 22+
- Go 1.24+ (only needed to build the agent)

## Commands

```sh
npm install                              # install workspace dependencies
npm test                                 # compile the backend, then run node --test
npm --prefix backend run build           # compile backend/src -> backend/dist
node scripts/build-agent.mjs --dry-run   # list the supported agent targets
node scripts/build-agent.mjs             # cross-compile the agent for all targets
```

Tests are plain `node --test` files ending in `.test.js` under `backend/test/`
and `installers/test/`. They run against compiled output in `backend/dist/`,
which is why `npm test` builds first.

## HTTP routing

`backend/src/http/router.ts` exports `createRouter()`:

```ts
const router = createRouter();
router.add('GET', '/api/v1/devices/{deviceId}/policies', async (req) => ({
  statusCode: 200,
  body: { deviceId: req.params.deviceId },
}));

const res = await router.handle({ method, path, query, headers, body });
// res -> { statusCode, headers: { 'content-type': 'application/json' }, body: '<json>' }
```

- `{name}` pattern segments arrive on the handler as `params.name`.
- `handle()` is async and never throws: a handler that throws is logged once
  with `console.error` and becomes `500 {"error":"internal_error"}`.
- No route for the path: `404 {"error":"not_found"}`. Path matches but the
  method does not: `405 {"error":"method_not_allowed"}`.

`backend/src/index.ts` exports the shared `router` and the Lambda
`handler(event)`, which adapts a Function URL payload-format-2.0 event
(including base64-encoded bodies) into a router request.

## Agent builds

`scripts/build-agent.mjs` cross-compiles `agent/cmd/mdmagent` into `agent/bin/`
for `windows/amd64`, `windows/arm64`, `darwin/amd64` and `darwin/arm64`. Any
other `--target` is rejected with exit code 2. Set `AGENT_VERSION` to stamp
`internal/version.Version`, which otherwise defaults to `0.0.0-dev`.

## Packaging installers

`scripts/deploy/package-installers.sh` builds the installers this host can
build, with every value they carry read from the deployed stack, so nobody
types a URL, tenant id or enrollment token:

```sh
scripts/deploy/build-agent.sh 1.2.3 --skip-installers   # agent binaries -> agent/bin/
scripts/deploy/package-installers.sh 1.2.3 --dry-run     # show the values and build commands
scripts/deploy/package-installers.sh 1.2.3              # build -> dist/
scripts/deploy/publish-installers.sh 1.2.3              # upload dist/ to the installer bucket
```

Options: `--platform windows|macos|auto` (default `auto`: Windows under Git
Bash, macOS on a Mac), `--arch x64|arm64` (default: both), `--stack MdmStack`,
`--profile P`, `--region R`, `--dry-run`.

1. The `CollectionUrl` output of the stack is read with
   `aws cloudformation describe-stacks`.
2. `GET <CollectionUrl>/api/v1/agent-auth/config` supplies the Entra
   `tenantId` and `clientId`.
3. Windows: `installers/windows/build-plan.mjs` builds the x64 and arm64 MSIs
   (needs the WiX toolset: `dotnet tool install --global wix --version 5.0.2`,
   plus `wix extension add -g WixToolset.UI.wixext/5.0.2` and
   `wix extension add -g WixToolset.Util.wixext/5.0.2`). macOS:
   `installers/macos/build.sh` builds the amd64 and arm64 pkgs
   (`MDM_SIGN_IDENTITY` must name a Developer ID Installer identity).

Either read failing stops the script with exit 1 before anything is built. The
logic lives in `scripts/package-installers.mjs` (covered by `node --test`); the
shell script is a thin wrapper.

### What the installers do

- **Windows MSI**: a branded wizard shows the collection URL (pre-filled,
  editable; Next stays disabled until it starts with `https://`) and the device
  type, *OfficeHQ device* or *BYOC (personal device)*. The finish page's
  "Sign in to OfficeHQ MDM now" (ticked by default) runs
  `mdmagent open-signin` as the user, which opens the sign-in page the agent
  has requested from the MDM site (`https://<mdm-host>/agent/signin/...`); a
  "Sign in to OfficeHQ MDM" Start-menu shortcut runs the same command later. Silent
  installs take the same values as properties:
  `msiexec /i OfficeHQ-MDM-1.2.3-x64.msi /qn COLLECTIONURL=https://... OWNERSHIP=byoc`
  (`OWNERSHIP` defaults to `officehq`; the legacy `ENROLLTOKEN` is still
  accepted).
- **macOS pkg**: with a user at the console, postinstall asks for the
  collection URL and the device type (cancel keeps the defaults), then runs
  `mdmagent open-signin` as that user to open the sign-in page in their
  browser. Command-line installs and installs with nobody logged in use the
  baked values. `/Applications/OfficeHQ/Sign in to OfficeHQ MDM.command`
  signs in later.

The device enrolls itself with the signed-in user's Entra token; until someone
signs in the agent is installed but unenrolled.

### Branding

`installers/branding/logo-au.svg` is a committed copy of the OfficeHQ logo.
`node installers/branding/render.mjs` renders it (with `@resvg/resvg-js`) into
the committed `banner.bmp` (493x58), `dialog.bmp` (493x312), `macos-background.png`
and `logo.png`. Builds use the committed files and never fetch the website.

### Manual Entra step (once per app registration)

Browser sign-in is brokered by the MDM site: Entra redirects back to
`https://<mdm-host>/agent/callback`, and the agent redeems the code itself as a
public client. In the Entra admin centre, open the app registration whose
client id the backend publishes, then under **Authentication**:

1. Under the **Mobile and desktop applications** platform (**Add a platform**
   if it is not there yet), add the custom redirect URI
   `https://<mdm-host>/agent/callback` for each MDM host, e.g.
   `https://mdm.officehq.cc/agent/callback`. Do **not** add it under **Web**:
   a Web redirect URI makes Entra demand a client secret when the code is
   redeemed, and the agent has none.
2. Remove the old `http://localhost` redirect URI from that platform if an
   earlier version of these steps added it.
3. Set **Allow public client flows** to **Yes** (already required by
   `mdmagent login`).

Without the redirect URI Entra shows its own error page after the user signs
in, and the agent stays unenrolled until the step is done and the user signs
in again.
