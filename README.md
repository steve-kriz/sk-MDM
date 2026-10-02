# SK-MDM

Cross-platform device management: a TypeScript backend behind a Lambda Function
URL, a Go device agent, and the Windows/macOS installers that deploy it.

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
