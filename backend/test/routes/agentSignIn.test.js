/**
 * Tests for the MDM-brokered agent sign-in (spec Amendment A, A.1/A.2):
 *
 *   POST /api/v1/agent-auth/sessions
 *   GET  /agent/signin/{sessionId}
 *   GET  /agent/callback?code=&state=
 *   GET  /api/v1/agent-auth/sessions/{sessionId}
 *
 * All storage is a Map-backed fake table; no AWS client is ever constructed.
 * Entra configuration and the public host come from an injected `env`.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const dist = (path) => `file://${join(__dirname, '../../dist', path)}`;

const {
  AGENT_SIGNIN_SESSIONS_PATH,
  AGENT_SIGNIN_SESSION_PATH,
  AGENT_SIGNIN_PAGE_PATH,
  AGENT_CALLBACK_PATH,
  AGENT_SIGNIN_LIFETIME_SECONDS,
  createAgentSignInHandlers,
  registerAgentSignInRoutes,
  configureAgentSignInRoutes,
  resolveAgentSignInDependencies,
} = await import(dist('routes/agentSignIn.js'));
const { agentSignInSession } = await import(dist('db/keys.js'));
const { createRouter } = await import(dist('http/router.js'));
const { SECURITY_HEADERS, CONTENT_TYPES } = await import(dist('ui/index.js'));
const indexModule = await import(dist('index.js'));

const TENANT = 'tenant-1';
const CLIENT = 'client-1';
const HOST = 'mdm.example.com';
const ENV = { ENTRA_TENANT_ID: TENANT, ENTRA_CLIENT_ID: CLIENT };
const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'; // 43 base64url chars
const NOW = new Date('2026-10-09T10:00:00.000Z');
const SESSION_ID = 'ab'.repeat(32);
const CODE = 'OAQABAAIAAAD--secret-authorization-code--xyz';

/** Map-backed fake honouring the two conditional writes the route issues. */
class FakeTable {
  constructor() {
    this.items = new Map();
    this.calls = [];
  }

  static keyOf(key) {
    return `${key.pk}|${key.sk}`;
  }

  async get(key) {
    this.calls.push({ op: 'get', key });
    const item = this.items.get(FakeTable.keyOf(key));
    return item === undefined ? undefined : structuredClone(item);
  }

  /** `#status = :<x>`: the stored item must exist and have that status. */
  check(key, fields) {
    if (fields?.ConditionExpression === undefined) {
      return;
    }
    const current = this.items.get(FakeTable.keyOf(key));
    const values = fields.ExpressionAttributeValues ?? {};
    const wanted = Object.values(values)[0];
    if (current === undefined || current.status !== wanted) {
      const error = new Error('The conditional request failed');
      error.name = 'ConditionalCheckFailedException';
      throw error;
    }
  }

  async put(item, fields) {
    this.calls.push({ op: 'put', item: structuredClone(item), fields });
    this.check(item, fields);
    this.items.set(FakeTable.keyOf(item), structuredClone(item));
  }

  async delete(key, fields) {
    this.calls.push({ op: 'delete', key, fields });
    this.check(key, fields);
    this.items.delete(FakeTable.keyOf(key));
  }

  seed(item) {
    this.items.set(FakeTable.keyOf(item), structuredClone(item));
  }

  stored(sessionId) {
    return this.items.get(FakeTable.keyOf(agentSignInSession(sessionId)));
  }
}

function setup({ env = ENV, now = NOW, table = new FakeTable() } = {}) {
  const random = (size) => Buffer.alloc(size, 0xab);
  const handlers = createAgentSignInHandlers({ table, now: () => now, randomBytes: random, env });
  return { table, handlers };
}

function req({ method = 'GET', path = '/', params = {}, query = {}, headers = { host: HOST }, body = null } = {}) {
  return { method, path, params, query, headers, body };
}

function createBody(overrides = {}) {
  return JSON.stringify({ codeChallenge: CHALLENGE, codeChallengeMethod: 'S256', ...overrides });
}

function pendingSession(overrides = {}) {
  const expires = new Date(NOW.getTime() + 3600_000);
  return {
    ...agentSignInSession(SESSION_ID),
    sessionId: SESSION_ID,
    status: 'pending',
    codeChallenge: CHALLENGE,
    codeChallengeMethod: 'S256',
    redirectUri: `https://${HOST}/agent/callback`,
    createdAt: NOW.toISOString(),
    expiresAt: expires.toISOString(),
    ttl: Math.floor(expires.getTime() / 1000),
    ...overrides,
  };
}

function assertHtml(result) {
  assert.ok(typeof result.rawBody === 'string', 'HTML pages are raw bodies');
  assert.strictEqual(result.headers['content-type'], 'text/html; charset=utf-8');
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    assert.strictEqual(result.headers[name], value, `security header ${name}`);
  }
  assert.strictEqual(result.headers['cache-control'], 'no-store');
  assert.ok(result.rawBody.includes('/assets/public/styles.css'));
  assert.ok(result.rawBody.includes('/assets/public/logo.svg'));
  assert.ok(!/<script/i.test(result.rawBody), 'no script at all');
  assert.ok(!/\sstyle=/i.test(result.rawBody), 'no inline style (CSP)');
  assert.ok(!result.rawBody.includes(CODE), 'the code is never in a page');
}

// ============================================================================
// Paths and key
// ============================================================================

test('paths, lifetime and key follow the contract', () => {
  assert.strictEqual(AGENT_SIGNIN_SESSIONS_PATH, '/api/v1/agent-auth/sessions');
  assert.strictEqual(AGENT_SIGNIN_SESSION_PATH, '/api/v1/agent-auth/sessions/{sessionId}');
  assert.strictEqual(AGENT_SIGNIN_PAGE_PATH, '/agent/signin/{sessionId}');
  assert.strictEqual(AGENT_CALLBACK_PATH, '/agent/callback');
  assert.strictEqual(AGENT_SIGNIN_LIFETIME_SECONDS, 24 * 3600);
  assert.deepStrictEqual(agentSignInSession(SESSION_ID), { pk: `AGENTSIGNIN#${SESSION_ID}`, sk: 'PROFILE' });
});

test('agentSignInSession rejects anything but 64 lower-case hex', () => {
  for (const bad of ['', 'AB'.repeat(32), 'ab'.repeat(31), `${'ab'.repeat(31)}a#`, '../x', 'ab'.repeat(33)]) {
    assert.throws(() => agentSignInSession(bad), /invalid id/);
  }
});

// ============================================================================
// POST /api/v1/agent-auth/sessions
// ============================================================================

test('create: 201 with sessionId, signInUrl and expiresAt; pending session stored with ttl', async () => {
  const { table, handlers } = setup();
  const result = await handlers.create(req({ method: 'POST', body: createBody() }));

  assert.strictEqual(result.statusCode, 201);
  assert.strictEqual(result.headers['cache-control'], 'no-store');
  assert.deepStrictEqual(result.body, {
    sessionId: SESSION_ID,
    signInUrl: `https://${HOST}/agent/signin/${SESSION_ID}`,
    expiresAt: '2026-10-10T10:00:00.000Z',
  });
  assert.match(result.body.sessionId, /^[0-9a-f]{64}$/);

  const stored = table.stored(SESSION_ID);
  assert.strictEqual(stored.status, 'pending');
  assert.strictEqual(stored.codeChallenge, CHALLENGE);
  assert.strictEqual(stored.codeChallengeMethod, 'S256');
  assert.strictEqual(stored.expiresAt, '2026-10-10T10:00:00.000Z');
  assert.strictEqual(stored.ttl, Math.floor(NOW.getTime() / 1000) + 86400);
  assert.strictEqual(stored.code, undefined);
});

test('create: PUBLIC_HOST wins over the Host header', async () => {
  const { handlers } = setup({ env: { ...ENV, PUBLIC_HOST: 'mdm.officehq.cc' } });
  const result = await handlers.create(req({ method: 'POST', body: createBody(), headers: { host: 'abc.lambda-url.aws' } }));
  assert.strictEqual(result.body.signInUrl, `https://mdm.officehq.cc/agent/signin/${SESSION_ID}`);
});

for (const [label, body] of [
  ['no body', null],
  ['not JSON', '{nope'],
  ['an array', '[]'],
  ['missing challenge', JSON.stringify({ codeChallengeMethod: 'S256' })],
  ['42-char challenge', createBody({ codeChallenge: CHALLENGE.slice(1) })],
  ['44-char challenge', createBody({ codeChallenge: `${CHALLENGE}A` })],
  ['padded challenge', createBody({ codeChallenge: `${CHALLENGE.slice(1)}=` })],
  ['non-base64url challenge', createBody({ codeChallenge: `${CHALLENGE.slice(1)}+` })],
  ['numeric challenge', createBody({ codeChallenge: 12 })],
  ['plain method', createBody({ codeChallengeMethod: 'plain' })],
  ['lower-case method', createBody({ codeChallengeMethod: 's256' })],
  ['missing method', JSON.stringify({ codeChallenge: CHALLENGE })],
]) {
  test(`create: ${label} -> 400 invalid_request, nothing stored`, async () => {
    const { table, handlers } = setup();
    const result = await handlers.create(req({ method: 'POST', body }));
    assert.strictEqual(result.statusCode, 400);
    assert.strictEqual(result.body.error, 'invalid_request');
    assert.strictEqual(table.items.size, 0);
  });
}

test('create: Entra not configured -> 500 not_configured, nothing stored', async () => {
  const { table, handlers } = setup({ env: { ENTRA_TENANT_ID: TENANT } });
  const result = await handlers.create(req({ method: 'POST', body: createBody() }));
  assert.strictEqual(result.statusCode, 500);
  assert.deepStrictEqual(result.body, { error: 'not_configured' });
  assert.strictEqual(table.items.size, 0);
});

// ============================================================================
// GET /agent/signin/{sessionId}
// ============================================================================

test('signin: 302 to the Entra authorize endpoint with every contract parameter', async () => {
  const { table, handlers } = setup();
  table.seed(pendingSession());
  const result = await handlers.signIn(req({ params: { sessionId: SESSION_ID } }));

  assert.strictEqual(result.statusCode, 302);
  assert.strictEqual(result.headers['cache-control'], 'no-store');
  const location = new URL(result.headers.location);
  assert.strictEqual(location.origin, 'https://login.microsoftonline.com');
  assert.strictEqual(location.pathname, `/${TENANT}/oauth2/v2.0/authorize`);
  const q = Object.fromEntries(location.searchParams);
  assert.deepStrictEqual(q, {
    client_id: CLIENT,
    response_type: 'code',
    redirect_uri: `https://${HOST}/agent/callback`,
    scope: `api://${CLIENT}/MDM.Agent offline_access openid profile`,
    state: SESSION_ID,
    code_challenge: CHALLENGE,
    code_challenge_method: 'S256',
    prompt: 'select_account',
  });
});

for (const [label, sessionId, seed] of [
  ['unknown session', SESSION_ID, null],
  ['malformed id', 'not-hex', null],
  ['expired session', SESSION_ID, pendingSession({ expiresAt: NOW.toISOString() })],
  ['completed session', SESSION_ID, pendingSession({ status: 'complete', code: CODE })],
]) {
  test(`signin: ${label} -> 404 HTML page`, async () => {
    const { table, handlers } = setup();
    if (seed !== null) {
      table.seed(seed);
    }
    const result = await handlers.signIn(req({ params: { sessionId } }));
    assert.strictEqual(result.statusCode, 404);
    assertHtml(result);
    if (sessionId === 'not-hex') {
      assert.strictEqual(table.calls.length, 0, 'no key is built for a malformed id');
    }
  });
}

test('signin: Entra not configured -> 500 not_configured', async () => {
  const { table, handlers } = setup({ env: {} });
  table.seed(pendingSession());
  const result = await handlers.signIn(req({ params: { sessionId: SESSION_ID } }));
  assert.strictEqual(result.statusCode, 500);
  assert.deepStrictEqual(result.body, { error: 'not_configured' });
});

// ============================================================================
// GET /agent/callback
// ============================================================================

test('callback: stores the code, completes the session and shows "Signed in"', async () => {
  const { table, handlers } = setup();
  table.seed(pendingSession());
  const logged = [];
  const originals = { log: console.log, error: console.error, warn: console.warn, info: console.info };
  for (const name of Object.keys(originals)) {
    console[name] = (...args) => logged.push(args.join(' '));
  }
  let result;
  try {
    result = await handlers.callback(req({ query: { code: CODE, state: SESSION_ID } }));
  } finally {
    Object.assign(console, originals);
  }

  assert.strictEqual(result.statusCode, 200);
  assertHtml(result);
  assert.ok(result.rawBody.includes('Signed in'));
  assert.ok(result.rawBody.includes('close this tab'));
  const stored = table.stored(SESSION_ID);
  assert.strictEqual(stored.status, 'complete');
  assert.strictEqual(stored.code, CODE);
  assert.strictEqual(stored.ttl, pendingSession().ttl, 'ttl is kept');
  assert.ok(!logged.some((line) => line.includes(CODE)), 'the code is never logged');
});

test('callback: error=access_denied -> failed/access_denied, "declined" page', async () => {
  const { table, handlers } = setup();
  table.seed(pendingSession());
  const result = await handlers.callback(req({ query: { error: 'access_denied', state: SESSION_ID } }));
  assert.strictEqual(result.statusCode, 200);
  assertHtml(result);
  assert.ok(result.rawBody.includes('Sign-in was declined'));
  const stored = table.stored(SESSION_ID);
  assert.strictEqual(stored.status, 'failed');
  assert.strictEqual(stored.error, 'access_denied');
  assert.strictEqual(stored.code, undefined);
});

test('callback: another error -> failed/sign_in_failed, no echo of the error text', async () => {
  const { table, handlers } = setup();
  table.seed(pendingSession());
  const result = await handlers.callback(
    req({ query: { error: 'server_error', error_description: '<b>boom</b>', state: SESSION_ID } }),
  );
  assertHtml(result);
  assert.ok(result.rawBody.includes('Sign-in failed'));
  assert.ok(!result.rawBody.includes('<b>boom</b>'));
  assert.strictEqual(table.stored(SESSION_ID).status, 'failed');
  assert.strictEqual(table.stored(SESSION_ID).error, 'sign_in_failed');
});

test('callback: Microsoft error is kept for diagnosis, logged, and named (escaped) on the page', async () => {
  const { table, handlers } = setup();
  table.seed(pendingSession());
  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (...args) => warnings.push(args.join(' '));
  let result;
  try {
    result = await handlers.callback(
      req({
        query: {
          error: 'invalid_scope',
          error_description: 'AADSTS70011: The provided value for scope is not valid.\r\nTrace ID: t-1 <x>',
          state: SESSION_ID,
        },
      }),
    );
  } finally {
    console.warn = originalWarn;
  }
  assertHtml(result);
  assert.ok(result.rawBody.includes('invalid_scope'));
  assert.ok(result.rawBody.includes('AADSTS70011'));
  assert.ok(!result.rawBody.includes('<x>'));
  const stored = table.stored(SESSION_ID);
  assert.strictEqual(stored.error, 'sign_in_failed');
  assert.strictEqual(
    stored.errorDetail,
    'invalid_scope: AADSTS70011: The provided value for scope is not valid. Trace ID: t-1 <x>',
  );
  assert.strictEqual(warnings.length, 1);
  assert.ok(warnings[0].includes('AADSTS70011'));
  assert.ok(!warnings[0].includes(SESSION_ID), 'the session id is not logged');
});

test('callback: the stored error detail is bounded', async () => {
  const { table, handlers } = setup();
  table.seed(pendingSession());
  const originalWarn = console.warn;
  console.warn = () => {};
  try {
    await handlers.callback(req({ query: { error: 'e'.repeat(1000), error_description: 'd'.repeat(5000), state: SESSION_ID } }));
  } finally {
    console.warn = originalWarn;
  }
  assert.ok(table.stored(SESSION_ID).errorDetail.length <= 500);
});

test('poll: a failed session answers its error detail so the agent can log it', async () => {
  const { table, handlers } = setup();
  table.seed(pendingSession({ status: 'failed', error: 'sign_in_failed', errorDetail: 'invalid_scope: AADSTS70011' }));
  const result = await handlers.poll(req({ params: { sessionId: SESSION_ID } }));
  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body, { status: 'failed', error: 'sign_in_failed', detail: 'invalid_scope: AADSTS70011' });
});

for (const [label, query, seed] of [
  ['missing state', { code: CODE }, pendingSession()],
  ['malformed state', { code: CODE, state: '<script>' }, pendingSession()],
  ['unknown state', { code: CODE, state: 'cd'.repeat(32) }, pendingSession()],
  ['expired session', { code: CODE, state: SESSION_ID }, pendingSession({ expiresAt: '2026-10-09T09:00:00.000Z' })],
  ['missing code', { state: SESSION_ID }, pendingSession()],
  ['empty code', { code: '', state: SESSION_ID }, pendingSession()],
]) {
  test(`callback: ${label} -> 400 HTML, session unchanged`, async () => {
    const { table, handlers } = setup();
    table.seed(seed);
    const before = structuredClone(table.stored(SESSION_ID));
    const result = await handlers.callback(req({ query }));
    assert.strictEqual(result.statusCode, 400);
    assertHtml(result);
    assert.ok(!result.rawBody.includes('<script>'));
    assert.deepStrictEqual(table.stored(SESSION_ID), before);
    assert.ok(!table.calls.some((call) => call.op === 'put'));
  });
}

test('callback: first callback wins -- a later one is 400 and does not overwrite', async () => {
  const { table, handlers } = setup();
  table.seed(pendingSession());
  const first = await handlers.callback(req({ query: { code: CODE, state: SESSION_ID } }));
  assert.strictEqual(first.statusCode, 200);

  const second = await handlers.callback(req({ query: { code: 'other-code', state: SESSION_ID } }));
  assert.strictEqual(second.statusCode, 400);
  assertHtml(second);
  const third = await handlers.callback(req({ query: { error: 'access_denied', state: SESSION_ID } }));
  assert.strictEqual(third.statusCode, 400);
  assert.strictEqual(table.stored(SESSION_ID).status, 'complete');
  assert.strictEqual(table.stored(SESSION_ID).code, CODE);
});

test('callback: a race lost at the conditional write is 400', async () => {
  const { table, handlers } = setup();
  table.seed(pendingSession());
  // Another callback completes the session between this one's read and write.
  const realGet = table.get.bind(table);
  table.get = async (key) => {
    const item = await realGet(key);
    table.seed(pendingSession({ status: 'failed', error: 'access_denied' }));
    return item;
  };
  const result = await handlers.callback(req({ query: { code: CODE, state: SESSION_ID } }));
  assert.strictEqual(result.statusCode, 400);
  assertHtml(result);
  assert.strictEqual(table.stored(SESSION_ID).status, 'failed');
});

// ============================================================================
// GET /api/v1/agent-auth/sessions/{sessionId}
// ============================================================================

test('poll: pending -> 200 {"status":"pending"}, session kept', async () => {
  const { table, handlers } = setup();
  table.seed(pendingSession());
  const result = await handlers.poll(req({ params: { sessionId: SESSION_ID } }));
  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(result.headers['cache-control'], 'no-store');
  assert.deepStrictEqual(result.body, { status: 'pending' });
  assert.ok(table.stored(SESSION_ID));
});

test('poll: complete -> code and redirectUri once, then 404', async () => {
  const { table, handlers } = setup();
  table.seed(pendingSession({ status: 'complete', code: CODE }));
  const result = await handlers.poll(req({ params: { sessionId: SESSION_ID } }));
  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body, {
    status: 'complete',
    code: CODE,
    redirectUri: `https://${HOST}/agent/callback`,
  });
  assert.strictEqual(table.stored(SESSION_ID), undefined, 'deleted on read');

  const again = await handlers.poll(req({ params: { sessionId: SESSION_ID } }));
  assert.strictEqual(again.statusCode, 404);
  assert.deepStrictEqual(again.body, { error: 'not_found' });
});

for (const error of ['access_denied', 'sign_in_failed']) {
  test(`poll: failed/${error} -> 200 and deleted`, async () => {
    const { table, handlers } = setup();
    table.seed(pendingSession({ status: 'failed', error }));
    const result = await handlers.poll(req({ params: { sessionId: SESSION_ID } }));
    assert.strictEqual(result.statusCode, 200);
    assert.deepStrictEqual(result.body, { status: 'failed', error });
    assert.strictEqual(table.stored(SESSION_ID), undefined);
  });
}

test('poll: a concurrent poll that already consumed the session -> 404', async () => {
  const { table, handlers } = setup();
  table.seed(pendingSession({ status: 'complete', code: CODE }));
  const realGet = table.get.bind(table);
  table.get = async (key) => {
    const item = await realGet(key);
    table.items.clear();
    return item;
  };
  const result = await handlers.poll(req({ params: { sessionId: SESSION_ID } }));
  assert.strictEqual(result.statusCode, 404);
  assert.deepStrictEqual(result.body, { error: 'not_found' });
});

for (const [label, sessionId, seed] of [
  ['unknown', SESSION_ID, null],
  ['malformed', 'ABC', null],
  ['expired pending', SESSION_ID, pendingSession({ expiresAt: NOW.toISOString() })],
  ['expired complete', SESSION_ID, pendingSession({ status: 'complete', code: CODE, expiresAt: NOW.toISOString() })],
]) {
  test(`poll: ${label} -> 404 not_found`, async () => {
    const { table, handlers } = setup();
    if (seed !== null) {
      table.seed(seed);
    }
    const result = await handlers.poll(req({ params: { sessionId } }));
    assert.strictEqual(result.statusCode, 404);
    assert.deepStrictEqual(result.body, { error: 'not_found' });
    assert.ok(!JSON.stringify(result.body).includes(CODE));
  });
}

test('poll: Entra not configured -> 500 not_configured', async () => {
  const { table, handlers } = setup({ env: {} });
  table.seed(pendingSession());
  const result = await handlers.poll(req({ params: { sessionId: SESSION_ID } }));
  assert.strictEqual(result.statusCode, 500);
  assert.deepStrictEqual(result.body, { error: 'not_configured' });
});

// ============================================================================
// Wiring: a router, configure/resolve, the app router, the logo
// ============================================================================

test('full flow through a router: create -> signin -> callback -> poll', async () => {
  const table = new FakeTable();
  const router = createRouter();
  registerAgentSignInRoutes(router, {
    table,
    now: () => NOW,
    randomBytes: (size) => Buffer.alloc(size, 0xab),
    env: ENV,
  });
  const headers = { host: HOST };
  const created = await router.handle({ method: 'POST', path: AGENT_SIGNIN_SESSIONS_PATH, query: {}, headers, body: createBody() });
  assert.strictEqual(created.statusCode, 201);
  const { sessionId, signInUrl } = JSON.parse(created.body);

  const signIn = await router.handle({ method: 'GET', path: new URL(signInUrl).pathname, query: {}, headers, body: null });
  assert.strictEqual(signIn.statusCode, 302);

  const pending = await router.handle({ method: 'GET', path: `/api/v1/agent-auth/sessions/${sessionId}`, query: {}, headers, body: null });
  assert.deepStrictEqual(JSON.parse(pending.body), { status: 'pending' });

  const callback = await router.handle({ method: 'GET', path: '/agent/callback', query: { code: CODE, state: sessionId }, headers, body: null });
  assert.strictEqual(callback.statusCode, 200);
  assert.strictEqual(callback.headers['content-type'], 'text/html; charset=utf-8');

  const done = await router.handle({ method: 'GET', path: `/api/v1/agent-auth/sessions/${sessionId}`, query: {}, headers, body: null });
  assert.strictEqual(JSON.parse(done.body).code, CODE);
});

test('configure/resolve: resolve throws until configured, then returns the dependencies', () => {
  assert.throws(() => resolveAgentSignInDependencies(), /not configured/);
  const deps = { table: new FakeTable() };
  configureAgentSignInRoutes(deps);
  assert.strictEqual(resolveAgentSignInDependencies(), deps);
});

test('the application router serves the routes, and the index re-exports them', async () => {
  assert.strictEqual(typeof indexModule.configureAgentSignInRoutes, 'function');
  assert.strictEqual(typeof indexModule.agentSignInSession, 'function');
  const table = new FakeTable();
  indexModule.configureAgentSignInRoutes({ table, env: ENV, now: () => NOW });
  const response = await indexModule.router.handle({
    method: 'GET',
    path: `/api/v1/agent-auth/sessions/${SESSION_ID}`,
    query: {},
    headers: { host: HOST },
    body: null,
  });
  assert.strictEqual(response.statusCode, 404);
  assert.deepStrictEqual(JSON.parse(response.body), { error: 'not_found' });
});

test('the logo is served as SVG with the security headers', async () => {
  assert.strictEqual(CONTENT_TYPES['.svg'], 'image/svg+xml');
  const response = await indexModule.router.handle({
    method: 'GET',
    path: '/assets/public/logo.svg',
    query: {},
    headers: {},
    body: null,
  });
  assert.strictEqual(response.statusCode, 200);
  assert.strictEqual(response.headers['content-type'], 'image/svg+xml');
  assert.ok(response.body.startsWith('<svg'));
  assert.strictEqual(response.headers['content-security-policy'], SECURITY_HEADERS['content-security-policy']);
});
