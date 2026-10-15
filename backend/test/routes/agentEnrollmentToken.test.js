/**
 * Spec Amendment B: `POST /api/v1/agent-auth/enrollment-token` -- the Entra
 * access token from the agent sign-in is used once, to mint a single-use
 * enrollment token.
 *
 * Spec: docs/superpowers/specs/2026-10-09-installer-signin-enrollment-design.md
 * sections B.1, B.2. The table and the user token verifier are fakes.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { createHash } from 'node:crypto';

const {
  AGENT_ENROLLMENT_TOKEN_PATH,
  createAgentEnrollmentTokenHandler,
  registerAgentEnrollmentTokenRoute,
  configureAgentEnrollmentTokenRoute,
  resolveAgentEnrollmentTokenDependencies,
} = await import('../../dist/routes/agentEnrollmentToken.js');
const { createEnrollHandler, ENROLLMENT_TOKEN_HEADER } = await import('../../dist/routes/enroll.js');
const { enrollmentToken, deviceProfile } = await import('../../dist/db/keys.js');
const { createRouter } = await import('../../dist/index.js');

const NOW = new Date('2026-10-09T12:00:00Z');
const ENV = { ENTRA_TENANT_ID: 'tenant-1', ENTRA_CLIENT_ID: 'client-1' };
const BEARER = 'eyJhbGciOiJSUzI1NiJ9.user-token-body.signature';
const CLAIMS = {
  oid: 'oid-amy',
  tid: 'tenant-1',
  preferred_username: 'amy@contoso.com',
  name: 'Amy Pond',
  scp: 'MDM.Agent',
  exp: Math.floor(NOW.getTime() / 1000) + 3600,
};

class FakeTable {
  constructor() {
    this.items = new Map();
    this.calls = [];
  }
  keyOf(key) {
    return `${key.pk}|${key.sk}`;
  }
  peek(key) {
    return this.items.get(this.keyOf(key));
  }
  async get(key) {
    this.calls.push({ operation: 'get', key });
    const item = this.items.get(this.keyOf(key));
    return item === undefined ? undefined : { ...item };
  }
  async put(item) {
    this.calls.push({ operation: 'put', item: { ...item } });
    this.items.set(this.keyOf(item), { ...item });
  }
  async putIfAbsent(item) {
    if (this.items.has(this.keyOf(item))) {
      return { written: false };
    }
    this.items.set(this.keyOf(item), { ...item });
    return { written: true };
  }
  async update(key) {
    const existing = this.items.get(this.keyOf(key));
    if ((existing.useCount ?? 0) >= existing.maxUses) {
      throw Object.assign(new Error('failed'), { name: 'ConditionalCheckFailedException' });
    }
    const updated = { ...existing, useCount: (existing.useCount ?? 0) + 1 };
    this.items.set(this.keyOf(key), updated);
    return updated;
  }
  audits() {
    return [...this.items.values()].filter((item) => String(item.pk).startsWith('AUDIT#'));
  }
  tokens() {
    return [...this.items.values()].filter((item) => String(item.pk).startsWith('ENROLLTOKEN#'));
  }
}

function stubVerifier({ claims = CLAIMS, rejection } = {}) {
  const seen = [];
  return {
    seen,
    async verify(token) {
      seen.push(token);
      if (rejection !== undefined) {
        throw rejection;
      }
      return claims;
    },
  };
}

/** Deterministic bytes: 0x11.. for the id, 0x22.. for the secret. */
function fixedBytes() {
  let call = 0;
  return (size) => Buffer.alloc(size, call++ === 0 ? 0x11 : 0x22);
}

function handlerFor(table, verifier = stubVerifier(), extra = {}) {
  return createAgentEnrollmentTokenHandler({
    table,
    userVerifier: verifier,
    now: () => NOW,
    randomBytes: fixedBytes(),
    env: ENV,
    ...extra,
  });
}

function request(headers = { authorization: `Bearer ${BEARER}` }, body = '{}') {
  return { method: 'POST', path: AGENT_ENROLLMENT_TOKEN_PATH, query: {}, headers, body };
}

// ---------------------------------------------------------------------------
// Success
// ---------------------------------------------------------------------------

test('Path is /api/v1/agent-auth/enrollment-token', () => {
  assert.equal(AGENT_ENROLLMENT_TOKEN_PATH, '/api/v1/agent-auth/enrollment-token');
});

test('A valid user token answers 201 with exactly tokenId, token and expiresAt', async () => {
  const table = new FakeTable();
  const verifier = stubVerifier();
  const result = await handlerFor(table, verifier)(request());

  assert.equal(result.statusCode, 201);
  assert.deepEqual(Object.keys(result.body).sort(), ['expiresAt', 'token', 'tokenId']);
  assert.equal(result.body.tokenId, '11'.repeat(8));
  assert.equal(result.body.token, `${'11'.repeat(8)}.${'22'.repeat(32)}`);
  assert.match(result.body.token, /^[0-9a-f]{16}\.[0-9a-f]{64}$/);
  assert.equal(result.body.expiresAt, null, 'a sign-in token never expires');
  assert.deepEqual(verifier.seen, [BEARER], 'the bearer is handed to the verifier verbatim');
  assert.equal(result.headers?.['cache-control'], 'no-store');
});

test('The stored record has the admin shape, maxUses 1, no expiry and enrolledBy', async () => {
  const table = new FakeTable();
  const result = await handlerFor(table)(request());
  const record = table.peek(enrollmentToken(result.body.tokenId));

  assert.ok(record, 'the record is stored under the token key');
  assert.equal(record.tokenId, result.body.tokenId);
  assert.equal(record.tokenHash, createHash('sha256').update(result.body.token, 'utf8').digest('hex'));
  assert.equal(record.maxUses, 1);
  assert.equal(record.useCount, 0);
  assert.ok(!('expiresAt' in record), 'a token that never expires stores no expiresAt');
  assert.equal(record.label, 'sign-in amy@contoso.com');
  assert.equal(record.createdBy, 'user:amy@contoso.com');
  assert.equal(record.createdAt, '2026-10-09T12:00:00Z');
  assert.deepEqual(record.enrolledBy, { oid: 'oid-amy', upn: 'amy@contoso.com', name: 'Amy Pond' });
});

test('Minting is audited as enrollment_token.created with source agent-sign-in', async () => {
  const table = new FakeTable();
  const result = await handlerFor(table)(request());
  const audits = table.audits();
  assert.equal(audits.length, 1);
  assert.equal(audits[0].action, 'enrollment_token.created');
  assert.equal(audits[0].target, result.body.tokenId);
  assert.equal(audits[0].actor, 'user:amy@contoso.com');
  assert.equal(audits[0].detail.source, 'agent-sign-in');
  assert.equal(audits[0].detail.maxUses, 1);
  assert.equal(audits[0].detail.expiresAt, null);
});

test('Neither the minted token, its secret nor the bearer is stored or audited', async () => {
  const table = new FakeTable();
  const result = await handlerFor(table)(request());
  const everything = JSON.stringify([...table.items.values()]);
  assert.ok(!everything.includes(result.body.token));
  assert.ok(!everything.includes('22'.repeat(32)), 'the secret half is never stored');
  assert.ok(!everything.includes(BEARER));
});

test('Nothing is logged that carries the token or the bearer', async (t) => {
  const lines = [];
  for (const method of ['log', 'info', 'warn', 'error', 'debug']) {
    t.mock.method(console, method, (...args) => lines.push(args.map(String).join(' ')));
  }
  const table = new FakeTable();
  const result = await handlerFor(table)(request());
  await handlerFor(new FakeTable(), stubVerifier({ rejection: { status: 401, error: 'invalid_token' } }))(request());
  const logged = lines.join('\n');
  assert.ok(!logged.includes(result.body.token));
  assert.ok(!logged.includes(BEARER));
});

test('No upn claim: label and createdBy fall back to the oid, enrolledBy carries nulls', async () => {
  const table = new FakeTable();
  const verifier = stubVerifier({ claims: { oid: 'oid-x', tid: 'tenant-1', scp: 'MDM.Agent', exp: 9999999999 } });
  const result = await handlerFor(table, verifier)(request());
  assert.equal(result.statusCode, 201);
  const record = table.peek(enrollmentToken(result.body.tokenId));
  assert.equal(record.label, 'sign-in oid-x');
  assert.equal(record.createdBy, 'user:oid-x');
  assert.deepEqual(record.enrolledBy, { oid: 'oid-x', upn: null, name: null });
});

test('The scheme and header name are matched case-insensitively', async () => {
  const table = new FakeTable();
  const result = await handlerFor(table)(request({ Authorization: `bearer ${BEARER}` }));
  assert.equal(result.statusCode, 201);
});

test('The body is not required: an empty or absent body still mints', async () => {
  for (const body of ['', null, '{}', 'not json']) {
    const result = await handlerFor(new FakeTable())(request(undefined, body));
    assert.equal(result.statusCode, 201, `body ${JSON.stringify(body)}`);
  }
});

// ---------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------

for (const [label, headers] of [
  ['no header', {}],
  ['blank bearer', { authorization: 'Bearer ' }],
  ['whitespace bearer', { authorization: 'Bearer    ' }],
  ['other scheme', { authorization: `Basic ${BEARER}` }],
]) {
  test(`${label} answers 401 user_token_missing and writes nothing`, async () => {
    const table = new FakeTable();
    const verifier = stubVerifier();
    const result = await handlerFor(table, verifier)(request(headers));
    assert.equal(result.statusCode, 401);
    assert.deepEqual(result.body, { error: 'user_token_missing' });
    assert.deepEqual(verifier.seen, []);
    assert.deepEqual(table.calls, []);
  });
}

test('A verifier 503 answers 503 jwks_unavailable and writes nothing', async () => {
  const table = new FakeTable();
  const result = await handlerFor(table, stubVerifier({ rejection: { status: 503, error: 'jwks_unavailable' } }))(
    request(),
  );
  assert.equal(result.statusCode, 503);
  assert.deepEqual(result.body, { error: 'jwks_unavailable' });
  assert.deepEqual(table.calls, []);
});

for (const rejection of [
  { status: 401, error: 'invalid_token' },
  { status: 401, error: 'missing_scope' },
  { status: 401, error: 'invalid_subject' },
  new Error('boom'),
]) {
  test(`Verifier rejection ${JSON.stringify(rejection.error ?? rejection.message)} answers 401 invalid_user_token`, async () => {
    const table = new FakeTable();
    const result = await handlerFor(table, stubVerifier({ rejection }))(request());
    assert.equal(result.statusCode, 401);
    assert.deepEqual(result.body, { error: 'invalid_user_token' });
    assert.deepEqual(table.calls, []);
    assert.ok(!JSON.stringify(result.body).includes(BEARER));
  });
}

for (const env of [{}, { ENTRA_TENANT_ID: 'tenant-1' }, { ENTRA_CLIENT_ID: 'client-1' }]) {
  test(`Entra not configured (${JSON.stringify(env)}) answers 500 not_configured`, async () => {
    const table = new FakeTable();
    const verifier = stubVerifier();
    const result = await handlerFor(table, verifier, { env })(request());
    assert.equal(result.statusCode, 500);
    assert.deepEqual(result.body, { error: 'not_configured' });
    assert.deepEqual(verifier.seen, []);
    assert.deepEqual(table.calls, []);
  });
}

test('No verifier configured answers 500 not_configured', async () => {
  const table = new FakeTable();
  const result = await handlerFor(table, undefined, { userVerifier: undefined })(request());
  assert.equal(result.statusCode, 500);
  assert.deepEqual(result.body, { error: 'not_configured' });
});

// ---------------------------------------------------------------------------
// End to end: the minted token enrolls once
// ---------------------------------------------------------------------------

test('The minted token enrolls exactly once and the device records who signed in', async () => {
  const table = new FakeTable();
  const minted = await handlerFor(table)(request());
  const enroll = createEnrollHandler({
    table,
    pepper: 'ab'.repeat(32),
    now: () => NOW,
  });
  const enrollRequest = {
    method: 'POST',
    path: '/api/v1/enroll',
    query: {},
    headers: { [ENROLLMENT_TOKEN_HEADER]: minted.body.token },
    body: JSON.stringify({
      hostname: 'h',
      platform: 'darwin',
      osVersion: '15.0',
      hardwareUuid: 'HW-1',
      agentVersion: '1.0.0',
    }),
  };
  const first = await enroll(enrollRequest);
  assert.equal(first.statusCode, 200);
  assert.deepEqual(table.peek(deviceProfile(first.body.deviceId)).enrolledBy, {
    oid: 'oid-amy',
    upn: 'amy@contoso.com',
    name: 'Amy Pond',
  });
  const enrolled = table.audits().find((a) => a.action === 'device.enrolled');
  assert.equal(enrolled.detail.enrolledByUpn, 'amy@contoso.com');

  const second = await enroll(enrollRequest);
  assert.equal(second.statusCode, 403);
  assert.deepEqual(second.body, { error: 'enrollment_token_exhausted' });
});

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

test('The route is registered as a public POST', async () => {
  const router = createRouter();
  const table = new FakeTable();
  registerAgentEnrollmentTokenRoute(router, {
    table,
    userVerifier: stubVerifier(),
    now: () => NOW,
    env: ENV,
  });
  const response = await router.handle({
    method: 'POST',
    path: AGENT_ENROLLMENT_TOKEN_PATH,
    query: {},
    headers: { authorization: `Bearer ${BEARER}` },
    body: '{}',
  });
  assert.equal(response.statusCode, 201);
  assert.match(JSON.parse(response.body).token, /^[0-9a-f]{16}\.[0-9a-f]{64}$/);
});

test('configure/resolve round-trips the dependencies', () => {
  const deps = { table: new FakeTable(), userVerifier: stubVerifier() };
  configureAgentEnrollmentTokenRoute(deps);
  assert.strictEqual(resolveAgentEnrollmentTokenDependencies(), deps);
});
