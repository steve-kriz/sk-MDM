/**
 * Agent sign-in configuration and the signed-in user report.
 *
 * TASK-031 introduced both routes; spec Amendment B (B.2) replaced the
 * token-based user report with the operating-system user: the route is device
 * HMAC only, with body `{"username": <string <= 256> | null}`.
 *
 * Every table is an in-memory fake -- no real DB connection is made.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const {
  agentAuthConfig,
  handleAgentAuthConfig,
  createUserSessionHandler,
  registerUserSessionRoutes,
  configureUserSessionRoute,
  resolveUserSessionDependencies,
  loginUserKey,
  MAX_LOGIN_USERS_PER_DEVICE,
  AGENT_AUTH_CONFIG_PATH,
  USER_SESSION_PATH,
  USERNAME_MAX_LENGTH,
} = await import(`file://${join(__dirname, '../../dist/routes/userSession.js')}`);

const { AGENT_SCOPE_NAME } = await import(`file://${join(__dirname, '../../dist/auth/userToken.js')}`);
const { deviceSignedInUser, deviceProfile, deviceLoginUser, LOGIN_USER_SK_PREFIX } = await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);
const { encryptDeviceSecret } = await import(`file://${join(__dirname, '../../dist/crypto/deviceSecret.js')}`);
const { signRequest } = await import(`file://${join(__dirname, '../../dist/contract/signing.js')}`);

const TENANT_ID = 'tenant-001';
const CLIENT_ID = 'client-001';
const NOW_SECONDS = 1_790_000_000;
const NOW_ISO = new Date(NOW_SECONDS * 1000).toISOString().replace('.000Z', 'Z');

class FakeTable {
  constructor() {
    this.items = new Map();
    this.putCalls = [];
    this.updateCalls = [];
  }
  keyStr(key) {
    return `${key.pk}|${key.sk}`;
  }
  async get(key) {
    const item = this.items.get(this.keyStr(key));
    return item === undefined ? undefined : { ...item };
  }
  async putIfAbsent(item) {
    const key = this.keyStr(item);
    if (this.items.has(key)) {
      return { written: false };
    }
    this.items.set(key, { ...item });
    return { written: true };
  }
  async put(item) {
    this.putCalls.push({ ...item });
    this.items.set(this.keyStr(item), { ...item });
  }
  async update(key, fields) {
    this.updateCalls.push({ key: { ...key }, fields });
    const keyStr = this.keyStr(key);
    let item = this.items.get(keyStr);
    if (!item) {
      item = { ...key };
    }

    // Apply update expression
    if (fields?.UpdateExpression) {
      const updates = this.parseUpdateExpression(
        fields.UpdateExpression,
        fields.ExpressionAttributeNames || {},
        fields.ExpressionAttributeValues || {}
      );
      item = { ...item, ...updates };
    }

    this.items.set(keyStr, item);
    return item;
  }
  parseUpdateExpression(expr, names, values) {
    const updates = {};
    const setPart = expr.match(/SET\s+(.*?)(?:$|REMOVE|ADD|DELETE)/i)?.[1] || '';

    if (setPart) {
      const assignments = setPart.split(',');
      for (const assignment of assignments) {
        const [lhs, rhs] = assignment.trim().split('=').map(s => s.trim());
        if (lhs && rhs) {
          const fieldName = names[lhs] || lhs;
          const fieldValue = values[rhs];
          if (fieldValue !== undefined) {
            updates[fieldName] = fieldValue;
          }
        }
      }
    }

    return updates;
  }
  signedInUserItems() {
    return this.putCalls.filter((item) => item.sk === 'SIGNEDINUSER');
  }
  async query(request) {
    if (!request) {
      return { items: [], cursor: null };
    }
    const { KeyConditionExpression, ExpressionAttributeValues } = request;
    const pk = ExpressionAttributeValues?.[':pk'];
    const prefix = ExpressionAttributeValues?.[':loginPrefix'];

    if (!pk || !prefix) {
      return { items: [], cursor: null };
    }

    const items = Array.from(this.items.values()).filter(item => {
      return item.pk === pk && typeof item.sk === 'string' && item.sk.startsWith(prefix);
    });

    return { items, cursor: null };
  }
  async delete(key) {
    const keyStr = this.keyStr(key);
    this.items.delete(keyStr);
  }
  loginUserItems() {
    return Array.from(this.items.values())
      .filter((item) => typeof item.sk === 'string' && item.sk.startsWith(LOGIN_USER_SK_PREFIX));
  }
}

class FakeRouter {
  constructor() {
    this.routes = [];
  }
  add(method, path, handler) {
    this.routes.push({ method, path, handler });
    return this;
  }
  getRoute(method, path) {
    return this.routes.find((r) => r.method === method && r.path === path);
  }
}

/** A handler whose device check is stubbed to accept `deviceId`. */
function handlerFor(table, { deviceId = 'd1', verifyDevice } = {}) {
  return createUserSessionHandler({
    table,
    now: () => NOW_SECONDS,
    pepper: 'a'.repeat(64),
    verifyDevice: verifyDevice ?? (async () => ({ ok: true, deviceId })),
  });
}

function request(body, { deviceId = 'd1', headers = {} } = {}) {
  return {
    method: 'POST',
    path: `/api/v1/devices/${deviceId}/user-session`,
    params: { deviceId },
    query: {},
    headers,
    body: typeof body === 'string' || body === null ? body : JSON.stringify(body),
  };
}

// ============================================================================
// GET /api/v1/agent-auth/config (unchanged)
// ============================================================================

test('Config: returns configured values with the correct shape', () => {
  const config = agentAuthConfig({
    ENTRA_TENANT_ID: TENANT_ID,
    ENTRA_CLIENT_ID: CLIENT_ID,
    ENTRA_ADMIN_GROUP_ID: 'g-secret',
    PEPPER_SECRET_ARN: 'arn:pep',
  });
  assert.deepStrictEqual(Object.keys(config).sort(), ['clientId', 'scopes', 'tenantId']);
  assert.strictEqual(config.tenantId, TENANT_ID);
  assert.strictEqual(config.clientId, CLIENT_ID);
  assert.deepStrictEqual(config.scopes, [`api://${CLIENT_ID}/MDM.Agent`, 'offline_access', 'openid', 'profile']);
});

test('Config: the response never carries other environment values', () => {
  const result = handleAgentAuthConfig();
  const body = JSON.stringify(result.body);
  assert.ok(!body.includes('g-secret'));
  assert.ok(!body.includes('arn:pep'));
});

for (const env of [{ ENTRA_TENANT_ID: '', ENTRA_CLIENT_ID: CLIENT_ID }, { ENTRA_TENANT_ID: TENANT_ID }, {}]) {
  test(`Config: not configured (${JSON.stringify(env)}) reads as null`, () => {
    assert.strictEqual(agentAuthConfig(env), null);
  });
}

// ============================================================================
// POST /api/v1/devices/{deviceId}/user-session
// ============================================================================

test('User session: a username is stored as SIGNEDINUSER {deviceId, username, source, reportedAt}', async () => {
  const table = new FakeTable();
  const result = await handlerFor(table)(request({ username: 'CONTOSO\\amy' }));

  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body, { user: { username: 'CONTOSO\\amy' } });

  const items = table.signedInUserItems();
  assert.strictEqual(items.length, 1);
  assert.deepStrictEqual(items[0], {
    ...deviceSignedInUser('d1'),
    deviceId: 'd1',
    username: 'CONTOSO\\amy',
    source: 'os',
    reportedAt: NOW_ISO,
  });
});

test('User session: null (nobody at the console) is stored and echoed as null', async () => {
  const table = new FakeTable();
  const result = await handlerFor(table)(request({ username: null }));
  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body, { user: { username: null } });
  assert.strictEqual(table.signedInUserItems()[0].username, null);
  assert.strictEqual(table.signedInUserItems()[0].source, 'os');
});

test(`User session: a username of exactly ${256} characters is accepted`, async () => {
  assert.strictEqual(USERNAME_MAX_LENGTH, 256);
  const table = new FakeTable();
  const name = 'a'.repeat(256);
  const result = await handlerFor(table)(request({ username: name }));
  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(table.signedInUserItems()[0].username, name);
});

test('User session: a second report replaces the first', async () => {
  const table = new FakeTable();
  await handlerFor(table)(request({ username: 'amy' }));
  await handlerFor(table)(request({ username: 'bob' }));
  assert.strictEqual((await table.get(deviceSignedInUser('d1'))).username, 'bob');
});

for (const [label, body] of [
  ['a 257-character username', { username: 'a'.repeat(257) }],
  ['a numeric username', { username: 42 }],
  ['an object username', { username: { name: 'amy' } }],
  ['an array username', { username: ['amy'] }],
  ['a boolean username', { username: true }],
  ['a missing username', {}],
  ['a JSON array body', '[]'],
  ['a JSON null body', 'null'],
  ['a non-JSON body', 'not json'],
  ['an empty body', ''],
  ['an absent body', null],
]) {
  test(`User session: ${label} answers 400 invalid_request naming username and writes nothing`, async () => {
    const table = new FakeTable();
    const result = await handlerFor(table)(request(body));
    assert.strictEqual(result.statusCode, 400);
    assert.deepStrictEqual(result.body, { error: 'invalid_request', fields: ['username'] });
    assert.deepStrictEqual(table.putCalls, []);
  });
}

test('User session: a failed device check answers its own status and body, unchanged', async () => {
  const table = new FakeTable();
  const handler = handlerFor(table, {
    verifyDevice: async () => ({ ok: false, status: 401, body: { error: 'bad_signature' } }),
  });
  const result = await handler(request({ username: 'amy' }));
  assert.strictEqual(result.statusCode, 401);
  assert.deepStrictEqual(result.body, { error: 'bad_signature' });
  assert.deepStrictEqual(table.putCalls, []);
});

test('User session: a revoked device answers 403 device_revoked', async () => {
  const table = new FakeTable();
  const handler = handlerFor(table, {
    verifyDevice: async () => ({ ok: false, status: 403, body: { error: 'device_revoked' } }),
  });
  const result = await handler(request({ username: 'amy' }));
  assert.strictEqual(result.statusCode, 403);
  assert.deepStrictEqual(result.body, { error: 'device_revoked' });
});

test('User session: the signed device must be the one the path names (403 device_mismatch)', async () => {
  const table = new FakeTable();
  const result = await handlerFor(table, { deviceId: 'd1' })(request({ username: 'amy' }, { deviceId: 'd2' }));
  assert.strictEqual(result.statusCode, 403);
  assert.deepStrictEqual(result.body, { error: 'device_mismatch' });
  assert.deepStrictEqual(table.putCalls, []);
});

test('User session: the device check runs before the body is validated', async () => {
  const table = new FakeTable();
  const handler = handlerFor(table, {
    verifyDevice: async () => ({ ok: false, status: 401, body: { error: 'missing_auth_headers' } }),
  });
  const result = await handler(request('not json'));
  assert.strictEqual(result.statusCode, 401);
});

test('User session: an Authorization header is ignored -- no bearer is needed or read', async () => {
  const table = new FakeTable();
  const result = await handlerFor(table)(
    request({ username: 'amy' }, { headers: { authorization: 'Bearer some.jwt.value' } }),
  );
  assert.strictEqual(result.statusCode, 200);
  assert.ok(!JSON.stringify(table.putCalls).includes('some.jwt.value'));
});

test('User session: a really signed request verifies with the body in the signature', async () => {
  const pepper = randomBytes(32).toString('hex');
  const secret = randomBytes(32).toString('hex');
  const deviceId = 'dev-real';
  const table = new FakeTable();
  await table.put({ ...deviceProfile(deviceId), deviceId, secretEnc: encryptDeviceSecret(secret, pepper, deviceId) });
  table.putCalls = [];

  const handler = createUserSessionHandler({ table, now: () => NOW_SECONDS, pepper });
  const body = JSON.stringify({ username: 'amy' });
  const path = `/api/v1/devices/${deviceId}/user-session`;
  const sign = (signedBody, nonce) => ({
    method: 'POST',
    path,
    params: { deviceId },
    query: {},
    body,
    headers: {
      'x-mdm-device-id': deviceId,
      'x-mdm-timestamp': String(NOW_SECONDS),
      'x-mdm-nonce': nonce,
      'x-mdm-signature': signRequest(secret, {
        method: 'POST',
        path,
        query: {},
        body: signedBody ?? body,
        timestamp: NOW_SECONDS,
        nonce,
        deviceId,
      }),
    },
  });

  const ok = await handler(sign(undefined, 'nonce-1'));
  assert.strictEqual(ok.statusCode, 200);
  assert.deepStrictEqual(ok.body, { user: { username: 'amy' } });

  // A signature over a different body does not verify.
  const tampered = await handler(sign(JSON.stringify({ username: 'mallory' }), 'nonce-2'));
  assert.strictEqual(tampered.statusCode, 401);
  assert.deepStrictEqual(tampered.body, { error: 'bad_signature' });
});

// ============================================================================
// Key builder
// ============================================================================

test('deviceSignedInUser returns DEVICE#<id> / SIGNEDINUSER', () => {
  assert.deepStrictEqual(deviceSignedInUser('d1'), { pk: 'DEVICE#d1', sk: 'SIGNEDINUSER' });
});

test('deviceSignedInUser throws on an id carrying #', () => {
  assert.throws(() => deviceSignedInUser('a#b'), /invalid id: a#b/);
});

// ============================================================================
// Wiring
// ============================================================================

test('Wiring: both routes are registered on their paths', () => {
  const router = new FakeRouter();
  registerUserSessionRoutes(router, { table: new FakeTable(), now: () => NOW_SECONDS, pepper: 'a'.repeat(64) });
  assert.ok(router.getRoute('GET', AGENT_AUTH_CONFIG_PATH));
  assert.ok(router.getRoute('POST', USER_SESSION_PATH));
});

test('Wiring: path constants and the agent scope name', () => {
  assert.strictEqual(AGENT_AUTH_CONFIG_PATH, '/api/v1/agent-auth/config');
  assert.strictEqual(USER_SESSION_PATH, '/api/v1/devices/{deviceId}/user-session');
  assert.strictEqual(AGENT_SCOPE_NAME, 'MDM.Agent');
});

test('Wiring: dependencies round-trip, with no user token verifier', () => {
  const deps = { table: new FakeTable(), now: () => NOW_SECONDS, pepper: 'a'.repeat(64) };
  configureUserSessionRoute(deps);
  const resolved = resolveUserSessionDependencies();
  assert.strictEqual(resolved, deps);
  assert.strictEqual(resolved.userVerifier, undefined);
});

// ============================================================================
// E2E Cucumber-style tests: Per-device login history
// ============================================================================

test('E2E: loginUserKey - normalises username with trim and lowercase', () => {
  assert.strictEqual(loginUserKey('  CONTOSO\\Amy '), loginUserKey('contoso\\amy'));
  assert.strictEqual(loginUserKey('CONTOSO\\amy'), loginUserKey('contoso\\amy'));
  assert.notStrictEqual(loginUserKey('CONTOSO\\amy'), loginUserKey('amy@contoso.com'));
});

test('E2E: deviceLoginUser - builds correct key structure', () => {
  const key = deviceLoginUser('d1', 'a'.repeat(64));
  assert.strictEqual(key.pk, 'DEVICE#d1');
  assert.ok(key.sk.startsWith(LOGIN_USER_SK_PREFIX));
});

test('E2E: deviceLoginUser - accepts empty usernameKey for prefix query', () => {
  const key = deviceLoginUser('d1', '');
  assert.strictEqual(key.pk, 'DEVICE#d1');
  assert.strictEqual(key.sk, LOGIN_USER_SK_PREFIX);
});

test('E2E: deviceLoginUser - throws on deviceId with #', () => {
  assert.throws(() => deviceLoginUser('a#b', 'a'.repeat(64)), /invalid id: a#b/);
});

test('E2E: deviceLoginUser - throws on invalid usernameKey', () => {
  assert.throws(() => deviceLoginUser('d1', 'XYZ'), /invalid id/);
  assert.throws(() => deviceLoginUser('d1', 'a'.repeat(63)), /invalid id/);
  assert.throws(() => deviceLoginUser('d1', 'Z'.repeat(64)), /invalid id/);
});

test('E2E: First report of username creates record with loginCount 1', async () => {
  const table = new FakeTable();
  const handler = handlerFor(table);
  await handler(request({ username: 'CONTOSO\\amy' }));

  const loginItems = table.loginUserItems();
  assert.strictEqual(loginItems.length, 1);
  assert.strictEqual(loginItems[0].username, 'CONTOSO\\amy');
  assert.strictEqual(loginItems[0].loginCount, 1);
  assert.strictEqual(loginItems[0].firstSeenAt, NOW_ISO);
  assert.strictEqual(loginItems[0].lastSeenAt, NOW_ISO);
});

test('E2E: Same user reported again only updates lastSeenAt, keeps loginCount', async () => {
  const table = new FakeTable();
  const firstHandler = handlerFor(table);

  // First report at NOW_SECONDS
  await firstHandler(request({ username: 'CONTOSO\\amy' }));
  const firstItem = table.loginUserItems()[0];
  assert.strictEqual(firstItem.loginCount, 1);
  assert.strictEqual(firstItem.firstSeenAt, NOW_ISO);
  assert.strictEqual(firstItem.lastSeenAt, NOW_ISO);

  // Set up SIGNEDINUSER to have the same user
  const signedIn = { ...deviceSignedInUser('d1'), deviceId: 'd1', username: 'CONTOSO\\amy', source: 'os', reportedAt: NOW_ISO };
  table.items.set(`${signedIn.pk}|${signedIn.sk}`, signedIn);

  // Create a handler at a later time
  const laterTime = NOW_SECONDS + 3600;
  const laterIso = new Date(laterTime * 1000).toISOString().replace('.000Z', 'Z');
  const laterHandler = createUserSessionHandler({
    table,
    now: () => laterTime,
    pepper: 'a'.repeat(64),
    verifyDevice: async () => ({ ok: true, deviceId: 'd1' }),
  });

  // Report the same user again
  await laterHandler(request({ username: 'CONTOSO\\amy' }));

  const loginItems = table.loginUserItems();
  assert.strictEqual(loginItems.length, 1);
  assert.strictEqual(loginItems[0].firstSeenAt, NOW_ISO, 'firstSeenAt should not change');
  assert.strictEqual(loginItems[0].loginCount, 1, 'loginCount should not increase when same user');
  assert.strictEqual(loginItems[0].lastSeenAt, laterIso, 'lastSeenAt should update to later time');
});

test('E2E: User returning after another user increments loginCount', async () => {
  const table = new FakeTable();
  const handler = handlerFor(table);

  // Report amy
  await handler(request({ username: 'amy' }));
  // Report bob (simulating previous SIGNEDINUSER was amy)
  const signedIn = { ...deviceSignedInUser('d1'), deviceId: 'd1', username: 'amy', source: 'os', reportedAt: NOW_ISO };
  table.items.set(`${signedIn.pk}|${signedIn.sk}`, signedIn);
  await handler(request({ username: 'bob' }));
  // Report amy again (simulating previous was bob)
  const signedIn2 = { ...deviceSignedInUser('d1'), deviceId: 'd1', username: 'bob', source: 'os', reportedAt: NOW_ISO };
  table.items.set(`${signedIn2.pk}|${signedIn2.sk}`, signedIn2);
  await handler(request({ username: 'amy' }));

  const loginItems = table.loginUserItems();
  const amyRecord = loginItems.find(u => u.username === 'amy');
  const bobRecord = loginItems.find(u => u.username === 'bob');

  assert.strictEqual(amyRecord.loginCount, 2, 'amy should have loginCount 2');
  assert.strictEqual(bobRecord.loginCount, 1, 'bob should have loginCount 1');
});

test('E2E: User returning after null increments loginCount', async () => {
  const table = new FakeTable();
  const handler = handlerFor(table);

  // Report amy
  await handler(request({ username: 'amy' }));
  // Report null (nobody logged in)
  const signedIn = { ...deviceSignedInUser('d1'), deviceId: 'd1', username: 'amy', source: 'os', reportedAt: NOW_ISO };
  table.items.set(`${signedIn.pk}|${signedIn.sk}`, signedIn);
  await handler(request({ username: null }));
  // Report amy again
  const signedIn2 = { ...deviceSignedInUser('d1'), deviceId: 'd1', username: null, source: 'os', reportedAt: NOW_ISO };
  table.items.set(`${signedIn2.pk}|${signedIn2.sk}`, signedIn2);
  await handler(request({ username: 'amy' }));

  const loginItems = table.loginUserItems();
  assert.strictEqual(loginItems.length, 1);
  assert.strictEqual(loginItems[0].loginCount, 2);
});

test('E2E: Case and whitespace variants share one record', async () => {
  const table = new FakeTable();
  const handler = handlerFor(table);

  await handler(request({ username: 'Amy' }));
  const signedIn = { ...deviceSignedInUser('d1'), deviceId: 'd1', username: 'Amy', source: 'os', reportedAt: NOW_ISO };
  table.items.set(`${signedIn.pk}|${signedIn.sk}`, signedIn);
  await handler(request({ username: 'amy ' }));

  const loginItems = table.loginUserItems();
  assert.strictEqual(loginItems.length, 1);
  assert.strictEqual(loginItems[0].username, 'amy');
  assert.strictEqual(loginItems[0].loginCount, 1);
});

test('E2E: Different spellings are separate records', async () => {
  const table = new FakeTable();
  const handler = handlerFor(table);

  await handler(request({ username: 'CONTOSO\\amy' }));
  const signedIn = { ...deviceSignedInUser('d1'), deviceId: 'd1', username: 'CONTOSO\\amy', source: 'os', reportedAt: NOW_ISO };
  table.items.set(`${signedIn.pk}|${signedIn.sk}`, signedIn);
  await handler(request({ username: 'amy@contoso.com' }));

  const loginItems = table.loginUserItems();
  assert.strictEqual(loginItems.length, 2);
});

test('E2E: Null username creates no record', async () => {
  const table = new FakeTable();
  const handler = handlerFor(table);

  const result = await handler(request({ username: null }));

  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body, { user: { username: null } });
  assert.strictEqual(table.loginUserItems().length, 0);
});

test('E2E: Empty string username creates no record', async () => {
  const table = new FakeTable();
  const handler = handlerFor(table);

  const result = await handler(request({ username: '' }));

  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body, { user: { username: '' } });
  assert.strictEqual(table.loginUserItems().length, 0);
});

test('E2E: Whitespace-only username creates no record', async () => {
  const table = new FakeTable();
  const handler = handlerFor(table);

  const result = await handler(request({ username: '   ' }));

  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body, { user: { username: '   ' } });
  assert.strictEqual(table.loginUserItems().length, 0);
});

test('E2E: 401 auth failure writes no login record', async () => {
  const table = new FakeTable();
  const handler = handlerFor(table, {
    verifyDevice: async () => ({ ok: false, status: 401, body: { error: 'bad_signature' } }),
  });

  const result = await handler(request({ username: 'amy' }));

  assert.strictEqual(result.statusCode, 401);
  assert.deepStrictEqual(table.loginUserItems().length, 0);
});

test('E2E: 403 device_mismatch writes no login record', async () => {
  const table = new FakeTable();
  const result = await handlerFor(table, { deviceId: 'd1' })(request({ username: 'amy' }, { deviceId: 'd2' }));

  assert.strictEqual(result.statusCode, 403);
  assert.deepStrictEqual(table.loginUserItems().length, 0);
});

test('E2E: 400 invalid_request (257-char username) writes no login record', async () => {
  const table = new FakeTable();
  const handler = handlerFor(table);

  const result = await handler(request({ username: 'a'.repeat(257) }));

  assert.strictEqual(result.statusCode, 400);
  assert.deepStrictEqual(table.loginUserItems().length, 0);
});

test('E2E: 100-record cap evicts least recently seen user', async () => {
  const table = new FakeTable();
  const handler = handlerFor(table);

  // Create 100 login users
  for (let i = 0; i < 100; i++) {
    const user = `user${i}`;
    const key = deviceLoginUser('d1', loginUserKey(user));
    table.items.set(`${key.pk}|${key.sk}`, {
      ...key,
      deviceId: 'd1',
      username: user,
      firstSeenAt: NOW_ISO,
      lastSeenAt: new Date((NOW_SECONDS - (100 - i) * 100) * 1000).toISOString().replace('.000Z', 'Z'),
      loginCount: 1,
    });
  }

  // Report a new user - should evict the oldest
  const signedIn = { ...deviceSignedInUser('d1'), deviceId: 'd1', username: 'user0', source: 'os', reportedAt: NOW_ISO };
  table.items.set(`${signedIn.pk}|${signedIn.sk}`, signedIn);
  await handler(request({ username: 'newcomer' }));

  const loginItems = table.loginUserItems();
  assert.strictEqual(loginItems.length, 100);
  assert.ok(!loginItems.find(u => u.username === 'user0'));
  assert.ok(loginItems.find(u => u.username === 'newcomer'));
});

test('E2E: At 100-record cap, reporting known user evicts nothing', async () => {
  const table = new FakeTable();
  const handler = handlerFor(table);

  // Create 100 login users
  for (let i = 0; i < 100; i++) {
    const user = `user${i}`;
    const key = deviceLoginUser('d1', loginUserKey(user));
    table.items.set(`${key.pk}|${key.sk}`, {
      ...key,
      deviceId: 'd1',
      username: user,
      firstSeenAt: NOW_ISO,
      lastSeenAt: new Date((NOW_SECONDS - (100 - i) * 100) * 1000).toISOString().replace('.000Z', 'Z'),
      loginCount: 1,
    });
  }

  // Report an existing user - should NOT evict anything
  const signedIn = { ...deviceSignedInUser('d1'), deviceId: 'd1', username: 'user0', source: 'os', reportedAt: NOW_ISO };
  table.items.set(`${signedIn.pk}|${signedIn.sk}`, signedIn);
  await handler(request({ username: 'user50' }));

  const loginItems = table.loginUserItems();
  assert.strictEqual(loginItems.length, 100);
});

test('E2E: Table error logs console.warn and still returns 200 with SIGNEDINUSER', async () => {
  const consoleLogs = [];
  const originalWarn = console.warn;
  console.warn = (...args) => consoleLogs.push(args);

  const table = new FakeTable();
  const originalQuery = table.query.bind(table);
  let queryThrows = false;
  table.query = async () => {
    if (queryThrows) throw new Error('query fails');
    return originalQuery();
  };

  // Make recordLoginHistory fail on query
  queryThrows = true;
  const handler = handlerFor(table);
  const result = await handler(request({ username: 'amy' }));

  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body, { user: { username: 'amy' } });
  assert.ok(table.signedInUserItems().length > 0);
  assert.ok(consoleLogs.some(log =>
    typeof log[0] === 'string' && log[0].includes('login history update failed')
  ));

  console.warn = originalWarn;
});

test('E2E: Previous SIGNEDINUSER get error skips history, logs once, no reads/writes', async () => {
  const consoleLogs = [];
  const originalWarn = console.warn;
  console.warn = (...args) => consoleLogs.push(args);

  const table = new FakeTable();
  const originalGet = table.get.bind(table);
  let getThrows = false;
  table.get = async (key) => {
    if (getThrows && key.sk === 'SIGNEDINUSER') throw new Error('get fails');
    return originalGet(key);
  };

  // First, put an existing login user
  const existingKey = deviceLoginUser('d1', loginUserKey('amy'));
  table.items.set(`${existingKey.pk}|${existingKey.sk}`, {
    ...existingKey,
    deviceId: 'd1',
    username: 'amy',
    firstSeenAt: NOW_ISO,
    lastSeenAt: NOW_ISO,
    loginCount: 1,
  });

  const initialLoginItems = table.loginUserItems().length;

  // Make the SIGNEDINUSER get fail
  getThrows = true;
  const handler = handlerFor(table);
  const result = await handler(request({ username: 'amy' }));

  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body, { user: { username: 'amy' } });

  // The login record should not have been modified
  const loginItems = table.loginUserItems();
  assert.strictEqual(loginItems.length, initialLoginItems);
  assert.strictEqual(loginItems[0].loginCount, 1, 'loginCount should not change');

  // Should have exactly one warning
  const warnLogs = consoleLogs.filter(log =>
    typeof log[0] === 'string' && log[0].includes('login history update failed')
  );
  assert.strictEqual(warnLogs.length, 1);

  console.warn = originalWarn;
});

test('E2E: SIGNEDINUSER behavior unchanged - stored exactly as before', async () => {
  const table = new FakeTable();
  const result = await handlerFor(table)(request({ username: 'CONTOSO\\amy' }));

  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body, { user: { username: 'CONTOSO\\amy' } });

  const items = table.signedInUserItems();
  assert.strictEqual(items.length, 1);
  assert.deepStrictEqual(items[0], {
    ...deviceSignedInUser('d1'),
    deviceId: 'd1',
    username: 'CONTOSO\\amy',
    source: 'os',
    reportedAt: NOW_ISO,
  });
});
