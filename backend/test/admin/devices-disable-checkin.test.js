/**
 * TASK-041 AC14 and AC16.
 *
 * AC14: the real admin disable/enable handlers and the real device check-in
 * route (with the real `verifyDeviceRequest`) share one in-memory fake table.
 * After disable, a validly signed check-in is refused 403 device_revoked; after
 * enable, the same device secret -- no re-enroll in between -- is accepted 200.
 *
 * AC16: the three new admin routes, as registered on the application `router`
 * exported by dist/index.js, answer 401 without a valid admin bearer (and so
 * are real routes, not 404).
 *
 * The table is an in-memory fake; nothing reaches DynamoDB.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { handleDeviceDisable, handleDeviceEnable } from '../../dist/admin/devices.js';
import { createCheckInHandler } from '../../dist/routes/checkin.js';
import { verifyDeviceRequest } from '../../dist/http/deviceAuth.js';
import { signRequest } from '../../dist/contract/signing.js';
import { encryptDeviceSecret } from '../../dist/crypto/deviceSecret.js';
import { deviceProfile } from '../../dist/db/keys.js';
import { router, configureAdminRoutes } from '../../dist/index.js';

function randomHex(bytes = 32) {
  return randomBytes(bytes).toString('hex');
}

/** A generic in-memory table: get/put/putIfAbsent/update (SET/REMOVE)/query. */
class FakeTable {
  constructor() {
    this.items = new Map();
    this.calls = [];
  }

  keyOf(key) {
    return `${key.pk}|${key.sk}`;
  }

  async get(key) {
    this.calls.push({ op: 'get', key });
    const item = this.items.get(this.keyOf(key));
    return item === undefined ? undefined : structuredClone(item);
  }

  async put(item) {
    this.calls.push({ op: 'put', item });
    this.items.set(this.keyOf(item), structuredClone(item));
  }

  async putIfAbsent(item) {
    this.calls.push({ op: 'putIfAbsent', item });
    const k = this.keyOf(item);
    if (this.items.has(k)) {
      return { written: false };
    }
    this.items.set(k, structuredClone(item));
    return { written: true };
  }

  async update(key, fields = {}) {
    this.calls.push({ op: 'update', key, fields });
    const k = this.keyOf(key);
    const item = { ...(this.items.get(k) ?? { pk: key.pk, sk: key.sk }) };
    const names = fields.ExpressionAttributeNames ?? {};
    const values = fields.ExpressionAttributeValues ?? {};
    const resolve = (name) => names[name] ?? name;
    const expr = fields.UpdateExpression ?? '';
    const setPart = /SET\s+(.*?)(?=\s+REMOVE\s+|\s+ADD\s+|\s+DELETE\s+|$)/i.exec(expr)?.[1];
    if (setPart) {
      for (const assignment of setPart.split(',')) {
        const [lhs, rhs] = assignment.split('=').map((s) => s.trim());
        if (lhs && rhs && rhs.startsWith(':')) {
          item[resolve(lhs)] = values[rhs];
        }
      }
    }
    const removePart = /REMOVE\s+(.*?)(?=\s+SET\s+|\s+ADD\s+|\s+DELETE\s+|$)/i.exec(expr)?.[1];
    if (removePart) {
      for (const name of removePart.split(',')) {
        delete item[resolve(name.trim())];
      }
    }
    this.items.set(k, item);
    return structuredClone(item);
  }

  async query() {
    this.calls.push({ op: 'query' });
    return { items: [], cursor: null };
  }
}

const NOW = new Date('2026-10-02T12:00:00Z');
const NOW_SECONDS = Math.floor(NOW.getTime() / 1000);

function checkInBody() {
  return JSON.stringify({
    collectedAt: '2026-10-02T11:59:00Z',
    inventory: {
      hardware: { manufacturer: 'Dell', model: 'X', serialNumber: 'S1', cpu: 'i7', ramBytes: 1, diskBytes: 1 },
      os: { name: 'Windows', version: '11', build: '22621', architecture: 'x86_64' },
      software: [],
    },
    posture: {
      diskEncryption: { enabled: true, method: 'bitlocker' },
      firewall: { enabled: true },
      antivirus: { name: 'Defender', enabled: true, definitionsAgeDays: 1 },
      osUpdate: { lastCheckedAt: '2026-10-02T10:00:00Z', pendingCount: 0, rebootRequired: false },
      localAdmins: [],
    },
  });
}

/** A check-in request signed with the device secret, fresh nonce each time. */
function signedCheckIn(deviceId, secret) {
  const path = `/api/v1/devices/${deviceId}/checkin`;
  const body = checkInBody();
  const nonce = randomHex(16);
  const signature = signRequest(secret, {
    method: 'POST',
    path,
    query: '',
    body,
    timestamp: NOW_SECONDS,
    nonce,
    deviceId,
  });
  return {
    method: 'POST',
    path,
    query: '',
    params: { deviceId },
    headers: {
      'x-mdm-device-id': deviceId,
      'x-mdm-timestamp': String(NOW_SECONDS),
      'x-mdm-nonce': nonce,
      'x-mdm-signature': signature,
    },
    body,
  };
}

function adminRequest(deviceId) {
  return {
    method: 'POST',
    path: `/admin/api/v1/devices/${deviceId}/disable`,
    params: { deviceId },
    query: {},
    headers: {},
    body: null,
    claims: { preferred_username: 'admin@contoso.com' },
  };
}

// ============================================================================
// AC14
// ============================================================================

test('AC14 Scenario: disable refuses a validly signed check-in; enable restores it with the same secret', async () => {
  const table = new FakeTable();
  const pepper = randomHex(32);
  const deviceId = randomUUID();
  const secret = randomHex(32);
  await table.put({
    ...deviceProfile(deviceId),
    deviceId,
    hostname: 'PC-1',
    enrolledAt: '2026-10-01T00:00:00Z',
    secretEnc: encryptDeviceSecret(secret, pepper, deviceId),
  });

  const checkIn = createCheckInHandler({
    table,
    pepper,
    now: () => NOW,
    verifyDevice: verifyDeviceRequest,
  });
  const adminDeps = { table, now: () => NOW };

  // Baseline: the active device's signed check-in is accepted.
  const before = await checkIn(signedCheckIn(deviceId, secret));
  assert.equal(before.statusCode, 200, JSON.stringify(before.body));

  // Given the admin disables D
  const disabled = await handleDeviceDisable(adminRequest(deviceId), adminDeps);
  assert.equal(disabled.statusCode, 200);
  assert.equal(disabled.body.credential.status, 'disabled');

  // When D sends a validly signed check-in
  const refused = await checkIn(signedCheckIn(deviceId, secret));

  // Then it is refused 403 device_revoked
  assert.equal(refused.statusCode, 403);
  assert.deepEqual(refused.body, { error: 'device_revoked' });

  // Given the admin enables D (no re-enroll; the stored secret is untouched)
  const secretEncBefore = (await table.get(deviceProfile(deviceId))).secretEnc;
  const enabled = await handleDeviceEnable(adminRequest(deviceId), adminDeps);
  assert.equal(enabled.statusCode, 200);
  assert.equal(enabled.body.credential.status, 'active');
  assert.equal((await table.get(deviceProfile(deviceId))).secretEnc, secretEncBefore);

  // When D signs with the same secret
  const accepted = await checkIn(signedCheckIn(deviceId, secret));

  // Then it is accepted 200
  assert.equal(accepted.statusCode, 200, JSON.stringify(accepted.body));
  assert.equal(typeof accepted.body.checkInIntervalSeconds, 'number');
});

// ============================================================================
// AC16
// ============================================================================

const ADMIN_TOKEN = 'valid-admin-token';
const adminTable = new FakeTable();
configureAdminRoutes({
  verifier: {
    async verify(token) {
      if (token === ADMIN_TOKEN) {
        return { sub: 'admin', preferred_username: 'admin@contoso.com', roles: ['MDM.Administrator'] };
      }
      throw { status: 401, error: 'unauthorized' };
    },
  },
  table: adminTable,
  now: () => NOW,
});

const NEW_ROUTES = [
  ['GET', '/admin/api/v1/enrollment-tokens'],
  ['POST', `/admin/api/v1/enrollment-tokens/${'a'.repeat(32)}/revoke`],
  ['POST', `/admin/api/v1/devices/${randomUUID()}/disable`],
  ['POST', `/admin/api/v1/devices/${randomUUID()}/enable`],
];

function routerRequest(method, path, headers = {}) {
  return router.handle({ method, path, query: {}, headers, body: method === 'POST' ? '{}' : null });
}

test('AC16 control: an unregistered admin path on the application router is 404', async () => {
  const res = await routerRequest('GET', '/admin/api/v1/no-such-route-xyz');
  assert.equal(res.statusCode, 404);
});

for (const [method, path] of NEW_ROUTES) {
  test(`AC16 Scenario: ${method} ${path} answers 401 with no Authorization header (not 404)`, async () => {
    const res = await routerRequest(method, path);
    assert.equal(res.statusCode, 401);
    const body = typeof res.body === 'string' ? JSON.parse(res.body) : res.body;
    assert.equal(body.error, 'unauthorized');
  });

  test(`AC16 Scenario: ${method} ${path} answers 401 with an invalid bearer`, async () => {
    const res = await routerRequest(method, path, { authorization: 'Bearer not-a-valid-token' });
    assert.equal(res.statusCode, 401);
  });
}

test('AC16 control: with a valid admin bearer the list route reaches its handler (200)', async () => {
  const res = await routerRequest('GET', '/admin/api/v1/enrollment-tokens', { authorization: `Bearer ${ADMIN_TOKEN}` });
  assert.equal(res.statusCode, 200);
});
