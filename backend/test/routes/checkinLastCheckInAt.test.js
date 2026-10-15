/**
 * E2E cucumber-style tests for TASK-054's AC5: an accepted check-in records
 * `lastCheckInAt` on the device profile, and a rejected check-in records
 * none.
 *
 * New file per TASK-054 instructions: backend/test/routes/checkin.test.js,
 * checkin-heartbeat.test.js and checkin-analytics.test.js (AC16) must pass
 * unchanged.
 *
 * All database calls are mocked; no real DB connection is ever opened.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { createCheckInHandler } = await import(`file://${join(__dirname, '../../dist/routes/checkin.js')}`);

// ============================================================================
// Fakes
// ============================================================================

class FakeTable {
  constructor() {
    this.items = new Map();
    this.calls = [];
  }

  keyStr(key) {
    return JSON.stringify({ pk: key.pk, sk: key.sk });
  }

  async get(key) {
    this.calls.push({ operation: 'get', key });
    return this.items.get(this.keyStr(key));
  }

  async put(item) {
    this.calls.push({ operation: 'put', item: { ...item } });
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  async putIfAbsent(item) {
    const keyStr = this.keyStr(item);
    this.calls.push({ operation: 'putIfAbsent', item: { ...item } });
    if (this.items.has(keyStr)) {
      return { written: false };
    }
    this.items.set(keyStr, { ...item });
    return { written: true };
  }

  async update(key, fields) {
    this.calls.push({ operation: 'update', key, fields });
    const existing = this.items.get(this.keyStr(key)) ?? { ...key };
    this.items.set(this.keyStr(key), { ...existing });
    return existing;
  }

  async query() {
    return { items: [], cursor: null };
  }

  profileUpdates() {
    return this.calls.filter((c) => c.operation === 'update' && c.key.sk === 'PROFILE');
  }
}

function randomHex(bytes = 32) {
  return randomBytes(bytes).toString('hex');
}

function createFakeVerifier(deviceIdToReturn = 'test-device-id', authOk = true, authStatus = 401, authError = 'unauthorized') {
  return async () => (authOk ? { ok: true, deviceId: deviceIdToReturn } : { ok: false, status: authStatus, body: { error: authError } });
}

function createValidCheckInRequest(overrides = {}) {
  const baseRequest = {
    method: 'POST',
    path: '/api/v1/devices/test-device-id/checkin',
    query: {},
    headers: {
      'x-mdm-device-id': 'test-device-id',
      'x-mdm-timestamp': Math.floor(Date.now() / 1000).toString(),
      'x-mdm-nonce': randomHex(16),
      'x-mdm-signature': randomHex(32),
    },
    params: { deviceId: 'test-device-id' },
    body: null,
  };

  const defaultBody = {
    collectedAt: '2026-10-11T11:50:00Z',
    inventory: {
      hardware: { manufacturer: 'Dell', model: 'OptiPlex', serialNumber: 'ABC123', cpu: 'i7', ramBytes: 1, diskBytes: 1 },
      os: { name: 'Windows', version: '11', build: '22621', architecture: 'x86_64' },
      software: [],
      warnings: [],
    },
    posture: {
      diskEncryption: { enabled: true, method: 'bitlocker' },
      firewall: { enabled: true },
      antivirus: { name: 'Defender', enabled: true, definitionsAgeDays: 1 },
      osUpdate: { lastCheckedAt: '2026-10-11T10:00:00Z', pendingCount: 0, rebootRequired: false },
      localAdmins: [],
      warnings: [],
    },
  };

  const body = { ...defaultBody, ...overrides };
  return {
    ...baseRequest,
    body: JSON.stringify(body),
    ...overrides.requestOverride,
  };
}

const NOW = () => new Date('2026-10-11T12:00:00Z');

// ============================================================================
// Scenario: An accepted check-in records lastCheckInAt (AC5)
// ============================================================================

test('Scenario: An accepted check-in records lastCheckInAt', async () => {
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: NOW,
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  // When "d1" posts a valid signed check-in
  const result = await handler(createValidCheckInRequest());

  // Then the response is 200
  assert.strictEqual(result.statusCode, 200);

  // And the PROFILE update includes "lastCheckInAt = :lastCheckInAt"
  const profileUpdates = table.profileUpdates();
  assert.strictEqual(profileUpdates.length, 1);
  const update = profileUpdates[0];
  assert.ok(
    update.fields.UpdateExpression.includes('lastCheckInAt = :lastCheckInAt'),
    `UpdateExpression ${update.fields.UpdateExpression} should include lastCheckInAt = :lastCheckInAt`,
  );

  // And ":lastCheckInAt" equals ":lastSeenAt" which is "2026-10-11T12:00:00Z"
  const values = update.fields.ExpressionAttributeValues;
  assert.strictEqual(values[':lastSeenAt'], '2026-10-11T12:00:00Z');
  assert.strictEqual(values[':lastCheckInAt'], values[':lastSeenAt']);
});

// ============================================================================
// Scenario Outline: A rejected check-in records no lastCheckInAt (AC5,
// failure)
// ============================================================================

test('Scenario Outline: A rejected check-in records no lastCheckInAt', async () => {
  // 413: larger than MAX_BODY_BYTES.
  {
    const table = new FakeTable();
    const handler = createCheckInHandler({
      table,
      pepper: randomHex(32),
      now: NOW,
      verifyDevice: createFakeVerifier('test-device-id', true),
    });
    const request = createValidCheckInRequest();
    request.body = 'x'.repeat(300000);
    const result = await handler(request);
    assert.strictEqual(result.statusCode, 413);
    assert.strictEqual(table.profileUpdates().length, 0);
  }

  // 401: unsigned / failed verification.
  {
    const table = new FakeTable();
    const handler = createCheckInHandler({
      table,
      pepper: randomHex(32),
      now: NOW,
      verifyDevice: createFakeVerifier('test-device-id', false, 401, 'unauthorized'),
    });
    const result = await handler(createValidCheckInRequest());
    assert.strictEqual(result.statusCode, 401);
    assert.strictEqual(table.profileUpdates().length, 0);
  }

  // 403: signed by another device (path names test-device-id, signed as d-other).
  {
    const table = new FakeTable();
    const handler = createCheckInHandler({
      table,
      pepper: randomHex(32),
      now: NOW,
      verifyDevice: createFakeVerifier('d-other', true),
    });
    const result = await handler(createValidCheckInRequest());
    assert.strictEqual(result.statusCode, 403);
    assert.strictEqual(result.body.error, 'device_mismatch');
    assert.strictEqual(table.profileUpdates().length, 0);
  }

  // 400: missing collectedAt.
  {
    const table = new FakeTable();
    const handler = createCheckInHandler({
      table,
      pepper: randomHex(32),
      now: NOW,
      verifyDevice: createFakeVerifier('test-device-id', true),
    });
    const result = await handler(createValidCheckInRequest({ collectedAt: undefined }));
    assert.strictEqual(result.statusCode, 400);
    assert.strictEqual(result.body.error, 'invalid_request');
    assert.strictEqual(table.profileUpdates().length, 0);
  }
});
