/**
 * E2E and unit tests for TASK-055 AC25/AC26: storing the last scheduled
 * antivirus scan an agent reports on check-in. Mock all database calls --
 * no real DB connections are ever opened; the FakeTable below stands in
 * for the DynamoDB document client.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { createCheckInHandler } = await import(`file://${join(__dirname, '../../dist/routes/checkin.js')}`);

const { deviceProfile, deviceAntivirusScan } = await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);

// ============================================================================
// Mock Table Client
// ============================================================================

class FakeTable {
  constructor() {
    this.items = new Map();
    this.queryResponses = [];
  }

  keyStr(key) {
    return JSON.stringify({ pk: key.pk, sk: key.sk });
  }

  async get(key) {
    return this.items.get(this.keyStr(key));
  }

  async put(item) {
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  async putIfAbsent(item) {
    const keyStr = this.keyStr({ pk: item.pk, sk: item.sk });
    if (this.items.has(keyStr)) {
      return { written: false };
    }
    this.items.set(keyStr, { ...item });
    return { written: true };
  }

  async update(key, fields) {
    const existing = this.items.get(this.keyStr(key)) || {};
    const updated = { ...existing, ...key };
    this.items.set(this.keyStr(key), updated);
    return updated;
  }

  async query(request) {
    if (this.queryResponses.length > 0) {
      return this.queryResponses.shift();
    }
    return { items: [], cursor: null };
  }

  seedItem(item) {
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  getStoredItem(key) {
    return this.items.get(this.keyStr(key));
  }
}

function createFakeVerifier(deviceIdToReturn = 'test-device-id', authOk = true) {
  return async () => {
    if (!authOk) {
      return { ok: false, status: 401, body: { error: 'bad_signature' } };
    }
    return { ok: true, deviceId: deviceIdToReturn };
  };
}

function createCheckInRequest(deviceId, { antivirusScan } = {}) {
  const body = {
    collectedAt: '2026-10-11T01:00:00Z',
    inventory: {
      hardware: {
        manufacturer: 'Dell',
        model: 'Test',
        serialNumber: 'SN123',
        cpu: 'Intel',
        ramBytes: 16000000000,
        diskBytes: 500000000000,
      },
      os: { name: 'Windows', version: '11', build: '22621', architecture: 'x86_64' },
      software: [],
      warnings: [],
    },
    posture: {
      diskEncryption: { enabled: true, method: 'bitlocker' },
      firewall: { enabled: true },
      antivirus: { name: 'Windows Defender', enabled: true, definitionsAgeDays: 1 },
      osUpdate: { lastCheckedAt: '2026-10-11T00:00:00Z', pendingCount: 0, rebootRequired: false },
      localAdmins: [],
      warnings: [],
    },
  };
  if (antivirusScan !== undefined) {
    body.antivirusScan = antivirusScan;
  }
  return {
    method: 'POST',
    path: `/api/v1/devices/${deviceId}/checkin`,
    query: {},
    headers: {
      'x-mdm-device-id': deviceId,
      'x-mdm-timestamp': Math.floor(Date.now() / 1000).toString(),
      'x-mdm-nonce': 'test-nonce-value',
      'x-mdm-signature': 'test-signature-value',
    },
    params: { deviceId },
    body: JSON.stringify(body),
  };
}

function validScan(overrides = {}) {
  return {
    scanType: 'quick',
    result: 'threats_found',
    startedAt: '2026-10-11T01:00:00Z',
    completedAt: '2026-10-11T01:05:00Z',
    threatsFound: 2,
    ...overrides,
  };
}

function makeHandler(table, deviceId, now = '2026-10-11T01:06:00Z') {
  return createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date(now),
    verifyDevice: createFakeVerifier(deviceId, true),
  });
}

// ============================================================================
// AC25: A valid scan is stored
// ============================================================================

test('Scenario: AC25 - A valid scan is stored', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler = makeHandler(table, deviceId, '2026-10-11T01:06:00Z');
  const result = await handler(createCheckInRequest(deviceId, { antivirusScan: validScan() }));

  assert.strictEqual(result.statusCode, 200);

  const stored = table.getStoredItem(deviceAntivirusScan(deviceId));
  assert.ok(stored, 'expected an item at DEVICE#d1 / AVSCAN');
  assert.strictEqual(stored.deviceId, deviceId);
  assert.strictEqual(stored.scanType, 'quick');
  assert.strictEqual(stored.result, 'threats_found');
  assert.strictEqual(stored.startedAt, '2026-10-11T01:00:00Z');
  assert.strictEqual(stored.completedAt, '2026-10-11T01:05:00Z');
  assert.strictEqual(stored.threatsFound, 2);
  assert.strictEqual(stored.reportedAt, '2026-10-11T01:06:00Z');
});

test('Scenario: AC25 - A later valid scan overwrites the earlier one', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const firstHandler = makeHandler(table, deviceId, '2026-10-11T01:06:00Z');
  await firstHandler(createCheckInRequest(deviceId, { antivirusScan: validScan({ result: 'clean', threatsFound: 0 }) }));

  const secondHandler = makeHandler(table, deviceId, '2026-10-12T01:06:00Z');
  await secondHandler(
    createCheckInRequest(deviceId, {
      antivirusScan: validScan({ result: 'threats_found', threatsFound: 5, startedAt: '2026-10-12T01:00:00Z', completedAt: '2026-10-12T01:05:00Z' }),
    }),
  );

  const stored = table.getStoredItem(deviceAntivirusScan(deviceId));
  assert.strictEqual(stored.result, 'threats_found');
  assert.strictEqual(stored.threatsFound, 5);
  assert.strictEqual(stored.reportedAt, '2026-10-12T01:06:00Z');
});

test('Scenario: AC25 - A detail string is cut to 256 characters', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler = makeHandler(table, deviceId);
  const longDetail = 'x'.repeat(300);
  await handler(
    createCheckInRequest(deviceId, {
      antivirusScan: validScan({ result: 'failed', threatsFound: 0, startedAt: null, completedAt: null, detail: longDetail }),
    }),
  );

  const stored = table.getStoredItem(deviceAntivirusScan(deviceId));
  assert.strictEqual(stored.detail.length, 256);
  assert.strictEqual(stored.startedAt, null);
  assert.strictEqual(stored.completedAt, null);
});

test('Scenario: A missing detail is omitted from the stored item', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler = makeHandler(table, deviceId);
  await handler(createCheckInRequest(deviceId, { antivirusScan: validScan({ result: 'clean', threatsFound: 0 }) }));

  const stored = table.getStoredItem(deviceAntivirusScan(deviceId));
  assert.ok(!('detail' in stored), 'detail should be omitted when absent');
});

// ============================================================================
// AC26: An invalid scan is ignored without refusing the check-in
// ============================================================================

test('Scenario Outline: AC26 - An invalid scan is ignored without refusing the check-in', async (t) => {
  const cases = [
    'clean',
    { scanType: 'quick', result: 'bogus', startedAt: null, completedAt: null, threatsFound: 0 },
    { scanType: 'full', result: 'clean', startedAt: null, completedAt: null, threatsFound: 0 },
    { scanType: 'quick', result: 'clean', startedAt: null, completedAt: null, threatsFound: -1 },
    { scanType: 'quick', result: 'clean', startedAt: 'yesterday', completedAt: null, threatsFound: 0 },
    { scanType: 'quick', result: 'clean', startedAt: null, completedAt: null, threatsFound: 1.5 },
    null,
    42,
  ];

  for (const value of cases) {
    const table = new FakeTable();
    const deviceId = 'd1';
    table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

    const handler = makeHandler(table, deviceId);
    const result = await handler(createCheckInRequest(deviceId, { antivirusScan: value }));

    assert.strictEqual(result.statusCode, 200, `expected 200 for ${JSON.stringify(value)}`);
    assert.strictEqual(
      table.getStoredItem(deviceAntivirusScan(deviceId)),
      undefined,
      `no AVSCAN item should be written for ${JSON.stringify(value)}`,
    );
  }
});

test('Scenario: AC26 - An absent scan leaves the stored one unchanged', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  // Given an AVSCAN item exists for the device
  const firstHandler = makeHandler(table, deviceId, '2026-10-11T01:06:00Z');
  await firstHandler(createCheckInRequest(deviceId, { antivirusScan: validScan() }));
  const before = table.getStoredItem(deviceAntivirusScan(deviceId));
  assert.ok(before);

  // When the device checks in without antivirusScan
  const secondHandler = makeHandler(table, deviceId, '2026-10-12T01:06:00Z');
  const result = await secondHandler(createCheckInRequest(deviceId, {}));
  assert.strictEqual(result.statusCode, 200);

  // Then the AVSCAN item is unchanged
  const after = table.getStoredItem(deviceAntivirusScan(deviceId));
  assert.deepStrictEqual(after, before);
});
