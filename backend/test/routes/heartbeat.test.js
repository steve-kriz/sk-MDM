/**
 * E2E cucumber-style tests for TASK-044's device heartbeat route
 * (`backend/src/routes/heartbeat.ts`): POST /api/v1/devices/{deviceId}/heartbeat.
 *
 * Mocks all database calls and the CloudWatch heartbeat log; no real
 * connection of either kind is ever opened.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const {
  createHeartbeatHandler,
  HEARTBEAT_PATH,
  MAX_HEARTBEAT_BODY_BYTES,
  isHeartbeatEnabled,
} = await import(`file://${join(__dirname, '../../dist/routes/heartbeat.js')}`);

const { deviceProfile, deviceHeartbeatSettings } = await import(
  `file://${join(__dirname, '../../dist/db/keys.js')}`
);

// ============================================================================
// Fakes
// ============================================================================

class FakeTable {
  constructor() {
    this.items = new Map();
    this.getCalls = [];
    this.updateCalls = [];
  }

  keyStr(key) {
    return JSON.stringify({ pk: key.pk, sk: key.sk });
  }

  async get(key) {
    this.getCalls.push(key);
    return this.items.get(this.keyStr(key));
  }

  async putIfAbsent(item) {
    const keyStr = this.keyStr(item);
    if (this.items.has(keyStr)) {
      return { written: false };
    }
    this.items.set(keyStr, { ...item });
    return { written: true };
  }

  async update(key, fields) {
    this.updateCalls.push({ key, fields });
    const existing = this.items.get(this.keyStr(key)) ?? { ...key };
    let updated = { ...existing };
    if (fields?.ExpressionAttributeValues?.[':lastSeenAt'] !== undefined) {
      updated.lastSeenAt = fields.ExpressionAttributeValues[':lastSeenAt'];
    }
    this.items.set(this.keyStr(key), updated);
    return updated;
  }

  seedItem(item) {
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  getStoredItem(key) {
    return this.items.get(this.keyStr(key));
  }
}

function seedDevice(table, deviceId = 'd1') {
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });
}

function createFakeVerifier(deviceId = 'd1', ok = true, status = 401, error = 'bad_signature') {
  return async () => (ok ? { ok: true, deviceId } : { ok: false, status, body: { error } });
}

function fakeHeartbeatLog({ writeError = null } = {}) {
  const writeCalls = [];
  return {
    writeCalls,
    async write(deviceId, event) {
      writeCalls.push({ deviceId, event });
      if (writeError !== null) {
        throw writeError;
      }
    },
  };
}

function heartbeatRequest({
  deviceId = 'd1',
  body = { collectedAt: '2026-10-11T11:59:58Z', performance: {} },
  rawBody = undefined,
} = {}) {
  return {
    method: 'POST',
    path: `/api/v1/devices/${deviceId}/heartbeat`,
    query: {},
    headers: {},
    params: { deviceId },
    body: rawBody !== undefined ? rawBody : body === null ? null : JSON.stringify(body),
  };
}

const NOW = () => new Date('2026-10-11T12:00:00Z');

// ============================================================================
// Module shape (AC20)
// ============================================================================

test('Scenario: Module exports the path and size constant', () => {
  assert.strictEqual(HEARTBEAT_PATH, '/api/v1/devices/{deviceId}/heartbeat');
  assert.strictEqual(MAX_HEARTBEAT_BODY_BYTES, 16384);
});

test('Unit: isHeartbeatEnabled', () => {
  assert.strictEqual(isHeartbeatEnabled(undefined), false);
  assert.strictEqual(isHeartbeatEnabled(null), false);
  assert.strictEqual(isHeartbeatEnabled({}), false);
  assert.strictEqual(isHeartbeatEnabled({ heartbeatEnabled: 'true', intervalSeconds: 300 }), false);
  assert.strictEqual(isHeartbeatEnabled({ heartbeatEnabled: true, intervalSeconds: 120 }), false);
  assert.strictEqual(isHeartbeatEnabled({ heartbeatEnabled: true, intervalSeconds: 300 }), true);
});

// ============================================================================
// Scenario Outline: Rejected heartbeats read and write nothing (AC20)
// ============================================================================

test('Scenario Outline: Rejected heartbeats read and write nothing', async () => {
  // 413: oversized body, before auth.
  {
    const table = new FakeTable();
    seedDevice(table);
    const heartbeatLog = fakeHeartbeatLog();
    const handler = createHeartbeatHandler({
      table,
      now: NOW,
      heartbeatLog,
      verifyDevice: createFakeVerifier('d1'),
    });
    const req = heartbeatRequest({ rawBody: 'x'.repeat(16385) });
    const result = await handler(req);
    assert.strictEqual(result.statusCode, 413);
    assert.strictEqual(result.body.error, 'payload_too_large');
    assert.strictEqual(table.getCalls.filter((k) => k.sk === 'HEARTBEAT').length, 0);
    assert.strictEqual(heartbeatLog.writeCalls.length, 0);
  }

  // Verifier failure passes through unchanged.
  {
    const table = new FakeTable();
    seedDevice(table);
    const heartbeatLog = fakeHeartbeatLog();
    const handler = createHeartbeatHandler({
      table,
      now: NOW,
      heartbeatLog,
      verifyDevice: createFakeVerifier('d1', false, 401, 'bad_signature'),
    });
    const result = await handler(heartbeatRequest());
    assert.strictEqual(result.statusCode, 401);
    assert.strictEqual(table.getCalls.filter((k) => k.sk === 'HEARTBEAT').length, 0);
    assert.strictEqual(heartbeatLog.writeCalls.length, 0);
  }

  // Signed device differs from the path device.
  {
    const table = new FakeTable();
    seedDevice(table, 'd1');
    seedDevice(table, 'd2');
    const heartbeatLog = fakeHeartbeatLog();
    const handler = createHeartbeatHandler({
      table,
      now: NOW,
      heartbeatLog,
      verifyDevice: createFakeVerifier('d1'), // signed d1, path says d2
    });
    const result = await handler(heartbeatRequest({ deviceId: 'd2' }));
    assert.strictEqual(result.statusCode, 403);
    assert.strictEqual(result.body.error, 'device_mismatch');
    assert.strictEqual(table.getCalls.filter((k) => k.sk === 'HEARTBEAT').length, 0);
    assert.strictEqual(heartbeatLog.writeCalls.length, 0);
  }
});

// ============================================================================
// Scenario Outline: Malformed heartbeat bodies are refused (AC21)
// ============================================================================

test('Scenario Outline: Malformed heartbeat bodies are refused', async () => {
  const cases = [
    { body: { collectedAt: 'yesterday', performance: {} }, fields: ['collectedAt'] },
    { body: { collectedAt: '2026-10-11T11:59:00Z', performance: [] }, fields: ['performance'] },
    { rawBody: 'not json', fields: ['collectedAt', 'performance'] },
  ];

  for (const tc of cases) {
    const table = new FakeTable();
    seedDevice(table);
    const heartbeatLog = fakeHeartbeatLog();
    const handler = createHeartbeatHandler({
      table,
      now: NOW,
      heartbeatLog,
      verifyDevice: createFakeVerifier('d1'),
    });
    const req = tc.rawBody !== undefined ? heartbeatRequest({ rawBody: tc.rawBody }) : heartbeatRequest({ body: tc.body });
    const result = await handler(req);

    assert.strictEqual(result.statusCode, 400);
    assert.strictEqual(result.body.error, 'invalid_request');
    assert.deepStrictEqual(result.body.fields, tc.fields);
    assert.strictEqual(heartbeatLog.writeCalls.length, 0);
  }
});

// ============================================================================
// Scenario Outline: Heartbeat from a device whose heartbeat is off (AC22)
// ============================================================================

test('Scenario Outline: Heartbeat from a device whose heartbeat is off', async () => {
  const cases = [
    { description: 'absent', stored: null },
    { description: 'heartbeatEnabled: false', stored: { heartbeatEnabled: false, intervalSeconds: 300 } },
    { description: 'heartbeatEnabled: "true"', stored: { heartbeatEnabled: 'true', intervalSeconds: 300 } },
    { description: 'interval not an option', stored: { heartbeatEnabled: true, intervalSeconds: 120 } },
  ];

  for (const tc of cases) {
    const table = new FakeTable();
    seedDevice(table);
    if (tc.stored !== null) {
      table.seedItem({ ...deviceHeartbeatSettings('d1'), deviceId: 'd1', ...tc.stored });
    }
    const heartbeatLog = fakeHeartbeatLog();
    const handler = createHeartbeatHandler({
      table,
      now: NOW,
      heartbeatLog,
      verifyDevice: createFakeVerifier('d1'),
    });

    const result = await handler(heartbeatRequest());

    assert.strictEqual(result.statusCode, 200, tc.description);
    assert.deepStrictEqual(result.body, { heartbeatIntervalSeconds: 0 }, tc.description);
    assert.strictEqual(heartbeatLog.writeCalls.length, 0, tc.description);

    const profileUpdate = table.updateCalls.find((u) => u.key.sk === 'PROFILE');
    assert.ok(profileUpdate, `profile update issued for ${tc.description}`);
    assert.strictEqual(profileUpdate.fields.ExpressionAttributeValues[':lastSeenAt'], '2026-10-11T12:00:00Z');
  }
});

// ============================================================================
// Scenario: Heartbeat from an enabled device is written to CloudWatch
// sanitised (AC23)
// ============================================================================

test('Scenario: Heartbeat from an enabled device is written to CloudWatch sanitised', async () => {
  const table = new FakeTable();
  seedDevice(table);
  table.seedItem({ ...deviceHeartbeatSettings('d1'), deviceId: 'd1', heartbeatEnabled: true, intervalSeconds: 300 });
  const heartbeatLog = fakeHeartbeatLog();
  const handler = createHeartbeatHandler({
    table,
    now: NOW,
    heartbeatLog,
    verifyDevice: createFakeVerifier('d1'),
  });

  const result = await handler(
    heartbeatRequest({
      body: {
        collectedAt: '2026-10-11T11:59:58Z',
        performance: { cpuPercent: 150, memoryUsedBytes: 20, memoryTotalBytes: 10 },
      },
    }),
  );

  assert.strictEqual(heartbeatLog.writeCalls.length, 1);
  const { deviceId, event } = heartbeatLog.writeCalls[0];
  assert.strictEqual(deviceId, 'd1');
  assert.strictEqual(event.deviceId, 'd1');
  assert.strictEqual(event.collectedAt, '2026-10-11T11:59:58Z');
  assert.strictEqual(event.receivedAt, '2026-10-11T12:00:00Z');
  assert.strictEqual(event.performance.cpuPercent, null);
  assert.strictEqual(event.performance.memoryUsedBytes, null);
  assert.strictEqual(event.performance.memoryTotalBytes, 10);
  assert.ok(!('warnings' in event), 'no warnings key when none remain');

  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body, { heartbeatIntervalSeconds: 300 });

  const profileUpdate = table.updateCalls.find((u) => u.key.sk === 'PROFILE');
  assert.ok(profileUpdate);
  assert.strictEqual(profileUpdate.fields.ExpressionAttributeValues[':lastSeenAt'], '2026-10-11T12:00:00Z');
});

// ============================================================================
// Scenario Outline: Enabled heartbeat when CloudWatch is unusable (AC24)
// ============================================================================

test('Scenario Outline: Enabled heartbeat when CloudWatch is unusable', async () => {
  // No heartbeatLog configured.
  {
    const table = new FakeTable();
    seedDevice(table);
    table.seedItem({ ...deviceHeartbeatSettings('d1'), deviceId: 'd1', heartbeatEnabled: true, intervalSeconds: 300 });
    const handler = createHeartbeatHandler({ table, now: NOW, verifyDevice: createFakeVerifier('d1') });

    const result = await handler(heartbeatRequest());
    assert.strictEqual(result.statusCode, 503);
    assert.strictEqual(result.body.error, 'heartbeat_not_configured');
    assert.strictEqual(table.updateCalls.filter((u) => u.key.sk === 'PROFILE').length, 0);
  }

  // Write rejects.
  {
    const table = new FakeTable();
    seedDevice(table);
    table.seedItem({ ...deviceHeartbeatSettings('d1'), deviceId: 'd1', heartbeatEnabled: true, intervalSeconds: 300 });
    const heartbeatLog = fakeHeartbeatLog({ writeError: new Error('boom') });
    const handler = createHeartbeatHandler({ table, now: NOW, heartbeatLog, verifyDevice: createFakeVerifier('d1') });

    const result = await handler(heartbeatRequest());
    assert.strictEqual(result.statusCode, 503);
    assert.strictEqual(result.body.error, 'heartbeat_store_unavailable');
    assert.strictEqual(table.updateCalls.filter((u) => u.key.sk === 'PROFILE').length, 0);
  }
});

// ============================================================================
// Scenario: The application router serves the device heartbeat route (AC25)
// ============================================================================

test('Scenario: The application router serves the device heartbeat route', async () => {
  const dist = await import('../../dist/index.js');
  const { router, configureHeartbeatRoute, registerHeartbeatRoute } = dist;
  assert.strictEqual(typeof configureHeartbeatRoute, 'function');
  assert.strictEqual(typeof registerHeartbeatRoute, 'function');

  // Configure the route for real, the way bootstrap() does, so the shared
  // router's handler resolves instead of throwing "not configured".
  configureHeartbeatRoute({ table: new FakeTable(), now: NOW, verifyDevice: createFakeVerifier('d1', false, 401, 'bad_signature') });

  const result = await router.handle({
    method: 'POST',
    path: '/api/v1/devices/d1/heartbeat',
    query: {},
    headers: {},
    params: { deviceId: 'd1' },
    body: null,
  });
  assert.strictEqual(result.statusCode, 401);
  assert.notStrictEqual(result.statusCode, 404);
});

// ============================================================================
// Scenario: The network block is sanitised and stored with the heartbeat
// ============================================================================

const { sanitiseNetwork, MAX_HEARTBEAT_NETWORK_ADAPTERS } = await import(
  `file://${join(__dirname, '../../dist/routes/heartbeat.js')}`
);

const GOOD_ADAPTER = {
  name: 'Ethernet',
  linkSpeedBitsPerSecond: 1000000000,
  receiveBitsPerSecond: 200000000,
  sendBitsPerSecond: 20000000,
  utilizationPercent: 20,
  packetsReceivedPerSecond: 20000,
  packetsSentPerSecond: 5000,
  receiveErrors: 0,
  sendErrors: 405,
  receiveDiscards: 12,
  sendDiscards: 0,
};

async function postNetwork(network) {
  const table = new FakeTable();
  seedDevice(table);
  table.seedItem({ ...deviceHeartbeatSettings('d1'), deviceId: 'd1', heartbeatEnabled: true, intervalSeconds: 300 });
  const heartbeatLog = fakeHeartbeatLog();
  const handler = createHeartbeatHandler({ table, now: NOW, heartbeatLog, verifyDevice: createFakeVerifier('d1') });
  const body = { collectedAt: '2026-10-11T11:59:58Z', performance: {} };
  if (network !== undefined) {
    body.network = network;
  }
  const result = await handler(heartbeatRequest({ body }));
  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(heartbeatLog.writeCalls.length, 1);
  return heartbeatLog.writeCalls[0].event;
}

test('Scenario: A valid network block is stored unchanged', async () => {
  const event = await postNetwork([GOOD_ADAPTER]);
  assert.deepStrictEqual(event.network, [GOOD_ADAPTER]);
});

test('Scenario: A heartbeat without network stores no network key', async () => {
  const event = await postNetwork(undefined);
  assert.ok(!('network' in event));
  const notArray = await postNetwork({ name: 'Ethernet' });
  assert.ok(!('network' in notArray));
});

test('Scenario: Bad network values become null and nameless entries are dropped', async () => {
  const event = await postNetwork([
    {
      ...GOOD_ADAPTER,
      name: '  Wi-Fi  ',
      linkSpeedBitsPerSecond: 0,
      receiveBitsPerSecond: -1,
      sendBitsPerSecond: 1.5,
      utilizationPercent: 101,
      packetsReceivedPerSecond: 'many',
      receiveErrors: null,
    },
    { name: '' },
    'Ethernet',
    { linkSpeedBitsPerSecond: 1 },
  ]);
  assert.deepStrictEqual(event.network, [
    {
      ...GOOD_ADAPTER,
      name: 'Wi-Fi',
      linkSpeedBitsPerSecond: null,
      receiveBitsPerSecond: null,
      sendBitsPerSecond: null,
      utilizationPercent: null,
      packetsReceivedPerSecond: null,
      receiveErrors: null,
    },
  ]);
});

test('Unit: sanitiseNetwork keeps at most MAX_HEARTBEAT_NETWORK_ADAPTERS and fills every key', () => {
  assert.strictEqual(MAX_HEARTBEAT_NETWORK_ADAPTERS, 8);
  const many = Array.from({ length: 12 }, (_, i) => ({ name: `nic${i}` }));
  const kept = sanitiseNetwork(many);
  assert.strictEqual(kept.length, 8);
  assert.deepStrictEqual(Object.keys(kept[0]).sort(), Object.keys(GOOD_ADAPTER).sort());
  assert.ok(Object.entries(kept[0]).every(([key, value]) => key === 'name' || value === null));
  assert.strictEqual(sanitiseNetwork('x'), undefined);
  assert.strictEqual(sanitiseNetwork([{ name: 'x'.repeat(300) }])[0].name.length, 128);
});
