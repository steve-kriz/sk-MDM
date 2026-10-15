/**
 * E2E cucumber-style tests for TASK-044: the check-in response tells the
 * agent the heartbeat interval only when the heartbeat is on
 * (`backend/src/routes/checkin.ts`). Independent of the TASK-040 analytics
 * collection switch -- both can be present in the same response.
 *
 * All database calls are mocked.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { createCheckInHandler, MAX_BODY_BYTES } = await import(`file://${join(__dirname, '../../dist/routes/checkin.js')}`);
const { deviceProfile, deviceHeartbeatSettings, deviceSettings } = await import(
  `file://${join(__dirname, '../../dist/db/keys.js')}`
);

class FakeTable {
  constructor() {
    this.items = new Map();
    this.getRequests = [];
  }

  keyStr(key) {
    return JSON.stringify({ pk: key.pk, sk: key.sk });
  }

  async get(key) {
    this.getRequests.push(key);
    return this.items.get(this.keyStr(key));
  }

  async put(item) {
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  async update(key, fields) {
    const existing = this.items.get(this.keyStr(key)) || {};
    const updated = { ...existing, ...fields };
    this.items.set(this.keyStr(key), updated);
    return updated;
  }

  async query() {
    return { items: [], cursor: null };
  }

  seedItem(item) {
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }
}

function createFakeVerifier(deviceId) {
  return async () => ({ ok: true, deviceId });
}

function createCheckInRequest(deviceId, overrides = {}) {
  const body = {
    collectedAt: '2026-10-11T11:55:00Z',
    inventory: {
      hardware: { manufacturer: 'Dell', model: 'Test', serialNumber: 'SN1', cpu: 'Intel', ramBytes: 1, diskBytes: 1 },
      os: { name: 'Windows', version: '11', build: '1', architecture: 'x86_64' },
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
    ...overrides,
  };
  return {
    method: 'POST',
    path: `/api/v1/devices/${deviceId}/checkin`,
    query: {},
    headers: {},
    params: { deviceId },
    body: JSON.stringify(body),
  };
}

const NOW = () => new Date('2026-10-11T12:00:00Z');

// ============================================================================
// Scenario Outline: Check-in tells the agent the heartbeat interval only
// when on (AC26)
// ============================================================================

test('Scenario Outline: Check-in tells the agent the heartbeat interval only when on', async () => {
  const cases = [
    {
      description: 'heartbeat on, no SETTINGS',
      heartbeat: { heartbeatEnabled: true, intervalSeconds: 300 },
      settings: undefined,
      hasHeartbeat: true,
      heartbeatValue: 300,
      hasAnalyticsEnabled: false,
    },
    {
      description: 'no HEARTBEAT item',
      heartbeat: undefined,
      settings: undefined,
      hasHeartbeat: false,
      hasAnalyticsEnabled: false,
    },
    {
      description: 'heartbeat off',
      heartbeat: { heartbeatEnabled: false, intervalSeconds: 300 },
      settings: undefined,
      hasHeartbeat: false,
      hasAnalyticsEnabled: false,
    },
    {
      description: 'heartbeat on and analytics collection off together',
      heartbeat: { heartbeatEnabled: true, intervalSeconds: 300 },
      settings: { analyticsEnabled: false },
      hasHeartbeat: true,
      heartbeatValue: 300,
      hasAnalyticsEnabled: true,
      analyticsValue: false,
    },
  ];

  for (const tc of cases) {
    const table = new FakeTable();
    const deviceId = 'd1';
    table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });
    if (tc.heartbeat !== undefined) {
      table.seedItem({ ...deviceHeartbeatSettings(deviceId), deviceId, ...tc.heartbeat });
    }
    if (tc.settings !== undefined) {
      table.seedItem({ ...deviceSettings(deviceId), deviceId, ...tc.settings, updatedAt: '2026-10-11T11:00:00Z', updatedBy: 'a@x' });
    }

    const handler = createCheckInHandler({ table, pepper: 'a'.repeat(64), now: NOW, verifyDevice: createFakeVerifier(deviceId) });
    const result = await handler(createCheckInRequest(deviceId));

    assert.strictEqual(result.statusCode, 200, tc.description);
    if (tc.hasHeartbeat) {
      assert.strictEqual(result.body.heartbeatIntervalSeconds, tc.heartbeatValue, tc.description);
    } else {
      assert.strictEqual('heartbeatIntervalSeconds' in result.body, false, tc.description);
    }
    if (tc.hasAnalyticsEnabled) {
      assert.strictEqual(result.body.analyticsEnabled, tc.analyticsValue, tc.description);
    } else {
      assert.strictEqual('analyticsEnabled' in result.body, false, tc.description);
    }
  }
});

// ============================================================================
// Scenario Outline: Rejected check-ins never read the heartbeat setting (AC27)
// ============================================================================

test('Scenario Outline: Rejected check-ins never read the heartbeat setting', async () => {
  const deviceId = 'd1';

  // 413: body larger than MAX_BODY_BYTES.
  {
    const table = new FakeTable();
    table.seedItem({ ...deviceProfile(deviceId), deviceId });
    const handler = createCheckInHandler({ table, pepper: 'a'.repeat(64), now: NOW, verifyDevice: createFakeVerifier(deviceId) });
    const request = createCheckInRequest(deviceId);
    request.body = 'x'.repeat((MAX_BODY_BYTES ?? 262144) + 1);
    const result = await handler(request);
    assert.strictEqual(result.statusCode, 413);
    assert.strictEqual(table.getRequests.filter((k) => k.sk === 'HEARTBEAT').length, 0);
  }

  // 401: verifier failure.
  {
    const table = new FakeTable();
    table.seedItem({ ...deviceProfile(deviceId), deviceId });
    const handler = createCheckInHandler({
      table,
      pepper: 'a'.repeat(64),
      now: NOW,
      verifyDevice: async () => ({ ok: false, status: 401, body: { error: 'bad_signature' } }),
    });
    const result = await handler(createCheckInRequest(deviceId));
    assert.strictEqual(result.statusCode, 401);
    assert.strictEqual(table.getRequests.filter((k) => k.sk === 'HEARTBEAT').length, 0);
  }

  // 403: device mismatch (verifier says d1, path says d2).
  {
    const table = new FakeTable();
    table.seedItem({ ...deviceProfile(deviceId), deviceId });
    table.seedItem({ ...deviceProfile('d2'), deviceId: 'd2' });
    const handler = createCheckInHandler({ table, pepper: 'a'.repeat(64), now: NOW, verifyDevice: createFakeVerifier('d1') });
    const result = await handler(createCheckInRequest('d2'));
    assert.strictEqual(result.statusCode, 403);
    assert.strictEqual(table.getRequests.filter((k) => k.sk === 'HEARTBEAT').length, 0);
  }

  // 400: invalid collectedAt.
  {
    const table = new FakeTable();
    table.seedItem({ ...deviceProfile(deviceId), deviceId });
    const handler = createCheckInHandler({ table, pepper: 'a'.repeat(64), now: NOW, verifyDevice: createFakeVerifier(deviceId) });
    const result = await handler(createCheckInRequest(deviceId, { collectedAt: 'yesterday' }));
    assert.strictEqual(result.statusCode, 400);
    assert.strictEqual(table.getRequests.filter((k) => k.sk === 'HEARTBEAT').length, 0);
  }
});
