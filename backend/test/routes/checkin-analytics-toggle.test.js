/**
 * E2E tests for analytics collection on/off during check-in (TASK-040).
 *
 * Tests verify that disabled devices do not get analytics stored, and that
 * the response includes analyticsEnabled when collection is off.
 * All database calls are mocked.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const {
  createCheckInHandler,
} = await import(`file://${join(__dirname, '../../dist/routes/checkin.js')}`);

const {
  deviceProfile,
  deviceSettings,
  deviceAnalytics,
  deviceBootHistory,
  deviceAppCrash,
  analyticsListIndex,
  appCrashListIndex,
  APP_CRASH_SK_PREFIX,
} = await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);

// ============================================================================
// Mock Table Client
// ============================================================================

class FakeTable {
  constructor() {
    this.items = new Map();
    this.getRequests = [];
    this.putRequests = [];
    this.updateRequests = [];
  }

  keyStr(key) {
    return JSON.stringify({ pk: key.pk, sk: key.sk });
  }

  async get(key) {
    this.getRequests.push(key);
    return this.items.get(this.keyStr(key));
  }

  async put(item) {
    this.putRequests.push(item);
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  async update(key, fields) {
    this.updateRequests.push({ key, fields });
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

  getStoredItem(key) {
    return this.items.get(this.keyStr(key));
  }

  getPutRequests() {
    return this.putRequests;
  }

  getGetRequests() {
    return this.getRequests;
  }
}

function createFakeVerifier(deviceId) {
  return async () => {
    return { ok: true, deviceId };
  };
}

function createCheckInRequest(deviceId, { analytics } = {}) {
  const body = {
    collectedAt: '2026-10-02T07:15:00Z',
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
      osUpdate: { lastCheckedAt: '2026-10-02T10:00:00Z', pendingCount: 0, rebootRequired: false },
      localAdmins: [],
      warnings: [],
    },
  };
  if (analytics !== undefined) {
    body.analytics = analytics;
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

function validAnalytics(overrides = {}) {
  const defaults = {
    boot: {
      lastBootAt: '2026-10-02T06:41:09Z',
      bootDurationSeconds: 38.4,
      uptimeSeconds: 2031,
    },
    performance: {
      cpuPercent: 12.5,
      memoryUsedBytes: 9663676416,
      memoryTotalBytes: 34359738368,
      systemDiskFreeBytes: 210453397504,
      systemDiskTotalBytes: 1023741952000,
    },
    crashes: [],
  };
  return { ...defaults, ...overrides };
}

// ============================================================================
// E2E Test Scenarios
// ============================================================================

test('Scenario Outline: Enabled devices check in exactly as before', async () => {
  const testCases = [
    { settings: undefined, description: 'no SETTINGS item' },
    { settings: { analyticsEnabled: true }, description: 'analyticsEnabled: true' },
    { settings: { analyticsEnabled: 'false' }, description: 'analyticsEnabled: "false" (string)' },
    { settings: { analyticsEnabled: 0 }, description: 'analyticsEnabled: 0' },
  ];

  for (const tc of testCases) {
    const table = new FakeTable();
    const deviceId = 'd1';
    table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });
    if (tc.settings) {
      table.seedItem({
        ...deviceSettings(deviceId),
        deviceId,
        ...tc.settings,
        updatedAt: '2026-10-10T11:00:00Z',
        updatedBy: 'admin@x',
      });
    }

    const handler = createCheckInHandler({
      table,
      pepper: 'a'.repeat(64),
      now: () => new Date('2026-10-02T07:20:00Z'),
      verifyDevice: createFakeVerifier(deviceId),
    });

    const request = createCheckInRequest(deviceId, { analytics: validAnalytics() });
    const result = await handler(request);

    assert.strictEqual(result.statusCode, 200, `Should accept for ${tc.description}`);

    // Response should not have analyticsEnabled key
    assert.strictEqual(result.body.analyticsEnabled, undefined, `No analyticsEnabled in response for ${tc.description}`);

    // Analytics item should be stored
    const stored = table.getStoredItem(deviceAnalytics(deviceId));
    assert.ok(stored, `Should store ANALYTICS for ${tc.description}`);
  }
});

test('Scenario: Disabled device drops analytics and signals the agent', async () => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });
  table.seedItem({
    ...deviceSettings(deviceId),
    deviceId,
    analyticsEnabled: false,
    updatedAt: '2026-10-10T11:00:00Z',
    updatedBy: 'admin@x',
  });

  // Seed pre-existing analytics items
  table.seedItem({
    ...deviceAnalytics(deviceId),
    ...analyticsListIndex(deviceId),
    deviceId,
    receivedAt: '2026-10-02T07:20:00Z',
    boot: { lastBootAt: '2026-10-02T06:00:00Z', bootDurationSeconds: 30, uptimeSeconds: 1000 },
  });

  table.seedItem({
    ...deviceBootHistory(deviceId),
    deviceId,
    boots: [{ bootAt: '2026-10-02T06:00:00Z', bootDurationSeconds: 30 }],
    updatedAt: '2026-10-02T07:20:00Z',
  });

  table.seedItem({
    ...deviceAppCrash(deviceId, '2026-10-02T06:58:12Z', 'abc'),
    ...appCrashListIndex('2026-10-02T06:58:12Z', deviceId),
    deviceId,
    eventId: 'abc',
    appName: 'OUTLOOK.EXE',
    appVersion: '16.0',
    occurredAt: '2026-10-02T06:58:12Z',
    kind: 'crash',
    reportedAt: '2026-10-02T07:20:00Z',
  });

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T07:20:00Z'),
    verifyDevice: createFakeVerifier(deviceId),
  });

  const request = createCheckInRequest(deviceId, { analytics: validAnalytics() });
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);

  // Response must have exactly these keys
  const responseKeys = Object.keys(result.body).sort();
  assert.ok(responseKeys.includes('checkInIntervalSeconds'));
  assert.ok(responseKeys.includes('pendingCommandCount'));
  assert.ok(responseKeys.includes('analyticsEnabled'));
  assert.strictEqual(result.body.analyticsEnabled, false, 'analyticsEnabled must be false');

  // Verify no new ANALYTICS, BOOTHISTORY or APPCRASH items were written
  const putRequests = table.getPutRequests();
  const analyticsWrites = putRequests.filter((item) => item.sk === 'ANALYTICS');
  const bootHistoryWrites = putRequests.filter((item) => item.sk === 'BOOTHISTORY');
  const crashWrites = putRequests.filter((item) => item.sk?.startsWith('APPCRASH#'));

  assert.strictEqual(analyticsWrites.length, 0, 'no ANALYTICS items should be written');
  assert.strictEqual(bootHistoryWrites.length, 0, 'no BOOTHISTORY items should be written');
  assert.strictEqual(crashWrites.length, 0, 'no APPCRASH items should be written');

  // Verify pre-seeded analytics items are unchanged
  assert.ok(table.getStoredItem(deviceAnalytics(deviceId)), 'Pre-seeded ANALYTICS should remain');
  assert.ok(table.getStoredItem(deviceBootHistory(deviceId)), 'Pre-seeded BOOTHISTORY should remain');
});

test('Scenario: Disabled device still records inventory, posture and lastSeenAt', async () => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });
  table.seedItem({
    ...deviceSettings(deviceId),
    deviceId,
    analyticsEnabled: false,
    updatedAt: '2026-10-10T11:00:00Z',
    updatedBy: 'admin@x',
  });

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T07:20:00Z'),
    verifyDevice: createFakeVerifier(deviceId),
  });

  const request = createCheckInRequest(deviceId);
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);

  // Verify INVENTORY and POSTURE items were written
  const putRequests = table.getPutRequests();
  const inventoryWrites = putRequests.filter((item) => item.sk === 'INVENTORY');
  const postureWrites = putRequests.filter((item) => item.sk === 'POSTURE');

  assert.ok(inventoryWrites.length > 0, 'INVENTORY should be written');
  assert.ok(postureWrites.length > 0, 'POSTURE should be written');

  // Verify profile was updated with lastSeenAt
  const updateRequests = table.updateRequests;
  const profileUpdates = updateRequests.filter((req) => req.key.sk === 'PROFILE');
  assert.ok(profileUpdates.length > 0, 'PROFILE should be updated');
});

test('Scenario Outline: Rejected check-ins never read the setting', async () => {
  const testCases = [
    {
      name: 'body larger than MAX_BODY_BYTES',
      setup: (req) => {
        req.body = 'x'.repeat(262145); // > MAX_BODY_BYTES
      },
    },
    {
      name: 'invalid collectedAt date',
      setup: (req) => {
        const body = JSON.parse(req.body);
        body.collectedAt = 'yesterday';
        req.body = JSON.stringify(body);
      },
    },
  ];

  for (const tc of testCases) {
    const table = new FakeTable();
    const deviceId = 'd1';
    table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });
    table.seedItem({
      ...deviceSettings(deviceId),
      deviceId,
      analyticsEnabled: false,
      updatedAt: '2026-10-10T11:00:00Z',
      updatedBy: 'admin@x',
    });

    const handler = createCheckInHandler({
      table,
      pepper: 'a'.repeat(64),
      now: () => new Date('2026-10-02T07:20:00Z'),
      verifyDevice: createFakeVerifier(deviceId),
    });

    let request = createCheckInRequest(deviceId);
    tc.setup(request);
    const result = await handler(request);

    // Should be rejected
    assert.ok(result.statusCode >= 400, `Should reject for ${tc.name}`);

    // Verify no get for deviceSettings was issued
    const getRequests = table.getGetRequests();
    const settingsGets = getRequests.filter((key) => key.sk === 'SETTINGS');
    assert.strictEqual(settingsGets.length, 0, `No get for SETTINGS for ${tc.name}`);
  }
});
