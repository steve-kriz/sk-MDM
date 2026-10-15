/**
 * E2E and unit tests for analytics storage during check-in (TASK-034).
 * Tests implement the Gherkin scenarios for snapshot, boot history and crash
 * event ingestion, sanitisation, bounding and storage. Mock all database calls
 * — no real DB connections.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const {
  createCheckInHandler,
  MAX_APP_CRASHES,
  MAX_APP_NAME_LENGTH,
  MAX_APP_VERSION_LENGTH,
  MAX_BOOT_HISTORY,
  APP_CRASH_RETENTION_SECONDS,
  APP_CRASH_FUTURE_SKEW_SECONDS,
  MAX_BOOT_DURATION_SECONDS,
  MAX_UPTIME_SECONDS,
  MAX_ANALYTICS_WARNINGS,
  MAX_ANALYTICS_WARNING_LENGTH,
} = await import(`file://${join(__dirname, '../../dist/routes/checkin.js')}`);

const {
  deviceProfile,
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
    this.queryResponses = [];
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

  async putIfAbsent(item) {
    const keyStr = this.keyStr({ pk: item.pk, sk: item.sk });
    if (this.items.has(keyStr)) {
      return { written: false };
    }
    this.items.set(keyStr, { ...item });
    return { written: true };
  }

  async update(key, fields) {
    this.updateRequests.push({ key, fields });
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

  seedQueryResponses(responses) {
    this.queryResponses = [...responses];
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

  getUpdateRequests() {
    return this.updateRequests;
  }

  getCalls() {
    return {
      get: this.getRequests,
      put: this.putRequests,
      update: this.updateRequests,
    };
  }
}

function createFakeVerifier(deviceIdToReturn = 'test-device-id', authOk = true) {
  return async (req, options) => {
    if (!authOk) {
      return { ok: false, status: 401, body: { error: 'bad_signature' } };
    }
    return { ok: true, deviceId: deviceIdToReturn };
  };
}

function createCheckInRequest(deviceId, { analytics, policyCompliance } = {}) {
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
  if (policyCompliance !== undefined) {
    body.policyCompliance = policyCompliance;
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

function eventIdFor(kind, appName, appVersion, occurredAt) {
  return createHash('sha256')
    .update(`${kind}\n${appName}\n${appVersion ?? ''}\n${occurredAt}`, 'utf8')
    .digest('hex')
    .slice(0, 32);
}

// ============================================================================
// E2E Contract Tests
// ============================================================================

test('Scenario: Bounds are exported constants', async (t) => {
  assert.strictEqual(MAX_APP_CRASHES, 50);
  assert.strictEqual(MAX_APP_NAME_LENGTH, 256);
  assert.strictEqual(MAX_APP_VERSION_LENGTH, 128);
  assert.strictEqual(MAX_BOOT_HISTORY, 30);
  assert.strictEqual(APP_CRASH_RETENTION_SECONDS, 2592000);
  assert.strictEqual(APP_CRASH_FUTURE_SKEW_SECONDS, 86400);
  assert.strictEqual(MAX_BOOT_DURATION_SECONDS, 3600);
  assert.strictEqual(MAX_UPTIME_SECONDS, 315360000);
  assert.strictEqual(MAX_ANALYTICS_WARNINGS, 20);
  assert.strictEqual(MAX_ANALYTICS_WARNING_LENGTH, 512);
  assert.strictEqual(APP_CRASH_SK_PREFIX, 'APPCRASH#');
});

// ============================================================================
// E2E Backward Compatibility Tests
// ============================================================================

test('Scenario: Older agent check-in without analytics is unchanged', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  // Seed pre-existing analytics items
  const existingAnalytics = {
    ...deviceAnalytics(deviceId),
    ...analyticsListIndex(deviceId),
    deviceId,
    collectedAt: '2026-10-02T07:15:00Z',
    receivedAt: '2026-10-02T07:20:00Z',
    boot: { lastBootAt: '2026-10-02T06:00:00Z', bootDurationSeconds: 30, uptimeSeconds: 1000 },
    performance: { cpuPercent: 10, memoryUsedBytes: 1000, memoryTotalBytes: 2000, systemDiskFreeBytes: 100, systemDiskTotalBytes: 200 },
  };
  table.seedItem(existingAnalytics);

  const existingBootHistory = {
    ...deviceBootHistory(deviceId),
    deviceId,
    boots: [{ bootAt: '2026-10-02T06:00:00Z', bootDurationSeconds: 30 }],
    updatedAt: '2026-10-02T07:20:00Z',
  };
  table.seedItem(existingBootHistory);

  const existingCrash = {
    ...deviceAppCrash(deviceId, '2026-10-02T06:58:12Z', 'abc'),
    ...appCrashListIndex('2026-10-02T06:58:12Z', deviceId),
    deviceId,
    eventId: 'abc',
    appName: 'OUTLOOK.EXE',
    appVersion: '16.0',
    occurredAt: '2026-10-02T06:58:12Z',
    kind: 'crash',
    reportedAt: '2026-10-02T07:20:00Z',
    ttl: Math.floor(Date.parse('2026-10-02T06:58:12Z') / 1000) + APP_CRASH_RETENTION_SECONDS,
  };
  table.seedItem(existingCrash);

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T07:20:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const request = createCheckInRequest(deviceId);
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);

  // Check response body has expected keys
  assert.deepStrictEqual(
    Object.keys(result.body).sort(),
    ['checkInIntervalSeconds', 'pendingCommandCount'].sort(),
  );

  // Verify no new ANALYTICS, BOOTHISTORY or APPCRASH items were written
  const putRequests = table.getPutRequests();
  const analyticsWrites = putRequests.filter((item) => item.sk === 'ANALYTICS');
  const bootHistoryWrites = putRequests.filter((item) => item.sk === 'BOOTHISTORY');
  const crashWrites = putRequests.filter((item) => item.sk.startsWith('APPCRASH#'));

  assert.strictEqual(analyticsWrites.length, 0, 'no ANALYTICS items should be written');
  assert.strictEqual(bootHistoryWrites.length, 0, 'no BOOTHISTORY items should be written');
  assert.strictEqual(crashWrites.length, 0, 'no APPCRASH items should be written');

  // Verify existing items are unchanged
  assert.deepStrictEqual(table.getStoredItem(deviceAnalytics(deviceId)), existingAnalytics);
  assert.deepStrictEqual(table.getStoredItem(deviceBootHistory(deviceId)), existingBootHistory);
  assert.deepStrictEqual(table.getStoredItem(deviceAppCrash(deviceId, '2026-10-02T06:58:12Z', 'abc')), existingCrash);
});

test('Scenario Outline: Non-object analytics is ignored', async (t) => {
  const testCases = [
    { value: null, description: 'null' },
    { value: [], description: '[]' },
    { value: 'x', description: '"x"' },
  ];

  for (const tc of testCases) {
    await t.test(`with analytics set to ${tc.description}`, async (tt) => {
      const table = new FakeTable();
      const deviceId = 'd1';
      table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

      const handler = createCheckInHandler({
        table,
        pepper: 'a'.repeat(64),
        now: () => new Date('2026-10-02T07:20:00Z'),
        verifyDevice: createFakeVerifier(deviceId, true),
      });

      const request = createCheckInRequest(deviceId, { analytics: tc.value });
      const result = await handler(request);

      assert.strictEqual(result.statusCode, 200);
      assert.strictEqual(
        table.getStoredItem(deviceAnalytics(deviceId)),
        undefined,
        `no ANALYTICS item for analytics: ${tc.description}`,
      );
      assert.strictEqual(
        table.getStoredItem(deviceBootHistory(deviceId)),
        undefined,
        `no BOOTHISTORY item for analytics: ${tc.description}`,
      );

      // Check no APPCRASH items exist
      const crashItems = [...table.items.keys()].filter((key) => key.includes('APPCRASH#'));
      assert.strictEqual(crashItems.length, 0, `no APPCRASH items for analytics: ${tc.description}`);
    });
  }
});

test('Scenario Outline: Rejected check-ins write no analytics', async (t) => {
  const testCases = [
    {
      name: 'body larger than MAX_BODY_BYTES',
      setup: (req) => {
        req.body = 'x'.repeat(262145); // > MAX_BODY_BYTES
      },
      expectedStatus: 413,
    },
    {
      name: 'verifier fails authentication',
      setup: (req) => {
        // Use failed verifier
      },
      verifier: createFakeVerifier('d1', false),
      expectedStatus: 401,
    },
    {
      name: 'device_mismatch (path device != signed device)',
      setup: (req) => {
        req.params.deviceId = 'dev-2';
        req.path = '/api/v1/devices/dev-2/checkin';
      },
      expectedStatus: 403,
    },
    {
      name: 'invalid request body (bad collectedAt)',
      setup: (req) => {
        const body = JSON.parse(req.body);
        body.collectedAt = 'yesterday';
        req.body = JSON.stringify(body);
      },
      expectedStatus: 400,
    },
  ];

  for (const tc of testCases) {
    await t.test(tc.name, async (tt) => {
      const table = new FakeTable();
      const deviceId = 'd1';
      table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

      const handler = createCheckInHandler({
        table,
        pepper: 'a'.repeat(64),
        now: () => new Date('2026-10-02T07:20:00Z'),
        verifyDevice: tc.verifier || createFakeVerifier(deviceId, true),
      });

      const request = createCheckInRequest(deviceId, { analytics: validAnalytics() });
      if (tc.setup) {
        tc.setup(request);
      }

      const result = await handler(request);

      assert.strictEqual(result.statusCode, tc.expectedStatus);
      assert.strictEqual(
        table.getStoredItem(deviceAnalytics(deviceId)),
        undefined,
        `no ANALYTICS item for ${tc.name}`,
      );
      assert.strictEqual(
        table.getStoredItem(deviceBootHistory(deviceId)),
        undefined,
        `no BOOTHISTORY item for ${tc.name}`,
      );

      const crashItems = [...table.items.keys()].filter((key) => key.includes('APPCRASH#'));
      assert.strictEqual(crashItems.length, 0, `no APPCRASH items for ${tc.name}`);
    });
  }
});

test('Scenario: Malformed analytics never rejects the heartbeat', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T07:20:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const malformedAnalytics = {
    boot: 5, // should be object
    performance: { cpuPercent: 'high' }, // should be number
    crashes: 'none', // should be array
    warnings: 7, // should be array
  };

  const request = createCheckInRequest(deviceId, { analytics: malformedAnalytics });
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(
    Object.keys(result.body).sort(),
    ['checkInIntervalSeconds', 'pendingCommandCount'].sort(),
  );
});

// ============================================================================
// E2E Snapshot Tests
// ============================================================================

test('Scenario: Snapshot is stored from a full analytics block', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T07:20:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const analytics = validAnalytics({
    warnings: ['boot duration unavailable'],
  });

  const request = createCheckInRequest(deviceId, { analytics });
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);

  const stored = table.getStoredItem(deviceAnalytics(deviceId));
  assert.ok(stored, 'analytics snapshot should be stored');
  assert.strictEqual(stored.gsi1pk, 'ANALYTICS');
  assert.strictEqual(stored.gsi1sk, deviceId);
  assert.strictEqual(stored.deviceId, deviceId);
  assert.strictEqual(stored.collectedAt, '2026-10-02T07:15:00Z');
  assert.strictEqual(stored.receivedAt, '2026-10-02T07:20:00Z');
  assert.deepStrictEqual(stored.boot, analytics.boot);
  assert.deepStrictEqual(stored.performance, analytics.performance);
  assert.deepStrictEqual(stored.warnings, analytics.warnings);
});

test('Scenario: A later check-in overwrites the snapshot', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler1 = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T07:20:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const analytics1 = validAnalytics({
    performance: { ...validAnalytics().performance, cpuPercent: 10 },
  });
  const request1 = createCheckInRequest(deviceId, { analytics: analytics1 });
  await handler1(request1);

  const stored1 = table.getStoredItem(deviceAnalytics(deviceId));
  assert.strictEqual(stored1.performance.cpuPercent, 10);

  const handler2 = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T07:21:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const analytics2 = validAnalytics({
    performance: { ...validAnalytics().performance, cpuPercent: 55.5 },
  });
  const request2 = createCheckInRequest(deviceId, { analytics: analytics2 });
  await handler2(request2);

  const stored2 = table.getStoredItem(deviceAnalytics(deviceId));
  assert.strictEqual(stored2.performance.cpuPercent, 55.5);
  assert.strictEqual(stored2.receivedAt, '2026-10-02T07:21:00Z');
});

test('Scenario Outline: Invalid boot and performance scalars are stored null', async (t) => {
  const testCases = [
    { field: 'boot.lastBootAt', value: '02/10/2026 06:41', expectedNull: 'lastBootAt' },
    { field: 'boot.bootDurationSeconds', value: 0, expectedNull: 'bootDurationSeconds' },
    { field: 'boot.bootDurationSeconds', value: 3600.5, expectedNull: 'bootDurationSeconds' },
    { field: 'boot.bootDurationSeconds', value: '38', expectedNull: 'bootDurationSeconds' },
    { field: 'boot.uptimeSeconds', value: -1, expectedNull: 'uptimeSeconds' },
    { field: 'boot.uptimeSeconds', value: 12.5, expectedNull: 'uptimeSeconds' },
    { field: 'boot.uptimeSeconds', value: 315360001, expectedNull: 'uptimeSeconds' },
    { field: 'performance.cpuPercent', value: 100.1, expectedNull: 'cpuPercent' },
    { field: 'performance.cpuPercent', value: -0.5, expectedNull: 'cpuPercent' },
  ];

  for (const tc of testCases) {
    await t.test(`${tc.field} = ${JSON.stringify(tc.value)}`, async (tt) => {
      const table = new FakeTable();
      const deviceId = 'd1';
      table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

      const handler = createCheckInHandler({
        table,
        pepper: 'a'.repeat(64),
        now: () => new Date('2026-10-02T07:20:00Z'),
        verifyDevice: createFakeVerifier(deviceId, true),
      });

      const analytics = validAnalytics();
      const parts = tc.field.split('.');
      if (parts[0] === 'boot') {
        analytics.boot[parts[1]] = tc.value;
      } else {
        analytics.performance[parts[1]] = tc.value;
      }

      const request = createCheckInRequest(deviceId, { analytics });
      await handler(request);

      const stored = table.getStoredItem(deviceAnalytics(deviceId));
      if (tc.field.startsWith('boot')) {
        assert.strictEqual(stored.boot[tc.expectedNull], null, `${tc.field} should be null`);
      } else {
        assert.strictEqual(stored.performance[tc.expectedNull], null, `${tc.field} should be null`);
      }
    });
  }
});

test('Scenario: A non-object sub-block stores every key as null', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T07:20:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const analytics = validAnalytics({
    boot: null,
    performance: 'n/a',
  });

  const request = createCheckInRequest(deviceId, { analytics });
  await handler(request);

  const stored = table.getStoredItem(deviceAnalytics(deviceId));
  assert.deepStrictEqual(stored.boot, { lastBootAt: null, bootDurationSeconds: null, uptimeSeconds: null });
  assert.deepStrictEqual(stored.performance, {
    cpuPercent: null,
    memoryUsedBytes: null,
    memoryTotalBytes: null,
    systemDiskFreeBytes: null,
    systemDiskTotalBytes: null,
  });
});

test('Scenario Outline: Memory and disk pairs are sanitised together', async (t) => {
  const testCases = [
    {
      usedField: 'memoryUsedBytes',
      used: 100,
      totalField: 'memoryTotalBytes',
      total: 0,
      storedUsed: null,
      storedTotal: null,
    },
    {
      usedField: 'memoryUsedBytes',
      used: 100,
      totalField: 'memoryTotalBytes',
      total: '1000',
      storedUsed: null,
      storedTotal: null,
    },
    {
      usedField: 'memoryUsedBytes',
      used: 2000,
      totalField: 'memoryTotalBytes',
      total: 1000,
      storedUsed: null,
      storedTotal: 1000,
    },
    {
      usedField: 'memoryUsedBytes',
      used: 1.5,
      totalField: 'memoryTotalBytes',
      total: 1000,
      storedUsed: null,
      storedTotal: 1000,
    },
    {
      usedField: 'systemDiskFreeBytes',
      used: 5000,
      totalField: 'systemDiskTotalBytes',
      total: -1,
      storedUsed: null,
      storedTotal: null,
    },
    {
      usedField: 'systemDiskFreeBytes',
      used: 9000,
      totalField: 'systemDiskTotalBytes',
      total: 8000,
      storedUsed: null,
      storedTotal: 8000,
    },
    {
      usedField: 'systemDiskFreeBytes',
      used: 0,
      totalField: 'systemDiskTotalBytes',
      total: 8000,
      storedUsed: 0,
      storedTotal: 8000,
    },
  ];

  for (const tc of testCases) {
    await t.test(
      `${tc.usedField} ${tc.used}, ${tc.totalField} ${JSON.stringify(tc.total)}`,
      async (tt) => {
        const table = new FakeTable();
        const deviceId = 'd1';
        table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

        const handler = createCheckInHandler({
          table,
          pepper: 'a'.repeat(64),
          now: () => new Date('2026-10-02T07:20:00Z'),
          verifyDevice: createFakeVerifier(deviceId, true),
        });

        const analytics = validAnalytics();
        if (tc.usedField === 'memoryUsedBytes') {
          analytics.performance.memoryUsedBytes = tc.used;
          analytics.performance.memoryTotalBytes = tc.total;
        } else {
          analytics.performance.systemDiskFreeBytes = tc.used;
          analytics.performance.systemDiskTotalBytes = tc.total;
        }

        const request = createCheckInRequest(deviceId, { analytics });
        await handler(request);

        const stored = table.getStoredItem(deviceAnalytics(deviceId));
        assert.strictEqual(
          stored.performance[tc.usedField],
          tc.storedUsed,
          `stored ${tc.usedField} should be ${tc.storedUsed}`,
        );
        assert.strictEqual(
          stored.performance[tc.totalField],
          tc.storedTotal,
          `stored ${tc.totalField} should be ${tc.storedTotal}`,
        );
      },
    );
  }
});

test('Scenario: Fractional-second timestamps are normalised', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T07:20:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const analytics = validAnalytics({
    boot: { ...validAnalytics().boot, lastBootAt: '2026-10-02T06:41:09.734Z' },
    crashes: [
      {
        appName: 'OUTLOOK.EXE',
        appVersion: '16.0',
        occurredAt: '2026-10-02T06:58:12.250Z',
        kind: 'crash',
      },
    ],
  });

  const request = createCheckInRequest(deviceId, { analytics });
  await handler(request);

  const stored = table.getStoredItem(deviceAnalytics(deviceId));
  assert.strictEqual(stored.boot.lastBootAt, '2026-10-02T06:41:09Z');

  const crashItems = [...table.items.keys()].filter((key) => key.includes('APPCRASH#'));
  assert.strictEqual(crashItems.length, 1);
  const crashKey = crashItems[0];
  const storedCrash = table.items.get(crashKey);
  assert.strictEqual(storedCrash.occurredAt, '2026-10-02T06:58:12Z');
});

test('Scenario: Analytics warnings are filtered and bounded', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T07:20:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const warnings = [];
  // 25 strings, each 600 chars (will be truncated to 512)
  for (let i = 0; i < 25; i++) {
    warnings.push('x'.repeat(600));
  }
  warnings.push(3); // non-string, should be filtered

  const analytics = validAnalytics({ warnings });

  const request = createCheckInRequest(deviceId, { analytics });
  await handler(request);

  const stored = table.getStoredItem(deviceAnalytics(deviceId));
  assert.ok(stored.warnings, 'warnings should be present');
  assert.strictEqual(stored.warnings.length, 20, 'should keep first 20 warnings');
  for (const warning of stored.warnings) {
    assert.strictEqual(warning.length, 512, 'each warning truncated to 512 chars');
  }
});

test('Scenario: Analytics warnings absent when none remain', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T07:20:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const analytics = validAnalytics({ warnings: [1, null] }); // only non-strings

  const request = createCheckInRequest(deviceId, { analytics });
  await handler(request);

  const stored = table.getStoredItem(deviceAnalytics(deviceId));
  assert.strictEqual(stored.warnings, undefined, 'warnings should be absent when none remain');
});

// ============================================================================
// E2E Boot History Tests
// ============================================================================

test('Scenario: First boot creates the history', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T07:20:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const analytics = validAnalytics({
    boot: {
      lastBootAt: '2026-10-02T06:41:09Z',
      bootDurationSeconds: 38.4,
      uptimeSeconds: 2031,
    },
  });

  const request = createCheckInRequest(deviceId, { analytics });
  await handler(request);

  const stored = table.getStoredItem(deviceBootHistory(deviceId));
  assert.ok(stored, 'boot history should be stored');
  assert.strictEqual(stored.deviceId, deviceId);
  assert.deepStrictEqual(stored.boots, [{ bootAt: '2026-10-02T06:41:09Z', bootDurationSeconds: 38.4 }]);
  assert.strictEqual(stored.updatedAt, '2026-10-02T07:20:00Z');
});

test('Scenario: History stays newest-first and capped at 30', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  // Seed boot history with 30 boots on consecutive days ending 2026-10-01
  const boots = [];
  for (let i = 0; i < 30; i++) {
    const date = new Date('2026-10-01T06:00:00Z');
    date.setUTCDate(date.getUTCDate() - i);
    boots.push({
      bootAt: date.toISOString().split('T')[0] + 'T06:00:00Z',
      bootDurationSeconds: 30,
    });
  }
  table.seedItem({
    ...deviceBootHistory(deviceId),
    deviceId,
    boots,
    updatedAt: '2026-10-02T07:15:00Z',
  });

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T07:20:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const analytics = validAnalytics({
    boot: { lastBootAt: '2026-10-02T06:41:09Z', bootDurationSeconds: 38.4, uptimeSeconds: 2031 },
  });

  const request = createCheckInRequest(deviceId, { analytics });
  await handler(request);

  const stored = table.getStoredItem(deviceBootHistory(deviceId));
  assert.strictEqual(stored.boots.length, 30, 'history capped at 30');
  assert.strictEqual(stored.boots[0].bootAt, '2026-10-02T06:41:09Z', 'newest boot first');
  const oldestInStored = boots[29].bootAt;
  const hasOldest = stored.boots.some((b) => b.bootAt === oldestInStored);
  assert.strictEqual(hasOldest, false, 'oldest boot was dropped');
});

test('Scenario: Re-reported boot is not duplicated and a null duration does not overwrite', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  table.seedItem({
    ...deviceBootHistory(deviceId),
    deviceId,
    boots: [{ bootAt: '2026-10-02T06:41:09Z', bootDurationSeconds: null }],
    updatedAt: '2026-10-02T07:15:00Z',
  });

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T07:20:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  // First check-in: update duration
  const analytics1 = validAnalytics({
    boot: { lastBootAt: '2026-10-02T06:41:09Z', bootDurationSeconds: 41, uptimeSeconds: 2031 },
  });
  const request1 = createCheckInRequest(deviceId, { analytics: analytics1 });
  await handler(request1);

  let stored = table.getStoredItem(deviceBootHistory(deviceId));
  assert.strictEqual(stored.boots.length, 1);
  assert.strictEqual(stored.boots[0].bootAt, '2026-10-02T06:41:09Z');
  assert.strictEqual(stored.boots[0].bootDurationSeconds, 41);

  // Second check-in: re-report boot with null duration
  const analytics2 = validAnalytics({
    boot: { lastBootAt: '2026-10-02T06:41:09Z', bootDurationSeconds: null, uptimeSeconds: 2031 },
  });
  const request2 = createCheckInRequest(deviceId, { analytics: analytics2 });
  await handler(request2);

  stored = table.getStoredItem(deviceBootHistory(deviceId));
  assert.strictEqual(stored.boots.length, 1, 'still one entry');
  assert.strictEqual(stored.boots[0].bootDurationSeconds, 41, 'null duration did not overwrite');
});

test('Scenario: No boot history activity without a valid boot time', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T07:20:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const analytics = validAnalytics({
    boot: { lastBootAt: null, bootDurationSeconds: 38.4, uptimeSeconds: 2031 },
  });

  const request = createCheckInRequest(deviceId, { analytics });
  await handler(request);

  const getRequests = table.getGetRequests();
  const bootHistoryGets = getRequests.filter((key) => key.sk === 'BOOTHISTORY');
  assert.strictEqual(bootHistoryGets.length, 0, 'no get for boot history');

  const putRequests = table.getPutRequests();
  const bootHistoryPuts = putRequests.filter((item) => item.sk === 'BOOTHISTORY');
  assert.strictEqual(bootHistoryPuts.length, 0, 'no put for boot history');
});

// ============================================================================
// E2E Crash Event Tests
// ============================================================================

test('Scenario: A kept crash is stored with index, eventId and ttl', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T07:20:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const crash = {
    appName: 'OUTLOOK.EXE',
    appVersion: '16.0.17928.20156',
    occurredAt: '2026-10-02T06:58:12Z',
    kind: 'crash',
  };

  const analytics = validAnalytics({ crashes: [crash] });
  const request = createCheckInRequest(deviceId, { analytics });
  await handler(request);

  const expectedEventId = eventIdFor('crash', 'OUTLOOK.EXE', '16.0.17928.20156', '2026-10-02T06:58:12Z');
  const stored = table.getStoredItem(deviceAppCrash(deviceId, '2026-10-02T06:58:12Z', expectedEventId));

  assert.ok(stored, 'crash item should be stored');
  assert.strictEqual(stored.gsi1pk, 'APPCRASH');
  assert.strictEqual(stored.gsi1sk, '2026-10-02T06:58:12Z#d1');
  assert.strictEqual(stored.deviceId, deviceId);
  assert.strictEqual(stored.eventId, expectedEventId);
  assert.strictEqual(stored.appName, 'OUTLOOK.EXE');
  assert.strictEqual(stored.appVersion, '16.0.17928.20156');
  assert.strictEqual(stored.occurredAt, '2026-10-02T06:58:12Z');
  assert.strictEqual(stored.kind, 'crash');
  assert.strictEqual(stored.reportedAt, '2026-10-02T07:20:00Z');
  assert.strictEqual(stored.ttl, Math.floor(Date.parse('2026-10-02T06:58:12Z') / 1000) + APP_CRASH_RETENTION_SECONDS);
});

test('Scenario: The same crash posted twice is stored once', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const crash = {
    appName: 'OUTLOOK.EXE',
    appVersion: '16.0.17928.20156',
    occurredAt: '2026-10-02T06:58:12Z',
    kind: 'crash',
  };

  // First check-in: single crash posted twice
  const handler1 = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T07:20:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const analytics1 = validAnalytics({ crashes: [crash, crash] });
  const request1 = createCheckInRequest(deviceId, { analytics: analytics1 });
  await handler1(request1);

  const crashItems1 = [...table.items.keys()].filter((key) => key.includes('APPCRASH#'));
  assert.strictEqual(crashItems1.length, 1, 'only one item after first check-in');

  // Second check-in: same crash reported again
  const handler2 = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T07:21:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const analytics2 = validAnalytics({ crashes: [crash] });
  const request2 = createCheckInRequest(deviceId, { analytics: analytics2 });
  await handler2(request2);

  const crashItems2 = [...table.items.keys()].filter((key) => key.includes('APPCRASH#'));
  assert.strictEqual(crashItems2.length, 1, 'still only one item after second check-in');
});

test('Scenario: Only the first 50 crash entries are considered', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T07:20:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const crashes = [];
  for (let i = 1; i <= 55; i++) {
    crashes.push({
      appName: `app${i}`,
      appVersion: null,
      occurredAt: '2026-10-02T06:58:12Z',
      kind: 'crash',
    });
  }

  const analytics = validAnalytics({ crashes });
  const request = createCheckInRequest(deviceId, { analytics });
  await handler(request);

  const crashItems = [...table.items.keys()].filter((key) => key.includes('APPCRASH#'));
  assert.strictEqual(crashItems.length, 50, 'only 50 crash items stored');

  // Verify entries 1-50 exist, 51-55 do not
  for (let i = 1; i <= 50; i++) {
    const stored = [...table.items.values()].find(
      (item) => item.appName === `app${i}` && item.occurredAt === '2026-10-02T06:58:12Z',
    );
    assert.ok(stored, `crash app${i} should be stored`);
  }
  for (let i = 51; i <= 55; i++) {
    const stored = [...table.items.values()].find(
      (item) => item.appName === `app${i}` && item.occurredAt === '2026-10-02T06:58:12Z',
    );
    assert.strictEqual(stored, undefined, `crash app${i} should not be stored`);
  }
});

test('Scenario Outline: Invalid crash entries are dropped while siblings are kept', async (t) => {
  const testCases = [
    { bad: 'OUTLOOK.EXE', description: 'not an object' },
    {
      bad: { appName: '   ', appVersion: null, occurredAt: '2026-10-02T06:58:12Z', kind: 'crash' },
      description: 'empty appName (whitespace-only)',
    },
    {
      bad: { appName: 7, appVersion: null, occurredAt: '2026-10-02T06:58:12Z', kind: 'crash' },
      description: 'appName is not a string',
    },
    {
      bad: { appName: 'A', appVersion: null, occurredAt: '2026-10-02T06:58:12Z', kind: 'freeze' },
      description: 'kind is not crash or hang',
    },
    {
      bad: { appName: 'A', appVersion: null, occurredAt: '2026-10-02 06:58', kind: 'crash' },
      description: 'occurredAt is not ISO-UTC',
    },
    {
      bad: { appName: 'A', appVersion: null, occurredAt: '2026-08-01T00:00:00Z', kind: 'crash' },
      description: 'occurredAt is more than 30 days ago',
    },
    {
      bad: { appName: 'A', appVersion: null, occurredAt: '2026-10-04T00:00:00Z', kind: 'hang' },
      description: 'occurredAt is more than 1 day in the future',
    },
  ];

  for (const tc of testCases) {
    await t.test(tc.description, async (tt) => {
      const table = new FakeTable();
      const deviceId = 'd1';
      table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

      const handler = createCheckInHandler({
        table,
        pepper: 'a'.repeat(64),
        now: () => new Date('2026-10-02T07:20:00Z'),
        verifyDevice: createFakeVerifier(deviceId, true),
      });

      const validCrash = {
        appName: 'VALID.EXE',
        appVersion: null,
        occurredAt: '2026-10-02T06:58:12Z',
        kind: 'crash',
      };

      const analytics = validAnalytics({ crashes: [tc.bad, validCrash] });
      const request = createCheckInRequest(deviceId, { analytics });
      await handler(request);

      // Bad entry should not be stored
      if (typeof tc.bad === 'object' && tc.bad.appName && typeof tc.bad.appName === 'string') {
        const badStored = [...table.items.values()].find((item) => item.appName === tc.bad.appName);
        assert.strictEqual(badStored, undefined, `bad entry should not be stored: ${tc.description}`);
      }

      // Valid entry should be stored
      const validStored = [...table.items.values()].find((item) => item.appName === 'VALID.EXE');
      assert.ok(validStored, `valid entry should be stored: ${tc.description}`);
    });
  }
});

test('Scenario Outline: Crash names and versions are trimmed and bounded', async (t) => {
  const testCases = [
    {
      name: '  Teams  ',
      version: '  24.1  ',
      storedName: 'Teams',
      storedVersion: '24.1',
      description: 'trimmed',
    },
    {
      name: 'x'.repeat(300),
      version: '9'.repeat(200),
      storedName: 'x'.repeat(256),
      storedVersion: '9'.repeat(128),
      description: 'truncated',
    },
    {
      name: 'Teams',
      version: '',
      storedName: 'Teams',
      storedVersion: null,
      description: 'empty version becomes null',
    },
    {
      name: 'Teams',
      version: 24,
      storedName: 'Teams',
      storedVersion: null,
      description: 'non-string version becomes null',
    },
  ];

  for (const tc of testCases) {
    await t.test(`${tc.description}: name="${tc.name.substring(0, 20)}...", version="${tc.version}"`, async (tt) => {
      const table = new FakeTable();
      const deviceId = 'd1';
      table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

      const handler = createCheckInHandler({
        table,
        pepper: 'a'.repeat(64),
        now: () => new Date('2026-10-02T07:20:00Z'),
        verifyDevice: createFakeVerifier(deviceId, true),
      });

      const crash = {
        appName: tc.name,
        appVersion: tc.version,
        occurredAt: '2026-10-02T06:58:12Z',
        kind: 'crash',
      };

      const analytics = validAnalytics({ crashes: [crash] });
      const request = createCheckInRequest(deviceId, { analytics });
      await handler(request);

      const crashItems = [...table.items.values()].filter((item) => item.kind === 'crash');
      assert.strictEqual(crashItems.length, 1);
      const stored = crashItems[0];
      assert.strictEqual(stored.appName, tc.storedName);
      assert.strictEqual(stored.appVersion, tc.storedVersion);
    });
  }
});

test('Scenario Outline: A non-array crashes value stores no crash items but still stores the snapshot', async (t) => {
  const testCases = [
    { value: null, description: 'null' },
    { value: {}, description: 'object' },
    { value: 'none', description: 'string' },
    { value: undefined, description: 'absent (via deletion)' },
  ];

  for (const tc of testCases) {
    await t.test(`crashes = ${tc.description}`, async (tt) => {
      const table = new FakeTable();
      const deviceId = 'd1';
      table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

      const handler = createCheckInHandler({
        table,
        pepper: 'a'.repeat(64),
        now: () => new Date('2026-10-02T07:20:00Z'),
        verifyDevice: createFakeVerifier(deviceId, true),
      });

      const analyticsObj = validAnalytics();
      if (tc.value === undefined) {
        delete analyticsObj.crashes;
      } else {
        analyticsObj.crashes = tc.value;
      }

      const request = createCheckInRequest(deviceId, { analytics: analyticsObj });
      await handler(request);

      // No crash items
      const crashItems = [...table.items.keys()].filter((key) => key.includes('APPCRASH#'));
      assert.strictEqual(crashItems.length, 0, `no crash items for crashes=${tc.description}`);

      // Snapshot still exists
      const snapshot = table.getStoredItem(deviceAnalytics(deviceId));
      assert.ok(snapshot, `snapshot exists for crashes=${tc.description}`);
    });
  }
});

test('Scenario: Analytics ingest never touches complianceState', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T07:20:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const analytics = validAnalytics({
    warnings: ['boot duration unavailable'],
  });

  const request = createCheckInRequest(deviceId, { analytics, policyCompliance: undefined });
  await handler(request);

  // Check that no update call sets complianceState
  const updateRequests = table.getUpdateRequests();
  for (const req of updateRequests) {
    if (req.fields) {
      // If there's an update expression, it should not set complianceState
      const expressionStr = JSON.stringify(req.fields);
      assert.ok(!expressionStr.includes('complianceState'), 'update should not set complianceState');
    }
  }
});

// ============================================================================
// Export constants for verification
// ============================================================================

test('Unit: All required constants are exported', async (t) => {
  assert.strictEqual(typeof MAX_APP_CRASHES, 'number');
  assert.strictEqual(typeof MAX_APP_NAME_LENGTH, 'number');
  assert.strictEqual(typeof MAX_APP_VERSION_LENGTH, 'number');
  assert.strictEqual(typeof MAX_BOOT_HISTORY, 'number');
  assert.strictEqual(typeof APP_CRASH_RETENTION_SECONDS, 'number');
  assert.strictEqual(typeof APP_CRASH_FUTURE_SKEW_SECONDS, 'number');
  assert.strictEqual(typeof MAX_BOOT_DURATION_SECONDS, 'number');
  assert.strictEqual(typeof MAX_UPTIME_SECONDS, 'number');
  assert.strictEqual(typeof MAX_ANALYTICS_WARNINGS, 'number');
  assert.strictEqual(typeof MAX_ANALYTICS_WARNING_LENGTH, 'number');
  assert.strictEqual(APP_CRASH_SK_PREFIX, 'APPCRASH#');
});
