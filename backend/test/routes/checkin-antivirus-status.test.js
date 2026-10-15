/**
 * E2E and unit tests for TASK-058 AC18/AC19/AC20: storing the full antivirus
 * status an agent reports on check-in. Mock all database calls -- no real DB
 * connections are ever opened; the FakeTable below stands in for the
 * DynamoDB document client.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { createCheckInHandler } = await import(`file://${join(__dirname, '../../dist/routes/checkin.js')}`);

const { deviceProfile, deviceAntivirusStatus } = await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);

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

function createCheckInRequest(deviceId, { antivirusStatus, collectedAt } = {}) {
  const body = {
    collectedAt: collectedAt ?? '2026-10-11T09:55:00Z',
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
  if (antivirusStatus !== undefined) {
    body.antivirusStatus = antivirusStatus;
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

function validStatus(overrides = {}) {
  return {
    product: 'Microsoft Defender',
    defenderAvailable: true,
    runningMode: 'Normal',
    protection: {
      amServiceEnabled: true,
      antispywareEnabled: true,
      antivirusEnabled: true,
      behaviorMonitorEnabled: true,
      ioavProtectionEnabled: true,
      onAccessProtectionEnabled: true,
      realTimeProtectionEnabled: true,
      nisEnabled: true,
      tamperProtected: true,
    },
    versions: {
      engine: '1.1.24090.11',
      product: '4.18.24090.11',
      service: '4.18.24090.11',
      nisEngine: '1.1.24090.11',
      antivirusSignature: '1.419.163.0',
      antispywareSignature: '1.419.163.0',
      nisSignature: '1.419.163.0',
      xprotectDefinitions: null,
      xprotectRemediator: null,
    },
    signatures: {
      antivirusLastUpdatedAt: '2026-10-10T20:12:00Z',
      antivirusAgeDays: 1,
      antispywareLastUpdatedAt: '2026-10-10T20:12:00Z',
      antispywareAgeDays: 1,
      nisLastUpdatedAt: '2026-10-10T20:12:00Z',
      nisAgeDays: 1,
      outOfDate: false,
    },
    scans: {
      quickStartedAt: '2026-10-10T02:00:00Z',
      quickEndedAt: '2026-10-10T02:06:31Z',
      quickAgeDays: 1,
      quickOverdue: false,
      fullStartedAt: null,
      fullEndedAt: null,
      fullAgeDays: null,
      fullOverdue: false,
      fullRequired: false,
    },
    computerState: 0,
    rebootRequired: false,
    securityCenterProducts: [{ name: 'Windows Defender', state: 'on', definitionsUpToDate: true }],
    ...overrides,
  };
}

function makeHandler(table, deviceId, now = '2026-10-11T10:00:00Z') {
  return createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date(now),
    verifyDevice: createFakeVerifier(deviceId, true),
  });
}

// ============================================================================
// AC18: The backend stores the latest status
// ============================================================================

test('Scenario: AC18 - The backend stores the latest status', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler = makeHandler(table, deviceId, '2026-10-11T10:00:00Z');
  const result = await handler(
    createCheckInRequest(deviceId, { antivirusStatus: validStatus(), collectedAt: '2026-10-11T09:55:00Z' }),
  );
  assert.strictEqual(result.statusCode, 200);

  const stored = table.getStoredItem(deviceAntivirusStatus(deviceId));
  assert.ok(stored, 'expected an item at DEVICE#d1 / AVSTATUS');
  assert.strictEqual(stored.deviceId, deviceId);
  assert.strictEqual(stored.collectedAt, '2026-10-11T09:55:00Z');
  assert.strictEqual(stored.reportedAt, '2026-10-11T10:00:00Z');
  assert.strictEqual(stored.product, 'Microsoft Defender');
  assert.strictEqual(stored.defenderAvailable, true);
  assert.strictEqual(stored.runningMode, 'Normal');
  assert.strictEqual(stored.protection.realTimeProtectionEnabled, true);
  assert.strictEqual(stored.signatures.antivirusAgeDays, 1);
  assert.strictEqual(stored.scans.quickEndedAt, '2026-10-10T02:06:31Z');
  assert.strictEqual(stored.computerState, 0);
  assert.deepStrictEqual(stored.securityCenterProducts, [{ name: 'Windows Defender', state: 'on', definitionsUpToDate: true }]);
});

test('Scenario: AC18 - A second check-in with a different block overwrites it', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const firstHandler = makeHandler(table, deviceId, '2026-10-11T10:00:00Z');
  await firstHandler(createCheckInRequest(deviceId, { antivirusStatus: validStatus({ runningMode: 'Normal' }) }));

  const secondHandler = makeHandler(table, deviceId, '2026-10-11T11:00:00Z');
  await secondHandler(
    createCheckInRequest(deviceId, {
      antivirusStatus: validStatus({ runningMode: 'Passive Mode', defenderAvailable: false }),
    }),
  );

  const stored = table.getStoredItem(deviceAntivirusStatus(deviceId));
  assert.strictEqual(stored.runningMode, 'Passive Mode');
  assert.strictEqual(stored.defenderAvailable, false);
  assert.strictEqual(stored.reportedAt, '2026-10-11T11:00:00Z');
});

// ============================================================================
// AC19: The backend sanitises every field
// ============================================================================

test('Scenario: AC19 - The backend sanitises every field', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  // 12 entries: one with an empty name (dropped before the cap), one with an
  // unknown state, placed early enough to survive the 10-entry cap, and ten
  // more ordinary ones so the drop + cap interaction is exercised together.
  const products = [{ name: '', state: 'on', definitionsUpToDate: true }, { name: 'Weird', state: 'weird', definitionsUpToDate: true }];
  for (let i = 0; i < 10; i++) {
    products.push({ name: `AV${i}`, state: 'on', definitionsUpToDate: true });
  }

  const malformed = validStatus({
    protection: { ...validStatus().protection, antivirusEnabled: 'yes' },
    signatures: { ...validStatus().signatures, antivirusAgeDays: 65535 },
    computerState: 70000,
    scans: { ...validStatus().scans, quickEndedAt: '/Date(1)/' },
    versions: { ...validStatus().versions, engine: 'x'.repeat(100) },
    securityCenterProducts: products,
  });
  malformed.evil = 'surprise';

  const handler = makeHandler(table, deviceId);
  const result = await handler(createCheckInRequest(deviceId, { antivirusStatus: malformed }));
  assert.strictEqual(result.statusCode, 200);

  const stored = table.getStoredItem(deviceAntivirusStatus(deviceId));
  assert.strictEqual(stored.protection.antivirusEnabled, null);
  assert.strictEqual(stored.signatures.antivirusAgeDays, null);
  assert.strictEqual(stored.computerState, null);
  assert.strictEqual(stored.scans.quickEndedAt, null);
  assert.strictEqual(stored.versions.engine.length, 64);
  assert.strictEqual(stored.securityCenterProducts.length, 10);
  assert.ok(stored.securityCenterProducts.every((p) => p.name.length > 0));
  const weird = stored.securityCenterProducts.find((p) => p.name === 'Weird');
  assert.ok(weird, 'the 11th surviving product should still be present');
  assert.strictEqual(weird.state, 'unknown');
  assert.strictEqual(stored.evil, undefined, 'the stored item should have no evil attribute');
});

// ============================================================================
// AC20: A malformed antivirusStatus never fails the check-in
// ============================================================================

test('Scenario Outline: AC20 - A malformed antivirusStatus never fails the check-in', async (t) => {
  const cases = ['absent', null, 'status', 42, []];

  for (const value of cases) {
    const table = new FakeTable();
    const deviceId = 'd1';
    table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

    // Given device "d1" already has a stored AVSTATUS item
    const seedHandler = makeHandler(table, deviceId, '2026-10-11T09:00:00Z');
    await seedHandler(createCheckInRequest(deviceId, { antivirusStatus: validStatus() }));
    const before = table.getStoredItem(deviceAntivirusStatus(deviceId));
    assert.ok(before);

    const handler = makeHandler(table, deviceId, '2026-10-11T10:00:00Z');
    const request =
      value === 'absent' ? createCheckInRequest(deviceId, {}) : createCheckInRequest(deviceId, { antivirusStatus: value });
    const result = await handler(request);

    assert.strictEqual(result.statusCode, 200, `expected 200 for ${JSON.stringify(value)}`);
    const after = table.getStoredItem(deviceAntivirusStatus(deviceId));
    assert.deepStrictEqual(after, before, `AVSTATUS should be unchanged for ${JSON.stringify(value)}`);

    const profile = table.getStoredItem(deviceProfile(deviceId));
    assert.strictEqual(
      profile.complianceState,
      undefined,
      `complianceState should not be written by antivirusStatus for ${JSON.stringify(value)}`,
    );
  }
});

test('Scenario: AC20 - A device with no prior AVSTATUS item stays without one', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler = makeHandler(table, deviceId);
  const result = await handler(createCheckInRequest(deviceId, { antivirusStatus: 'not-an-object' }));

  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(table.getStoredItem(deviceAntivirusStatus(deviceId)), undefined);
});
