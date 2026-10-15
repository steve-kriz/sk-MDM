/**
 * E2E and unit tests for antivirus findings storage during check-in (TASK-030).
 * Tests implement the Gherkin scenarios for finding ingestion, deduplication,
 * bounding and display. Mock all database calls — no real DB connections.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { createCheckInHandler, MAX_ANTIVIRUS_FINDINGS } = await import(
  `file://${join(__dirname, '../../dist/routes/checkin.js')}`
);

const { deviceProfile, deviceAntivirusFinding } = await import(
  `file://${join(__dirname, '../../dist/db/keys.js')}`
);

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

  seedQueryResponses(responses) {
    this.queryResponses = [...responses];
  }

  getStoredItem(key) {
    return this.items.get(this.keyStr(key));
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

function createCheckInRequest(deviceId, { antivirusFindings } = {}) {
  const body = {
    collectedAt: '2026-10-02T11:00:00Z',
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
  if (antivirusFindings !== undefined) {
    body.antivirusFindings = antivirusFindings;
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

function validFinding(findingId, overrides = {}) {
  return {
    findingId,
    threatName: 'Trojan:Win32/Wacatac.B!ml',
    severity: 'severe',
    detectedAt: '2026-10-02T06:58:12Z',
    resources: ['file:_C:\\Users\\a\\invoice.exe'],
    remediated: true,
    ...overrides,
  };
}

// ============================================================================
// E2E Tests
// ============================================================================

test('Scenario: Backend stores a reported finding', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-03T01:00:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const request = createCheckInRequest(deviceId, { antivirusFindings: [validFinding('F1')] });
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);

  const stored = table.getStoredItem(deviceAntivirusFinding(deviceId, 'F1'));
  assert.ok(stored, 'expected an item at DEVICE#d1 / AVFINDING#F1');
  assert.strictEqual(stored.deviceId, deviceId);
  assert.strictEqual(stored.findingId, 'F1');
  assert.strictEqual(stored.threatName, 'Trojan:Win32/Wacatac.B!ml');
  assert.strictEqual(stored.severity, 'severe');
  assert.strictEqual(stored.detectedAt, '2026-10-02T06:58:12Z');
  assert.deepStrictEqual(stored.resources, ['file:_C:\\Users\\a\\invoice.exe']);
  assert.strictEqual(stored.remediated, true);
  assert.strictEqual(stored.firstReportedAt, '2026-10-03T01:00:00Z');
  assert.strictEqual(stored.lastReportedAt, '2026-10-03T01:00:00Z');
});

test('Scenario: Re-reported finding keeps firstReportedAt', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  // Given: finding F1 was stored at 2026-10-03T01:00:00Z
  const firstHandler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-03T01:00:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });
  await firstHandler(createCheckInRequest(deviceId, { antivirusFindings: [validFinding('F1', { remediated: false })] }));

  // When: d1 checks in at 2026-10-03T02:00:00Z with F1 now remediated true, and F2 reported twice
  const secondHandler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-03T02:00:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });
  const result = await secondHandler(
    createCheckInRequest(deviceId, {
      antivirusFindings: [
        validFinding('F1', { remediated: true }),
        validFinding('F2'),
        validFinding('F2'),
      ],
    }),
  );
  assert.strictEqual(result.statusCode, 200);

  // Then: exactly one item exists for F1 with firstReportedAt unchanged, lastReportedAt updated and remediated true
  const stored = table.getStoredItem(deviceAntivirusFinding(deviceId, 'F1'));
  assert.ok(stored);
  assert.strictEqual(stored.firstReportedAt, '2026-10-03T01:00:00Z');
  assert.strictEqual(stored.lastReportedAt, '2026-10-03T02:00:00Z');
  assert.strictEqual(stored.remediated, true);

  // And: a body carrying F2 twice leaves exactly one F2 item
  const f2 = table.getStoredItem(deviceAntivirusFinding(deviceId, 'F2'));
  assert.ok(f2);
  assert.strictEqual(f2.firstReportedAt, '2026-10-03T02:00:00Z');
});

test('Scenario: Malformed findings never refuse the check-in', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-03T01:00:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  // When d1 checks in with antivirusFindings "oops"
  const oopsResult = await handler(createCheckInRequest(deviceId, { antivirusFindings: 'oops' }));
  // Then the status is 200 and no AVFINDING item is written
  assert.strictEqual(oopsResult.statusCode, 200);
  const avFindingKeys = [...table.items.keys()].filter((key) => key.includes('AVFINDING#'));
  assert.deepStrictEqual(avFindingKeys, [], 'no AVFINDING item should be written');

  // When d1 checks in with 25 entries exercising every drop reason, plus the cap
  const entries = [
    validFinding('a#b'), // entry 1: findingId contains '#'
    validFinding('x'.repeat(129)), // entry 2: findingId too long
    validFinding('valid-03', { threatName: '' }), // entry 3: empty threatName
    validFinding('valid-04', { detectedAt: '2026-10-02' }), // entry 4: not ISO-UTC
    42, // entry 5: not an object
    validFinding('valid-06', { severity: 'critical', remediated: 'yes', resources: ['x', 5, 'y', 'z', 'w'] }), // entry 6
  ];
  // entries 7-20: 14 ordinary valid entries
  for (let i = 7; i <= 20; i++) {
    entries.push(validFinding(`valid-${i}`));
  }
  // entries 21-25: valid-shaped, but beyond the 20-entry cap
  for (let i = 21; i <= 25; i++) {
    entries.push(validFinding(`valid-${i}`));
  }
  assert.strictEqual(entries.length, 25);

  const result = await handler(createCheckInRequest(deviceId, { antivirusFindings: entries }));
  assert.strictEqual(result.statusCode, 200);

  // entries 1 to 5 store nothing. Entry 1's id contains "#", so no key can even
  // be built for it; check directly against the raw stored key set instead.
  const storedFindingKeys = [...table.items.keys()].filter((key) => key.includes('AVFINDING#'));
  assert.ok(!storedFindingKeys.some((key) => key.includes('AVFINDING#a#b')), 'entry 1 should not be stored');
  assert.strictEqual(table.getStoredItem(deviceAntivirusFinding(deviceId, 'x'.repeat(129))), undefined);
  assert.strictEqual(table.getStoredItem(deviceAntivirusFinding(deviceId, 'valid-03')), undefined);
  assert.strictEqual(table.getStoredItem(deviceAntivirusFinding(deviceId, 'valid-04')), undefined);

  // entries 21 to 25 store nothing (beyond MAX_ANTIVIRUS_FINDINGS entries considered)
  assert.strictEqual(MAX_ANTIVIRUS_FINDINGS, 20);
  for (let i = 21; i <= 25; i++) {
    assert.strictEqual(table.getStoredItem(deviceAntivirusFinding(deviceId, `valid-${i}`)), undefined);
  }

  // entry 6 is stored with severity "unknown", remediated false and resources ["x","y","z"]
  const entry6 = table.getStoredItem(deviceAntivirusFinding(deviceId, 'valid-06'));
  assert.ok(entry6, 'entry 6 should be stored');
  assert.strictEqual(entry6.severity, 'unknown');
  assert.strictEqual(entry6.remediated, false);
  assert.deepStrictEqual(entry6.resources, ['x', 'y', 'z']);

  // entries 7-20 are stored normally
  for (let i = 7; i <= 20; i++) {
    assert.ok(table.getStoredItem(deviceAntivirusFinding(deviceId, `valid-${i}`)), `entry ${i} should be stored`);
  }
});

test('Scenario: Check-in without findings leaves stored findings and compliance alone', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({
    ...deviceProfile(deviceId),
    deviceId,
    hostname: 'host-d1',
    complianceState: 'compliant',
  });
  const existing = {
    ...deviceAntivirusFinding(deviceId, 'F1'),
    deviceId,
    findingId: 'F1',
    threatName: 'Old',
    severity: 'low',
    detectedAt: '2026-10-01T00:00:00Z',
    resources: [],
    remediated: false,
    firstReportedAt: '2026-10-01T00:00:00Z',
    lastReportedAt: '2026-10-01T00:00:00Z',
  };
  table.seedItem(existing);

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-03T01:00:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  // When d1 checks in without antivirusFindings
  const result = await handler(createCheckInRequest(deviceId));
  assert.strictEqual(result.statusCode, 200);

  // Then F1 is unchanged, no new AVFINDING item exists, and the response keys are unchanged
  const stillStored = table.getStoredItem(deviceAntivirusFinding(deviceId, 'F1'));
  assert.deepStrictEqual(stillStored, existing);
  assert.deepStrictEqual(
    Object.keys(result.body).sort(),
    ['checkInIntervalSeconds', 'pendingCommandCount'].sort(),
  );

  // And complianceState is compliant
  const profile = table.getStoredItem(deviceProfile(deviceId));
  assert.strictEqual(profile.complianceState, 'compliant');

  // When d1 checks in with one new finding
  const result2 = await handler(createCheckInRequest(deviceId, { antivirusFindings: [validFinding('F2')] }));
  assert.strictEqual(result2.statusCode, 200);

  // Then complianceState is still compliant
  const profile2 = table.getStoredItem(deviceProfile(deviceId));
  assert.strictEqual(profile2.complianceState, 'compliant');
});

// ============================================================================
// TASK-058 AC21: Extended finding fields are stored and bounded
// ============================================================================

test('Scenario: AC21 - Extended finding fields are stored and bounded', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-03T01:00:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const finding = validFinding('F1', {
    status: 'quarantined',
    action: 'bogus',
    category: 'c'.repeat(100),
    processName: 'p'.repeat(300),
    user: 7,
    active: 'true',
    remediatedAt: 'yesterday',
  });

  const result = await handler(createCheckInRequest(deviceId, { antivirusFindings: [finding] }));
  assert.strictEqual(result.statusCode, 200);

  const stored = table.getStoredItem(deviceAntivirusFinding(deviceId, 'F1'));
  assert.strictEqual(stored.status, 'quarantined');
  assert.strictEqual(stored.action, 'unknown');
  assert.strictEqual(stored.category.length, 64);
  assert.strictEqual(stored.processName.length, 260);
  assert.ok(!('user' in stored), 'user should be omitted: it was not a string');
  assert.ok(!('active' in stored), 'active should be omitted: it was not a boolean');
  assert.ok(!('remediatedAt' in stored), 'remediatedAt should be omitted: not ISO-8601 UTC');
});

test('Scenario: AC21 - A finding with none of the new fields stores only the original attributes', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-03T01:00:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const result = await handler(createCheckInRequest(deviceId, { antivirusFindings: [validFinding('F1')] }));
  assert.strictEqual(result.statusCode, 200);

  const stored = table.getStoredItem(deviceAntivirusFinding(deviceId, 'F1'));
  const expectedKeys = [
    'pk', 'sk', 'deviceId', 'findingId', 'threatName', 'severity', 'detectedAt',
    'resources', 'remediated', 'firstReportedAt', 'lastReportedAt',
  ].sort();
  assert.deepStrictEqual(Object.keys(stored).sort(), expectedKeys);
});

test('Scenario: AC21 - Valid extended fields are stored as reported', async (t) => {
  const table = new FakeTable();
  const deviceId = 'd1';
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-03T01:00:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const finding = validFinding('F1', {
    status: 'quarantined',
    action: 'quarantine',
    category: 'Trojan',
    active: true,
    lastStatusChangeAt: '2026-10-02T07:00:00Z',
    remediatedAt: '2026-10-02T07:00:00Z',
    processName: 'C:\\x.exe',
    user: 'CONTOSO\\a',
  });

  const result = await handler(createCheckInRequest(deviceId, { antivirusFindings: [finding] }));
  assert.strictEqual(result.statusCode, 200);

  const stored = table.getStoredItem(deviceAntivirusFinding(deviceId, 'F1'));
  assert.strictEqual(stored.status, 'quarantined');
  assert.strictEqual(stored.action, 'quarantine');
  assert.strictEqual(stored.category, 'Trojan');
  assert.strictEqual(stored.active, true);
  assert.strictEqual(stored.lastStatusChangeAt, '2026-10-02T07:00:00Z');
  assert.strictEqual(stored.remediatedAt, '2026-10-02T07:00:00Z');
  assert.strictEqual(stored.processName, 'C:\\x.exe');
  assert.strictEqual(stored.user, 'CONTOSO\\a');
});
