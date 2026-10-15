/**
 * E2E cucumber-style tests for TASK-056: IP-based device location captured at
 * check-in (`createCheckInHandler` in `src/routes/checkin.ts`).
 *
 * Scenarios are Given/When/Then, matching the ticket's Gherkin. The table is
 * the real `TableClient` (`src/db/table.ts`) wired to an in-memory fake
 * document client (`test/helpers/fakeDynamo.js`), so query semantics (gsi1
 * key conditions, begins_with) are exercised faithfully. No real database
 * connection is ever opened.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { createCheckInHandler } = await import(`file://${join(__dirname, '../../dist/routes/checkin.js')}`);
const {
  deviceProfile,
  deviceLocation,
  group,
  groupListIndex,
  groupMember,
  groupIndex,
  policy: policyKey,
  policyAssignment,
  policyAssignmentIndex,
} = await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);
const { createFakeTable } = await import(`file://${join(__dirname, '../helpers/fakeDynamo.js')}`);

// ============================================================================
// Test helpers
// ============================================================================

function createFakeVerifier(deviceIdToReturn = 'dev-1', ok = true, failure = { status: 401, body: { error: 'bad_signature' } }) {
  return async () => (ok ? { ok: true, deviceId: deviceIdToReturn } : { ok: false, ...failure });
}

function createCheckInRequest(deviceId, headers = {}, bodyOverrides = {}) {
  const body = {
    collectedAt: '2026-10-11T00:00:00Z',
    inventory: {
      hardware: { manufacturer: 'Dell', model: 'X', serialNumber: 'S1', cpu: 'Intel', ramBytes: 1, diskBytes: 1 },
      os: { name: 'Windows', version: '11', build: '1', architecture: 'x86_64' },
      software: [],
      warnings: [],
    },
    posture: {
      diskEncryption: { enabled: true, method: 'bitlocker' },
      firewall: { enabled: true },
      antivirus: { name: 'Defender', enabled: true, definitionsAgeDays: 1 },
      osUpdate: { lastCheckedAt: '2026-10-11T00:00:00Z', pendingCount: 0, rebootRequired: false },
      localAdmins: [],
      warnings: [],
    },
    ...bodyOverrides,
  };
  return {
    method: 'POST',
    path: `/api/v1/devices/${deviceId}/checkin`,
    query: {},
    headers: {
      'x-mdm-device-id': deviceId,
      'x-mdm-timestamp': '1234567890',
      'x-mdm-nonce': 'nonce-value',
      'x-mdm-signature': 'signature-value',
      ...headers,
    },
    params: { deviceId },
    body: JSON.stringify(body),
  };
}

const SYDNEY_HEADERS = {
  'CloudFront-Viewer-Latitude': '-33.8688',
  'CloudFront-Viewer-Longitude': '151.2093',
  'CloudFront-Viewer-City': 'Sydney',
  'CloudFront-Viewer-Country-Region-Name': 'New South Wales',
  'CloudFront-Viewer-Country': 'AU',
};

async function seedDevice(table, deviceId) {
  await table.put({ ...deviceProfile(deviceId), deviceId, hostname: 'host-1' });
}

/** Seed a group holding `settings`, assigned, with the device a member of it. */
async function seedTrackingGroup(table, { groupId, policyId, deviceId, settings }) {
  await table.put({ ...group(groupId), ...groupListIndex(`Group ${groupId}`), groupId, name: `Group ${groupId}` });
  await table.put({ ...groupMember(groupId, deviceId), ...groupIndex(groupId, deviceId), groupId, deviceId });
  await table.put({
    ...policyAssignment(policyId, groupId),
    ...policyAssignmentIndex(groupId, policyId),
    policyId,
    groupId,
  });
  await table.put({ ...policyKey(policyId), policyId, version: 1, settings });
}

function handlerFor(table, now, verifyDevice) {
  return createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => now,
    verifyDevice,
  });
}

/** Captures console.warn lines for the duration of `fn`, then restores it. */
async function captureWarnings(fn) {
  const lines = [];
  const original = console.warn;
  console.warn = (line) => lines.push(line);
  try {
    await fn();
  } finally {
    console.warn = original;
  }
  return lines;
}

// ============================================================================
// Scenario: First check-in with tracking on captures the IP location
// ============================================================================

test('Scenario: First check-in with tracking on captures the IP location', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-1';
  await seedDevice(table, deviceId);
  await seedTrackingGroup(table, { groupId: 'grp-1', policyId: 'pol-1', deviceId, settings: { locationTracking: true } });

  const at = new Date('2026-10-11T00:00:00Z');
  const handler = handlerFor(table, at, createFakeVerifier(deviceId, true));

  const result = await handler(createCheckInRequest(deviceId, SYDNEY_HEADERS));
  assert.strictEqual(result.statusCode, 200);

  const stored = await table.get(deviceLocation(deviceId));
  assert.ok(stored, 'expected a LOCATION item to be written');
  assert.strictEqual(stored.latitude, -33.8688);
  assert.strictEqual(stored.longitude, 151.2093);
  assert.strictEqual(stored.city, 'Sydney');
  assert.strictEqual(stored.region, 'New South Wales');
  assert.strictEqual(stored.country, 'AU');
  assert.strictEqual(stored.source, 'ip');
  assert.strictEqual(stored.accuracyMeters, null);
  assert.strictEqual(stored.capturedAt, '2026-10-11T00:00:00Z');
  assert.strictEqual(stored.history.length, 1);
});

// ============================================================================
// Scenario Outline: Tracking off stores nothing
// ============================================================================

test('Scenario Outline: Tracking off stores nothing - has no assigned policy', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-1';
  await seedDevice(table, deviceId);

  const handler = handlerFor(table, new Date('2026-10-11T00:00:00Z'), createFakeVerifier(deviceId, true));
  const result = await handler(createCheckInRequest(deviceId, SYDNEY_HEADERS));

  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(await table.get(deviceLocation(deviceId)), undefined);
});

test('Scenario Outline: Tracking off stores nothing - is assigned a policy without locationTracking', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-1';
  await seedDevice(table, deviceId);
  await seedTrackingGroup(table, { groupId: 'grp-1', policyId: 'pol-1', deviceId, settings: { firewallEnabled: true } });

  const handler = handlerFor(table, new Date('2026-10-11T00:00:00Z'), createFakeVerifier(deviceId, true));
  const result = await handler(createCheckInRequest(deviceId, SYDNEY_HEADERS));

  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(await table.get(deviceLocation(deviceId)), undefined);
});

test('Scenario Outline: Tracking off stores nothing - is assigned a policy with locationTracking false', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-1';
  await seedDevice(table, deviceId);
  await seedTrackingGroup(table, { groupId: 'grp-1', policyId: 'pol-1', deviceId, settings: { locationTracking: false } });

  const handler = handlerFor(table, new Date('2026-10-11T00:00:00Z'), createFakeVerifier(deviceId, true));
  const result = await handler(createCheckInRequest(deviceId, SYDNEY_HEADERS));

  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(await table.get(deviceLocation(deviceId)), undefined);
});

// ============================================================================
// Scenario: Conflicting policies resolve by smallest policy id
// ============================================================================

test('Scenario: Conflicting policies resolve by smallest policy id', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-1';
  await seedDevice(table, deviceId);
  // pol-a (smallest) sets false; pol-b sets true. pol-a wins, so tracking is off.
  await seedTrackingGroup(table, { groupId: 'grp-a', policyId: 'pol-a', deviceId, settings: { locationTracking: false } });
  await seedTrackingGroup(table, { groupId: 'grp-b', policyId: 'pol-b', deviceId, settings: { locationTracking: true } });

  const handler = handlerFor(table, new Date('2026-10-11T00:00:00Z'), createFakeVerifier(deviceId, true));
  const result = await handler(createCheckInRequest(deviceId, SYDNEY_HEADERS));

  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(await table.get(deviceLocation(deviceId)), undefined);
});

// ============================================================================
// Scenario: Capture younger than 24 hours is not replaced / 24h boundary
// ============================================================================

test('Scenario: Capture younger than 24 hours (86399s) is not replaced', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-1';
  await seedDevice(table, deviceId);
  await seedTrackingGroup(table, { groupId: 'grp-1', policyId: 'pol-1', deviceId, settings: { locationTracking: true } });
  await table.put({
    ...deviceLocation(deviceId),
    deviceId,
    latitude: 1,
    longitude: 1,
    city: 'Old City',
    region: null,
    country: null,
    source: 'ip',
    accuracyMeters: null,
    capturedAt: '2026-10-10T00:00:01Z', // 86399s before 2026-10-11T00:00:00Z
    history: [{ latitude: 1, longitude: 1, city: 'Old City', region: null, country: null, source: 'ip', accuracyMeters: null, capturedAt: '2026-10-10T00:00:01Z' }],
  });

  const handler = handlerFor(table, new Date('2026-10-11T00:00:00Z'), createFakeVerifier(deviceId, true));
  const result = await handler(
    createCheckInRequest(deviceId, { ...SYDNEY_HEADERS, 'CloudFront-Viewer-City': 'Melbourne' }),
  );

  assert.strictEqual(result.statusCode, 200);
  const stored = await table.get(deviceLocation(deviceId));
  assert.strictEqual(stored.city, 'Old City');
  assert.strictEqual(stored.history.length, 1);
});

test('Scenario: Capture 24 hours old (86400s) is replaced and prepended to history', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-1';
  await seedDevice(table, deviceId);
  await seedTrackingGroup(table, { groupId: 'grp-1', policyId: 'pol-1', deviceId, settings: { locationTracking: true } });
  await table.put({
    ...deviceLocation(deviceId),
    deviceId,
    latitude: 1,
    longitude: 1,
    city: 'Old City',
    region: null,
    country: null,
    source: 'ip',
    accuracyMeters: null,
    capturedAt: '2026-10-10T00:00:00Z', // exactly 86400s before 2026-10-11T00:00:00Z
    history: [{ latitude: 1, longitude: 1, city: 'Old City', region: null, country: null, source: 'ip', accuracyMeters: null, capturedAt: '2026-10-10T00:00:00Z' }],
  });

  const handler = handlerFor(table, new Date('2026-10-11T00:00:00Z'), createFakeVerifier(deviceId, true));
  const result = await handler(
    createCheckInRequest(deviceId, { ...SYDNEY_HEADERS, 'CloudFront-Viewer-City': 'Melbourne' }),
  );

  assert.strictEqual(result.statusCode, 200);
  const stored = await table.get(deviceLocation(deviceId));
  assert.strictEqual(stored.city, 'Melbourne');
  assert.strictEqual(stored.history.length, 2);
  assert.strictEqual(stored.history[0].city, 'Melbourne');
  assert.strictEqual(stored.history[1].city, 'Old City');
});

// ============================================================================
// Scenario: History is bounded at 30 entries
// ============================================================================

test('Scenario: History is bounded at 30 entries', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-1';
  await seedDevice(table, deviceId);
  await seedTrackingGroup(table, { groupId: 'grp-1', policyId: 'pol-1', deviceId, settings: { locationTracking: true } });

  const oldHistory = Array.from({ length: 30 }, (_, i) => ({
    latitude: i,
    longitude: i,
    city: null,
    region: null,
    country: null,
    source: 'ip',
    accuracyMeters: null,
    capturedAt: `2026-09-${String(i + 1).padStart(2, '0')}T00:00:00Z`,
  }));
  await table.put({
    ...deviceLocation(deviceId),
    deviceId,
    latitude: 0,
    longitude: 0,
    city: null,
    region: null,
    country: null,
    source: 'ip',
    accuracyMeters: null,
    // 25 hours old: more than 86400s, so a new capture is taken.
    capturedAt: '2026-10-09T23:00:00Z',
    history: oldHistory,
  });

  const handler = handlerFor(table, new Date('2026-10-11T00:00:00Z'), createFakeVerifier(deviceId, true));
  const result = await handler(createCheckInRequest(deviceId, SYDNEY_HEADERS));

  assert.strictEqual(result.statusCode, 200);
  const stored = await table.get(deviceLocation(deviceId));
  assert.strictEqual(stored.history.length, 30);
  assert.strictEqual(stored.history[0].city, 'Sydney');
  assert.ok(!stored.history.some((entry) => entry.latitude === 29), 'the previous oldest entry should be gone');
});

// ============================================================================
// Scenario Outline: Unusable coordinates store nothing and do not fail the check-in
// ============================================================================

const unusableCases = [
  { label: 'latitude absent', headers: { 'CloudFront-Viewer-Longitude': '151.2' } },
  { label: 'longitude absent', headers: { 'CloudFront-Viewer-Latitude': '-33.8' } },
  { label: 'latitude non-numeric', headers: { 'CloudFront-Viewer-Latitude': 'abc', 'CloudFront-Viewer-Longitude': '151.2' } },
  { label: 'latitude out of range (91)', headers: { 'CloudFront-Viewer-Latitude': '91', 'CloudFront-Viewer-Longitude': '151.2' } },
  { label: 'longitude out of range (-181)', headers: { 'CloudFront-Viewer-Latitude': '-33.8', 'CloudFront-Viewer-Longitude': '-181' } },
];

for (const { label, headers } of unusableCases) {
  test(`Scenario Outline: Unusable coordinates store nothing and do not fail the check-in - ${label}`, async () => {
    const { table } = createFakeTable();
    const deviceId = 'dev-1';
    await seedDevice(table, deviceId);
    await seedTrackingGroup(table, { groupId: 'grp-1', policyId: 'pol-1', deviceId, settings: { locationTracking: true } });

    const at = new Date('2026-10-11T00:00:00Z');
    const handlerWithHeaders = handlerFor(table, at, createFakeVerifier(deviceId, true));
    const resultWithHeaders = await handlerWithHeaders(createCheckInRequest(deviceId, headers));

    const { table: plainTable } = createFakeTable();
    await seedDevice(plainTable, deviceId);
    const handlerWithoutLocation = handlerFor(plainTable, at, createFakeVerifier(deviceId, true));
    const resultWithoutLocation = await handlerWithoutLocation(createCheckInRequest(deviceId, {}));

    assert.strictEqual(resultWithHeaders.statusCode, 200);
    assert.deepStrictEqual(resultWithHeaders.body, resultWithoutLocation.body);
    assert.strictEqual(await table.get(deviceLocation(deviceId)), undefined);
  });
}

// ============================================================================
// Scenario: Text fields are normalised
// ============================================================================

test('Scenario: Text fields are normalised (bad country, empty region, long city)', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-1';
  await seedDevice(table, deviceId);
  await seedTrackingGroup(table, { groupId: 'grp-1', policyId: 'pol-1', deviceId, settings: { locationTracking: true } });

  const longCity = 'c'.repeat(200);
  const handler = handlerFor(table, new Date('2026-10-11T00:00:00Z'), createFakeVerifier(deviceId, true));
  const result = await handler(
    createCheckInRequest(deviceId, {
      'CloudFront-Viewer-Latitude': '1',
      'CloudFront-Viewer-Longitude': '2',
      'CloudFront-Viewer-Country': 'usa',
      'CloudFront-Viewer-Country-Region-Name': '',
      'CloudFront-Viewer-City': longCity,
    }),
  );

  assert.strictEqual(result.statusCode, 200);
  const stored = await table.get(deviceLocation(deviceId));
  assert.strictEqual(stored.country, null);
  assert.strictEqual(stored.region, null);
  assert.strictEqual(stored.city, longCity.slice(0, 128));
  assert.strictEqual(stored.city.length, 128);
});

// ============================================================================
// Scenario: Headers are matched case-insensitively
// ============================================================================

test('Scenario: Headers are matched case-insensitively', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-1';
  await seedDevice(table, deviceId);
  await seedTrackingGroup(table, { groupId: 'grp-1', policyId: 'pol-1', deviceId, settings: { locationTracking: true } });

  const handler = handlerFor(table, new Date('2026-10-11T00:00:00Z'), createFakeVerifier(deviceId, true));
  const result = await handler(
    createCheckInRequest(deviceId, { 'cloudfront-viewer-latitude': '10', 'cloudfront-viewer-longitude': '20' }),
  );

  assert.strictEqual(result.statusCode, 200);
  const stored = await table.get(deviceLocation(deviceId));
  assert.strictEqual(stored.latitude, 10);
  assert.strictEqual(stored.longitude, 20);
});

// ============================================================================
// Scenario: A storage failure while capturing does not fail the check-in
// ============================================================================

test('Scenario: A storage failure while capturing does not fail the check-in', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-1';
  await seedDevice(table, deviceId);
  await seedTrackingGroup(table, { groupId: 'grp-1', policyId: 'pol-1', deviceId, settings: { locationTracking: true } });

  // Make the LOCATION item write throw, without touching any other write.
  const realPut = table.put.bind(table);
  table.put = async (item, fields) => {
    if (item.sk === 'LOCATION') {
      throw new Error('simulated location write failure');
    }
    return realPut(item, fields);
  };

  const handler = handlerFor(table, new Date('2026-10-11T00:00:00Z'), createFakeVerifier(deviceId, true));

  const lines = await captureWarnings(async () => {
    const result = await handler(createCheckInRequest(deviceId, SYDNEY_HEADERS));
    assert.strictEqual(result.statusCode, 200);
  });

  const locationWarnings = lines.filter((line) => line.includes('location capture failed') && line.includes(deviceId));
  assert.strictEqual(locationWarnings.length, 1);
});

// ============================================================================
// Scenario Outline: A rejected check-in touches no location
// ============================================================================

test('Scenario Outline: A rejected check-in touches no location - 413 payload_too_large', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-1';
  await seedDevice(table, deviceId);
  await seedTrackingGroup(table, { groupId: 'grp-1', policyId: 'pol-1', deviceId, settings: { locationTracking: true } });

  const handler = handlerFor(table, new Date('2026-10-11T00:00:00Z'), createFakeVerifier(deviceId, true));
  const huge = 'x'.repeat(300000);
  const request = createCheckInRequest(deviceId, SYDNEY_HEADERS, { hugePayload: huge });

  const result = await handler(request);
  assert.strictEqual(result.statusCode, 413);
  assert.strictEqual(await table.get(deviceLocation(deviceId)), undefined);
});

test('Scenario Outline: A rejected check-in touches no location - 401 auth failure', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-1';
  await seedDevice(table, deviceId);
  await seedTrackingGroup(table, { groupId: 'grp-1', policyId: 'pol-1', deviceId, settings: { locationTracking: true } });

  const handler = handlerFor(table, new Date('2026-10-11T00:00:00Z'), createFakeVerifier(deviceId, false));
  const result = await handler(createCheckInRequest(deviceId, SYDNEY_HEADERS));

  assert.strictEqual(result.statusCode, 401);
  assert.strictEqual(await table.get(deviceLocation(deviceId)), undefined);
});

test('Scenario Outline: A rejected check-in touches no location - 403 device_mismatch', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-1';
  await seedDevice(table, deviceId);
  await seedTrackingGroup(table, { groupId: 'grp-1', policyId: 'pol-1', deviceId, settings: { locationTracking: true } });

  // The verifier says "other-device", but the path names "dev-1": a mismatch.
  const handler = handlerFor(table, new Date('2026-10-11T00:00:00Z'), createFakeVerifier('other-device', true));
  const result = await handler(createCheckInRequest(deviceId, SYDNEY_HEADERS));

  assert.strictEqual(result.statusCode, 403);
  assert.strictEqual(result.body.error, 'device_mismatch');
  assert.strictEqual(await table.get(deviceLocation(deviceId)), undefined);
});

test('Scenario Outline: A rejected check-in touches no location - 400 invalid_request', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-1';
  await seedDevice(table, deviceId);
  await seedTrackingGroup(table, { groupId: 'grp-1', policyId: 'pol-1', deviceId, settings: { locationTracking: true } });

  const handler = handlerFor(table, new Date('2026-10-11T00:00:00Z'), createFakeVerifier(deviceId, true));
  // Missing the required body fields entirely.
  const request = createCheckInRequest(deviceId, SYDNEY_HEADERS);
  request.body = JSON.stringify({});

  const result = await handler(request);
  assert.strictEqual(result.statusCode, 400);
  assert.strictEqual(result.body.error, 'invalid_request');
  assert.strictEqual(await table.get(deviceLocation(deviceId)), undefined);
});
