/**
 * E2E cucumber-style tests for TASK-056: IP-based device location captured at
 * enrollment (`createEnrollHandler` in `src/routes/enroll.ts`).
 *
 * The table is the real `TableClient` wired to an in-memory fake document
 * client (`test/helpers/fakeDynamo.js`); no real database connection is ever
 * opened. These tests use `X-MDM-Enrollment-Token` auth, unlike check-in.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { createEnrollHandler, ENROLLMENT_TOKEN_HEADER } = await import(
  `file://${join(__dirname, '../../dist/routes/enroll.js')}`
);
const {
  enrollmentToken,
  deviceLocation,
  group,
  groupListIndex,
  groupMember,
  groupIndex,
  policy: policyKey,
  policyAssignment,
  policyAssignmentIndex,
  defaultAssignmentSettings,
} = await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);
const { createFakeTable } = await import(`file://${join(__dirname, '../helpers/fakeDynamo.js')}`);

function randomHex(bytes = 32) {
  return randomBytes(bytes).toString('hex');
}

function createEnrollmentToken() {
  const tokenId = randomBytes(8).toString('hex');
  const secret = randomBytes(32).toString('hex');
  const presented = `${tokenId}.${secret}`;
  const tokenHash = createHash('sha256').update(presented, 'utf8').digest('hex');
  return { tokenId, secret, presented, tokenHash };
}

async function seedToken(table, token, overrides = {}) {
  await table.put({
    ...enrollmentToken(token.tokenId),
    tokenHash: token.tokenHash,
    expiresAt: '2026-12-31T00:00:00Z',
    maxUses: 100,
    useCount: 0,
    ...overrides,
  });
}

function createEnrollRequest(presented, body = {}, headers = {}) {
  return {
    method: 'POST',
    path: '/api/v1/enroll',
    query: {},
    headers: { [ENROLLMENT_TOKEN_HEADER]: presented, ...headers },
    body: JSON.stringify(body),
  };
}

function validEnrollBody(overrides = {}) {
  return {
    hostname: 'my-machine',
    platform: 'windows',
    osVersion: '10.0.22631',
    hardwareUuid: `HW-${randomHex(4)}`,
    agentVersion: '1.0.0',
    ...overrides,
  };
}

function handlerFor(table, now = new Date('2026-10-11T12:00:00Z')) {
  return createEnrollHandler({
    table,
    pepper: randomHex(32),
    now: () => now,
    randomBytes: (size) => randomBytes(size),
  });
}

const SYDNEY_HEADERS = {
  'CloudFront-Viewer-Latitude': '-33.8688',
  'CloudFront-Viewer-Longitude': '151.2093',
  'CloudFront-Viewer-City': 'Sydney',
};

/** Seed a default-group policy for `ownership` that sets `settings`. */
async function seedDefaultGroupPolicy(table, { ownership, groupId, policyId, settings }) {
  await table.put({ ...group(groupId), ...groupListIndex(`Group ${groupId}`), groupId, name: `Group ${groupId}` });
  await table.put({
    ...policyAssignment(policyId, groupId),
    ...policyAssignmentIndex(groupId, policyId),
    policyId,
    groupId,
  });
  await table.put({ ...policyKey(policyId), policyId, version: 1, settings });
  const existing = (await table.get(defaultAssignmentSettings())) ?? {};
  await table.put({ ...defaultAssignmentSettings(), ...existing, [ownership]: groupId });
}

// ============================================================================
// Scenario: Enrollment captures when the default group's policy enables tracking
// ============================================================================

test("Scenario: Enrollment captures when the default group's policy enables tracking", async () => {
  const { table } = createFakeTable();
  await seedDefaultGroupPolicy(table, {
    ownership: 'officehq',
    groupId: 'grp-office',
    policyId: 'pol-1',
    settings: { locationTracking: true },
  });

  const hardwareUuid = `HW-${randomHex(4)}`;
  const token = createEnrollmentToken();
  await seedToken(table, token);
  const at = new Date('2026-10-11T12:00:00Z');
  const handler = handlerFor(table, at);

  const first = await handler(createEnrollRequest(token.presented, validEnrollBody({ hardwareUuid }), SYDNEY_HEADERS));
  assert.strictEqual(first.statusCode, 200);
  const deviceId = first.body.deviceId;

  // Overwrite the just-captured item with one 1 hour old and 1 history entry,
  // so the "re-enrollment despite a recent capture" case is exercised.
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
    capturedAt: '2026-10-11T11:00:00Z',
    history: [{ latitude: 1, longitude: 1, city: 'Old City', region: null, country: null, source: 'ip', accuracyMeters: null, capturedAt: '2026-10-11T11:00:00Z' }],
  });

  const token2 = createEnrollmentToken();
  await seedToken(table, token2);
  const second = await handler(
    createEnrollRequest(token2.presented, validEnrollBody({ hardwareUuid }), {
      ...SYDNEY_HEADERS,
      'CloudFront-Viewer-City': 'Melbourne',
    }),
  );
  assert.strictEqual(second.statusCode, 200);
  assert.strictEqual(second.body.deviceId, deviceId);

  const stored = await table.get(deviceLocation(deviceId));
  assert.strictEqual(stored.city, 'Melbourne');
  assert.strictEqual(stored.history.length, 2);
  assert.strictEqual(stored.history[0].city, 'Melbourne');
  assert.strictEqual(stored.history[1].city, 'Old City');
});

// ============================================================================
// Scenario: Enrollment without tracking enabled stores nothing
// ============================================================================

test('Scenario: Enrollment without tracking enabled stores nothing (no default group configured)', async () => {
  const { table } = createFakeTable();
  // No CONFIG/ASSIGNMENT item at all: no default group for "byoc".
  const token = createEnrollmentToken();
  await seedToken(table, token);
  const handler = handlerFor(table);

  const result = await handler(
    createEnrollRequest(token.presented, validEnrollBody({ ownership: 'byoc' }), SYDNEY_HEADERS),
  );

  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(await table.get(deviceLocation(result.body.deviceId)), undefined);
});

test('Scenario: Enrollment without tracking enabled stores nothing (default group policy does not set it true)', async () => {
  const { table } = createFakeTable();
  await seedDefaultGroupPolicy(table, {
    ownership: 'officehq',
    groupId: 'grp-office',
    policyId: 'pol-1',
    settings: { firewallEnabled: true },
  });
  const token = createEnrollmentToken();
  await seedToken(table, token);
  const handler = handlerFor(table);

  const result = await handler(createEnrollRequest(token.presented, validEnrollBody(), SYDNEY_HEADERS));

  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(await table.get(deviceLocation(result.body.deviceId)), undefined);
});

// ============================================================================
// Scenario: Enrollment survives a location failure
// ============================================================================

test('Scenario: Enrollment survives a location failure (the LOCATION write throws)', async () => {
  const { table } = createFakeTable();
  await seedDefaultGroupPolicy(table, {
    ownership: 'officehq',
    groupId: 'grp-office',
    policyId: 'pol-1',
    settings: { locationTracking: true },
  });

  const realPut = table.put.bind(table);
  table.put = async (item, fields) => {
    if (item.sk === 'LOCATION') {
      throw new Error('simulated location write failure');
    }
    return realPut(item, fields);
  };

  const token = createEnrollmentToken();
  await seedToken(table, token);
  const handler = handlerFor(table);

  const result = await handler(createEnrollRequest(token.presented, validEnrollBody(), SYDNEY_HEADERS));

  assert.strictEqual(result.statusCode, 200);
  assert.ok(result.body.deviceId);
  assert.ok(result.body.deviceSecret);
  assert.ok(result.body.checkInIntervalSeconds);
  assert.ok(result.body.serverTime);

  const profile = await table.get({ pk: `DEVICE#${result.body.deviceId}`, sk: 'PROFILE' });
  assert.ok(profile, 'the device profile is still written');
});

test('Scenario: Enrollment survives a location failure (policy resolution throws)', async () => {
  const { table } = createFakeTable();
  await seedDefaultGroupPolicy(table, {
    ownership: 'officehq',
    groupId: 'grp-office',
    policyId: 'pol-1',
    settings: { locationTracking: true },
  });

  // Make the gsi1 group-list query (readAllGroupIds, used by readAssignedPolicies
  // inside captureLocation) throw, simulating a resolution failure.
  const realQuery = table.query.bind(table);
  table.query = async (request) => {
    if (request?.ExpressionAttributeValues?.[':gsi1pk'] === 'GROUP') {
      throw new Error('simulated policy resolution failure');
    }
    return realQuery(request);
  };

  const token = createEnrollmentToken();
  await seedToken(table, token);
  const handler = handlerFor(table);

  const result = await handler(createEnrollRequest(token.presented, validEnrollBody(), SYDNEY_HEADERS));

  assert.strictEqual(result.statusCode, 200);
  assert.ok(result.body.deviceId);
  assert.ok(result.body.deviceSecret);
  assert.ok(result.body.checkInIntervalSeconds);
  assert.ok(result.body.serverTime);

  const profile = await table.get({ pk: `DEVICE#${result.body.deviceId}`, sk: 'PROFILE' });
  assert.ok(profile, 'the device profile is still written');
  const audit = [...(await collectAuditItems(table))].find(
    (item) => item.action === 'device.enrolled' && item.target === result.body.deviceId,
  );
  assert.ok(audit, 'the device.enrolled audit entry is still written');
});

/** Every AUDIT# item stored, by scanning the known day partition for `at`. */
async function collectAuditItems(table) {
  const page = await table.query({
    KeyConditionExpression: 'begins_with(#pk, :auditPrefix)',
    ExpressionAttributeNames: { '#pk': 'pk' },
    ExpressionAttributeValues: { ':auditPrefix': 'AUDIT#' },
  });
  return page.items ?? [];
}
