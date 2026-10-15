/**
 * E2E and unit tests for TASK-067 (History view): the device events written
 * during enrollment (device.enrolled/reenrolled and the default-group system
 * event). Tests implement the ticket's Gherkin scenarios in Given/When/Then
 * style using node:test. All database calls are mocked; no real DB
 * connection is ever made.
 */
import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { randomBytes, createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const { createEnrollHandler, ENROLLMENT_TOKEN_HEADER } = await import(
  `file://${join(__dirname, '../../dist/routes/enroll.js')}`
);
const { enrollmentToken, deviceProfile, group, groupListIndex, defaultAssignmentSettings } = await import(
  `file://${join(__dirname, '../../dist/db/keys.js')}`
);
const { FakeTable } = await import('../helpers/fakeTable.js');

function randomHex(bytes = 32) {
  return randomBytes(bytes).toString('hex');
}

function createEnrollmentToken(extra = {}) {
  const tokenId = randomBytes(8).toString('hex');
  const secret = randomBytes(32).toString('hex');
  const presented = `${tokenId}.${secret}`;
  const tokenHash = createHash('sha256').update(presented, 'utf8').digest('hex');
  return { tokenId, secret, presented, tokenHash, ...extra };
}

function seedToken(table, token, extra = {}) {
  table.seed({
    ...enrollmentToken(token.tokenId),
    tokenHash: token.tokenHash,
    expiresAt: '2026-10-31T00:00:00Z',
    maxUses: 10,
    useCount: 0,
    ...extra,
  });
}

function enrollRequest(presented, body) {
  return {
    method: 'POST',
    path: '/api/v1/enroll',
    query: {},
    headers: { [ENROLLMENT_TOKEN_HEADER]: presented },
    body: JSON.stringify(body),
  };
}

function validBody(overrides = {}) {
  return {
    hostname: 'my-machine',
    platform: 'windows',
    osVersion: '10.0.22631',
    hardwareUuid: 'HW-TEST-001',
    agentVersion: '1.4.0',
    ...overrides,
  };
}

function eventsOf(table, deviceId) {
  const { pk } = deviceProfile(deviceId);
  return table.all().filter((item) => item.pk === pk && item.sk.startsWith('EVENT#'));
}

function handler(table, now) {
  return createEnrollHandler({ table, pepper: randomHex(32), now: () => now, randomBytes: (size) => randomBytes(size) });
}

// ============================================================================
// Scenario: Enrollment and re-enrollment are recorded (AC10)
// ============================================================================

test('Scenario: Enrollment and re-enrollment are recorded (AC10)', async () => {
  const table = new FakeTable();
  const token = createEnrollmentToken();
  seedToken(table, token, { enrolledBy: { oid: 'o-1', upn: 'bob@x' } });
  const now = new Date('2026-10-12T01:00:00Z');

  // When a new machine enrolls with agentVersion "1.4.0", ownership "officehq"
  // and enrolledBy upn "bob@x"
  const first = await handler(table, now)(
    enrollRequest(token.presented, validBody({ ownership: 'officehq', agentVersion: '1.4.0' })),
  );
  assert.strictEqual(first.statusCode, 200);
  const deviceId = first.body.deviceId;

  // Then its event "device.enrolled" "Device enrolled" has source "agent" and
  // the right details
  let events = eventsOf(table, deviceId);
  const enrolled = events.find((event) => event.type === 'device.enrolled');
  assert.ok(enrolled, 'expected a device.enrolled event');
  assert.strictEqual(enrolled.summary, 'Device enrolled');
  assert.strictEqual(enrolled.source, 'agent');
  assert.strictEqual(enrolled.actor, null);
  assert.deepStrictEqual(enrolled.details, { ownership: 'officehq', agentVersion: '1.4.0', enrolledBy: 'bob@x' });

  // When the same hardware uuid enrolls again
  const token2 = createEnrollmentToken();
  seedToken(table, token2);
  const second = await handler(table, new Date(now.getTime() + 1000))(
    enrollRequest(token2.presented, validBody({ ownership: 'officehq', agentVersion: '1.4.1' })),
  );
  assert.strictEqual(second.statusCode, 200);
  assert.strictEqual(second.body.deviceId, deviceId);

  // Then the device also has an event "device.reenrolled" "Device re-enrolled"
  events = eventsOf(table, deviceId);
  const reenrolled = events.find((event) => event.type === 'device.reenrolled');
  assert.ok(reenrolled, 'expected a device.reenrolled event');
  assert.strictEqual(reenrolled.summary, 'Device re-enrolled');
  assert.strictEqual(reenrolled.source, 'agent');
});

// ============================================================================
// Scenario: A refused enrollment records nothing (AC10)
// ============================================================================

test('Scenario: A refused enrollment records nothing (AC10)', async () => {
  const table = new FakeTable();
  const token = createEnrollmentToken();
  // Given a revoked token
  seedToken(table, token, { revokedAt: '2026-10-11T00:00:00Z' });
  const now = new Date('2026-10-12T01:00:00Z');

  // When an enrollment presents a revoked token
  const result = await handler(table, now)(enrollRequest(token.presented, validBody()));
  assert.strictEqual(result.statusCode, 403);

  // Then no EVENT# item is written anywhere in the table
  assert.strictEqual(table.all().filter((item) => String(item.sk).startsWith('EVENT#')).length, 0);
});

// ============================================================================
// Scenario: Joining a default group is recorded as a system event (AC9)
// ============================================================================

test('Scenario: Joining a default group is recorded as a system event (AC9)', async () => {
  const table = new FakeTable();
  // Given the default group for "byoc" is "grp-byod" named "BYOD"
  table.seed({ ...group('grp-byod'), ...groupListIndex('BYOD'), groupId: 'grp-byod', name: 'BYOD' });
  table.seed({ ...defaultAssignmentSettings(), officehq: null, byoc: 'grp-byod' });
  const token = createEnrollmentToken();
  seedToken(table, token);
  const now = new Date('2026-10-12T01:00:00Z');

  // When a device enrolls with ownership "byoc"
  const result = await handler(table, now)(enrollRequest(token.presented, validBody({ ownership: 'byoc' })));
  assert.strictEqual(result.statusCode, 200);

  // Then the device has a "group.added" event with source "system", actor
  // null, summary "Auto-assigned to group BYOD" and details groupId
  // "grp-byod", ownership "byoc"
  const events = eventsOf(table, result.body.deviceId);
  const groupEvent = events.find((event) => event.type === 'group.added');
  assert.ok(groupEvent, 'expected a group.added event');
  assert.strictEqual(groupEvent.source, 'system');
  assert.strictEqual(groupEvent.actor, null);
  assert.strictEqual(groupEvent.summary, 'Auto-assigned to group BYOD');
  assert.deepStrictEqual(groupEvent.details, { groupId: 'grp-byod', ownership: 'byoc' });
});

// ============================================================================
// Scenario: No default group means no group event (AC9)
// ============================================================================

test('Scenario: No default group means no group event (AC9)', async () => {
  const table = new FakeTable();
  // Given no default group is configured for "officehq" (no CONFIG/ASSIGNMENT item at all)
  const token = createEnrollmentToken();
  seedToken(table, token);
  const now = new Date('2026-10-12T01:00:00Z');

  // When a device enrolls with ownership "officehq"
  const result = await handler(table, now)(enrollRequest(token.presented, validBody({ ownership: 'officehq' })));
  assert.strictEqual(result.statusCode, 200);

  // Then the device has no "group.added" event
  const events = eventsOf(table, result.body.deviceId);
  assert.strictEqual(events.filter((event) => event.type === 'group.added').length, 0);
});

test('Unit: enrolledBy is omitted from details when the token names no upn', async () => {
  const table = new FakeTable();
  const token = createEnrollmentToken();
  seedToken(table, token);
  const now = new Date('2026-10-12T01:00:00Z');
  const result = await handler(table, now)(enrollRequest(token.presented, validBody({ ownership: 'officehq' })));
  const enrolled = eventsOf(table, result.body.deviceId).find((event) => event.type === 'device.enrolled');
  assert.deepStrictEqual(enrolled.details, { ownership: 'officehq', agentVersion: '1.4.0' });
  assert.ok(!('enrolledBy' in enrolled.details));
});
