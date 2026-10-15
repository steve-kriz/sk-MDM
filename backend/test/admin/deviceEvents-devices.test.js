/**
 * E2E and unit tests for TASK-067 (History view): the device events written by
 * the admin device routes (disable/enable/update) and the device detail's
 * `deviceEvents` field, plus the delete route's partition cleanup. Tests
 * implement the ticket's Gherkin scenarios in Given/When/Then style using
 * node:test. All database calls are mocked; no real DB connection is ever
 * made.
 */
import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const { handleDeviceDisable, handleDeviceEnable, handleDeviceUpdate, handleDeviceDetail, handleDeviceDelete } =
  await import(`file://${join(__dirname, '../../dist/admin/devices.js')}`);
const { deviceProfile, deviceEvent, group, groupListIndex, defaultAssignmentSettings } = await import(
  `file://${join(__dirname, '../../dist/db/keys.js')}`
);
const { FakeTable } = await import('../helpers/fakeTable.js');

const claims = { preferred_username: 'alice@x' };

function profile(deviceId, extra = {}) {
  return { ...deviceProfile(deviceId), deviceId, hostname: `host-${deviceId}`, ...extra };
}

function eventsOf(table, deviceId) {
  const { pk } = deviceProfile(deviceId);
  return table.all().filter((item) => item.pk === pk && item.sk.startsWith('EVENT#'));
}

// ============================================================================
// Scenario: Disable and enable are recorded (AC4)
// ============================================================================

test('Scenario: Disable and enable are recorded (AC4)', async () => {
  const table = new FakeTable();
  table.seed(profile('dev-1'));
  const now = new Date('2026-10-12T01:00:00Z');
  const deps = { table, now: () => now };

  // When admin "alice@x" disables and then enables "dev-1"
  const disableResult = await handleDeviceDisable({ params: { deviceId: 'dev-1' }, query: {}, headers: {}, claims }, deps);
  assert.strictEqual(disableResult.statusCode, 200);
  const enableResult = await handleDeviceEnable({ params: { deviceId: 'dev-1' }, query: {}, headers: {}, claims }, deps);
  assert.strictEqual(enableResult.statusCode, 200);

  // Then "dev-1" has events "device.disabled" and "device.enabled", both
  // source "admin" and actor "alice@x"
  const events = eventsOf(table, 'dev-1');
  assert.strictEqual(events.length, 2);
  const disabled = events.find((event) => event.type === 'device.disabled');
  const enabled = events.find((event) => event.type === 'device.enabled');
  assert.strictEqual(disabled.summary, 'Device disabled');
  assert.strictEqual(disabled.source, 'admin');
  assert.strictEqual(disabled.actor, 'alice@x');
  assert.strictEqual(enabled.summary, 'Device enabled');
  assert.strictEqual(enabled.source, 'admin');
  assert.strictEqual(enabled.actor, 'alice@x');
});

// ============================================================================
// Scenario: A refused disable records nothing (AC4)
// ============================================================================

test('Scenario: A refused disable records nothing (AC4)', async () => {
  const table = new FakeTable();
  // Given "dev-1" is already disabled
  table.seed(profile('dev-1', { status: 'revoked' }));
  const now = new Date('2026-10-12T01:00:00Z');

  // When an admin disables "dev-1"
  const result = await handleDeviceDisable(
    { params: { deviceId: 'dev-1' }, query: {}, headers: {}, claims },
    { table, now: () => now },
  );

  // Then the response is 409 and no EVENT# item is written
  assert.strictEqual(result.statusCode, 409);
  assert.strictEqual(eventsOf(table, 'dev-1').length, 0);
});

test('Unit: a 404 disable (unknown device) writes no event', async () => {
  const table = new FakeTable();
  const result = await handleDeviceDisable(
    { params: { deviceId: 'ghost' }, query: {}, headers: {}, claims },
    { table, now: () => new Date() },
  );
  assert.strictEqual(result.statusCode, 404);
  assert.strictEqual(eventsOf(table, 'ghost').length, 0);
});

test('Unit: enabling a device that is not disabled is 409 and writes no event', async () => {
  const table = new FakeTable();
  table.seed(profile('dev-1'));
  const result = await handleDeviceEnable(
    { params: { deviceId: 'dev-1' }, query: {}, headers: {}, claims },
    { table, now: () => new Date() },
  );
  assert.strictEqual(result.statusCode, 409);
  assert.strictEqual(eventsOf(table, 'dev-1').length, 0);
});

// ============================================================================
// Scenario: Ownership change is recorded only when it changes (AC5)
// ============================================================================

test('Scenario: Ownership change is recorded only when it changes (AC5)', async () => {
  const table = new FakeTable();
  // Given "dev-1" has ownership "officehq"
  table.seed(profile('dev-1', { ownership: 'officehq' }));
  const now = new Date('2026-10-12T01:00:00Z');
  const req = (ownership) => ({
    params: { deviceId: 'dev-1' },
    query: {},
    headers: {},
    body: JSON.stringify({ ownership }),
    claims,
  });

  // When an admin sets ownership "byoc"
  const first = await handleDeviceUpdate(req('byoc'), { table, now: () => now });
  assert.strictEqual(first.statusCode, 200);

  // Then one event "device.ownership_changed" has the right summary and details
  let events = eventsOf(table, 'dev-1').filter((event) => event.type === 'device.ownership_changed');
  assert.strictEqual(events.length, 1);
  assert.strictEqual(events[0].summary, 'Ownership changed from officehq to byoc');
  assert.deepStrictEqual(events[0].details, { from: 'officehq', to: 'byoc' });
  assert.strictEqual(events[0].source, 'admin');
  assert.strictEqual(events[0].actor, 'alice@x');

  // When an admin sets ownership "byoc" again
  const second = await handleDeviceUpdate(req('byoc'), { table, now: () => now });
  assert.strictEqual(second.statusCode, 200);

  // Then no further "device.ownership_changed" event is written
  events = eventsOf(table, 'dev-1').filter((event) => event.type === 'device.ownership_changed');
  assert.strictEqual(events.length, 1);
});

// ============================================================================
// Scenario: Joining a default group is recorded as a system event (AC9)
// ============================================================================

test('Scenario: Joining a default group is recorded as a system event (AC9, via ownership change)', async () => {
  const table = new FakeTable();
  table.seed(profile('dev-1', { ownership: 'officehq' }));
  table.seed({ ...group('grp-byod'), ...groupListIndex('BYOD'), groupId: 'grp-byod', name: 'BYOD' });
  table.seed({ ...defaultAssignmentSettings(), officehq: null, byoc: 'grp-byod' });
  const now = new Date('2026-10-12T01:00:00Z');

  const result = await handleDeviceUpdate(
    {
      params: { deviceId: 'dev-1' },
      query: {},
      headers: {},
      body: JSON.stringify({ ownership: 'byoc' }),
      claims,
    },
    { table, now: () => now },
  );
  assert.strictEqual(result.statusCode, 200);

  const groupEvent = eventsOf(table, 'dev-1').find((event) => event.type === 'group.added');
  assert.ok(groupEvent, 'expected a group.added system event');
  assert.strictEqual(groupEvent.source, 'system');
  assert.strictEqual(groupEvent.actor, null);
  assert.strictEqual(groupEvent.summary, 'Auto-assigned to group BYOD');
  assert.deepStrictEqual(groupEvent.details, { groupId: 'grp-byod', ownership: 'byoc' });
});

test('Unit: no default group configured means no group.added event on ownership change (AC9)', async () => {
  const table = new FakeTable();
  table.seed(profile('dev-1', { ownership: 'officehq' }));
  // No CONFIG/ASSIGNMENT item at all: applyDefaultGroup returns null.
  const result = await handleDeviceUpdate(
    {
      params: { deviceId: 'dev-1' },
      query: {},
      headers: {},
      body: JSON.stringify({ ownership: 'byoc' }),
      claims,
    },
    { table, now: () => new Date('2026-10-12T01:00:00Z') },
  );
  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(eventsOf(table, 'dev-1').filter((event) => event.type === 'group.added').length, 0);
});

// ============================================================================
// Scenario: Detail endpoint returns recent events newest first (AC16)
// ============================================================================

test('Scenario: Detail endpoint returns recent events newest first (AC16)', async () => {
  const table = new FakeTable();
  table.seed(profile('dev-1'));
  const now = new Date('2026-10-12T00:00:00Z');

  // Given "dev-1" has 120 events within 30 days and 1 event from 31 days ago
  for (let i = 0; i < 120; i += 1) {
    const occurredAt = new Date(now.getTime() - i * 1000).toISOString().replace(/\.\d+Z$/, 'Z');
    const eventId = String(i).padStart(32, '0');
    table.seed({
      ...deviceEvent('dev-1', occurredAt, eventId),
      deviceId: 'dev-1',
      eventId,
      source: 'admin',
      type: 'device.disabled',
      summary: 'Device disabled',
      details: {},
      actor: 'alice@x',
      occurredAt,
      recordedAt: occurredAt,
      ttl: 0,
    });
  }
  const oldOccurredAt = new Date(now.getTime() - 31 * 86400 * 1000).toISOString().replace(/\.\d+Z$/, 'Z');
  table.seed({
    ...deviceEvent('dev-1', oldOccurredAt, 'o'.repeat(32)),
    deviceId: 'dev-1',
    eventId: 'o'.repeat(32),
    source: 'admin',
    type: 'device.disabled',
    summary: 'Old event',
    details: {},
    actor: 'alice@x',
    occurredAt: oldOccurredAt,
    recordedAt: oldOccurredAt,
    ttl: 0,
  });

  // When GET /admin/api/v1/devices/dev-1 is called
  const result = await handleDeviceDetail({ params: { deviceId: 'dev-1' }, query: {}, headers: {} }, { table, now: () => now });
  assert.strictEqual(result.statusCode, 200);

  // Then deviceEvents has 100 entries sorted by occurredAt descending, without
  // the 31-day-old event
  const { deviceEvents } = result.body;
  assert.strictEqual(deviceEvents.length, 100);
  assert.ok(!deviceEvents.some((event) => event.summary === 'Old event'));
  for (let i = 1; i < deviceEvents.length; i += 1) {
    assert.ok(deviceEvents[i - 1].occurredAt >= deviceEvents[i].occurredAt);
  }

  // And each entry has exactly eventId, source, type, summary, details, actor, occurredAt
  for (const event of deviceEvents) {
    assert.deepStrictEqual(Object.keys(event).sort(), [
      'actor',
      'details',
      'eventId',
      'occurredAt',
      'source',
      'summary',
      'type',
    ]);
  }
});

test('Scenario: A device with no events gets an empty list (AC16)', async () => {
  const table = new FakeTable();
  table.seed(profile('dev-2'));

  // When GET /admin/api/v1/devices/dev-2 is called for a device with no EVENT# items
  const result = await handleDeviceDetail(
    { params: { deviceId: 'dev-2' }, query: {}, headers: {} },
    { table, now: () => new Date('2026-10-12T00:00:00Z') },
  );
  assert.strictEqual(result.statusCode, 200);
  // Then deviceEvents is []
  assert.deepStrictEqual(result.body.deviceEvents, []);

  // And a stored event whose details is the string "x" would be returned with details {}
  table.seed({
    ...deviceEvent('dev-2', '2026-10-11T23:00:00Z', 'a'.repeat(32)),
    deviceId: 'dev-2',
    eventId: 'a'.repeat(32),
    source: 'admin',
    type: 'device.disabled',
    summary: 'Device disabled',
    details: 'x',
    actor: 123,
    occurredAt: '2026-10-11T23:00:00Z',
    recordedAt: '2026-10-11T23:00:00Z',
    ttl: 0,
  });
  const second = await handleDeviceDetail(
    { params: { deviceId: 'dev-2' }, query: {}, headers: {} },
    { table, now: () => new Date('2026-10-12T00:00:00Z') },
  );
  assert.strictEqual(second.body.deviceEvents.length, 1);
  assert.deepStrictEqual(second.body.deviceEvents[0].details, {});
  // actor is null when it is not a string
  assert.strictEqual(second.body.deviceEvents[0].actor, null);
});

test('Unit: ties at the same occurredAt order by eventId ascending (AC16)', async () => {
  const table = new FakeTable();
  table.seed(profile('dev-3'));
  const occurredAt = '2026-10-12T00:00:00Z';
  for (const eventId of ['b'.repeat(32), 'a'.repeat(32), 'c'.repeat(32)]) {
    table.seed({
      ...deviceEvent('dev-3', occurredAt, eventId),
      deviceId: 'dev-3',
      eventId,
      source: 'admin',
      type: 'device.disabled',
      summary: 'x',
      details: {},
      actor: null,
      occurredAt,
      recordedAt: occurredAt,
      ttl: 0,
    });
  }
  const result = await handleDeviceDetail(
    { params: { deviceId: 'dev-3' }, query: {}, headers: {} },
    { table, now: () => new Date('2026-10-12T00:00:01Z') },
  );
  assert.deepStrictEqual(
    result.body.deviceEvents.map((event) => event.eventId),
    ['a'.repeat(32), 'b'.repeat(32), 'c'.repeat(32)],
  );
});

// ============================================================================
// Scenario: Deleting a device removes its events (AC18)
// ============================================================================

test('Scenario: Deleting a device removes its events (AC18)', async () => {
  const table = new FakeTable();
  table.seed(profile('dev-1'));
  // Given "dev-1" has 3 EVENT# items
  for (let i = 0; i < 3; i += 1) {
    const occurredAt = `2026-10-1${i}T00:00:00Z`;
    const eventId = String(i).padStart(32, '0');
    table.seed({ ...deviceEvent('dev-1', occurredAt, eventId), deviceId: 'dev-1', occurredAt, eventId });
  }
  assert.strictEqual(eventsOf(table, 'dev-1').length, 3);

  // When "dev-1" is deleted through the admin API
  const result = await handleDeviceDelete(
    { params: { deviceId: 'dev-1' }, query: {}, headers: {}, body: JSON.stringify({ confirm: true }), claims },
    { table, now: () => new Date('2026-10-12T00:00:00Z') },
  );
  assert.strictEqual(result.statusCode, 200);

  // Then no item with pk "DEVICE#dev-1" and an sk starting "EVENT#" remains
  assert.strictEqual(eventsOf(table, 'dev-1').length, 0);
});

// ============================================================================
// Scenario: Audit entries are unchanged (AC19)
// ============================================================================

test('Scenario: Audit entries are unchanged (AC19)', async () => {
  const table = new FakeTable();
  table.seed(profile('dev-1'));
  const now = new Date('2026-10-12T01:00:00Z');

  // When an admin disables "dev-1"
  await handleDeviceDisable({ params: { deviceId: 'dev-1' }, query: {}, headers: {}, claims }, { table, now: () => now });

  // Then the audit item has action "device.disabled", target "dev-1" and
  // detail {source: "admin"} as before
  const audits = table.all().filter((item) => String(item.pk).startsWith('AUDIT#'));
  assert.strictEqual(audits.length, 1);
  assert.strictEqual(audits[0].action, 'device.disabled');
  assert.strictEqual(audits[0].actor, 'alice@x');
  assert.strictEqual(audits[0].target, 'dev-1');
  assert.deepStrictEqual(audits[0].detail, { source: 'admin' });
});

// ============================================================================
// AC17: the device-event query shape.
// ============================================================================

test('Unit: the device-event query uses #pk/#sk placeholders and the EVENT# prefix (AC17)', async () => {
  const table = new FakeTable();
  table.seed(profile('dev-1'));
  const queries = [];
  const originalQuery = table.query.bind(table);
  table.query = async (request) => {
    queries.push(request);
    return originalQuery(request);
  };
  await handleDeviceDetail({ params: { deviceId: 'dev-1' }, query: {}, headers: {} }, { table, now: () => new Date() });

  const eventQuery = queries.find((request) => request.ExpressionAttributeValues?.[':eventPrefix'] === 'EVENT#');
  assert.ok(eventQuery, 'expected a query carrying the EVENT# prefix');
  assert.strictEqual(eventQuery.KeyConditionExpression, '#pk = :pk AND begins_with(#sk, :eventPrefix)');
  assert.deepStrictEqual(eventQuery.ExpressionAttributeNames, { '#pk': 'pk', '#sk': 'sk' });
});
