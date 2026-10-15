/**
 * E2E and unit tests for TASK-067 (History view): the per-device event store
 * primitives -- the `EVENT#` key builder (AC1) and `recordDeviceEvent` (AC2,
 * AC3). Tests implement the ticket's Gherkin scenarios in Given/When/Then
 * style using node:test. All database calls are mocked; no real DB
 * connection is ever made.
 */
import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const { deviceEvent, DEVICE_EVENT_SK_PREFIX } = await import(`file://${join(__dirname, '../dist/db/keys.js')}`);
const {
  recordDeviceEvent,
  deviceEventGroupName,
  DEVICE_EVENT_RETENTION_SECONDS,
  MAX_DETAIL_DEVICE_EVENTS,
} = await import(`file://${join(__dirname, '../dist/deviceEvents.js')}`);
const { handleDeviceDisable } = await import(`file://${join(__dirname, '../dist/admin/devices.js')}`);
const { deviceProfile, group } = await import(`file://${join(__dirname, '../dist/db/keys.js')}`);
const { FakeTable, PutFailingTable, captureWarnings } = await import('./helpers/fakeTable.js');

// ============================================================================
// Scenario: Event keys are built and invalid ids rejected (AC1)
// ============================================================================

test('Scenario: Event keys are built and invalid ids rejected (AC1)', () => {
  assert.strictEqual(DEVICE_EVENT_SK_PREFIX, 'EVENT#');

  // When deviceEvent("dev-1", "2026-10-12T01:02:03Z", "ab12") is built
  const key = deviceEvent('dev-1', '2026-10-12T01:02:03Z', 'ab12');
  // Then the key is pk "DEVICE#dev-1" and sk "EVENT#2026-10-12T01:02:03Z#ab12"
  assert.deepStrictEqual(key, { pk: 'DEVICE#dev-1', sk: 'EVENT#2026-10-12T01:02:03Z#ab12' });

  // And deviceEvent("dev#1", ...) throws "invalid id: dev#1"
  assert.throws(() => deviceEvent('dev#1', '2026-10-12T01:02:03Z', 'ab12'), /invalid id: dev#1/);
  assert.throws(() => deviceEvent('dev-1', '2026-10-12T01:02:03Z#x', 'ab12'), /invalid id:/);
  assert.throws(() => deviceEvent('dev-1', '2026-10-12T01:02:03Z', 'ab#12'), /invalid id:/);

  // deviceEvent(id, '', '') yields the partition key, for queries.
  assert.deepStrictEqual(deviceEvent('dev-1', '', ''), { pk: 'DEVICE#dev-1', sk: 'EVENT##' });
});

// ============================================================================
// Scenario: recordDeviceEvent stores a normalised item (AC2)
// ============================================================================

test('Scenario: recordDeviceEvent stores a normalised item (AC2)', async () => {
  assert.strictEqual(DEVICE_EVENT_RETENTION_SECONDS, 2592000);
  assert.strictEqual(MAX_DETAIL_DEVICE_EVENTS, 100);

  const table = new FakeTable();
  const longSummary = 'S'.repeat(400);
  const longValue = 'x'.repeat(300);
  // 10 string entries, with one 300-character value, and one numeric entry
  // mixed in (skipped, and not counted toward the cap of 8).
  const details = { numeric: 42 };
  for (let i = 1; i <= 10; i += 1) {
    details[`key${i}`] = i === 3 ? longValue : `value${i}`;
  }

  // When recordDeviceEvent stores source "admin", type "device.disabled", a
  // 400-character summary, those details, actor "alice@x", occurredAt
  // 2026-10-12T01:02:03Z and no eventId
  await recordDeviceEvent(table, {
    deviceId: 'dev-1',
    source: 'admin',
    type: 'device.disabled',
    summary: longSummary,
    details,
    actor: 'alice@x',
    occurredAt: '2026-10-12T01:02:03Z',
  });

  // Then one item is put under deviceEvent(...)
  assert.strictEqual(table.puts.length, 1);
  const item = table.puts[0];
  assert.strictEqual(item.pk, 'DEVICE#dev-1');
  assert.match(item.sk, /^EVENT#2026-10-12T01:02:03Z#[0-9a-f]{32}$/);
  assert.strictEqual(item.deviceId, 'dev-1');
  assert.strictEqual(item.source, 'admin');
  assert.strictEqual(item.type, 'device.disabled');

  // summary length 256
  assert.strictEqual(item.summary.length, 256);
  assert.strictEqual(item.summary, 'S'.repeat(256));

  // 8 string details, the long value cut to 256 characters, numeric and the
  // trailing two string entries dropped by the cap.
  assert.strictEqual(Object.keys(item.details).length, 8);
  assert.strictEqual(item.details.key1, 'value1');
  assert.strictEqual(item.details.key3.length, 256);
  assert.strictEqual(item.details.key3, 'x'.repeat(256));
  assert.strictEqual(item.details.key8, 'value8');
  assert.strictEqual(item.details.key9, undefined);
  assert.strictEqual(item.details.numeric, undefined);

  // actor "alice@x"
  assert.strictEqual(item.actor, 'alice@x');

  // occurredAt and ttl epoch(2026-10-12T01:02:03Z)+2592000
  assert.strictEqual(item.occurredAt, '2026-10-12T01:02:03Z');
  const expectedTtl = Math.floor(Date.parse('2026-10-12T01:02:03Z') / 1000) + 2592000;
  assert.strictEqual(item.ttl, expectedTtl);

  // an eventId matching /^[0-9a-f]{32}$/
  assert.match(item.eventId, /^[0-9a-f]{32}$/);

  // recordedAt is present
  assert.strictEqual(typeof item.recordedAt, 'string');
});

test('Unit: details is {} when absent, actor is null when not given, eventId given is used as is', async () => {
  const table = new FakeTable();
  await recordDeviceEvent(table, {
    deviceId: 'dev-2',
    source: 'system',
    type: 'group.added',
    summary: 'Added to default group X',
    occurredAt: new Date('2026-10-12T01:02:03Z'),
    eventId: 'deadbeefdeadbeefdeadbeefdeadbeef',
  });
  const item = table.puts[0];
  assert.deepStrictEqual(item.details, {});
  assert.strictEqual(item.actor, null);
  assert.strictEqual(item.eventId, 'deadbeefdeadbeefdeadbeefdeadbeef');
  assert.strictEqual(item.sk, 'EVENT#2026-10-12T01:02:03Z#deadbeefdeadbeefdeadbeefdeadbeef');
});

test('Unit: a Date occurredAt is converted with isoUtc; a non-object details value yields {}', async () => {
  const table = new FakeTable();
  await recordDeviceEvent(table, {
    deviceId: 'dev-3',
    source: 'agent',
    type: 'device.enrolled',
    summary: 'Device enrolled',
    details: 'not-an-object',
    occurredAt: new Date('2026-10-12T01:02:03.999Z'),
  });
  const item = table.puts[0];
  assert.strictEqual(item.occurredAt, '2026-10-12T01:02:03Z');
  assert.deepStrictEqual(item.details, {});
});

// ============================================================================
// Scenario: A fractional-seconds occurredAt string is normalised (AC2)
// ============================================================================

test('Unit: a string occurredAt with fractional seconds is normalised to seconds precision (AC2)', async () => {
  const table = new FakeTable();
  await recordDeviceEvent(table, {
    deviceId: 'dev-4',
    source: 'agent',
    type: 'defender.protections_applied',
    summary: 'Defender protections applied: realTimeMonitoring',
    occurredAt: '2026-10-12T01:02:03.456Z',
  });
  const item = table.puts[0];
  assert.strictEqual(item.occurredAt, '2026-10-12T01:02:03Z');
  assert.strictEqual(item.sk, `EVENT#2026-10-12T01:02:03Z#${item.eventId}`);
});

// ============================================================================
// Scenario: A failing event write never fails the route (AC3)
// ============================================================================

test('Scenario: A failing event write never fails the route (AC3)', async () => {
  // Given a table whose put throws for any sk starting "EVENT#"
  const workingTable = new FakeTable();
  workingTable.seed({ ...deviceProfile('dev-1'), deviceId: 'dev-1', hostname: 'host-1' });
  const now = new Date('2026-10-12T01:00:00Z');
  const workingResult = await handleDeviceDisable(
    { params: { deviceId: 'dev-1' }, query: {}, headers: {}, claims: { preferred_username: 'alice@x' } },
    { table: workingTable, now: () => now },
  );

  const failingTable = new PutFailingTable('EVENT#');
  failingTable.seed({ ...deviceProfile('dev-1'), deviceId: 'dev-1', hostname: 'host-1' });

  const warnings = await captureWarnings(async () => {
    // When an admin disables device "dev-1"
    const result = await handleDeviceDisable(
      { params: { deviceId: 'dev-1' }, query: {}, headers: {}, claims: { preferred_username: 'alice@x' } },
      { table: failingTable, now: () => now },
    );
    // Then the response is 200 with the same body as with a working table
    assert.strictEqual(result.statusCode, 200);
    assert.deepStrictEqual(result.body, workingResult.body);
  });

  // And one console.warn line has msg "device event not recorded", deviceId
  // "dev-1", type "device.disabled"
  assert.strictEqual(warnings.length, 1);
  const parsed = JSON.parse(warnings[0]);
  assert.strictEqual(parsed.msg, 'device event not recorded');
  assert.strictEqual(parsed.deviceId, 'dev-1');
  assert.strictEqual(parsed.type, 'device.disabled');

  // And nothing with an EVENT# sk was written
  assert.strictEqual(failingTable.withSkPrefix('EVENT#').length, 0);
});

test('Unit: recordDeviceEvent never rejects even when building the item throws', async () => {
  const table = new FakeTable();
  const warnings = await captureWarnings(async () => {
    // occurredAt that cannot be parsed into a date throws inside the try block.
    await recordDeviceEvent(table, {
      deviceId: 'dev-5',
      source: 'admin',
      type: 'device.disabled',
      summary: 'Device disabled',
      occurredAt: 'not-a-date',
    });
  });
  assert.strictEqual(table.puts.length, 0);
  assert.strictEqual(warnings.length, 1);
  const parsed = JSON.parse(warnings[0]);
  assert.strictEqual(parsed.deviceId, 'dev-5');
  assert.strictEqual(parsed.type, 'device.disabled');
});

// ============================================================================
// deviceEventGroupName: the name a group is shown by in an event summary.
// ============================================================================

test('Unit: deviceEventGroupName reads the group record name, else the id', async () => {
  const table = new FakeTable();
  table.seed({ ...group('grp-1'), groupId: 'grp-1', name: 'Sales' });
  assert.strictEqual(await deviceEventGroupName(table, 'grp-1'), 'Sales');
  assert.strictEqual(await deviceEventGroupName(table, 'grp-missing'), 'grp-missing');
});

test('Unit: deviceEventGroupName falls back to the id when the read throws', async () => {
  const table = { get: async () => { throw new Error('boom'); } };
  assert.strictEqual(await deviceEventGroupName(table, 'grp-1'), 'grp-1');
});
