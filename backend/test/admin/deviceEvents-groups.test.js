/**
 * E2E and unit tests for TASK-067 (History view): the device events written by
 * the admin group routes (members add/remove, group delete). Tests implement
 * the ticket's Gherkin scenarios in Given/When/Then style using node:test.
 * All database calls are mocked; no real DB connection is ever made.
 */
import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const { handleGroupMembersAdd, handleGroupMembersRemove, handleGroupDelete } = await import(
  `file://${join(__dirname, '../../dist/admin/groups.js')}`
);
const { deviceProfile, group, groupMember, groupIndex, groupListIndex } = await import(
  `file://${join(__dirname, '../../dist/db/keys.js')}`
);
const { FakeTable } = await import('../helpers/fakeTable.js');

const claims = { preferred_username: 'alice@x' };

function profile(deviceId) {
  return { ...deviceProfile(deviceId), deviceId, hostname: `host-${deviceId}` };
}

function eventsOf(table, deviceId) {
  const { pk } = deviceProfile(deviceId);
  return table.all().filter((item) => item.pk === pk && item.sk.startsWith('EVENT#'));
}

function membersRequest(groupId, deviceIds) {
  return { params: { groupId }, query: {}, headers: {}, body: JSON.stringify({ deviceIds }), claims };
}

// ============================================================================
// Scenario: Group membership changes are recorded per device (AC6)
// ============================================================================

test('Scenario: Group membership changes are recorded per device (AC6)', async () => {
  const table = new FakeTable();
  // Given group "grp-1" named "Sales" and devices "dev-1" and "dev-2"
  table.seed({ ...group('grp-1'), ...groupListIndex('Sales'), groupId: 'grp-1', name: 'Sales' });
  table.seed(profile('dev-1'));
  table.seed(profile('dev-2'));
  const now = new Date('2026-10-12T01:00:00Z');
  const deps = { table, now: () => now };

  // When an admin adds ["dev-1", "dev-2", "ghost"] to "grp-1"
  const addResult = await handleGroupMembersAdd(membersRequest('grp-1', ['dev-1', 'dev-2', 'ghost']), deps);
  assert.strictEqual(addResult.statusCode, 200);
  assert.strictEqual(addResult.body.added, 2);

  // Then "dev-1" and "dev-2" each have a "group.added" event with details groupId "grp-1"
  for (const deviceId of ['dev-1', 'dev-2']) {
    const events = eventsOf(table, deviceId);
    assert.strictEqual(events.length, 1);
    assert.strictEqual(events[0].type, 'group.added');
    assert.strictEqual(events[0].summary, 'Added to group Sales');
    assert.deepStrictEqual(events[0].details, { groupId: 'grp-1' });
    assert.strictEqual(events[0].source, 'admin');
  }
  // And no event exists for "ghost"
  assert.strictEqual(eventsOf(table, 'ghost').length, 0);

  // When an admin removes ["dev-1", "dev-3"] from "grp-1"
  const removeResult = await handleGroupMembersRemove(membersRequest('grp-1', ['dev-1', 'dev-3']), deps);
  assert.strictEqual(removeResult.statusCode, 200);
  assert.strictEqual(removeResult.body.removed, 1);

  // Then "dev-1" has a "group.removed" event "Removed from group Sales" and
  // "dev-3" has none
  const dev1Events = eventsOf(table, 'dev-1').filter((event) => event.type === 'group.removed');
  assert.strictEqual(dev1Events.length, 1);
  assert.strictEqual(dev1Events[0].summary, 'Removed from group Sales');
  assert.strictEqual(eventsOf(table, 'dev-3').length, 0);
});

// ============================================================================
// Scenario: Adding to a group with no record uses its id (AC6)
// ============================================================================

test('Scenario: Adding to a group with no record uses its id (AC6)', async () => {
  const table = new FakeTable();
  table.seed(profile('dev-1'));
  const now = new Date('2026-10-12T01:00:00Z');

  // When an admin adds ["dev-1"] to group "grp-missing" which has no group record
  const result = await handleGroupMembersAdd(membersRequest('grp-missing', ['dev-1']), { table, now: () => now });
  assert.strictEqual(result.statusCode, 200);

  // Then "dev-1" has a "group.added" event "Added to group grp-missing"
  const events = eventsOf(table, 'dev-1');
  assert.strictEqual(events.length, 1);
  assert.strictEqual(events[0].summary, 'Added to group grp-missing');
});

test('Unit: ids skipped (unknown device, invalid id, not a member) get no event', async () => {
  const table = new FakeTable();
  table.seed({ ...group('grp-1'), groupId: 'grp-1', name: 'Sales' });
  table.seed(profile('dev-1'));
  const now = new Date('2026-10-12T01:00:00Z');

  // An id containing '#' can never form a key and is skipped by the add route.
  const result = await handleGroupMembersAdd(membersRequest('grp-1', ['dev#bad', 'unknown-device']), {
    table,
    now: () => now,
  });
  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(result.body.added, 0);
  assert.strictEqual(eventsOf(table, 'unknown-device').length, 0);

  // Removing an id that is not a member writes nothing.
  table.seed(profile('dev-2'));
  const removeResult = await handleGroupMembersRemove(membersRequest('grp-1', ['dev-2']), { table, now: () => now });
  assert.strictEqual(removeResult.body.removed, 0);
  assert.strictEqual(eventsOf(table, 'dev-2').length, 0);
});

// ============================================================================
// Scenario: Deleting a group records removal for each member (AC7)
// ============================================================================

test('Scenario: Deleting a group records removal for each member (AC7)', async () => {
  const table = new FakeTable();
  // Given group "grp-1" named "Sales" with members "dev-1" and "dev-2"
  table.seed({ ...group('grp-1'), groupId: 'grp-1', name: 'Sales' });
  for (const deviceId of ['dev-1', 'dev-2']) {
    table.seed(profile(deviceId));
    table.seed({ ...groupMember('grp-1', deviceId), ...groupIndex('grp-1', deviceId), groupId: 'grp-1', deviceId });
  }
  const now = new Date('2026-10-12T01:00:00Z');

  // When an admin deletes "grp-1" with confirm true
  const result = await handleGroupDelete(
    { params: { groupId: 'grp-1' }, query: {}, headers: {}, body: JSON.stringify({ confirm: true }), claims },
    { table, now: () => now },
  );
  assert.strictEqual(result.statusCode, 200);

  // Then "dev-1" and "dev-2" each have a "group.removed" event with the
  // "(group deleted)" summary and reason detail
  for (const deviceId of ['dev-1', 'dev-2']) {
    const events = eventsOf(table, deviceId);
    assert.strictEqual(events.length, 1);
    assert.strictEqual(events[0].type, 'group.removed');
    assert.strictEqual(events[0].summary, 'Removed from group Sales (group deleted)');
    assert.deepStrictEqual(events[0].details, { groupId: 'grp-1', reason: 'group_deleted' });
  }
});

// ============================================================================
// Scenario: An unconfirmed group delete records nothing (AC7)
// ============================================================================

test('Scenario: An unconfirmed group delete records nothing (AC7)', async () => {
  const table = new FakeTable();
  table.seed({ ...group('grp-1'), groupId: 'grp-1', name: 'Sales' });
  table.seed(profile('dev-1'));
  table.seed({ ...groupMember('grp-1', 'dev-1'), ...groupIndex('grp-1', 'dev-1'), groupId: 'grp-1', deviceId: 'dev-1' });

  // When an admin deletes "grp-1" without confirm
  const result = await handleGroupDelete(
    { params: { groupId: 'grp-1' }, query: {}, headers: {}, body: JSON.stringify({}), claims },
    { table, now: () => new Date('2026-10-12T01:00:00Z') },
  );

  // Then the response is 409 and no EVENT# item is written
  assert.strictEqual(result.statusCode, 409);
  assert.strictEqual(eventsOf(table, 'dev-1').length, 0);
});

test('Unit: deleting an unknown group is 404 and writes no event', async () => {
  const table = new FakeTable();
  const result = await handleGroupDelete(
    { params: { groupId: 'ghost' }, query: {}, headers: {}, body: JSON.stringify({ confirm: true }), claims },
    { table, now: () => new Date('2026-10-12T01:00:00Z') },
  );
  assert.strictEqual(result.statusCode, 404);
});
