/**
 * Per-group auto-assign by ownership (`src/admin/groups.ts`): the
 * `PUT /groups/{groupId}/auto-assign` route, the group list's
 * `autoAssignOwnership`, `applyAutoAssignGroups`, and the one-time move of the
 * legacy CONFIG / ASSIGNMENT item onto the groups. The table is the shared
 * in-memory fake; nothing opens a real database connection.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { FakeTable } from '../helpers/fakeTable.js';

const {
  applyAutoAssignGroups,
  handleGroupAutoAssign,
  handleGroupList,
  registerGroupRoutes,
  GROUP_AUTO_ASSIGN_CHANGED_ACTION,
  GROUP_AUTO_ASSIGN_PATH,
  GROUP_SUMMARY_FIELDS,
} = await import('../../dist/admin/groups.js');
const { defaultAssignmentSettings, group, groupListIndex, groupMember } = await import('../../dist/db/keys.js');

const AT = new Date('2026-10-15T01:00:00Z');

function seedGroup(table, groupId, name, extra = {}) {
  table.seed({ ...group(groupId), ...groupListIndex(name), groupId, name, createdAt: '2026-01-01T00:00:00Z', ...extra });
}

function deps(table) {
  return { table, now: () => AT };
}

function req(groupId, body) {
  return {
    params: { groupId },
    query: {},
    headers: {},
    body: body === undefined ? null : JSON.stringify(body),
    claims: { preferred_username: 'admin@officehq.com.au' },
  };
}

function stored(table, groupId) {
  return table.all().find((item) => item.pk === group(groupId).pk && item.sk === group(groupId).sk);
}

function audits(table) {
  return table.all().filter((item) => item.action === GROUP_AUTO_ASSIGN_CHANGED_ACTION);
}

function memberIds(table, deviceId) {
  return table
    .all()
    .filter((item) => item.deviceId === deviceId && typeof item.sk === 'string' && item.sk.startsWith('MEMBER#'))
    .map((item) => item.groupId)
    .sort();
}

test('Scenario: Setting a group to auto-assign BYOD stores it and audits the change', async () => {
  const table = new FakeTable();
  seedGroup(table, 'grp-byod', 'BYOD');

  const result = await handleGroupAutoAssign(req('grp-byod', { ownership: 'byoc' }), deps(table));

  assert.equal(result.statusCode, 200);
  assert.deepEqual(result.body, { groupId: 'grp-byod', autoAssignOwnership: 'byoc' });
  assert.equal(stored(table, 'grp-byod').autoAssignOwnership, 'byoc');
  assert.equal(stored(table, 'grp-byod').name, 'BYOD', 'the record is written back whole');
  const [entry] = audits(table);
  assert.equal(entry.target, 'grp-byod');
  assert.deepEqual(entry.detail, { from: null, to: 'byoc' });
});

test('Scenario: Setting None stores null, which overrides the legacy setting', async () => {
  const table = new FakeTable();
  seedGroup(table, 'grp-office', 'Office', { autoAssignOwnership: 'officehq' });

  const result = await handleGroupAutoAssign(req('grp-office', { ownership: null }), deps(table));

  assert.equal(result.statusCode, 200);
  assert.equal(stored(table, 'grp-office').autoAssignOwnership, null);
  assert.deepEqual(audits(table)[0].detail, { from: 'officehq', to: null });
});

test('Scenario Outline: An invalid auto-assign body is refused and writes nothing', async () => {
  for (const [body, fields] of [
    [{}, ['ownership']],
    [{ ownership: 'byod' }, ['ownership']],
    [{ ownership: '' }, ['ownership']],
    [{ ownership: 'byoc', extra: 1 }, ['extra']],
    [undefined, ['ownership']],
  ]) {
    const table = new FakeTable();
    seedGroup(table, 'grp-1', 'One');
    const result = await handleGroupAutoAssign(req('grp-1', body), deps(table));
    assert.equal(result.statusCode, 400, JSON.stringify(body));
    assert.deepEqual(result.body.fields, fields, JSON.stringify(body));
    assert.ok(!('autoAssignOwnership' in stored(table, 'grp-1')));
  }
});

test('Scenario: An unknown group is 404', async () => {
  const result = await handleGroupAutoAssign(req('grp-missing', { ownership: 'officehq' }), deps(new FakeTable()));
  assert.equal(result.statusCode, 404);
});

test('Scenario: A device joins every group that auto-assigns its ownership, and no other', async () => {
  const table = new FakeTable();
  seedGroup(table, 'grp-a', 'All OfficeHQ', { autoAssignOwnership: 'officehq' });
  seedGroup(table, 'grp-b', 'OfficeHQ Security', { autoAssignOwnership: 'officehq' });
  seedGroup(table, 'grp-c', 'BYOD', { autoAssignOwnership: 'byoc' });
  seedGroup(table, 'grp-d', 'Manual', { autoAssignOwnership: null });

  const joined = await applyAutoAssignGroups(table, 'dev-1', 'officehq', AT);

  assert.deepEqual([...joined].sort(), ['grp-a', 'grp-b']);
  assert.deepEqual(memberIds(table, 'dev-1'), ['grp-a', 'grp-b']);
  const member = table.all().find((item) => item.pk === groupMember('grp-a', 'dev-1').pk && item.sk === groupMember('grp-a', 'dev-1').sk);
  assert.equal(member.addedAt, '2026-10-15T01:00:00Z');
  assert.ok(member.gsi1pk, 'the membership carries the device-list index');

  const again = await applyAutoAssignGroups(table, 'dev-1', 'officehq', AT);
  assert.deepEqual([...again].sort(), ['grp-a', 'grp-b']);
  assert.deepEqual(memberIds(table, 'dev-1'), ['grp-a', 'grp-b'], 'joining twice leaves one membership each');
  assert.deepEqual(await applyAutoAssignGroups(table, 'dev-2', 'something-else', AT), []);
});

test('Scenario: A group without its own value still follows the legacy setting; its own value wins', async () => {
  const table = new FakeTable();
  table.seed({ ...defaultAssignmentSettings(), officehq: 'grp-old', byoc: 'grp-overridden' });
  seedGroup(table, 'grp-old', 'Old default');
  seedGroup(table, 'grp-overridden', 'Overridden', { autoAssignOwnership: null });

  assert.deepEqual(await applyAutoAssignGroups(table, 'dev-1', 'officehq', AT), ['grp-old']);
  assert.deepEqual(await applyAutoAssignGroups(table, 'dev-2', 'byoc', AT), []);

  const list = await handleGroupList(req(undefined), deps(table));
  const byId = Object.fromEntries(list.body.items.map((item) => [item.groupId, item.autoAssignOwnership]));
  assert.deepEqual(byId, { 'grp-old': 'officehq', 'grp-overridden': null });
  assert.deepEqual(Object.keys(list.body.items[0]).sort(), [...GROUP_SUMMARY_FIELDS].sort());
});

test('Scenario: The first auto-assign save moves the legacy setting onto the groups and deletes it', async () => {
  const table = new FakeTable();
  table.seed({ ...defaultAssignmentSettings(), officehq: 'grp-office', byoc: 'grp-gone' });
  seedGroup(table, 'grp-office', 'Office');
  seedGroup(table, 'grp-new', 'New');

  const result = await handleGroupAutoAssign(req('grp-new', { ownership: 'byoc' }), deps(table));

  assert.equal(result.statusCode, 200);
  assert.equal(stored(table, 'grp-office').autoAssignOwnership, 'officehq', 'moved onto its group');
  assert.equal(stored(table, 'grp-new').autoAssignOwnership, 'byoc');
  assert.equal(
    table.all().some((item) => item.pk === 'CONFIG' && item.sk === 'ASSIGNMENT'),
    false,
    'the legacy item is deleted',
  );
  // A deleted group named by the legacy item is skipped, not recreated.
  assert.equal(stored(table, 'grp-gone'), undefined);
  assert.deepEqual(await applyAutoAssignGroups(table, 'dev-1', 'officehq', AT), ['grp-office']);
});

test('Scenario: Moving the legacy setting keeps a group value that was already set', async () => {
  const table = new FakeTable();
  table.seed({ ...defaultAssignmentSettings(), officehq: 'grp-office', byoc: null });
  seedGroup(table, 'grp-office', 'Office', { autoAssignOwnership: null });
  seedGroup(table, 'grp-other', 'Other');

  await handleGroupAutoAssign(req('grp-other', { ownership: 'officehq' }), deps(table));

  assert.equal(stored(table, 'grp-office').autoAssignOwnership, null, 'an explicit None is not overwritten');
});

test('Unit: the auto-assign route is registered', () => {
  const added = [];
  const router = { add: (method, pattern) => (added.push(`${method} ${pattern}`), router) };
  registerGroupRoutes(router, {});
  assert.ok(added.some((route) => route.startsWith('PUT ') && route.endsWith(GROUP_AUTO_ASSIGN_PATH)), added.join(', '));
});
