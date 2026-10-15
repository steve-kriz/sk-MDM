/**
 * TASK-047: default group assignment by ownership, applied when an admin
 * changes a device's ownership. These scenarios seed the legacy CONFIG /
 * ASSIGNMENT item, which a group with no autoAssignOwnership of its own still
 * reads (see applyAutoAssignGroups in src/admin/groups.ts) (`PUT /admin/api/v1/devices/{deviceId}`). E2E
 * cucumber-style scenarios (Given/When/Then) for AC15a-AC15d. The table is an
 * in-memory fake; nothing here opens a real database connection.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

const { handleDeviceUpdate, DEVICE_UPDATED_ACTION } = await import('../../dist/admin/devices.js');
const { deviceProfile, group, groupListIndex, groupMember, groupIndex, defaultAssignmentSettings } = await import(
  '../../dist/db/keys.js'
);

class FakeTable {
  constructor() {
    this.items = new Map();
    this.auditItems = [];
    this.throwOnGet = null; // (key) => boolean
    this.throwOnPut = null; // (item) => boolean
  }

  keyStr(key) {
    return `${key.pk}#${key.sk}`;
  }

  async get(key) {
    if (this.throwOnGet && this.throwOnGet(key)) {
      throw new Error('simulated read failure');
    }
    return this.items.get(this.keyStr(key));
  }

  async put(item) {
    if (this.throwOnPut && this.throwOnPut(item)) {
      throw new Error('simulated write failure');
    }
    if (item.action) {
      this.auditItems.push(item);
    }
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  async update(key, fields) {
    const existing = this.items.get(this.keyStr(key)) ?? { ...key };
    const updated = { ...existing };
    const match = /SET\s+#(\w+)\s*=\s*(:\w+)/.exec(fields?.UpdateExpression ?? '');
    if (match) {
      const attrName = fields.ExpressionAttributeNames?.[`#${match[1]}`] ?? match[1];
      updated[attrName] = fields.ExpressionAttributeValues?.[match[2]];
    }
    this.items.set(this.keyStr(key), updated);
    return updated;
  }

  getItem(key) {
    return this.items.get(this.keyStr(key));
  }

  /** The gsi1 group list only: every item in the queried gsi1pk partition. */
  async query(request = {}) {
    const values = request.ExpressionAttributeValues ?? {};
    const items = [...this.items.values()].filter((item) => item.gsi1pk === values[':gsi1pk']);
    return { items, cursor: null };
  }

  memberItems() {
    return [...this.items.values()].filter((item) => typeof item.sk === 'string' && item.sk.startsWith('MEMBER#'));
  }

  seedGroup(groupId, name = `Group ${groupId}`) {
    this.items.set(this.keyStr(group(groupId)), { ...group(groupId), ...groupListIndex(name), groupId, name });
  }

  seedProfile(deviceId, ownership) {
    const key = deviceProfile(deviceId);
    this.items.set(this.keyStr(key), { ...key, deviceId, ownership, hostname: `host-${deviceId}` });
  }

  seedMembership(groupId, deviceId, addedAt = '2026-01-01T00:00:00Z') {
    this.items.set(this.keyStr(groupMember(groupId, deviceId)), {
      ...groupMember(groupId, deviceId),
      ...groupIndex(groupId, deviceId),
      groupId,
      deviceId,
      addedAt,
    });
  }

  seedSettings(officehq, byoc) {
    this.items.set(this.keyStr(defaultAssignmentSettings()), { ...defaultAssignmentSettings(), officehq, byoc });
  }
}

function createRequest(deviceId, body, actor = 'admin@officehq.com.au') {
  return {
    body: JSON.stringify(body),
    params: { deviceId },
    query: {},
    headers: {},
    claims: { sub: 'user123', preferred_username: actor },
  };
}

function createDeps(table, at = new Date('2026-10-11T15:00:00Z')) {
  return { table, now: () => Math.floor(at.getTime() / 1000) };
}

function auditFor(table, deviceId) {
  return table.auditItems.filter((item) => item.action === DEVICE_UPDATED_ACTION && item.target === deviceId);
}

// ============================================================================
// AC15a: Changing ownership adds the new ownership's default group
// ============================================================================

test('AC15a: Scenario: Changing ownership adds the new default group and keeps old memberships', async () => {
  const table = new FakeTable();
  table.seedGroup('grp-office', 'Office fleet');
  table.seedGroup('grp-byoc', 'Personal devices');
  table.seedSettings('grp-office', 'grp-byoc');
  table.seedProfile('dev-a', 'officehq');
  table.seedMembership('grp-office', 'dev-a');

  const result = await handleDeviceUpdate(createRequest('dev-a', { ownership: 'byoc' }), createDeps(table));

  // The response is 200 with body exactly {"deviceId": "dev-a", "ownership": "byoc"}
  assert.equal(result.statusCode, 200);
  assert.deepEqual(result.body, { deviceId: 'dev-a', ownership: 'byoc' });

  // Exactly one item exists at groupMember("grp-byoc", "dev-a") with groupIndex
  // attributes, groupId, deviceId, and addedAt equal to the request time
  const item = table.getItem(groupMember('grp-byoc', 'dev-a'));
  assert.ok(item);
  assert.equal(item.groupId, 'grp-byoc');
  assert.equal(item.deviceId, 'dev-a');
  assert.equal(item.addedAt, '2026-10-11T15:00:00Z');
  assert.equal(item.gsi1pk, groupIndex('grp-byoc', 'dev-a').gsi1pk);

  // Every groupMember item the device held before the request still exists.
  assert.ok(table.getItem(groupMember('grp-office', 'dev-a')));
});

test('AC15a (edge): Changing ownership into a group the device is already in does not duplicate it', async () => {
  const table = new FakeTable();
  table.seedGroup('grp-office', 'Office fleet');
  table.seedGroup('grp-byoc', 'Personal devices');
  table.seedSettings('grp-office', 'grp-byoc');
  table.seedProfile('dev-a', 'officehq');
  table.seedMembership('grp-byoc', 'dev-a');

  await handleDeviceUpdate(createRequest('dev-a', { ownership: 'byoc' }), createDeps(table));

  const matches = table.memberItems().filter((item) => item.deviceId === 'dev-a' && item.groupId === 'grp-byoc');
  assert.equal(matches.length, 1);
});

// ============================================================================
// AC15b (edge): No applicable default writes no membership
// ============================================================================

const noDefaultCases = [
  {
    label: 'setting maps both, to officehq (equals current ownership)',
    setup: (t) => t.seedSettings('grp-office', 'grp-byoc'),
    to: 'officehq',
  },
  {
    label: 'setting maps byoc to null',
    setup: (t) => t.seedSettings('grp-office', null),
    to: 'byoc',
  },
  {
    label: 'no CONFIG/ASSIGNMENT item exists',
    setup: () => {},
    to: 'byoc',
  },
  {
    label: 'the setting maps byoc to a group with no record',
    setup: (t) => t.seedSettings(null, 'grp-gone'),
    to: 'byoc',
  },
];

for (const { label, setup, to } of noDefaultCases) {
  test(`AC15b: Scenario Outline: An ownership change with no applicable default writes no membership - ${label}`, async () => {
    const table = new FakeTable();
    table.seedGroup('grp-office', 'Office fleet');
    table.seedGroup('grp-byoc', 'Personal devices');
    table.seedProfile('dev-a', 'officehq');
    setup(table);

    const result = await handleDeviceUpdate(createRequest('dev-a', { ownership: to }), createDeps(table));

    assert.equal(result.statusCode, 200);
    assert.deepEqual(result.body, { deviceId: 'dev-a', ownership: to });
    assert.equal(table.memberItems().filter((item) => item.deviceId === 'dev-a').length, 0);
  });
}

// ============================================================================
// AC15b (failure): A refused ownership change writes no membership
// ============================================================================

test('AC15b: Scenario Outline: A refused ownership change writes no membership - bad value (400)', async () => {
  const table = new FakeTable();
  table.seedGroup('grp-office', 'Office fleet');
  table.seedGroup('grp-byoc', 'Personal devices');
  table.seedSettings('grp-office', 'grp-byoc');
  table.seedProfile('dev-a', 'officehq');

  const result = await handleDeviceUpdate(createRequest('dev-a', { ownership: 'personal' }), createDeps(table));

  assert.equal(result.statusCode, 400);
  assert.equal(table.memberItems().length, 0);
});

test('AC15b: Scenario Outline: A refused ownership change writes no membership - unknown device (404)', async () => {
  const table = new FakeTable();
  table.seedGroup('grp-office', 'Office fleet');
  table.seedGroup('grp-byoc', 'Personal devices');
  table.seedSettings('grp-office', 'grp-byoc');
  // dev-missing has no profile.

  const result = await handleDeviceUpdate(createRequest('dev-missing', { ownership: 'byoc' }), createDeps(table));

  assert.equal(result.statusCode, 404);
  assert.equal(table.memberItems().length, 0);
});

// ============================================================================
// AC15c (failure): A failing default assignment never fails the ownership change
// ============================================================================

test('AC15c: Scenario Outline: the CONFIG/ASSIGNMENT item read throws', async () => {
  const table = new FakeTable();
  table.seedGroup('grp-office', 'Office fleet');
  table.seedGroup('grp-byoc', 'Personal devices');
  table.seedSettings('grp-office', 'grp-byoc');
  table.seedProfile('dev-a', 'officehq');
  table.throwOnGet = (key) => key.pk === 'CONFIG' && key.sk === 'ASSIGNMENT';

  const result = await handleDeviceUpdate(createRequest('dev-a', { ownership: 'byoc' }), createDeps(table));

  assert.equal(result.statusCode, 200);
  assert.deepEqual(result.body, { deviceId: 'dev-a', ownership: 'byoc' });
  const profile = table.getItem(deviceProfile('dev-a'));
  assert.equal(profile.ownership, 'byoc');
  const entries = auditFor(table, 'dev-a');
  assert.equal(entries.length, 1);
  assert.ok(!('autoAssignGroupIds' in entries[0].detail));
});

test('AC15c: Scenario Outline: the groupMember item write throws', async () => {
  const table = new FakeTable();
  table.seedGroup('grp-office', 'Office fleet');
  table.seedGroup('grp-byoc', 'Personal devices');
  table.seedSettings('grp-office', 'grp-byoc');
  table.seedProfile('dev-a', 'officehq');
  table.throwOnPut = (item) => typeof item.sk === 'string' && item.sk.startsWith('MEMBER#');

  const result = await handleDeviceUpdate(createRequest('dev-a', { ownership: 'byoc' }), createDeps(table));

  assert.equal(result.statusCode, 200);
  assert.deepEqual(result.body, { deviceId: 'dev-a', ownership: 'byoc' });
  const profile = table.getItem(deviceProfile('dev-a'));
  assert.equal(profile.ownership, 'byoc');
  const entries = auditFor(table, 'dev-a');
  assert.equal(entries.length, 1);
  assert.ok(!('autoAssignGroupIds' in entries[0].detail));
});

// ============================================================================
// AC15d: The device.updated audit names the default group only when written
// ============================================================================

test('AC15d: Scenario: The device.updated audit names the default group only when written', async () => {
  const table = new FakeTable();
  table.seedGroup('grp-byoc', 'Personal devices');
  table.seedSettings(null, 'grp-byoc');
  table.seedProfile('dev-a', 'officehq');

  const first = await handleDeviceUpdate(createRequest('dev-a', { ownership: 'byoc' }), createDeps(table));
  assert.equal(first.statusCode, 200);
  const firstEntries = auditFor(table, 'dev-a');
  assert.equal(firstEntries.length, 1);
  assert.deepEqual(firstEntries[0].detail, {
    ownership: { from: 'officehq', to: 'byoc' },
    autoAssignGroupIds: ['grp-byoc'],
  });

  const second = await handleDeviceUpdate(createRequest('dev-a', { ownership: 'officehq' }), createDeps(table));
  assert.equal(second.statusCode, 200);
  const secondEntries = auditFor(table, 'dev-a');
  assert.equal(secondEntries.length, 2);
  assert.deepEqual(secondEntries[1].detail, { ownership: { from: 'byoc', to: 'officehq' } });
});
