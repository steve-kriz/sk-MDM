/**
 * TASK-047: default group assignment by ownership, applied by the enroll
 * route. E2E cucumber-style scenarios (Given/When/Then) implementing the
 * ticket's Gherkin for AC7-AC13. The table is an in-memory fake; nothing here
 * opens a real database connection.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { randomBytes, createHash } from 'node:crypto';

const { createEnrollHandler, ENROLLMENT_TOKEN_HEADER } = await import('../../dist/routes/enroll.js');
const {
  enrollmentToken,
  group,
  groupListIndex,
  groupMember,
  groupIndex,
  policyAssignment,
  policyAssignmentIndex,
  defaultAssignmentSettings,
} = await import('../../dist/db/keys.js');
const { readAssignedPolicyIds } = await import('../../dist/policies/resolve.js');

function randomHex(bytes = 32) {
  return randomBytes(bytes).toString('hex');
}

/** In-memory fake implementing exactly what enroll.ts and resolve.ts need. */
class FakeTable {
  constructor() {
    this.items = new Map();
    this.conditionResults = new Map();
    this.throwOnGet = null; // (key) => boolean
    this.throwOnPut = null; // (item) => boolean
  }

  keyStr(key) {
    return JSON.stringify({ pk: key.pk, sk: key.sk });
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
    const keyStr = this.keyStr(key);
    const conditionKey = `update-${keyStr}`;
    if (this.conditionResults.has(conditionKey)) {
      const result = this.conditionResults.get(conditionKey);
      if (result instanceof Error) throw result;
    }
    const existing = this.items.get(keyStr) || {};
    const updated = { ...existing, ...key };
    if (fields?.ExpressionAttributeValues?.[':zero'] !== undefined) {
      updated.useCount = (existing.useCount ?? 0) + 1;
    }
    if (fields?.UpdateExpression?.includes('list_append')) {
      const deviceIdList = fields?.ExpressionAttributeValues?.[':deviceIdList'];
      if (Array.isArray(deviceIdList)) {
        updated.deviceIds = [...(existing.deviceIds || []), ...deviceIdList];
      }
    }
    this.items.set(keyStr, updated);
    return updated;
  }

  /** Enough query support for readAssignedPolicyIds: filter by gsi1pk equality. */
  async query(request) {
    const gsi1pk = request?.ExpressionAttributeValues?.[':gsi1pk'];
    const items =
      gsi1pk !== undefined ? [...this.items.values()].filter((item) => item.gsi1pk === gsi1pk) : [];
    return { items, cursor: null };
  }

  setItem(item) {
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  getItem(key) {
    return this.items.get(this.keyStr(key));
  }

  memberItems() {
    return [...this.items.values()].filter((item) => typeof item.sk === 'string' && item.sk.startsWith('MEMBER#'));
  }

  makeConditionalCheckFail(key) {
    const error = new Error('ConditionalCheckFailedException');
    error.name = 'ConditionalCheckFailedException';
    this.conditionResults.set(`update-${this.keyStr(key)}`, error);
  }

  seedGroup(groupId, name = `Group ${groupId}`) {
    this.setItem({ ...group(groupId), ...groupListIndex(name), groupId, name, createdAt: '2026-01-01T00:00:00Z' });
  }

  seedAssignment(policyId, groupId) {
    this.setItem({
      ...policyAssignment(policyId, groupId),
      ...policyAssignmentIndex(groupId, policyId),
      policyId,
      groupId,
      assignedAt: '2026-01-01T00:00:00Z',
    });
  }

  seedMembership(groupId, deviceId) {
    this.setItem({
      ...groupMember(groupId, deviceId),
      ...groupIndex(groupId, deviceId),
      groupId,
      deviceId,
      addedAt: '2026-01-01T00:00:00Z',
    });
  }

  seedSettings(officehq, byoc) {
    this.setItem({ ...defaultAssignmentSettings(), officehq, byoc });
  }
}

function createEnrollmentToken() {
  const tokenId = randomBytes(8).toString('hex');
  const secret = randomBytes(32).toString('hex');
  const presented = `${tokenId}.${secret}`;
  const tokenHash = createHash('sha256').update(presented, 'utf8').digest('hex');
  return { tokenId, secret, presented, tokenHash };
}

function seedToken(table, token, overrides = {}) {
  table.setItem({
    ...enrollmentToken(token.tokenId),
    tokenHash: token.tokenHash,
    expiresAt: '2026-12-31T00:00:00Z',
    maxUses: 100,
    useCount: 0,
    ...overrides,
  });
}

function createEnrollRequest(presented, body = {}) {
  return {
    method: 'POST',
    path: '/api/v1/enroll',
    query: {},
    headers: { [ENROLLMENT_TOKEN_HEADER]: presented },
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

/** Background: groups grp-office / grp-byoc, pol-1 assigned to grp-office. */
function background() {
  const table = new FakeTable();
  table.seedGroup('grp-office', 'Office fleet');
  table.seedGroup('grp-byoc', 'Personal devices');
  table.seedAssignment('pol-1', 'grp-office');
  return table;
}

// ============================================================================
// AC7: A new OfficeHQ device joins the OfficeHQ default group
// ============================================================================

test('AC7: Scenario: A new OfficeHQ device joins the OfficeHQ default group', async () => {
  // Given the setting is {"officehq": "grp-office", "byoc": "grp-byoc"}
  const table = background();
  table.seedSettings('grp-office', 'grp-byoc');
  const token = createEnrollmentToken();
  seedToken(table, token);
  const at = new Date('2026-10-11T12:00:00Z');
  const handler = handlerFor(table, at);

  // When a valid enrollment arrives with no ownership field
  const result = await handler(createEnrollRequest(token.presented, validEnrollBody()));

  // Then the response is 200
  assert.equal(result.statusCode, 200);
  const deviceId = result.body.deviceId;

  // And exactly one item exists at groupMember("grp-office", deviceId) with
  // groupIndex attributes, groupId, deviceId and addedAt equal to the enrollment time
  const item = table.getItem(groupMember('grp-office', deviceId));
  assert.ok(item);
  assert.equal(item.groupId, 'grp-office');
  assert.equal(item.deviceId, deviceId);
  assert.equal(item.addedAt, '2026-10-11T12:00:00Z');
  assert.equal(item.gsi1pk, groupIndex('grp-office', deviceId).gsi1pk);
  assert.equal(item.gsi1sk, groupIndex('grp-office', deviceId).gsi1sk);

  // And readAssignedPolicyIds for the device includes "pol-1"
  const assigned = await readAssignedPolicyIds(table, deviceId);
  assert.ok(assigned.includes('pol-1'));
});

// ============================================================================
// AC8: A new BYOC device joins only the BYOC default group
// ============================================================================

test('AC8: Scenario: A new BYOC device joins only the BYOC default group', async () => {
  const table = background();
  table.seedSettings('grp-office', 'grp-byoc');
  const token = createEnrollmentToken();
  seedToken(table, token);
  const handler = handlerFor(table);

  const result = await handler(createEnrollRequest(token.presented, validEnrollBody({ ownership: 'byoc' })));
  assert.equal(result.statusCode, 200);
  const deviceId = result.body.deviceId;

  // A membership exists in grp-byoc
  assert.ok(table.getItem(groupMember('grp-byoc', deviceId)));
  // No membership exists in grp-office
  assert.equal(table.getItem(groupMember('grp-office', deviceId)), undefined);
});

// ============================================================================
// AC9 (edge): No default group means no membership
// ============================================================================

const noDefaultCases = [
  { label: 'no CONFIG/ASSIGNMENT item exists', setup: () => {} },
  { label: 'the setting is {"officehq": "grp-office", "byoc": null}', setup: (t) => t.seedSettings('grp-office', null) },
  {
    label: 'the setting maps byoc to "grp-gone" which has no group record',
    setup: (t) => t.seedSettings(null, 'grp-gone'),
  },
];

for (const { label, setup } of noDefaultCases) {
  test(`AC9: Scenario Outline: No default group means no membership - ${label}`, async () => {
    const table = background();
    setup(table);
    const token = createEnrollmentToken();
    seedToken(table, token);
    const handler = handlerFor(table);

    const result = await handler(createEnrollRequest(token.presented, validEnrollBody({ ownership: 'byoc' })));

    // Then the response is 200
    assert.equal(result.statusCode, 200);
    // And no groupMember item exists for the device
    assert.equal(table.memberItems().filter((item) => item.deviceId === result.body.deviceId).length, 0);
  });
}

// ============================================================================
// AC10 (edge): Re-binding
// ============================================================================

test('AC10: Scenario: Re-binding applies the new ownership default and keeps old memberships', async () => {
  const table = background();
  table.seedSettings('grp-office', 'grp-byoc');
  const token = createEnrollmentToken();
  seedToken(table, token, { maxUses: 100 });
  const handler = handlerFor(table);
  const hardwareUuid = `HW-${randomHex(4)}`;

  // Given a device enrolled as officehq is a member of grp-office
  const first = await handler(createEnrollRequest(token.presented, validEnrollBody({ hardwareUuid })));
  assert.equal(first.statusCode, 200);
  const deviceId = first.body.deviceId;
  assert.ok(table.getItem(groupMember('grp-office', deviceId)));

  // When the same hardwareUuid re-enrolls with ownership "byoc"
  const second = await handler(
    createEnrollRequest(token.presented, validEnrollBody({ hardwareUuid, ownership: 'byoc' })),
  );
  assert.equal(second.statusCode, 200);
  assert.equal(second.body.deviceId, deviceId);

  // Then the device is a member of grp-byoc
  assert.ok(table.getItem(groupMember('grp-byoc', deviceId)));
  // And the device is still a member of grp-office
  assert.ok(table.getItem(groupMember('grp-office', deviceId)));
});

test('AC10: Scenario: Re-binding into an existing membership does not duplicate it', async () => {
  const table = background();
  table.seedSettings('grp-office', null);
  const token = createEnrollmentToken();
  seedToken(table, token, { maxUses: 100 });
  const handler = handlerFor(table);
  const hardwareUuid = `HW-${randomHex(4)}`;

  const first = await handler(createEnrollRequest(token.presented, validEnrollBody({ hardwareUuid })));
  const deviceId = first.body.deviceId;
  await handler(createEnrollRequest(token.presented, validEnrollBody({ hardwareUuid })));

  const matches = table.memberItems().filter((item) => item.deviceId === deviceId && item.groupId === 'grp-office');
  assert.equal(matches.length, 1);
});

// ============================================================================
// AC11: The enrollment audit names the default group
// ============================================================================

test('AC11: Scenario: The enrollment audit names the default group', async () => {
  const table = background();
  table.seedSettings('grp-office', null);
  const handler = handlerFor(table);

  const token1 = createEnrollmentToken();
  seedToken(table, token1);
  const result1 = await handler(createEnrollRequest(token1.presented, validEnrollBody({ ownership: 'officehq' })));
  assert.equal(result1.statusCode, 200);
  const audit1 = [...table.items.values()].find(
    (item) => item.action === 'device.enrolled' && item.target === result1.body.deviceId,
  );
  assert.ok(audit1, 'expected a device.enrolled audit entry');
  assert.deepEqual(audit1.detail.autoAssignGroupIds, ['grp-office']);

  const token2 = createEnrollmentToken();
  seedToken(table, token2);
  const result2 = await handler(
    createEnrollRequest(token2.presented, validEnrollBody({ ownership: 'byoc', hardwareUuid: `HW-${randomHex(4)}` })),
  );
  assert.equal(result2.statusCode, 200);
  const audit2 = [...table.items.values()].find(
    (item) => item.action === 'device.enrolled' && item.target === result2.body.deviceId,
  );
  assert.ok(audit2);
  assert.ok(!('autoAssignGroupIds' in audit2.detail));
});

// ============================================================================
// AC12 (failure): A failing default assignment never fails enrollment
// ============================================================================

test('AC12: Scenario Outline: the CONFIG/ASSIGNMENT item read throws', async () => {
  const table = background();
  table.seedSettings('grp-office', null);
  table.throwOnGet = (key) => key.pk === 'CONFIG' && key.sk === 'ASSIGNMENT';
  const token = createEnrollmentToken();
  seedToken(table, token);
  const handler = handlerFor(table);

  const result = await handler(createEnrollRequest(token.presented, validEnrollBody({ ownership: 'officehq' })));

  assert.equal(result.statusCode, 200);
  assert.ok(result.body.deviceId);
  assert.equal(result.body.deviceSecret.length, 64);
  const profile = table.getItem({ pk: `DEVICE#${result.body.deviceId}`, sk: 'PROFILE' });
  assert.ok(profile, 'device profile is written');
  const audit = [...table.items.values()].find(
    (item) => item.action === 'device.enrolled' && item.target === result.body.deviceId,
  );
  assert.ok(audit);
  assert.ok(!('defaultGroupId' in audit.detail));
});

test('AC12: Scenario Outline: the groupMember item write throws', async () => {
  const table = background();
  table.seedSettings('grp-office', null);
  table.throwOnPut = (item) => typeof item.sk === 'string' && item.sk.startsWith('MEMBER#');
  const token = createEnrollmentToken();
  seedToken(table, token);
  const handler = handlerFor(table);

  const result = await handler(createEnrollRequest(token.presented, validEnrollBody({ ownership: 'officehq' })));

  assert.equal(result.statusCode, 200);
  assert.ok(result.body.deviceId);
  assert.equal(result.body.deviceSecret.length, 64);
  const profile = table.getItem({ pk: `DEVICE#${result.body.deviceId}`, sk: 'PROFILE' });
  assert.ok(profile, 'device profile is written');
  const audit = [...table.items.values()].find(
    (item) => item.action === 'device.enrolled' && item.target === result.body.deviceId,
  );
  assert.ok(audit);
  assert.ok(!('defaultGroupId' in audit.detail));
});

// ============================================================================
// AC13 (failure): A refused enrollment writes no membership
// ============================================================================

test('AC13: Scenario: A refused enrollment writes no membership', async () => {
  const table = background();
  table.seedSettings('grp-office', null);
  const token = createEnrollmentToken();
  // An expired token.
  seedToken(table, token, { expiresAt: '2020-01-01T00:00:00Z' });
  let readConfig = false;
  const realGet = table.get.bind(table);
  table.get = async (key) => {
    if (key.pk === 'CONFIG' && key.sk === 'ASSIGNMENT') readConfig = true;
    return realGet(key);
  };
  const handler = handlerFor(table);

  const result = await handler(createEnrollRequest(token.presented, validEnrollBody()));

  // Then the response is 403 enrollment_token_expired
  assert.equal(result.statusCode, 403);
  assert.equal(result.body.error, 'enrollment_token_expired');
  // And the CONFIG/ASSIGNMENT item was not read
  assert.equal(readConfig, false);
  // And no groupMember item is written
  assert.equal(table.memberItems().length, 0);
});
