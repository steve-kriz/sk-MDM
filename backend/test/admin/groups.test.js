/**
 * E2E and unit tests for TASK-011: Admin API groups.
 *
 * Tests implement the Gherkin scenarios in Given/When/Then style using node:test,
 * with all database calls mocked and deterministic clock injection.
 */

import test from 'node:test';
import assert from 'node:assert';
import { createRouter } from '../../dist/index.js';
import { registerGroupRoutes } from '../../dist/admin/groups.js';
import { appendAudit, isoUtc } from '../../dist/audit.js';
import {
  group,
  groupMember,
  groupListIndex,
  deviceProfile,
} from '../../dist/db/keys.js';

// ============================================================================
// Mock Table Client
// ============================================================================

class FakeTable {
  constructor() {
    this.items = new Map();
  }

  async put(item) {
    const key = `${item.pk}#${item.sk}`;
    this.items.set(key, { ...item });
  }

  async get(keyObj) {
    const fullKey = `${keyObj.pk}#${keyObj.sk}`;
    return this.items.get(fullKey);
  }

  async query(request) {
    const items = [];
    const { KeyConditionExpression, ExpressionAttributeNames, ExpressionAttributeValues, IndexName, limit = 50, cursor } = request;

    let startIdx = 0;
    if (cursor) {
      const decoded = JSON.parse(Buffer.from(cursor, 'base64').toString());
      startIdx = decoded.offset || 0;
    }

    for (const [, item] of this.items) {
      if (IndexName === 'gsi1') {
        const gsi1pk = ExpressionAttributeValues[':gsi1pk'];
        if (item.gsi1pk !== gsi1pk) continue;
        items.push(item);
      } else {
        const pk = ExpressionAttributeValues[':pk'];
        if (item.pk !== pk) continue;

        if (KeyConditionExpression.includes('begins_with')) {
          const prefix = ExpressionAttributeValues[':memberPrefix'];
          if (!item.sk.startsWith(prefix)) continue;
        }
        items.push(item);
      }
    }

    const sorted = items.sort((a, b) => {
      const skA = a.sk || '';
      const skB = b.sk || '';
      return skA < skB ? 1 : -1;
    });

    const pageSize = Math.min(limit, sorted.length - startIdx);
    const page = sorted.slice(startIdx, startIdx + pageSize);
    const nextCursor = startIdx + pageSize < sorted.length
      ? Buffer.from(JSON.stringify({ offset: startIdx + pageSize })).toString('base64')
      : null;

    return { items: page, cursor: nextCursor };
  }
}

// ============================================================================
// Mock Token Verifier
// ============================================================================

class StubVerifier {
  constructor(claims = {}) {
    this.claims = { sub: 'user123', preferred_username: 'admin@example.com', ...claims };
  }

  async verify(token) {
    if (token === 'invalid') {
      throw { status: 401, error: 'invalid_token' };
    }
    return this.claims;
  }
}

// ============================================================================
// Helper: Make a request to the router
// ============================================================================

async function makeRequest(router, method, path, options = {}) {
  const { headers = {}, query = {}, body = null } = options;
  return router.handle({
    method,
    path,
    query,
    headers,
    body,
  });
}

// ============================================================================
// Scenario: Group is created and populated
// ============================================================================

test('Scenario: Group is created and populated', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');

  registerGroupRoutes(router, { verifier, table, now: () => now, randomBytes: (n) => Buffer.alloc(n) });

  // Setup: add devices d1 and d2 to the table
  await table.put({
    ...deviceProfile('d1'),
    deviceId: 'd1',
    hostname: 'host-d1',
  });

  await table.put({
    ...deviceProfile('d2'),
    deviceId: 'd2',
    hostname: 'host-d2',
  });

  // When an admin creates group "Finance"
  const createResp = await makeRequest(router, 'POST', '/admin/api/v1/groups', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ name: 'Finance' }),
  });

  assert.strictEqual(createResp.statusCode, 201);
  const createBody = JSON.parse(createResp.body);
  const groupId = createBody.groupId;
  assert.strictEqual(createBody.name, 'Finance');

  // And adds devices d1 and d2
  const addResp = await makeRequest(router, 'POST', `/admin/api/v1/groups/${groupId}/members`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ deviceIds: ['d1', 'd2'] }),
  });

  // Then the status is 201 then 200 and added equals 2
  assert.strictEqual(addResp.statusCode, 200);
  const addBody = JSON.parse(addResp.body);
  assert.strictEqual(addBody.added, 2);
});

// ============================================================================
// Scenario: Adding an unknown device is not counted
// ============================================================================

test('Scenario: Adding an unknown device is not counted', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');

  registerGroupRoutes(router, { verifier, table, now: () => now, randomBytes: (n) => Buffer.alloc(n) });

  // Setup: add device d1 but NOT d9
  await table.put({
    ...deviceProfile('d1'),
    deviceId: 'd1',
    hostname: 'host-d1',
  });

  // Create a group
  const createResp = await makeRequest(router, 'POST', '/admin/api/v1/groups', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ name: 'TestGroup' }),
  });
  const groupId = JSON.parse(createResp.body).groupId;

  // When an admin adds d1 and d9 to the group
  const addResp = await makeRequest(router, 'POST', `/admin/api/v1/groups/${groupId}/members`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ deviceIds: ['d1', 'd9'] }),
  });

  // Then added equals 1 (only d1)
  assert.strictEqual(addResp.statusCode, 200);
  const addBody = JSON.parse(addResp.body);
  assert.strictEqual(addBody.added, 1);
});

// ============================================================================
// Unit: Group creation returns correct fields
// ============================================================================

test('Unit: Group creation returns groupId and name', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerGroupRoutes(router, { verifier, table });

  const response = await makeRequest(router, 'POST', '/admin/api/v1/groups', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ name: 'TestGroup' }),
  });

  assert.strictEqual(response.statusCode, 201);
  const body = JSON.parse(response.body);
  assert(body.groupId);
  assert.strictEqual(body.name, 'TestGroup');
  assert(body.groupId.startsWith('grp-'));
});

// ============================================================================
// Unit: Group creation with missing name
// ============================================================================

test('Unit: Group creation with missing name returns 400', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerGroupRoutes(router, { verifier, table });

  const response = await makeRequest(router, 'POST', '/admin/api/v1/groups', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({}),
  });

  assert.strictEqual(response.statusCode, 400);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'invalid_request');
});

// ============================================================================
// Unit: Group list shows created groups
// ============================================================================

test('Unit: Group list shows created groups', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerGroupRoutes(router, { verifier, table });

  // Create a group
  const createResp = await makeRequest(router, 'POST', '/admin/api/v1/groups', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ name: 'MyGroup' }),
  });
  assert.strictEqual(createResp.statusCode, 201);

  // List groups
  const listResp = await makeRequest(router, 'GET', '/admin/api/v1/groups', {
    headers: { authorization: 'Bearer valid-token' },
    query: { limit: '50' },
  });

  assert.strictEqual(listResp.statusCode, 200);
  const body = JSON.parse(listResp.body);
  assert(Array.isArray(body.items));
  assert(body.items.length >= 1);
  const found = body.items.find((item) => item.name === 'MyGroup');
  assert(found);
  assert(found.groupId);
  assert(found.createdAt);
});

// ============================================================================
// Enhanced FakeTable with delete() and gsi1 query support for policy assignments
// ============================================================================

class EnhancedFakeTable extends FakeTable {
  async delete(keyObj) {
    const fullKey = `${keyObj.pk}#${keyObj.sk}`;
    this.items.delete(fullKey);
  }

  async query(request) {
    const items = [];
    const { KeyConditionExpression, ExpressionAttributeNames, ExpressionAttributeValues, IndexName, limit = 50, cursor } = request;

    let startIdx = 0;
    if (cursor) {
      const decoded = JSON.parse(Buffer.from(cursor, 'base64').toString());
      startIdx = decoded.offset || 0;
    }

    for (const [, item] of this.items) {
      if (IndexName === 'gsi1') {
        const gsi1pk = ExpressionAttributeValues[':gsi1pk'];
        if (item.gsi1pk !== gsi1pk) continue;
        items.push(item);
      } else if (IndexName === 'gsi1' || !IndexName) {
        // Handle policy assignments query on gsi1: GROUP#<id>/POLICY#<p>
        if (request.KeyConditionExpression && request.KeyConditionExpression.includes('gsi1pk')) {
          const gsi1pk = ExpressionAttributeValues[':gsi1pk'];
          if (item.gsi1pk !== gsi1pk) continue;
          items.push(item);
        } else if (request.KeyConditionExpression && request.KeyConditionExpression.includes(':pk')) {
          const pk = ExpressionAttributeValues[':pk'];
          if (item.pk !== pk) continue;

          if (KeyConditionExpression.includes('begins_with')) {
            const prefix = ExpressionAttributeValues[':memberPrefix'];
            if (!item.sk.startsWith(prefix)) continue;
          }
          items.push(item);
        }
      }
    }

    const sorted = items.sort((a, b) => {
      const skA = a.sk || '';
      const skB = b.sk || '';
      return skA < skB ? 1 : -1;
    });

    const pageSize = Math.min(limit, sorted.length - startIdx);
    const page = sorted.slice(startIdx, startIdx + pageSize);
    const nextCursor = startIdx + pageSize < sorted.length
      ? Buffer.from(JSON.stringify({ offset: startIdx + pageSize })).toString('base64')
      : null;

    return { items: page, cursor: nextCursor };
  }
}

// ============================================================================
// Scenario: AC1 - Rename a group
// ============================================================================

test('Scenario: AC1 - Rename a group updates name and gsi1sk', async (t) => {
  const router = createRouter();
  const table = new EnhancedFakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-01-01T00:00:00Z');

  registerGroupRoutes(router, { verifier, table, now: () => now, randomBytes: (n) => Buffer.alloc(n) });

  // Setup: create a group
  const createResp = await makeRequest(router, 'POST', '/admin/api/v1/groups', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ name: 'Sydney' }),
  });
  assert.strictEqual(createResp.statusCode, 201);
  const groupId = JSON.parse(createResp.body).groupId;

  // Get the initial createdAt from the stored record
  const initialRecord = await table.get({ pk: `GROUP#${groupId}`, sk: 'PROFILE' });
  const createdAt = initialRecord.createdAt;

  // When: rename the group
  const renameResp = await makeRequest(router, 'PUT', `/admin/api/v1/groups/${groupId}`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ name: 'Melbourne' }),
  });

  // Then: response is 200 with new name
  assert.strictEqual(renameResp.statusCode, 200);
  const renameBody = JSON.parse(renameResp.body);
  assert.strictEqual(renameBody.groupId, groupId);
  assert.strictEqual(renameBody.name, 'Melbourne');

  // And: gsi1sk is updated
  const record = await table.get({ pk: `GROUP#${groupId}`, sk: 'PROFILE' });
  assert(record);
  assert.strictEqual(record.name, 'Melbourne');

  // And: createdAt is unchanged
  assert.strictEqual(record.createdAt, createdAt);

  // And: list shows new name
  const listResp = await makeRequest(router, 'GET', '/admin/api/v1/groups', {
    headers: { authorization: 'Bearer valid-token' },
    query: { limit: '50' },
  });
  const listBody = JSON.parse(listResp.body);
  const found = listBody.items.find((g) => g.groupId === groupId);
  assert(found);
  assert.strictEqual(found.name, 'Melbourne');

  // And: audit entry is recorded
  let auditEntry = null;
  for (const [, item] of table.items) {
    if (item.action === 'group.renamed' && item.target === groupId) {
      auditEntry = item;
      break;
    }
  }
  assert(auditEntry);
  assert.strictEqual(auditEntry.detail.from, 'Sydney');
  assert.strictEqual(auditEntry.detail.to, 'Melbourne');
});

// ============================================================================
// Scenario: AC2 - Rename failures (empty name, unknown group)
// ============================================================================

test('Scenario: AC2 - Rename with empty name returns 400', async (t) => {
  const router = createRouter();
  const table = new EnhancedFakeTable();
  const verifier = new StubVerifier();

  registerGroupRoutes(router, { verifier, table });

  const response = await makeRequest(router, 'PUT', '/admin/api/v1/groups/grp-a', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ name: '' }),
  });

  assert.strictEqual(response.statusCode, 400);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'invalid_request');
  assert(Array.isArray(body.fields));
  assert(body.fields.includes('name'));
});

test('Scenario: AC2 - Rename unknown group returns 404', async (t) => {
  const router = createRouter();
  const table = new EnhancedFakeTable();
  const verifier = new StubVerifier();

  registerGroupRoutes(router, { verifier, table });

  const response = await makeRequest(router, 'PUT', '/admin/api/v1/groups/grp-none', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ name: 'X' }),
  });

  assert.strictEqual(response.statusCode, 404);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'not_found');
});

// ============================================================================
// Scenario: AC3 - Delete a group with cascade
// ============================================================================

test('Scenario: AC3 - Delete group cascades to memberships and assignments', async (t) => {
  const router = createRouter();
  const table = new EnhancedFakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');

  registerGroupRoutes(router, { verifier, table, now: () => now, randomBytes: (n) => Buffer.alloc(n) });

  // Setup: add devices
  await table.put({ ...deviceProfile('dev-1'), deviceId: 'dev-1', hostname: 'host-1' });
  await table.put({ ...deviceProfile('dev-2'), deviceId: 'dev-2', hostname: 'host-2' });

  // Create group
  const createResp = await makeRequest(router, 'POST', '/admin/api/v1/groups', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ name: 'TestGroup' }),
  });
  const groupId = JSON.parse(createResp.body).groupId;

  // Add members
  await makeRequest(router, 'POST', `/admin/api/v1/groups/${groupId}/members`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ deviceIds: ['dev-1', 'dev-2'] }),
  });

  // Setup: add policy assignments (manually, since we're testing cascade)
  const { policyAssignment } = await import('../../dist/db/keys.js');
  await table.put({
    ...policyAssignment('pol-1', groupId),
    gsi1pk: `GROUP#${groupId}`,
    gsi1sk: `POLICY#pol-1`,
    policyId: 'pol-1',
  });
  await table.put({
    ...policyAssignment('pol-2', groupId),
    gsi1pk: `GROUP#${groupId}`,
    gsi1sk: `POLICY#pol-2`,
    policyId: 'pol-2',
  });

  // When: delete the group with confirmation
  const deleteResp = await makeRequest(router, 'DELETE', `/admin/api/v1/groups/${groupId}`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ confirm: true }),
  });

  // Then: response is 200
  assert.strictEqual(deleteResp.statusCode, 200);
  const deleteBody = JSON.parse(deleteResp.body);
  assert.strictEqual(deleteBody.groupId, groupId);
  assert.strictEqual(deleteBody.membersRemoved, 2);
  assert.strictEqual(deleteBody.assignmentsRemoved, 2);

  // And: group record is deleted
  const groupRecord = await table.get({ pk: `GROUP#${groupId}`, sk: 'PROFILE' });
  assert.strictEqual(groupRecord, undefined);

  // And: memberships are deleted
  const member1 = await table.get({ pk: `GROUP#${groupId}`, sk: 'MEMBER#dev-1' });
  assert.strictEqual(member1, undefined);

  // And: policy assignments are deleted
  const assign1 = await table.get({ pk: `POLICY#pol-1`, sk: `ASSIGN#${groupId}` });
  assert.strictEqual(assign1, undefined);

  // And: audit entry is recorded
  let auditEntry = null;
  for (const [, item] of table.items) {
    if (item.action === 'group.deleted' && item.target === groupId) {
      auditEntry = item;
      break;
    }
  }
  assert(auditEntry);
  assert.strictEqual(auditEntry.detail.membersRemoved, 2);
  assert.strictEqual(auditEntry.detail.assignmentsRemoved, 2);
});

// ============================================================================
// Scenario: AC4 - Delete failures (no confirmation, unknown group)
// ============================================================================

test('Scenario: AC4 - Delete without confirmation returns 409', async (t) => {
  const router = createRouter();
  const table = new EnhancedFakeTable();
  const verifier = new StubVerifier();

  registerGroupRoutes(router, { verifier, table });

  // Setup: create a group
  const createResp = await makeRequest(router, 'POST', '/admin/api/v1/groups', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ name: 'TestGroup' }),
  });
  const groupId = JSON.parse(createResp.body).groupId;

  // When: try to delete without confirmation
  const response = await makeRequest(router, 'DELETE', `/admin/api/v1/groups/${groupId}`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({}),
  });

  // Then: response is 409
  assert.strictEqual(response.statusCode, 409);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'confirmation_required');

  // And: group is not deleted
  const record = await table.get({ pk: `GROUP#${groupId}`, sk: 'PROFILE' });
  assert(record);
});

test('Scenario: AC4 - Delete unknown group returns 404', async (t) => {
  const router = createRouter();
  const table = new EnhancedFakeTable();
  const verifier = new StubVerifier();

  registerGroupRoutes(router, { verifier, table });

  const response = await makeRequest(router, 'DELETE', '/admin/api/v1/groups/grp-none', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ confirm: true }),
  });

  assert.strictEqual(response.statusCode, 404);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'not_found');
});

// ============================================================================
// Scenario: AC5 - After delete, group no longer carries policies to members
// ============================================================================

test('Scenario: AC5 - A deleted group no longer carries policies to its members', async (t) => {
  const { readAssignedPolicyIds } = await import('../../dist/policies/resolve.js');
  const { policyAssignment } = await import('../../dist/db/keys.js');

  const router = createRouter();
  const table = new EnhancedFakeTable();
  const verifier = new StubVerifier();

  registerGroupRoutes(router, { verifier, table });

  // Setup: add a device
  await table.put({ ...deviceProfile('dev-1'), deviceId: 'dev-1', hostname: 'host-1' });

  // Setup: add a policy (minimal record for testing)
  await table.put({
    pk: 'POLICY#pol-1',
    sk: 'PROFILE',
    policyId: 'pol-1',
    name: 'Test Policy',
  });

  // Setup: create a group
  const createResp = await makeRequest(router, 'POST', '/admin/api/v1/groups', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ name: 'TestGroup' }),
  });
  const groupId = JSON.parse(createResp.body).groupId;

  // Setup: assign policy to group only (not direct device assignment)
  await table.put({
    ...policyAssignment('pol-1', groupId),
    gsi1pk: `GROUP#${groupId}`,
    gsi1sk: `POLICY#pol-1`,
    policyId: 'pol-1',
  });

  // Setup: add device to group
  await makeRequest(router, 'POST', `/admin/api/v1/groups/${groupId}/members`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ deviceIds: ['dev-1'] }),
  });

  // Verify: device receives policy through group
  let assignedPolicies = await readAssignedPolicyIds(table, 'dev-1');
  assert(assignedPolicies.includes('pol-1'), 'device should receive policy through group before delete');

  // When: delete the group with confirmation
  const deleteResp = await makeRequest(router, 'DELETE', `/admin/api/v1/groups/${groupId}`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ confirm: true }),
  });
  assert.strictEqual(deleteResp.statusCode, 200);

  // Then: membership is deleted (no members remain in group)
  const memberAfterDelete = await table.get({ pk: `GROUP#${groupId}`, sk: 'MEMBER#dev-1' });
  assert.strictEqual(memberAfterDelete, undefined, 'membership should be deleted');

  // And: policy assignment is deleted (group no longer carries policy)
  const assignmentAfterDelete = await table.get({ pk: `POLICY#pol-1`, sk: `ASSIGN#${groupId}` });
  assert.strictEqual(assignmentAfterDelete, undefined, 'policy assignment to group should be deleted');

  // And: readAssignedPolicyIds for device excludes the policy
  assignedPolicies = await readAssignedPolicyIds(table, 'dev-1');
  assert(!assignedPolicies.includes('pol-1'), 'device should no longer receive policy after group delete');
});

// ============================================================================
// Scenario: AC6 - Remove members from a group
// ============================================================================

test('Scenario: AC6 - Remove members counts only existing members', async (t) => {
  const router = createRouter();
  const table = new EnhancedFakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');

  registerGroupRoutes(router, { verifier, table, now: () => now, randomBytes: (n) => Buffer.alloc(n) });

  // Setup: create group and add members
  await table.put({ ...deviceProfile('dev-1'), deviceId: 'dev-1', hostname: 'host-1' });
  await table.put({ ...deviceProfile('dev-2'), deviceId: 'dev-2', hostname: 'host-2' });

  const createResp = await makeRequest(router, 'POST', '/admin/api/v1/groups', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ name: 'TestGroup' }),
  });
  const groupId = JSON.parse(createResp.body).groupId;

  await makeRequest(router, 'POST', `/admin/api/v1/groups/${groupId}/members`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ deviceIds: ['dev-1', 'dev-2'] }),
  });

  // When: remove dev-1, dev-9 (non-existent), and x#y (invalid key)
  const removeResp = await makeRequest(router, 'DELETE', `/admin/api/v1/groups/${groupId}/members`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ deviceIds: ['dev-1', 'dev-9', 'x#y'] }),
  });

  // Then: response is 200, only dev-1 removed
  assert.strictEqual(removeResp.statusCode, 200);
  const removeBody = JSON.parse(removeResp.body);
  assert.strictEqual(removeBody.removed, 1);

  // And: dev-2 is still a member
  const member2 = await table.get({ pk: `GROUP#${groupId}`, sk: 'MEMBER#dev-2' });
  assert(member2);

  // And: audit entry is recorded
  let auditEntry = null;
  for (const [, item] of table.items) {
    if (item.action === 'group.members_removed' && item.target === groupId) {
      auditEntry = item;
      break;
    }
  }
  assert(auditEntry);
  assert.strictEqual(auditEntry.detail.removed, 1);
  assert(Array.isArray(auditEntry.detail.deviceIds));
  assert(auditEntry.detail.deviceIds.includes('dev-1'));
});

// ============================================================================
// Scenario: AC7 - Remove members failures (bad body, unknown group)
// ============================================================================

test('Scenario: AC7 - Remove members with non-array deviceIds returns 400', async (t) => {
  const router = createRouter();
  const table = new EnhancedFakeTable();
  const verifier = new StubVerifier();

  registerGroupRoutes(router, { verifier, table });

  const response = await makeRequest(router, 'DELETE', '/admin/api/v1/groups/grp-a/members', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ deviceIds: 'dev-1' }),
  });

  assert.strictEqual(response.statusCode, 400);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'invalid_request');
});

test('Scenario: AC7 - Remove from unknown group returns 404', async (t) => {
  const router = createRouter();
  const table = new EnhancedFakeTable();
  const verifier = new StubVerifier();

  registerGroupRoutes(router, { verifier, table });

  const response = await makeRequest(router, 'DELETE', '/admin/api/v1/groups/grp-none/members', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ deviceIds: ['dev-1'] }),
  });

  assert.strictEqual(response.statusCode, 404);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'not_found');
});

// ============================================================================
// Scenario: AC11 - Authorization (no bearer token)
// ============================================================================

test('Scenario: AC11 - PUT without bearer token returns 401', async (t) => {
  const router = createRouter();
  const table = new EnhancedFakeTable();
  const verifier = new StubVerifier();

  registerGroupRoutes(router, { verifier, table });

  const response = await makeRequest(router, 'PUT', '/admin/api/v1/groups/grp-a', {
    body: JSON.stringify({ name: 'Test' }),
  });

  assert.strictEqual(response.statusCode, 401);
});

test('Scenario: AC11 - DELETE group without bearer token returns 401', async (t) => {
  const router = createRouter();
  const table = new EnhancedFakeTable();
  const verifier = new StubVerifier();

  registerGroupRoutes(router, { verifier, table });

  const response = await makeRequest(router, 'DELETE', '/admin/api/v1/groups/grp-a', {
    body: JSON.stringify({ confirm: true }),
  });

  assert.strictEqual(response.statusCode, 401);
});

test('Scenario: AC11 - DELETE members without bearer token returns 401', async (t) => {
  const router = createRouter();
  const table = new EnhancedFakeTable();
  const verifier = new StubVerifier();

  registerGroupRoutes(router, { verifier, table });

  const response = await makeRequest(router, 'DELETE', '/admin/api/v1/groups/grp-a/members', {
    body: JSON.stringify({ deviceIds: ['dev-1'] }),
  });

  assert.strictEqual(response.statusCode, 401);
});
