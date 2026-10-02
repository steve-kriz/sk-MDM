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
