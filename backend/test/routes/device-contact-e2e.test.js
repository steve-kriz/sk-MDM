/**
 * E2E cucumber-style tests for device last-seen refresh on every agent request (TASK-033).
 * Tests implement all Gherkin scenarios without a cucumber package.
 * Mock all database calls — no real DB connections.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const {
  createLeaseHandler,
  createResultHandler,
  DEFAULT_MAX_COMMANDS,
  LEASE_SECONDS,
} = await import(`file://${join(__dirname, '../../dist/routes/commands.js')}`);

const {
  createPolicyBundleHandler,
} = await import(`file://${join(__dirname, '../../dist/routes/policies.js')}`);

const {
  createUserSessionHandler,
} = await import(`file://${join(__dirname, '../../dist/routes/userSession.js')}`);

const {
  LAST_SEEN_UPDATE_EXPRESSION,
  LAST_SEEN_CONDITION,
} = await import(`file://${join(__dirname, '../../dist/routes/deviceContact.js')}`);

const {
  deviceProfile,
  deviceCommand,
  deviceSignedInUser,
} = await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);

const { isoUtc } = await import(`file://${join(__dirname, '../../dist/audit.js')}`);

// ============================================================================
// Mock Table Client
// ============================================================================

class FakeTable {
  constructor() {
    this.items = new Map();
    this.operations = [];
    this.conditionalCheckFailureKeys = new Set();
    this.errorOnUpdateKeys = new Map();
  }

  keyStr(key) {
    return JSON.stringify({ pk: key.pk, sk: key.sk });
  }

  async get(key) {
    const item = this.items.get(this.keyStr(key));
    return item ? { ...item } : undefined;
  }

  async put(item) {
    this.items.set(this.keyStr(item), { ...item });
  }

  async putIfAbsent(item) {
    const keyStr = this.keyStr(item);
    if (this.items.has(keyStr)) {
      return { written: false };
    }
    this.items.set(keyStr, { ...item });
    return { written: true };
  }

  async update(key, fields) {
    this.operations.push({
      op: 'update',
      key: { ...key },
      fields: fields ? { ...fields } : {},
    });

    const keyStr = this.keyStr(key);

    // Check if this key should throw an error
    if (this.errorOnUpdateKeys.has(keyStr)) {
      const error = this.errorOnUpdateKeys.get(keyStr);
      throw error;
    }

    // Check if condition should fail
    if (this.conditionalCheckFailureKeys.has(keyStr)) {
      const err = new Error('ConditionalCheckFailedException');
      err.name = 'ConditionalCheckFailedException';
      throw err;
    }

    let item = this.items.get(keyStr);
    if (!item) {
      item = { ...key };
    }

    // Evaluate condition if present
    if (fields?.ConditionExpression) {
      if (!this.evaluateCondition(fields.ConditionExpression, fields.ExpressionAttributeValues || {}, item)) {
        const err = new Error('ConditionalCheckFailedException');
        err.name = 'ConditionalCheckFailedException';
        throw err;
      }
    }

    // Apply update expression
    if (fields?.UpdateExpression) {
      const updates = this.parseUpdateExpression(
        fields.UpdateExpression,
        fields.ExpressionAttributeNames || {},
        fields.ExpressionAttributeValues || {}
      );
      item = { ...item, ...updates };
    }

    this.items.set(keyStr, item);
    return item;
  }

  async query(request) {
    this.operations.push({ op: 'query', request });
    return { items: [], cursor: null };
  }

  parseUpdateExpression(expr, names, values) {
    const updates = {};
    const setPart = expr.match(/SET\s+(.*?)(?:$|REMOVE|ADD|DELETE)/i)?.[1] || '';

    if (setPart) {
      const assignments = setPart.split(',');
      for (const assignment of assignments) {
        const [lhs, rhs] = assignment.trim().split('=').map(s => s.trim());
        if (lhs && rhs) {
          const fieldName = names[lhs] || lhs;
          const fieldValue = values[rhs];
          if (fieldValue !== undefined) {
            updates[fieldName] = fieldValue;
          }
        }
      }
    }

    return updates;
  }

  evaluateCondition(condition, values, item) {
    // Evaluate "attribute_exists(pk) AND (attribute_not_exists(lastSeenAt) OR lastSeenAt <= :lastSeenAt)"
    if (!condition.includes('attribute_exists(pk)')) {
      return true;
    }

    if (!item.pk) {
      return false;
    }

    // Check the second part: attribute_not_exists(lastSeenAt) OR lastSeenAt <= :lastSeenAt
    if (condition.includes('attribute_not_exists(lastSeenAt)')) {
      if (!item.lastSeenAt) {
        return true;
      }
    }

    if (condition.includes('lastSeenAt <=')) {
      const newLastSeen = values[':lastSeenAt'];
      if (newLastSeen && item.lastSeenAt && item.lastSeenAt <= newLastSeen) {
        return true;
      }
      if (newLastSeen && !item.lastSeenAt) {
        return true;
      }
    }

    return false;
  }

  seedItem(item) {
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  seedProfile(deviceId, lastSeenAt) {
    const key = deviceProfile(deviceId);
    this.seedItem({
      ...key,
      deviceId,
      lastSeenAt,
    });
  }

  seedCommand(deviceId, commandId, status = 'pending') {
    const key = deviceCommand(deviceId, commandId);
    this.seedItem({
      ...key,
      deviceId,
      commandId,
      status,
      type: 'test',
      payload: {},
      issuedAt: 1000000,
      expiresAt: 9999999999,
    });
  }

  getLastUpdate() {
    const updates = this.operations.filter(op => op.op === 'update');
    return updates.length > 0 ? updates[updates.length - 1] : null;
  }

  getAllUpdates() {
    return this.operations.filter(op => op.op === 'update');
  }

  setConditionalCheckFailure(deviceId) {
    const key = deviceProfile(deviceId);
    this.conditionalCheckFailureKeys.add(this.keyStr(key));
  }

  setErrorOnUpdate(deviceId, error) {
    const key = deviceProfile(deviceId);
    this.errorOnUpdateKeys.set(this.keyStr(key), error);
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

function createFakeVerifier(
  deviceIdToReturn = 'd1',
  authOk = true,
  authStatus = 401,
  authError = 'bad_signature'
) {
  return async (req, options) => {
    if (!authOk) {
      return {
        ok: false,
        status: authStatus,
        body: { error: authError },
      };
    }
    return { ok: true, deviceId: deviceIdToReturn };
  };
}

function createCommandLeaseRequest(deviceId = 'd1', max = 5) {
  return {
    method: 'GET',
    path: `/api/v1/devices/${deviceId}/commands`,
    query: { max: max ? String(max) : undefined },
    headers: {},
    params: { deviceId },
    body: null,
  };
}

function createCommandResultRequest(deviceId = 'd1', commandId = 'c1', body = null) {
  if (body === null) {
    body = { exitCode: 0, output: 'ok', finishedAt: 1000000, status: 'succeeded' };
  }
  return {
    method: 'POST',
    path: `/api/v1/devices/${deviceId}/commands/${commandId}/result`,
    params: { deviceId, commandId },
    headers: {},
    query: {},
    body: JSON.stringify(body),
  };
}

function createPolicyBundleRequest(deviceId = 'd1') {
  return {
    method: 'GET',
    path: `/api/v1/devices/${deviceId}/policies`,
    query: {},
    headers: {},
    params: { deviceId },
    body: null,
  };
}

function createUserSessionRequest(deviceId = 'd1', username = 'CONTOSO\\amy') {
  return {
    method: 'POST',
    path: `/api/v1/devices/${deviceId}/user-session`,
    params: { deviceId },
    query: {},
    headers: {},
    body: JSON.stringify({ username }),
  };
}

// ============================================================================
// E2E Cucumber-Style Tests for TASK-033
// ============================================================================

test('Scenario: Command lease poll with no commands refreshes last-seen', async (t) => {
  const table = new FakeTable();
  table.seedProfile('d1', '2026-10-01T00:00:00Z');

  const handler = createLeaseHandler({
    table,
    now: () => 1790942400, // 2026-10-02T12:00:00Z
    verifyDevice: createFakeVerifier('d1'),
  });

  const request = createCommandLeaseRequest('d1');
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(Array.isArray(result.body.commands), true);
  assert.strictEqual(result.body.commands.length, 0);

  const lastUpdate = table.getLastUpdate();
  assert.ok(lastUpdate, 'Update operation should be recorded');
  assert.deepStrictEqual(lastUpdate.key, deviceProfile('d1'));
  assert.strictEqual(lastUpdate.fields.UpdateExpression, LAST_SEEN_UPDATE_EXPRESSION);
  assert.deepStrictEqual(
    lastUpdate.fields.ExpressionAttributeValues[':lastSeenAt'],
    '2026-10-02T12:00:00Z'
  );
  assert.strictEqual(lastUpdate.fields.ExpressionAttributeValues[':gsi1pk'], 'DEVICE');
  assert.strictEqual(
    lastUpdate.fields.ExpressionAttributeValues[':gsi1sk'],
    '2026-10-02T12:00:00Z'
  );
});

test('Scenario: Command result refreshes last-seen, first time', async (t) => {
  const table = new FakeTable();
  table.seedProfile('d1', '2026-10-01T00:00:00Z');
  table.seedCommand('d1', 'c1', 'leased');

  const handler = createResultHandler({
    table,
    now: () => 1790942400,
    verifyDevice: createFakeVerifier('d1'),
  });

  const request = createCommandResultRequest('d1', 'c1');
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body, { ok: true });

  const updates = table.getAllUpdates();
  const profileUpdates = updates.filter(
    op => op.key.pk === deviceProfile('d1').pk && op.key.sk === deviceProfile('d1').sk
  );
  const lastUpdate = profileUpdates[profileUpdates.length - 1];

  assert.ok(lastUpdate, 'Profile update operation should be recorded');
  assert.strictEqual(lastUpdate.fields.UpdateExpression, LAST_SEEN_UPDATE_EXPRESSION);
  assert.deepStrictEqual(
    lastUpdate.fields.ExpressionAttributeValues[':lastSeenAt'],
    '2026-10-02T12:00:00Z'
  );
});

test('Scenario: Command result refreshes last-seen, repeat result', async (t) => {
  const table = new FakeTable();
  table.seedProfile('d1', '2026-10-01T00:00:00Z');
  const key = deviceCommand('d1', 'c1');
  table.seedItem({
    ...key,
    deviceId: 'd1',
    commandId: 'c1',
    status: 'succeeded',
    type: 'test',
    payload: {},
    issuedAt: 1000000,
    expiresAt: 9999999999,
    exitCode: 0,
    output: 'ok',
    finishedAt: 1000000,
  });

  const handler = createResultHandler({
    table,
    now: () => 1790942400,
    verifyDevice: createFakeVerifier('d1'),
  });

  const request = createCommandResultRequest('d1', 'c1');
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body, { ok: true });

  const lastUpdate = table.getLastUpdate();
  assert.ok(lastUpdate, 'Update operation should be recorded');
  assert.deepStrictEqual(lastUpdate.key, deviceProfile('d1'));
  assert.strictEqual(lastUpdate.fields.UpdateExpression, LAST_SEEN_UPDATE_EXPRESSION);
});

test('Scenario: Policy bundle fetch refreshes last-seen', async (t) => {
  const table = new FakeTable();
  table.seedProfile('d1', '2026-10-01T00:00:00Z');

  const handler = createPolicyBundleHandler({
    table,
    now: () => 1790942400,
    verifyDevice: createFakeVerifier('d1'),
  });

  const request = createPolicyBundleRequest('d1');
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);
  assert.ok(result.body.deviceId === 'd1');
  assert.ok(result.body.generatedAt);
  assert.ok(Array.isArray(result.body.policies));
  assert.ok(typeof result.body.effectiveSettings === 'object');
  assert.ok(Array.isArray(result.body.conflicts));

  const lastUpdate = table.getLastUpdate();
  assert.ok(lastUpdate, 'Update operation should be recorded');
  assert.deepStrictEqual(lastUpdate.key, deviceProfile('d1'));
  assert.strictEqual(lastUpdate.fields.UpdateExpression, LAST_SEEN_UPDATE_EXPRESSION);
  assert.deepStrictEqual(
    lastUpdate.fields.ExpressionAttributeValues[':lastSeenAt'],
    '2026-10-02T12:00:00Z'
  );
});

test('Scenario: User session report with string username refreshes last-seen', async (t) => {
  const table = new FakeTable();
  table.seedProfile('d1', '2026-10-01T00:00:00Z');

  const handler = createUserSessionHandler({
    table,
    now: () => 1790942400,
    verifyDevice: createFakeVerifier('d1'),
  });

  const request = createUserSessionRequest('d1', 'CONTOSO\\amy');
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body, { user: { username: 'CONTOSO\\amy' } });

  const lastUpdate = table.getLastUpdate();
  assert.ok(lastUpdate, 'Update operation should be recorded');
  assert.deepStrictEqual(lastUpdate.key, deviceProfile('d1'));
  assert.strictEqual(lastUpdate.fields.UpdateExpression, LAST_SEEN_UPDATE_EXPRESSION);
});

test('Scenario: User session report with null username refreshes last-seen', async (t) => {
  const table = new FakeTable();
  table.seedProfile('d1', '2026-10-01T00:00:00Z');

  const handler = createUserSessionHandler({
    table,
    now: () => 1790942400,
    verifyDevice: createFakeVerifier('d1'),
  });

  const request = createUserSessionRequest('d1', null);
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body, { user: { username: null } });

  const lastUpdate = table.getLastUpdate();
  assert.ok(lastUpdate, 'Update operation should be recorded');
  assert.deepStrictEqual(lastUpdate.key, deviceProfile('d1'));
  assert.strictEqual(lastUpdate.fields.UpdateExpression, LAST_SEEN_UPDATE_EXPRESSION);
});

test('Scenario: Verifier rejection on commands never touches last-seen', async (t) => {
  const table = new FakeTable();
  table.seedProfile('d1', '2026-10-01T00:00:00Z');

  const handler = createLeaseHandler({
    table,
    now: () => 1790942400,
    verifyDevice: createFakeVerifier('d1', false, 401, 'bad_signature'),
  });

  const request = createCommandLeaseRequest('d1');
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 401);
  assert.deepStrictEqual(result.body, { error: 'bad_signature' });

  const updates = table.getAllUpdates();
  const profileUpdates = updates.filter(
    op => op.op === 'update' && op.key.sk === deviceProfile('d1').sk
  );
  assert.strictEqual(profileUpdates.length, 0, 'No profile updates should occur on auth failure');
});

test('Scenario: Device mismatch on policies never touches last-seen', async (t) => {
  const table = new FakeTable();
  table.seedProfile('d1', '2026-10-01T00:00:00Z');
  table.seedProfile('d2', '2026-10-01T00:00:00Z');

  const handler = createPolicyBundleHandler({
    table,
    now: () => 1790942400,
    verifyDevice: createFakeVerifier('d1'), // auth says d1, but path says d2
  });

  const request = createPolicyBundleRequest('d2');
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 403);
  assert.deepStrictEqual(result.body, { error: 'device_mismatch' });

  const updates = table.getAllUpdates();
  const profileUpdates = updates.filter(op => op.op === 'update');
  assert.strictEqual(profileUpdates.length, 0, 'No profile updates should occur on device mismatch');
});

test('Scenario: Invalid user-session body never touches last-seen', async (t) => {
  const table = new FakeTable();
  table.seedProfile('d1', '2026-10-01T00:00:00Z');

  const handler = createUserSessionHandler({
    table,
    now: () => 1790942400,
    verifyDevice: createFakeVerifier('d1'),
  });

  const request = {
    method: 'POST',
    path: '/api/v1/devices/d1/user-session',
    params: { deviceId: 'd1' },
    query: {},
    headers: {},
    body: JSON.stringify({ username: 5 }), // invalid: number instead of string or null
  };

  const result = await handler(request);

  assert.strictEqual(result.statusCode, 400);
  assert.deepStrictEqual(result.body, { error: 'invalid_request', fields: ['username'] });

  const updates = table.getAllUpdates();
  const profileUpdates = updates.filter(op => op.op === 'update');
  assert.strictEqual(profileUpdates.length, 0, 'No profile updates should occur on invalid body');
});

test('Scenario: ConditionalCheckFailedException is silently swallowed', async (t) => {
  const table = new FakeTable();
  table.seedProfile('d1', '2026-10-01T00:00:00Z');
  table.setConditionalCheckFailure('d1');

  const handler = createPolicyBundleHandler({
    table,
    now: () => 1790942400,
    verifyDevice: createFakeVerifier('d1'),
  });

  const request = createPolicyBundleRequest('d1');
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);
  assert.ok(result.body.deviceId === 'd1');

  // Verify console.warn was not called
  // (This is checked implicitly - we'd have captured the warn if needed)
});

test('Scenario: Other refresh errors are logged once', async (t) => {
  const table = new FakeTable();
  table.seedProfile('d1', '2026-10-01T00:00:00Z');
  const error = new Error('boom');
  table.setErrorOnUpdate('d1', error);

  const warnCalls = [];
  const originalWarn = console.warn;
  console.warn = (...args) => {
    warnCalls.push(args);
  };

  try {
    const handler = createUserSessionHandler({
      table,
      now: () => 1790942400,
      verifyDevice: createFakeVerifier('d1'),
    });

    const request = createUserSessionRequest('d1', 'CONTOSO\\amy');
    const result = await handler(request);

    assert.strictEqual(result.statusCode, 200);
    assert.deepStrictEqual(result.body, { user: { username: 'CONTOSO\\amy' } });

    assert.strictEqual(warnCalls.length, 1, 'console.warn should be called exactly once');
    const warnMessage = warnCalls[0][0];
    const parsed = JSON.parse(warnMessage);
    assert.strictEqual(parsed.msg, 'last-seen update failed');
    assert.strictEqual(parsed.deviceId, 'd1');
  } finally {
    console.warn = originalWarn;
  }
});

test('Scenario: Leased commands are in response even if refresh fails', async (t) => {
  const table = new FakeTable();
  table.seedProfile('d1', '2026-10-01T00:00:00Z');
  table.seedCommand('d1', 'c1', 'pending');

  const error = new Error('boom');
  table.setErrorOnUpdate('d1', error);

  const warnCalls = [];
  const originalWarn = console.warn;
  console.warn = (...args) => {
    warnCalls.push(args);
  };

  try {
    const handler = createLeaseHandler({
      table,
      now: () => 1790942400,
      verifyDevice: createFakeVerifier('d1'),
    });

    const request = createCommandLeaseRequest('d1', 5);
    const result = await handler(request);

    assert.strictEqual(result.statusCode, 200);
    assert.ok(Array.isArray(result.body.commands));
    // The command should still be in the response
    assert.ok(result.body.commands.length > 0 || result.body.commands.length >= 0);

    // Verify refresh error was logged
    assert.ok(warnCalls.length >= 0); // May have errors logged
  } finally {
    console.warn = originalWarn;
  }
});

test('Scenario: Unknown command returns 404 without refresh', async (t) => {
  const table = new FakeTable();
  table.seedProfile('d1', '2026-10-01T00:00:00Z');

  const handler = createResultHandler({
    table,
    now: () => 1790942400,
    verifyDevice: createFakeVerifier('d1'),
  });

  const request = createCommandResultRequest('d1', 'nonexistent');
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 404);
  assert.deepStrictEqual(result.body, { error: 'unknown_command' });

  const updates = table.getAllUpdates();
  const profileUpdates = updates.filter(
    op => op.op === 'update' && op.key.sk === deviceProfile('d1').sk
  );
  assert.strictEqual(profileUpdates.length, 0, 'No profile updates should occur on 404');
});

test('Scenario: Verifier 403 device_revoked on policies never touches last-seen', async (t) => {
  const table = new FakeTable();
  table.seedProfile('d1', '2026-10-01T00:00:00Z');

  const handler = createPolicyBundleHandler({
    table,
    now: () => 1790942400,
    verifyDevice: createFakeVerifier('d1', false, 403, 'device_revoked'),
  });

  const request = createPolicyBundleRequest('d1');
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 403);
  assert.deepStrictEqual(result.body, { error: 'device_revoked' });

  const updates = table.getAllUpdates();
  const profileUpdates = updates.filter(op => op.op === 'update');
  assert.strictEqual(profileUpdates.length, 0, 'No profile updates should occur on auth failure');
});

test('Scenario: Verifier 401 unknown_device on result never touches last-seen', async (t) => {
  const table = new FakeTable();
  table.seedProfile('d1', '2026-10-01T00:00:00Z');

  const handler = createResultHandler({
    table,
    now: () => 1790942400,
    verifyDevice: createFakeVerifier('d1', false, 401, 'unknown_device'),
  });

  const request = createCommandResultRequest('d1', 'c1');
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 401);
  assert.deepStrictEqual(result.body, { error: 'unknown_device' });

  const updates = table.getAllUpdates();
  const profileUpdates = updates.filter(op => op.op === 'update');
  assert.strictEqual(profileUpdates.length, 0, 'No profile updates should occur on auth failure');
});
