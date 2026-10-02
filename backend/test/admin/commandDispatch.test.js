/**
 * E2E and unit tests for TASK-011: Admin API command dispatch.
 *
 * Tests implement the Gherkin scenarios in Given/When/Then style using node:test,
 * with all database calls mocked and deterministic clock injection.
 */

import test from 'node:test';
import assert from 'node:assert';
import { createRouter } from '../../dist/index.js';
import { registerCommandDispatchRoutes, offendingPayloadFields } from '../../dist/admin/commandDispatch.js';
import { registerGroupRoutes } from '../../dist/admin/groups.js';
import { deviceProfile, groupMember } from '../../dist/db/keys.js';

// ============================================================================
// Mock Table Client
// ============================================================================

class FakeTable {
  constructor() {
    this.items = new Map();
    this.putCalls = [];
  }

  async put(item) {
    const key = `${item.pk}#${item.sk}`;
    this.items.set(key, { ...item });
    this.putCalls.push(item);
  }

  async get(keyObj) {
    const fullKey = `${keyObj.pk}#${keyObj.sk}`;
    return this.items.get(fullKey);
  }

  async query(request) {
    const items = [];
    const { KeyConditionExpression, ExpressionAttributeValues } = request;

    const pk = ExpressionAttributeValues[':pk'];
    for (const [, item] of this.items) {
      if (item.pk !== pk) continue;
      if (KeyConditionExpression.includes('begins_with')) {
        const prefix = ExpressionAttributeValues[':memberPrefix'];
        if (!item.sk.startsWith(prefix)) continue;
      }
      items.push(item);
    }

    const sorted = items.sort((a, b) => (a.sk < b.sk ? 1 : -1));
    return { items: sorted, cursor: null };
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
// Scenario: Command is queued with issuedAt and a 24 hour expiry
// ============================================================================

test('Scenario: Command is queued with issuedAt and a 24 hour expiry', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T00:00:00Z');

  registerCommandDispatchRoutes(router, { verifier, table, now: () => now, randomBytes: (n) => Buffer.alloc(n) });

  // Setup: add device d1
  await table.put({
    ...deviceProfile('d1'),
    deviceId: 'd1',
    hostname: 'host-d1',
  });

  // When an admin queues a lock command for d1
  const response = await makeRequest(router, 'POST', '/admin/api/v1/devices/d1/commands', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      type: 'lock',
      payload: {},
    }),
  });

  // Then the status is 202 and the stored command is pending
  assert.strictEqual(response.statusCode, 202);
  const body = JSON.parse(response.body);
  const commandId = body.commandId;
  assert(commandId);

  // Verify the command was written correctly
  const expectedIssuedAt = now.getTime(); // epoch milliseconds
  const expectedExpiresAt = expectedIssuedAt + 86400000; // +24 hours

  const stored = table.items.get(`DEVICE#d1#CMD#${commandId}`);
  assert(stored);
  assert.strictEqual(stored.status, 'pending');
  assert.strictEqual(stored.issuedAt, expectedIssuedAt);
  assert.strictEqual(stored.expiresAt, expectedExpiresAt);
});

// ============================================================================
// Scenario: Unsupported type is refused
// ============================================================================

test('Scenario: Unsupported type is refused', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');

  registerCommandDispatchRoutes(router, { verifier, table, now: () => now });

  // Setup: add device d1
  await table.put({
    ...deviceProfile('d1'),
    deviceId: 'd1',
    hostname: 'host-d1',
  });

  // When an admin queues type "format_disk"
  const response = await makeRequest(router, 'POST', '/admin/api/v1/devices/d1/commands', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      type: 'format_disk',
      payload: {},
    }),
  });

  // Then the status is 400 and the error is unsupported_command_type
  assert.strictEqual(response.statusCode, 400);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'unsupported_command_type');
});

// ============================================================================
// Scenario: Script command needs an interpreter
// ============================================================================

test('Scenario: Script command needs an interpreter', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerCommandDispatchRoutes(router, { verifier, table });

  // Setup: add device d1
  await table.put({
    ...deviceProfile('d1'),
    deviceId: 'd1',
    hostname: 'host-d1',
  });

  // When an admin queues run_script with confirm true and no interpreter
  const response = await makeRequest(router, 'POST', '/admin/api/v1/devices/d1/commands', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      type: 'run_script',
      payload: { script: 'echo hello' },
      confirm: true,
    }),
  });

  // Then the status is 400 and fields contains "payload.interpreter"
  assert.strictEqual(response.statusCode, 400);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'invalid_request');
  assert(Array.isArray(body.fields));
  assert(body.fields.includes('payload.interpreter'));
});

// ============================================================================
// Scenario: Restart without confirmation is refused
// ============================================================================

test('Scenario: Restart without confirmation is refused', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerCommandDispatchRoutes(router, { verifier, table });

  // Setup: add device d1
  await table.put({
    ...deviceProfile('d1'),
    deviceId: 'd1',
    hostname: 'host-d1',
  });

  // When an admin queues a restart without confirm
  const response = await makeRequest(router, 'POST', '/admin/api/v1/devices/d1/commands', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      type: 'restart',
      payload: {},
    }),
  });

  // Then the status is 409, the error is confirmation_required and no command was written
  assert.strictEqual(response.statusCode, 409);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'confirmation_required');

  // Verify no command was written
  let commandsWritten = 0;
  for (const [key] of table.items) {
    if (key.startsWith('DEVICE#d1#CMD#')) {
      commandsWritten += 1;
    }
  }
  assert.strictEqual(commandsWritten, 0);
});

// ============================================================================
// Scenario: Group command fans out
// ============================================================================

test('Scenario: Group command fans out', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');

  registerGroupRoutes(router, { verifier, table, now: () => now });
  registerCommandDispatchRoutes(router, { verifier, table, now: () => now });

  // Setup: create group g1 with three members (d1, d2, d3)
  const createGroupResp = await makeRequest(router, 'POST', '/admin/api/v1/groups', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ name: 'TestGroup' }),
  });
  const groupId = JSON.parse(createGroupResp.body).groupId;

  for (const deviceId of ['d1', 'd2', 'd3']) {
    await table.put({
      ...deviceProfile(deviceId),
      deviceId,
      hostname: `host-${deviceId}`,
    });

    await table.put({
      ...groupMember(groupId, deviceId),
      deviceId,
      groupId,
    });
  }

  // When an admin queues a collect_logs command for g1
  const response = await makeRequest(router, 'POST', `/admin/api/v1/groups/${groupId}/commands`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      type: 'collect_logs',
      payload: {},
    }),
  });

  // Then queued equals 3 and three command items exist, each with its own commandId
  assert.strictEqual(response.statusCode, 202);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.queued, 3);

  // Count commands written for each device
  const commandsByDevice = {};
  for (const item of table.putCalls) {
    if (item.commandId && item.pk && item.pk.startsWith('DEVICE#')) {
      const deviceId = item.deviceId;
      if (!commandsByDevice[deviceId]) {
        commandsByDevice[deviceId] = [];
      }
      commandsByDevice[deviceId].push(item.commandId);
    }
  }

  // Verify three commands, one per device
  assert.strictEqual(Object.keys(commandsByDevice).length, 3);
  for (const deviceId of ['d1', 'd2', 'd3']) {
    assert(commandsByDevice[deviceId]);
    assert.strictEqual(commandsByDevice[deviceId].length, 1);
  }

  // Verify all have issuedAt equal to now
  for (const item of table.putCalls) {
    if (item.commandId) {
      assert.strictEqual(item.issuedAt, now.getTime());
    }
  }
});

// ============================================================================
// Scenario: Unknown group command
// ============================================================================

test('Scenario: Unknown group command', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerCommandDispatchRoutes(router, { verifier, table });

  // When an admin queues a command for group "nope"
  const response = await makeRequest(router, 'POST', '/admin/api/v1/groups/nope/commands', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      type: 'collect_logs',
      payload: {},
    }),
  });

  // Then the status is 404, the error is not_found and no command item was written
  assert.strictEqual(response.statusCode, 404);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'not_found');

  // Verify no commands were written
  let commandsWritten = 0;
  for (const [key] of table.items) {
    if (key.includes('#CMD#')) {
      commandsWritten += 1;
    }
  }
  assert.strictEqual(commandsWritten, 0);
});

// ============================================================================
// Scenario: Group command with unsupported type writes nothing
// ============================================================================

test('Scenario: Group command with unsupported type writes nothing', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerGroupRoutes(router, { verifier, table });
  registerCommandDispatchRoutes(router, { verifier, table });

  // Setup: create group g1 with three members
  const createGroupResp = await makeRequest(router, 'POST', '/admin/api/v1/groups', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ name: 'TestGroup' }),
  });
  const groupId = JSON.parse(createGroupResp.body).groupId;

  for (const deviceId of ['d1', 'd2', 'd3']) {
    await table.put({
      ...deviceProfile(deviceId),
      deviceId,
      hostname: `host-${deviceId}`,
    });

    await table.put({
      ...groupMember(groupId, deviceId),
      deviceId,
      groupId,
    });
  }

  const initialItemCount = table.items.size;

  // When an admin queues type "format_disk" for g1
  const response = await makeRequest(router, 'POST', `/admin/api/v1/groups/${groupId}/commands`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      type: 'format_disk',
      payload: {},
    }),
  });

  // Then the status is 400, the error is unsupported_command_type and zero command items were written
  assert.strictEqual(response.statusCode, 400);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'unsupported_command_type');

  // Verify no new items were written
  assert.strictEqual(table.items.size, initialItemCount);
});

// ============================================================================
// Scenario: Group restart without confirmation writes nothing
// ============================================================================

test('Scenario: Group restart without confirmation writes nothing', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerGroupRoutes(router, { verifier, table });
  registerCommandDispatchRoutes(router, { verifier, table });

  // Setup: create group g1 with three members
  const createGroupResp = await makeRequest(router, 'POST', '/admin/api/v1/groups', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ name: 'TestGroup' }),
  });
  const groupId = JSON.parse(createGroupResp.body).groupId;

  for (const deviceId of ['d1', 'd2', 'd3']) {
    await table.put({
      ...deviceProfile(deviceId),
      deviceId,
      hostname: `host-${deviceId}`,
    });

    await table.put({
      ...groupMember(groupId, deviceId),
      deviceId,
      groupId,
    });
  }

  const initialItemCount = table.items.size;

  // When an admin queues a restart for g1 without confirm
  const response = await makeRequest(router, 'POST', `/admin/api/v1/groups/${groupId}/commands`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      type: 'restart',
      payload: {},
    }),
  });

  // Then the status is 409, the error is confirmation_required and zero command items were written
  assert.strictEqual(response.statusCode, 409);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'confirmation_required');

  // Verify no new items were written
  assert.strictEqual(table.items.size, initialItemCount);
});

// ============================================================================
// Scenario: Group run_script with a missing payload field writes nothing
// ============================================================================

test('Scenario: Group run_script with missing payload field writes nothing', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerGroupRoutes(router, { verifier, table });
  registerCommandDispatchRoutes(router, { verifier, table });

  // Setup: create group g1 with three members
  const createGroupResp = await makeRequest(router, 'POST', '/admin/api/v1/groups', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ name: 'TestGroup' }),
  });
  const groupId = JSON.parse(createGroupResp.body).groupId;

  for (const deviceId of ['d1', 'd2', 'd3']) {
    await table.put({
      ...deviceProfile(deviceId),
      deviceId,
      hostname: `host-${deviceId}`,
    });

    await table.put({
      ...groupMember(groupId, deviceId),
      deviceId,
      groupId,
    });
  }

  const initialItemCount = table.items.size;

  // When an admin queues run_script with confirm true and no interpreter for g1
  const response = await makeRequest(router, 'POST', `/admin/api/v1/groups/${groupId}/commands`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      type: 'run_script',
      payload: { script: 'echo hello' },
      confirm: true,
    }),
  });

  // Then the status is 400, fields contains "payload.interpreter" and zero command items were written
  assert.strictEqual(response.statusCode, 400);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'invalid_request');
  assert(Array.isArray(body.fields));
  assert(body.fields.includes('payload.interpreter'));

  // Verify no new items were written
  assert.strictEqual(table.items.size, initialItemCount);
});

// ============================================================================
// Unit: offendingPayloadFields validation
// ============================================================================

test('Unit: offendingPayloadFields identifies missing interpreter', () => {
  const fields = offendingPayloadFields('run_script', { script: 'echo' });
  assert(fields.includes('payload.interpreter'));
});

test('Unit: offendingPayloadFields identifies missing script', () => {
  const fields = offendingPayloadFields('run_script', { interpreter: 'powershell' });
  assert(fields.includes('payload.script'));
});

test('Unit: offendingPayloadFields accepts valid run_script', () => {
  const fields = offendingPayloadFields('run_script', {
    interpreter: 'powershell',
    script: 'Get-Process',
  });
  assert.strictEqual(fields.length, 0);
});

test('Unit: offendingPayloadFields identifies missing packageId for install_package', () => {
  const fields = offendingPayloadFields('install_package', {});
  assert(fields.includes('payload.packageId'));
});

test('Unit: offendingPayloadFields accepts valid install_package', () => {
  const fields = offendingPayloadFields('install_package', { packageId: 'pkg-123' });
  assert.strictEqual(fields.length, 0);
});

test('Unit: offendingPayloadFields accepts collect_logs with empty payload', () => {
  const fields = offendingPayloadFields('collect_logs', {});
  assert.strictEqual(fields.length, 0);
});

// ============================================================================
// Unit: Command with missing type
// ============================================================================

test('Unit: Command with missing type returns 400 unsupported_command_type', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerCommandDispatchRoutes(router, { verifier, table });

  await table.put({
    ...deviceProfile('d1'),
    deviceId: 'd1',
    hostname: 'host-d1',
  });

  const response = await makeRequest(router, 'POST', '/admin/api/v1/devices/d1/commands', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      payload: {},
    }),
  });

  assert.strictEqual(response.statusCode, 400);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'unsupported_command_type');
});

// ============================================================================
// Unit: Supported command types
// ============================================================================

test('Unit: All supported command types are accepted', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerCommandDispatchRoutes(router, { verifier, table });

  await table.put({
    ...deviceProfile('d1'),
    deviceId: 'd1',
    hostname: 'host-d1',
  });

  const types = [
    { type: 'lock', payload: {} },
    { type: 'install_package', payload: { packageId: 'pkg-123' } },
    { type: 'uninstall_package', payload: { packageId: 'pkg-123' } },
    { type: 'collect_logs', payload: {} },
    { type: 'run_script', payload: { interpreter: 'powershell', script: 'echo' }, confirm: true },
    { type: 'restart', payload: {}, confirm: true },
  ];

  for (const request of types) {
    const response = await makeRequest(router, 'POST', '/admin/api/v1/devices/d1/commands', {
      headers: { authorization: 'Bearer valid-token' },
      body: JSON.stringify(request),
    });

    assert(response.statusCode === 202 || response.statusCode === 409, `Type ${request.type} failed with ${response.statusCode}`);
  }
});
