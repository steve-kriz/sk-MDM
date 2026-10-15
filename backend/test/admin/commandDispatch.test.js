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
import { registerScriptRoutes } from '../../dist/admin/scripts.js';
import { deviceProfile, groupMember, deviceCommand, deviceCommandSeq, group, script as scriptKey, application as applicationKey } from '../../dist/db/keys.js';
import { createFakeTable } from '../helpers/fakeDynamo.js';
import { DEVICE_APPLICATION_PATH, INSTALL_APPLICATION_TYPE } from '../../dist/admin/commandDispatch.js';

async function seedApplication(table, applicationId, { name, platform }) {
  await table.put({
    ...applicationKey(applicationId),
    applicationId,
    name,
    platform,
    source: 'url',
    installerType: platform === 'darwin' ? 'pkg' : 'msi',
    url: 'https://example.test/a',
    sha256: 'a'.repeat(64),
    createdAt: '2026-10-01T00:00:00Z',
    createdBy: 'seed@officehq.com.au',
  });
}

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

// ============================================================================
// TASK-045: Command library queueing and ordering (Q1-Q11)
//
// These use the real createTableClient over an in-memory documentClient
// (test/helpers/fakeDynamo.js) rather than the hand-rolled FakeTable above, so
// the ADD counter, conditional updates and the move's TransactWrite all run
// through production code. No real database connection is made.
// ============================================================================

/** A deterministic randomBytes() that never repeats within a test. */
function makeRandomBytes() {
  let counter = 0;
  return (n) => {
    const buf = Buffer.alloc(n);
    for (let i = 0; i < n; i += 1) {
      buf[i] = ((counter + i) * 17 + 1) % 256;
    }
    counter += n;
    return buf;
  };
}

async function seedDevice(table, deviceId, platform, hostname) {
  await table.put({ ...deviceProfile(deviceId), deviceId, hostname: hostname ?? `host-${deviceId}`, platform });
}

async function seedScript(table, scriptId, { name, interpreter, platform, script, timeoutSeconds = 300 }) {
  await table.put({
    ...scriptKey(scriptId),
    scriptId,
    name,
    description: null,
    interpreter,
    platform,
    script,
    timeoutSeconds,
    createdAt: '2026-10-01T00:00:00Z',
    createdBy: 'seed@officehq.com.au',
    updatedAt: '2026-10-01T00:00:00Z',
    updatedBy: 'seed@officehq.com.au',
  });
}

async function seedGroup(table, groupId, name) {
  await table.put({ ...group(groupId), groupId, name });
}

async function seedGroupMember(table, groupId, deviceId) {
  await table.put({ ...groupMember(groupId, deviceId) });
}

function commandItemCount(documentClient) {
  let count = 0;
  for (const item of documentClient.items.values()) {
    if (typeof item.sk === 'string' && item.sk.startsWith('CMD#')) {
      count += 1;
    }
  }
  return count;
}

function auditEntries(documentClient, action) {
  return [...documentClient.items.values()].filter((item) => item.action === action);
}

test('Scenario: Q1 Queue a library command on a device', async () => {
  const { table } = createFakeTable();
  const router = createRouter();
  const now = new Date('2026-10-11T00:00:00Z');
  registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => now, randomBytes: makeRandomBytes() });

  await seedDevice(table, 'dev-1', 'windows');
  await seedScript(table, 'scr-0000000000000001', { name: 'Flush DNS', interpreter: 'cmd', platform: 'windows', script: 'ipconfig /flushdns', timeoutSeconds: 60 });

  const response = await makeRequest(router, 'POST', '/admin/api/v1/devices/dev-1/scripts', {
    headers: { authorization: 'Bearer t' },
    body: JSON.stringify({ scriptId: 'scr-0000000000000001', confirm: true }),
  });

  assert.strictEqual(response.statusCode, 202);
  const body = JSON.parse(response.body);
  assert.match(body.commandId, /^cmd-[0-9a-f]{16}$/);
  assert.strictEqual(body.seq, 1);

  const stored = await table.get(deviceCommand('dev-1', body.commandId));
  assert.strictEqual(stored.type, 'run_script');
  assert.strictEqual(stored.status, 'pending');
  assert.strictEqual(stored.seq, 1);
  assert.strictEqual(stored.scriptId, 'scr-0000000000000001');
  assert.strictEqual(stored.scriptName, 'Flush DNS');
  assert.deepStrictEqual(stored.payload, { interpreter: 'cmd', script: 'ipconfig /flushdns', timeoutSeconds: 60 });
  assert.strictEqual(stored.issuedAt, now.getTime());
  assert.ok(stored.issuedBy);
  assert.strictEqual('expiresAt' in stored, false);
});

test('Scenario: Q2 Sequence numbers are per device and increasing', async () => {
  const { table, documentClient } = createFakeTable();
  const router = createRouter();
  registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => new Date('2026-10-11T00:00:00Z'), randomBytes: makeRandomBytes() });

  await seedDevice(table, 'dev-1', 'windows');
  await seedDevice(table, 'dev-2', 'windows');
  await seedScript(table, 'scr-aaaaaaaaaaaaaaaa', { name: 'S', interpreter: 'cmd', platform: 'windows', script: 'echo' });

  const queue = (deviceId) =>
    makeRequest(router, 'POST', `/admin/api/v1/devices/${deviceId}/scripts`, {
      headers: { authorization: 'Bearer t' },
      body: JSON.stringify({ scriptId: 'scr-aaaaaaaaaaaaaaaa', confirm: true }),
    });

  const r1 = await queue('dev-1');
  const r2 = await queue('dev-1');
  const r3 = await queue('dev-2');

  assert.strictEqual(JSON.parse(r1.body).seq, 1);
  assert.strictEqual(JSON.parse(r2.body).seq, 2);
  assert.strictEqual(JSON.parse(r3.body).seq, 1);

  const counter = documentClient.peek('DEVICE#dev-1', 'CMDSEQ');
  assert.strictEqual(counter.next, 2);

  const counterUpdates = documentClient.sends.filter(
    (s) => s.operation === 'Update' && s.input.Key?.pk === 'DEVICE#dev-1' && s.input.Key?.sk === 'CMDSEQ',
  );
  assert.ok(counterUpdates.length >= 1);
  assert.strictEqual(counterUpdates[0].input.UpdateExpression, 'ADD #next :one');
  assert.deepStrictEqual(counterUpdates[0].input.ExpressionAttributeNames, { '#next': 'next' });
});

test('Scenario Outline: Q3 Refused device queue writes nothing', async () => {
  const macOnlyId = 'scr-bbbbbbbbbbbbbbbb';
  const cases = [
    { device: 'dev-1', body: () => ({ confirm: true }), status: 400, error: 'invalid_request' },
    { device: 'dev-1', body: () => ({ scriptId: macOnlyId }), status: 409, error: 'confirmation_required' },
    { device: 'dev-404', body: () => ({ scriptId: macOnlyId, confirm: true }), status: 404, error: 'not_found' },
    { device: 'dev-1', body: () => ({ scriptId: 'scr-0000000000000000', confirm: true }), status: 404, error: 'script_not_found' },
    { device: 'dev-1', body: () => ({ scriptId: macOnlyId, confirm: true }), status: 409, error: 'platform_mismatch' },
  ];

  for (const testCase of cases) {
    const { table, documentClient } = createFakeTable();
    const router = createRouter();
    registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => new Date('2026-10-11T00:00:00Z'), randomBytes: makeRandomBytes() });
    await seedDevice(table, 'dev-1', 'windows');
    await seedScript(table, macOnlyId, { name: 'Mac only', interpreter: 'bash', platform: 'darwin', script: 'ls' });

    const response = await makeRequest(router, 'POST', `/admin/api/v1/devices/${testCase.device}/scripts`, {
      headers: { authorization: 'Bearer t' },
      body: JSON.stringify(testCase.body()),
    });

    assert.strictEqual(response.statusCode, testCase.status, testCase.error);
    assert.strictEqual(JSON.parse(response.body).error, testCase.error);
    assert.strictEqual(commandItemCount(documentClient), 0, testCase.error);
    assert.strictEqual(documentClient.peek('DEVICE#dev-1', 'CMDSEQ'), undefined, testCase.error);
  }
});

test('Scenario: Q4 Editing or deleting the library does not change queued copies', async () => {
  const { table } = createFakeTable();
  const router = createRouter();
  const deps = { verifier: new StubVerifier(), table, now: () => new Date('2026-10-11T00:00:00Z'), randomBytes: makeRandomBytes() };
  registerCommandDispatchRoutes(router, deps);
  registerScriptRoutes(router, deps);

  await seedDevice(table, 'dev-1', 'windows');
  const createRes = await makeRequest(router, 'POST', '/admin/api/v1/scripts', {
    headers: { authorization: 'Bearer t' },
    body: JSON.stringify({ name: 'Alpha', interpreter: 'cmd', script: 'echo 1' }),
  });
  assert.strictEqual(createRes.statusCode, 201);
  const scriptId = JSON.parse(createRes.body).scriptId;

  const queueRes = await makeRequest(router, 'POST', '/admin/api/v1/devices/dev-1/scripts', {
    headers: { authorization: 'Bearer t' },
    body: JSON.stringify({ scriptId, confirm: true }),
  });
  assert.strictEqual(queueRes.statusCode, 202);
  const commandId = JSON.parse(queueRes.body).commandId;

  const putRes = await makeRequest(router, 'PUT', `/admin/api/v1/scripts/${scriptId}`, {
    headers: { authorization: 'Bearer t' },
    body: JSON.stringify({ name: 'Beta', interpreter: 'cmd', script: 'echo 2' }),
  });
  assert.strictEqual(putRes.statusCode, 200);
  const deleteRes = await makeRequest(router, 'DELETE', `/admin/api/v1/scripts/${scriptId}`, {
    headers: { authorization: 'Bearer t' },
  });
  assert.strictEqual(deleteRes.statusCode, 204);

  const stored = await table.get(deviceCommand('dev-1', commandId));
  assert.strictEqual(stored.payload.script, 'echo 1');
  assert.strictEqual(stored.scriptName, 'Alpha');
  assert.strictEqual(stored.status, 'pending');
});

test('Scenario: Q5 Group fan-out skips members on the wrong platform', async () => {
  const { table, documentClient } = createFakeTable();
  const router = createRouter();
  registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => new Date('2026-10-11T00:00:00Z'), randomBytes: makeRandomBytes() });

  await seedGroup(table, 'g-1', 'Group One');
  await seedGroupMember(table, 'g-1', 'w-1');
  await seedGroupMember(table, 'g-1', 'w-2');
  await seedGroupMember(table, 'g-1', 'm-1');
  await seedGroupMember(table, 'g-1', 'ghost');
  await seedDevice(table, 'w-1', 'windows');
  await seedDevice(table, 'w-2', 'windows');
  await seedDevice(table, 'm-1', 'darwin');
  // 'ghost' is a member with no device profile at all.

  await seedScript(table, 'scr-cccccccccccccccc', { name: 'Flush DNS', interpreter: 'cmd', platform: 'windows', script: 'ipconfig /flushdns' });

  const response = await makeRequest(router, 'POST', '/admin/api/v1/groups/g-1/scripts', {
    headers: { authorization: 'Bearer t' },
    body: JSON.stringify({ scriptId: 'scr-cccccccccccccccc', confirm: true }),
  });

  assert.strictEqual(response.statusCode, 202);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.queued, 2);
  assert.strictEqual(body.skipped.wrongPlatform, 2);

  const commandsFor = (deviceId) => [...documentClient.items.values()].filter((i) => i.pk === `DEVICE#${deviceId}` && i.sk.startsWith('CMD#'));
  const w1 = commandsFor('w-1');
  const w2 = commandsFor('w-2');
  assert.strictEqual(w1.length, 1);
  assert.strictEqual(w2.length, 1);
  assert.strictEqual(w1[0].groupId, 'g-1');
  assert.strictEqual(w2[0].groupId, 'g-1');
  assert.strictEqual(w1[0].seq, 1);
  assert.strictEqual(w2[0].seq, 1);
  assert.notStrictEqual(w1[0].commandId, w2[0].commandId);
  assert.strictEqual(commandsFor('m-1').length, 0);
  assert.strictEqual(commandsFor('ghost').length, 0);
});

test('Scenario: Q5 Empty group queues nothing', async () => {
  const { table } = createFakeTable();
  const router = createRouter();
  registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => new Date('2026-10-11T00:00:00Z'), randomBytes: makeRandomBytes() });

  await seedGroup(table, 'g-empty', 'Empty');
  await seedScript(table, 'scr-dddddddddddddddd', { name: 'S', interpreter: 'cmd', platform: 'windows', script: 'echo' });

  const response = await makeRequest(router, 'POST', '/admin/api/v1/groups/g-empty/scripts', {
    headers: { authorization: 'Bearer t' },
    body: JSON.stringify({ scriptId: 'scr-dddddddddddddddd', confirm: true }),
  });

  assert.strictEqual(response.statusCode, 202);
  assert.deepStrictEqual(JSON.parse(response.body), { queued: 0, skipped: { wrongPlatform: 0 } });
});

test('Scenario Outline: Q6 Refused group queue writes nothing', async () => {
  const winScriptId = 'scr-eeeeeeeeeeeeeeee';
  const cases = [
    { group: 'g-1', body: () => ({ confirm: true }), status: 400, error: 'invalid_request' },
    { group: 'g-1', body: () => ({ scriptId: winScriptId }), status: 409, error: 'confirmation_required' },
    { group: 'g-none', body: () => ({ scriptId: winScriptId, confirm: true }), status: 404, error: 'not_found' },
    { group: 'g-1', body: () => ({ scriptId: 'scr-0000000000000000', confirm: true }), status: 404, error: 'script_not_found' },
  ];

  for (const testCase of cases) {
    const { table, documentClient } = createFakeTable();
    const router = createRouter();
    registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => new Date('2026-10-11T00:00:00Z'), randomBytes: makeRandomBytes() });
    await seedGroup(table, 'g-1', 'G1');
    await seedGroupMember(table, 'g-1', 'w-1');
    await seedDevice(table, 'w-1', 'windows');
    await seedScript(table, winScriptId, { name: 'S', interpreter: 'cmd', platform: 'windows', script: 'echo' });

    const response = await makeRequest(router, 'POST', `/admin/api/v1/groups/${testCase.group}/scripts`, {
      headers: { authorization: 'Bearer t' },
      body: JSON.stringify(testCase.body()),
    });

    assert.strictEqual(response.statusCode, testCase.status, testCase.error);
    assert.strictEqual(JSON.parse(response.body).error, testCase.error);
    assert.strictEqual(commandItemCount(documentClient), 0, testCase.error);
  }
});

test('Scenario: Q7 Queuing is audited per command', async () => {
  const { table, documentClient } = createFakeTable();
  const router = createRouter();
  registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => new Date('2026-10-11T00:00:00Z'), randomBytes: makeRandomBytes() });

  await seedGroup(table, 'g-1', 'G1');
  await seedGroupMember(table, 'g-1', 'w-1');
  await seedGroupMember(table, 'g-1', 'w-2');
  await seedDevice(table, 'w-1', 'windows');
  await seedDevice(table, 'w-2', 'windows');
  await seedScript(table, 'scr-ffffffffffffffff', { name: 'S', interpreter: 'cmd', platform: 'windows', script: 'echo' });

  const response = await makeRequest(router, 'POST', '/admin/api/v1/groups/g-1/scripts', {
    headers: { authorization: 'Bearer t' },
    body: JSON.stringify({ scriptId: 'scr-ffffffffffffffff', confirm: true }),
  });
  assert.strictEqual(response.statusCode, 202);

  const audits = auditEntries(documentClient, 'command.queued');
  assert.strictEqual(audits.length, 2);
  assert.deepStrictEqual(audits.map((a) => a.target).sort(), ['w-1', 'w-2']);
  for (const entry of audits) {
    assert.strictEqual(entry.detail.type, 'run_script');
    assert.strictEqual(entry.detail.scriptId, 'scr-ffffffffffffffff');
    assert.strictEqual(entry.detail.groupId, 'g-1');
    assert.ok(entry.detail.commandId);
    assert.ok(entry.detail.seq);
  }
});

test('Scenario: Q8 Move up swaps with the nearest pending command', async () => {
  const { table, documentClient } = createFakeTable();
  const router = createRouter();
  registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => new Date('2026-10-11T00:00:00Z'), randomBytes: makeRandomBytes() });

  await seedDevice(table, 'dev-1', 'windows');
  await table.put({ ...deviceCommand('dev-1', 'A'), commandId: 'A', status: 'pending', seq: 1, type: 'run_script' });
  await table.put({ ...deviceCommand('dev-1', 'B'), commandId: 'B', status: 'leased', seq: 2, type: 'run_script' });
  await table.put({ ...deviceCommand('dev-1', 'C'), commandId: 'C', status: 'pending', seq: 3, type: 'run_script' });

  const response = await makeRequest(router, 'POST', '/admin/api/v1/devices/dev-1/commands/C/move', {
    headers: { authorization: 'Bearer t' },
    body: JSON.stringify({ direction: 'up' }),
  });
  assert.strictEqual(response.statusCode, 200);

  const a = await table.get(deviceCommand('dev-1', 'A'));
  const b = await table.get(deviceCommand('dev-1', 'B'));
  const c = await table.get(deviceCommand('dev-1', 'C'));
  assert.strictEqual(c.seq, 1);
  assert.strictEqual(a.seq, 3);
  assert.strictEqual(b.seq, 2);

  const transactWrites = documentClient.sends.filter((s) => s.operation === 'TransactWrite');
  assert.strictEqual(transactWrites.length, 1);
  const items = transactWrites[0].input.TransactItems;
  assert.strictEqual(items.length, 2);
  for (const item of items) {
    assert.match(item.Update.ConditionExpression, /#status = :pending/);
    assert.match(item.Update.ConditionExpression, /#seq = :readSeq/);
  }

  const audits = auditEntries(documentClient, 'command.moved');
  assert.strictEqual(audits.length, 1);
  assert.deepStrictEqual(audits[0].detail, { commandId: 'C', direction: 'up' });
});

test('Scenario: Q8 Move down swaps with the next pending command', async () => {
  const { table } = createFakeTable();
  const router = createRouter();
  registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => new Date('2026-10-11T00:00:00Z'), randomBytes: makeRandomBytes() });

  await seedDevice(table, 'dev-1', 'windows');
  await table.put({ ...deviceCommand('dev-1', 'A'), commandId: 'A', status: 'pending', seq: 1, type: 'run_script' });
  await table.put({ ...deviceCommand('dev-1', 'B'), commandId: 'B', status: 'pending', seq: 2, type: 'run_script' });

  const response = await makeRequest(router, 'POST', '/admin/api/v1/devices/dev-1/commands/A/move', {
    headers: { authorization: 'Bearer t' },
    body: JSON.stringify({ direction: 'down' }),
  });
  assert.strictEqual(response.statusCode, 200);

  const a = await table.get(deviceCommand('dev-1', 'A'));
  const b = await table.get(deviceCommand('dev-1', 'B'));
  assert.strictEqual(a.seq, 2);
  assert.strictEqual(b.seq, 1);
});

test('Scenario: Q9 Move at the edge is a no-op', async () => {
  const { table, documentClient } = createFakeTable();
  const router = createRouter();
  registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => new Date('2026-10-11T00:00:00Z'), randomBytes: makeRandomBytes() });

  await seedDevice(table, 'dev-1', 'windows');
  await table.put({ ...deviceCommand('dev-1', 'A'), commandId: 'A', status: 'pending', seq: 1, type: 'run_script' });
  await table.put({ ...deviceCommand('dev-1', 'B'), commandId: 'B', status: 'pending', seq: 2, type: 'run_script' });

  const response = await makeRequest(router, 'POST', '/admin/api/v1/devices/dev-1/commands/A/move', {
    headers: { authorization: 'Bearer t' },
    body: JSON.stringify({ direction: 'up' }),
  });
  assert.strictEqual(response.statusCode, 200);

  const a = await table.get(deviceCommand('dev-1', 'A'));
  const b = await table.get(deviceCommand('dev-1', 'B'));
  assert.strictEqual(a.seq, 1);
  assert.strictEqual(b.seq, 2);
  assert.strictEqual(auditEntries(documentClient, 'command.moved').length, 0);
  assert.strictEqual(documentClient.sends.filter((s) => s.operation === 'TransactWrite').length, 0);
});

test('Scenario Outline: Q9 Refused moves change nothing', async () => {
  const cases = [
    { command: 'L', direction: 'up', status: 409, error: 'not_pending' },
    { command: 'cmd-ffffffffffffffff', direction: 'up', status: 404, error: 'not_found' },
    { command: 'A', direction: 'left', status: 400, error: 'invalid_request' },
  ];

  for (const testCase of cases) {
    const { table } = createFakeTable();
    const router = createRouter();
    registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => new Date('2026-10-11T00:00:00Z'), randomBytes: makeRandomBytes() });
    await seedDevice(table, 'dev-1', 'windows');
    await table.put({ ...deviceCommand('dev-1', 'A'), commandId: 'A', status: 'pending', seq: 1, type: 'run_script' });
    await table.put({ ...deviceCommand('dev-1', 'L'), commandId: 'L', status: 'leased', seq: 2, type: 'run_script' });

    const response = await makeRequest(router, 'POST', `/admin/api/v1/devices/dev-1/commands/${testCase.command}/move`, {
      headers: { authorization: 'Bearer t' },
      body: JSON.stringify({ direction: testCase.direction }),
    });
    assert.strictEqual(response.statusCode, testCase.status, testCase.error);
    assert.strictEqual(JSON.parse(response.body).error, testCase.error);

    const a = await table.get(deviceCommand('dev-1', 'A'));
    const l = await table.get(deviceCommand('dev-1', 'L'));
    assert.strictEqual(a.seq, 1);
    assert.strictEqual(l.seq, 2);
  }
});

test('Scenario: Q9 Move losing a race with a lease', async () => {
  const { table, documentClient } = createFakeTable();
  const router = createRouter();
  registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => new Date('2026-10-11T00:00:00Z'), randomBytes: makeRandomBytes() });

  await seedDevice(table, 'dev-1', 'windows');
  await table.put({ ...deviceCommand('dev-1', 'A'), commandId: 'A', status: 'pending', seq: 1, type: 'run_script' });
  await table.put({ ...deviceCommand('dev-1', 'B'), commandId: 'B', status: 'pending', seq: 2, type: 'run_script' });

  // Simulate a lease winning the race for A between the move's read and its
  // TransactWrite: by the time the swap's condition is evaluated, A is no
  // longer pending at seq 1, so the whole transaction is cancelled.
  const originalSend = documentClient.send.bind(documentClient);
  documentClient.send = async (command) => {
    if (command.operation === 'TransactWrite') {
      documentClient.seed({ pk: 'DEVICE#dev-1', sk: 'CMD#A', commandId: 'A', status: 'leased', seq: 1, type: 'run_script' });
    }
    return originalSend(command);
  };

  const response = await makeRequest(router, 'POST', '/admin/api/v1/devices/dev-1/commands/B/move', {
    headers: { authorization: 'Bearer t' },
    body: JSON.stringify({ direction: 'up' }),
  });
  assert.strictEqual(response.statusCode, 409);
  assert.strictEqual(JSON.parse(response.body).error, 'not_pending');

  const a = await table.get(deviceCommand('dev-1', 'A'));
  const b = await table.get(deviceCommand('dev-1', 'B'));
  assert.strictEqual(a.seq, 1);
  assert.strictEqual(b.seq, 2);
});

test('Scenario: Q10 Cancel a pending command', async () => {
  const { table, documentClient } = createFakeTable();
  const router = createRouter();
  registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => new Date('2026-10-11T00:00:00Z'), randomBytes: makeRandomBytes() });

  await seedDevice(table, 'dev-1', 'windows');
  await table.put({ ...deviceCommand('dev-1', 'A'), commandId: 'A', status: 'pending', seq: 1, type: 'run_script' });

  const response = await makeRequest(router, 'POST', '/admin/api/v1/devices/dev-1/commands/A/cancel', {
    headers: { authorization: 'Bearer t' },
  });
  assert.strictEqual(response.statusCode, 200);
  assert.strictEqual(JSON.parse(response.body).status, 'cancelled');

  const a = await table.get(deviceCommand('dev-1', 'A'));
  assert.strictEqual(a.status, 'cancelled');

  const audits = auditEntries(documentClient, 'command.cancelled');
  assert.strictEqual(audits.length, 1);
  assert.deepStrictEqual(audits[0].detail, { commandId: 'A' });
});

test('Scenario Outline: Q10 Cancel refused for a non-pending or unknown command', async () => {
  const cases = [
    { status: 'leased', command: 'A', code: 409, error: 'not_pending' },
    { status: 'succeeded', command: 'A', code: 409, error: 'not_pending' },
    { status: 'skipped', command: 'A', code: 409, error: 'not_pending' },
    { status: 'pending', command: 'cmd-ffffffffffffffff', code: 404, error: 'not_found' },
  ];

  for (const testCase of cases) {
    const { table } = createFakeTable();
    const router = createRouter();
    registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => new Date('2026-10-11T00:00:00Z'), randomBytes: makeRandomBytes() });
    await seedDevice(table, 'dev-1', 'windows');
    await table.put({ ...deviceCommand('dev-1', 'A'), commandId: 'A', status: testCase.status, seq: 1, type: 'run_script' });

    const response = await makeRequest(router, 'POST', `/admin/api/v1/devices/dev-1/commands/${testCase.command}/cancel`, {
      headers: { authorization: 'Bearer t' },
    });
    assert.strictEqual(response.statusCode, testCase.code, testCase.error);
    assert.strictEqual(JSON.parse(response.body).error, testCase.error);

    const a = await table.get(deviceCommand('dev-1', 'A'));
    assert.strictEqual(a.status, testCase.status);
  }
});

test('Scenario: Q11 Raw dispatch accepts cmd and bash and keeps its expiry', async () => {
  const { table } = createFakeTable();
  const router = createRouter();
  const now = new Date('2026-10-11T00:00:00Z');
  registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => now, randomBytes: makeRandomBytes() });

  await seedDevice(table, 'dev-1', 'darwin');

  const response = await makeRequest(router, 'POST', '/admin/api/v1/devices/dev-1/commands', {
    headers: { authorization: 'Bearer t' },
    body: JSON.stringify({ type: 'run_script', payload: { interpreter: 'bash', script: 'ls' }, confirm: true }),
  });
  assert.strictEqual(response.statusCode, 202);
  const commandId = JSON.parse(response.body).commandId;

  const stored = await table.get(deviceCommand('dev-1', commandId));
  assert.strictEqual(stored.expiresAt, now.getTime() + 86400000);
  assert.strictEqual('seq' in stored, false);

  // cmd on a windows device is accepted too.
  await seedDevice(table, 'dev-2', 'windows');
  const cmdResponse = await makeRequest(router, 'POST', '/admin/api/v1/devices/dev-2/commands', {
    headers: { authorization: 'Bearer t' },
    body: JSON.stringify({ type: 'run_script', payload: { interpreter: 'cmd', script: 'dir' }, confirm: true }),
  });
  assert.strictEqual(cmdResponse.statusCode, 202);
});

// ============================================================================
// TASK-049 AC7: Queue an application install on a device
// ============================================================================

test('Scenario: Queue an install on a device', async () => {
  const { table, documentClient } = createFakeTable();
  const router = createRouter();
  const now = new Date('2026-10-11T00:00:00Z');
  registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => now, randomBytes: makeRandomBytes() });

  await seedDevice(table, 'dev-1', 'windows');
  await seedApplication(table, 'app-1', { name: '7-Zip', platform: 'windows' });
  // Given CMDSEQ next 4 already queued once before this request.
  await table.update(deviceCommandSeq('dev-1'), {
    UpdateExpression: 'ADD #next :one',
    ExpressionAttributeNames: { '#next': 'next' },
    ExpressionAttributeValues: { ':one': 4 },
  });

  const response = await makeRequest(router, 'POST', `/admin/api/v1${DEVICE_APPLICATION_PATH.replace('{deviceId}', 'dev-1')}`, {
    headers: { authorization: 'Bearer t' },
    body: JSON.stringify({ applicationId: 'app-1' }),
  });

  assert.strictEqual(response.statusCode, 202);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.seq, 5);

  const stored = await table.get(deviceCommand('dev-1', body.commandId));
  assert.strictEqual(stored.type, INSTALL_APPLICATION_TYPE);
  assert.deepStrictEqual(stored.payload, { applicationId: 'app-1', applicationName: '7-Zip', timeoutSeconds: 3600 });
  assert.strictEqual(stored.status, 'pending');
  assert.strictEqual(stored.scriptName, '7-Zip');
  assert.strictEqual('expiresAt' in stored, false);

  const audit = [...documentClient.items.values()].find((item) => item.action === 'command.queued');
  assert.ok(audit);
  assert.deepStrictEqual(audit.detail, { commandId: body.commandId, type: INSTALL_APPLICATION_TYPE, applicationId: 'app-1', seq: 5 });
});

test('Scenario Outline: Queue refused without touching the counter', async () => {
  const cases = [
    { body: () => ({ applicationId: '' }), status: 400, error: 'invalid_request' },
    { device: 'dev-404', body: () => ({ applicationId: 'app-1' }), status: 404, error: 'not_found' },
    { body: () => ({ applicationId: 'app-missing' }), status: 404, error: 'application_not_found' },
    { body: () => ({ applicationId: 'app-mac' }), status: 409, error: 'platform_mismatch' },
  ];

  for (const testCase of cases) {
    const { table, documentClient } = createFakeTable();
    const router = createRouter();
    registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => new Date('2026-10-11T00:00:00Z'), randomBytes: makeRandomBytes() });
    await seedDevice(table, 'dev-1', 'windows');
    await seedApplication(table, 'app-1', { name: '7-Zip', platform: 'windows' });
    await seedApplication(table, 'app-mac', { name: 'Mac App', platform: 'darwin' });

    const device = testCase.device ?? 'dev-1';
    const response = await makeRequest(router, 'POST', `/admin/api/v1${DEVICE_APPLICATION_PATH.replace('{deviceId}', device)}`, {
      headers: { authorization: 'Bearer t' },
      body: JSON.stringify(testCase.body()),
    });

    assert.strictEqual(response.statusCode, testCase.status, testCase.error);
    assert.strictEqual(JSON.parse(response.body).error, testCase.error);
    assert.strictEqual(commandItemCount(documentClient), 0, testCase.error);
    assert.strictEqual(documentClient.peek('DEVICE#dev-1', 'CMDSEQ'), undefined, testCase.error);
  }
});

test('Scenario: Raw dispatch cannot send install_application', async () => {
  const { table } = createFakeTable();
  const router = createRouter();
  registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => new Date('2026-10-11T00:00:00Z'), randomBytes: makeRandomBytes() });
  await seedDevice(table, 'dev-1', 'windows');

  const response = await makeRequest(router, 'POST', '/admin/api/v1/devices/dev-1/commands', {
    headers: { authorization: 'Bearer t' },
    body: JSON.stringify({ type: 'install_application', payload: { applicationId: 'app-1' } }),
  });

  assert.strictEqual(response.statusCode, 400);
  assert.strictEqual(JSON.parse(response.body).error, 'unsupported_command_type');
});
