/**
 * E2E and unit tests for agent-facing command queue routes.
 * Tests cover the Gherkin scenarios for TASK-008.
 * All database calls are mocked — no real DB connections.
 */

import test from 'node:test';
import assert from 'node:assert';
import {
  createLeaseHandler,
  createResultHandler,
  registerCommandRoutes,
  LEASE_CONDITION,
  LEASE_SECONDS,
  MAX_OUTPUT_BYTES,
  DEFAULT_MAX_COMMANDS,
  MAX_MAX_COMMANDS,
  LEASE_CONDITION as LEASE_COND,
  LEASE_TERMINAL_STATUSES,
  NO_EXPIRY_WIRE_MILLIS,
  byRunOrder,
} from '../../dist/routes/commands.js';
import { createRouter } from '../../dist/index.js';
import { createFakeTable } from '../helpers/fakeDynamo.js';
import { deviceCommand, deviceProfile, commandSettings } from '../../dist/db/keys.js';

/**
 * Fake table client that records operations and condition expressions.
 */
class FakeTable {
  constructor() {
    this.items = new Map(); // key: "pk#sk" -> item
    this.operations = [];
    this.conditionExpressions = [];
  }

  recordOperation(op, key, fields) {
    this.operations.push({ op, key, fields });
    if (fields?.ConditionExpression) {
      this.conditionExpressions.push(fields.ConditionExpression);
    }
  }

  setItem(pk, sk, item) {
    const key = `${pk}#${sk}`;
    this.items.set(key, { ...item, pk, sk });
  }

  async get(key) {
    this.recordOperation('get', key, {});
    const keyStr = `${key.pk}#${key.sk}`;
    const item = this.items.get(keyStr);
    return item || undefined;
  }

  async query(request) {
    this.recordOperation('query', request, {});
    const pkValue = request?.ExpressionAttributeValues?.[':pk'];
    const commandPrefix = request?.ExpressionAttributeValues?.[':commandPrefix'];

    if (!pkValue || !commandPrefix) {
      return { items: [], cursor: null };
    }

    const items = [];
    for (const item of this.items.values()) {
      if (item.pk === pkValue && item.sk.startsWith(commandPrefix)) {
        items.push(item);
      }
    }
    return { items, cursor: null };
  }

  async update(key, fields) {
    this.recordOperation('update', key, fields);

    const keyStr = `${key.pk}#${key.sk}`;
    let item = this.items.get(keyStr);

    if (!item) {
      return undefined;
    }

    // Evaluate condition if present
    if (fields?.ConditionExpression) {
      const condition = fields.ConditionExpression;
      const values = fields.ExpressionAttributeValues || {};
      const names = fields.ExpressionAttributeNames || {};

      if (!this.evaluateCondition(condition, values, names, item)) {
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
        fields.ExpressionAttributeValues || {},
      );
      item = { ...item, ...updates };
      this.items.set(keyStr, item);
    }

    return item;
  }

  async putIfAbsent(item) {
    this.recordOperation('putIfAbsent', { pk: item.pk, sk: item.sk }, {});
    const key = `${item.pk}#${item.sk}`;
    if (this.items.has(key)) {
      return { written: false };
    }
    this.items.set(key, item);
    return { written: true };
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

  /**
   * Evaluate a condition expression.
   * LEASE_CONDITION: "#status = :pending OR (#status = :leased AND leaseExpiresAt <= :now)"
   * EXPIRE_CONDITION: "#status = :pending OR #status = :leased"
   */
  evaluateCondition(condition, values, names, item) {
    // Replace attribute names with actual field names
    let cond = condition;
    for (const [placeholder, fieldName] of Object.entries(names)) {
      cond = cond.replace(new RegExp('\\' + placeholder, 'g'), fieldName);
    }

    // Parse the condition:
    // For LEASE_CONDITION: "status = :pending OR (status = :leased AND leaseExpiresAt <= :now)"
    // For EXPIRE_CONDITION: "status = :pending OR status = :leased"

    if (cond.includes(' OR ')) {
      // Split by OR at the top level (outside parentheses)
      const parts = this.splitByOr(cond);
      for (const part of parts) {
        if (this.evaluateSimpleCondition(part.trim(), values, item)) {
          return true;
        }
      }
      return false;
    }

    return this.evaluateSimpleCondition(cond, values, item);
  }

  splitByOr(expr) {
    const parts = [];
    let current = '';
    let parenLevel = 0;

    for (const char of expr) {
      if (char === '(') {
        parenLevel++;
        current += char;
      } else if (char === ')') {
        parenLevel--;
        current += char;
      } else if (parenLevel === 0 && expr.substring(expr.indexOf(current) + current.length).startsWith(' OR ')) {
        // This is a top-level OR
        parts.push(current);
        current = '';
      } else {
        current += char;
      }
    }
    if (current) {
      parts.push(current);
    }

    // Better approach: just split on " OR " when not in parentheses
    const result = [];
    let part = '';
    let depth = 0;
    for (let i = 0; i < expr.length; i++) {
      const char = expr[i];
      if (char === '(') depth++;
      else if (char === ')') depth--;

      if (depth === 0 && expr.substr(i, 4) === ' OR ') {
        result.push(part.trim());
        part = '';
        i += 3; // skip ' OR'
      } else {
        part += char;
      }
    }
    if (part) result.push(part.trim());
    return result;
  }

  evaluateSimpleCondition(condition, values, item) {
    condition = condition.trim();

    // Remove outer parentheses if present
    if (condition.startsWith('(') && condition.endsWith(')')) {
      condition = condition.slice(1, -1).trim();
    }

    // Handle "AND" conditions
    if (condition.includes(' AND ')) {
      const parts = this.splitByAnd(condition);
      for (const part of parts) {
        if (!this.evaluateSimpleCondition(part.trim(), values, item)) {
          return false;
        }
      }
      return true;
    }

    // Handle comparison: "field op value"
    if (condition.includes('<=')) {
      const [fieldPart, valuePart] = condition.split('<=').map(s => s.trim());
      const fieldValue = item[fieldPart];
      const compareValue = values[valuePart];
      return fieldValue <= compareValue;
    }

    if (condition.includes('=')) {
      const [fieldPart, valuePart] = condition.split('=').map(s => s.trim());
      const fieldValue = item[fieldPart];
      const compareValue = values[valuePart];
      return fieldValue === compareValue;
    }

    return true;
  }

  splitByAnd(expr) {
    const result = [];
    let part = '';
    let depth = 0;
    for (let i = 0; i < expr.length; i++) {
      const char = expr[i];
      if (char === '(') depth++;
      else if (char === ')') depth--;

      if (depth === 0 && expr.substr(i, 5) === ' AND ') {
        result.push(part.trim());
        part = '';
        i += 4; // skip ' AND'
      } else {
        part += char;
      }
    }
    if (part) result.push(part.trim());
    return result;
  }
}

function createFakeVerifier(deviceId) {
  return async () => ({
    ok: true,
    deviceId,
  });
}

// ===== E2E Scenarios (Gherkin-style) =====

test('E2E: Pending commands are leased', async () => {
  // Given three pending commands and max=2
  const table = new FakeTable();
  const now = () => 1000; // 1000 seconds = 1000000 milliseconds

  // Create 3 pending commands
  for (let i = 0; i < 3; i++) {
    table.setItem('DEVICE#dev1', `CMD#cmd${i}`, {
      commandId: `cmd${i}`,
      type: 'execute',
      payload: { script: 'echo hello' },
      issuedAt: 900000, // 900000 ms (in the past)
      expiresAt: 2000000, // 2000000 ms (in the future)
      status: 'pending',
    });
  }

  const handler = createLeaseHandler({
    table,
    now,
    verifyDevice: createFakeVerifier('dev1'),
  });

  // When the agent polls with max=2
  const response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev1/commands',
    params: { deviceId: 'dev1' },
    query: { max: '2' },
    headers: {},
    body: null,
  });

  // Then two commands are returned with correct fields
  assert.strictEqual(response.statusCode, 200);
  const body = response.body;
  assert.strictEqual(body.commands.length, 2);
  for (const cmd of body.commands) {
    assert.ok(cmd.commandId);
    assert.strictEqual(typeof cmd.type, 'string');
    assert.ok(cmd.payload !== undefined);
    assert.strictEqual(typeof cmd.issuedAt, 'number');
    assert.strictEqual(typeof cmd.expiresAt, 'number');
  }
});

test('E2E: Another device\'s queue is refused', async () => {
  // Given a request where verifyDeviceRequest returns d1 but path is d2
  const table = new FakeTable();
  const now = () => 1000;

  table.setItem('DEVICE#d1', 'CMD#cmd1', {
    commandId: 'cmd1',
    status: 'pending',
    issuedAt: 900000,
    expiresAt: 2000000,
  });

  const handler = createLeaseHandler({
    table,
    now,
    verifyDevice: createFakeVerifier('d1'),
  });

  // When polling /devices/d2/commands
  const response = await handler({
    method: 'GET',
    path: '/api/v1/devices/d2/commands',
    params: { deviceId: 'd2' },
    query: {},
    headers: {},
    body: null,
  });

  // Then status is 403, error is device_mismatch, and no query was issued
  assert.strictEqual(response.statusCode, 403);
  assert.strictEqual(response.body.error, 'device_mismatch');
  const queryOps = table.operations.filter(op => op.op === 'query');
  assert.strictEqual(queryOps.length, 0, 'no query should have been executed');
});

test('E2E: Lease stamps an expiry under the combined condition', async () => {
  // Given a pending command and server time 1000
  const table = new FakeTable();
  const now = () => 1000;

  table.setItem('DEVICE#dev1', 'CMD#cmd1', {
    commandId: 'cmd1',
    type: 'execute',
    payload: {},
    issuedAt: 900000,
    expiresAt: 2000000,
    status: 'pending',
  });

  const handler = createLeaseHandler({
    table,
    now,
    verifyDevice: createFakeVerifier('dev1'),
  });

  // When it is leased
  const response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev1/commands',
    params: { deviceId: 'dev1' },
    query: {},
    headers: {},
    body: null,
  });

  // Then its status is leased, leaseExpiresAt is 1300
  assert.strictEqual(response.statusCode, 200);
  assert.strictEqual(response.body.commands.length, 1);

  const item = table.items.get('DEVICE#dev1#CMD#cmd1');
  assert.strictEqual(item.status, 'leased');
  assert.strictEqual(item.leaseExpiresAt, 1300);

  // And the update condition was used
  const updateOps = table.operations.filter(op => op.op === 'update');
  assert.ok(updateOps.length > 0, 'at least one update should have occurred');
});

test('E2E: Expired lease is re-offered and re-stamped', async () => {
  // Given a leased command whose leaseExpiresAt is in the past and server time 2000
  const table = new FakeTable();
  const now = () => 2000;

  table.setItem('DEVICE#dev1', 'CMD#cmd1', {
    commandId: 'cmd1',
    type: 'execute',
    payload: {},
    issuedAt: 900000,
    expiresAt: 3000000,
    status: 'leased',
    leaseExpiresAt: 1500, // In the past relative to now (2000)
  });

  const handler = createLeaseHandler({
    table,
    now,
    verifyDevice: createFakeVerifier('dev1'),
  });

  // When the agent polls
  const response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev1/commands',
    params: { deviceId: 'dev1' },
    query: {},
    headers: {},
    body: null,
  });

  // Then that command is returned again and its leaseExpiresAt is 2300
  assert.strictEqual(response.statusCode, 200);
  assert.strictEqual(response.body.commands.length, 1);
  assert.strictEqual(response.body.commands[0].commandId, 'cmd1');

  const item = table.items.get('DEVICE#dev1#CMD#cmd1');
  assert.strictEqual(item.leaseExpiresAt, 2300);
});

test('E2E: Live lease is withheld', async () => {
  // Given a leased command whose leaseExpiresAt is in the future
  const table = new FakeTable();
  const now = () => 1000;

  table.setItem('DEVICE#dev1', 'CMD#cmd1', {
    commandId: 'cmd1',
    type: 'execute',
    payload: {},
    issuedAt: 900000,
    expiresAt: 2000000,
    status: 'leased',
    leaseExpiresAt: 1500, // In the future relative to now (1000)
  });

  const handler = createLeaseHandler({
    table,
    now,
    verifyDevice: createFakeVerifier('dev1'),
  });

  // When the agent polls
  const response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev1/commands',
    params: { deviceId: 'dev1' },
    query: {},
    headers: {},
    body: null,
  });

  // Then that command is not returned and its stored item is unchanged
  assert.strictEqual(response.statusCode, 200);
  assert.strictEqual(response.body.commands.length, 0);

  const item = table.items.get('DEVICE#dev1#CMD#cmd1');
  assert.strictEqual(item.leaseExpiresAt, 1500, 'stored item unchanged');
  assert.strictEqual(item.status, 'leased');
});

test('E2E: Expired command is dropped', async () => {
  // Given a pending command whose expiresAt is in the past
  const table = new FakeTable();
  const now = () => 6000; // 6000 seconds = 6000000 ms

  table.setItem('DEVICE#dev1', 'CMD#cmd1', {
    commandId: 'cmd1',
    type: 'execute',
    payload: {},
    issuedAt: 900000,
    expiresAt: 5000000, // 5000000 ms - in the past relative to now (6000000 ms)
    status: 'pending',
  });

  const handler = createLeaseHandler({
    table,
    now,
    verifyDevice: createFakeVerifier('dev1'),
  });

  // When the agent polls
  const response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev1/commands',
    params: { deviceId: 'dev1' },
    query: {},
    headers: {},
    body: null,
  });

  // Then no command is returned and the stored status is expired
  assert.strictEqual(response.statusCode, 200);
  assert.strictEqual(response.body.commands.length, 0);

  const item = table.items.get('DEVICE#dev1#CMD#cmd1');
  assert.strictEqual(item.status, 'expired', 'status should be marked as expired');
});

test('E2E: Result is recorded and truncated', async () => {
  // Given a leased command and a result with status succeeded, exitCode 0, finishedAt 1500 and 20000 bytes of output
  const table = new FakeTable();
  const now = () => 1000;

  table.setItem('DEVICE#dev1', 'CMD#cmd1', {
    commandId: 'cmd1',
    status: 'leased',
    leaseExpiresAt: 1500,
  });

  const longOutput = 'x'.repeat(20000);
  const resultBody = JSON.stringify({
    status: 'succeeded',
    exitCode: 0,
    output: longOutput,
    finishedAt: 1500,
  });

  const handler = createResultHandler({
    table,
    now,
    verifyDevice: createFakeVerifier('dev1'),
  });

  // When the result is posted
  const response = await handler({
    method: 'POST',
    path: '/api/v1/devices/dev1/commands/cmd1/result',
    params: { deviceId: 'dev1', commandId: 'cmd1' },
    query: {},
    headers: {},
    body: resultBody,
  });

  // Then the status is 200
  assert.strictEqual(response.statusCode, 200);

  // And the stored item has status succeeded, output of 8192 bytes, exitCode 0 and finishedAt 1500
  const item = table.items.get('DEVICE#dev1#CMD#cmd1');
  assert.strictEqual(item.status, 'succeeded');
  assert.strictEqual(item.exitCode, 0);
  assert.strictEqual(item.finishedAt, 1500);
  assert.ok(Buffer.byteLength(item.output, 'utf8') <= 8192, 'output should be truncated to 8192 bytes');
});

test('E2E: Repeated result is ignored', async () => {
  // Given a command already stored as succeeded
  const table = new FakeTable();
  const now = () => 1000;

  table.setItem('DEVICE#dev1', 'CMD#cmd1', {
    commandId: 'cmd1',
    status: 'succeeded',
    exitCode: 0,
    output: 'original output',
    finishedAt: 1000,
  });

  const resultBody = JSON.stringify({
    status: 'succeeded',
    exitCode: 99,
    output: 'new output',
    finishedAt: 2000,
  });

  const handler = createResultHandler({
    table,
    now,
    verifyDevice: createFakeVerifier('dev1'),
  });

  // When the same result is posted again
  const response = await handler({
    method: 'POST',
    path: '/api/v1/devices/dev1/commands/cmd1/result',
    params: { deviceId: 'dev1', commandId: 'cmd1' },
    query: {},
    headers: {},
    body: resultBody,
  });

  // Then the status is 200 and the stored item is unchanged
  assert.strictEqual(response.statusCode, 200);

  const item = table.items.get('DEVICE#dev1#CMD#cmd1');
  assert.strictEqual(item.exitCode, 0, 'original exitCode should be unchanged');
  assert.strictEqual(item.output, 'original output', 'original output should be unchanged');
  assert.strictEqual(item.finishedAt, 1000, 'original finishedAt should be unchanged');
});

test('E2E: Unknown command id returns 404', async () => {
  // When a valid result body is posted for commandId "nope"
  const table = new FakeTable();
  const now = () => 1000;

  const resultBody = JSON.stringify({
    status: 'succeeded',
    exitCode: 0,
    output: 'output',
    finishedAt: 1000,
  });

  const handler = createResultHandler({
    table,
    now,
    verifyDevice: createFakeVerifier('dev1'),
  });

  const response = await handler({
    method: 'POST',
    path: '/api/v1/devices/dev1/commands/nope/result',
    params: { deviceId: 'dev1', commandId: 'nope' },
    query: {},
    headers: {},
    body: resultBody,
  });

  // Then the status is 404 and the error is unknown_command
  assert.strictEqual(response.statusCode, 404);
  assert.strictEqual(response.body.error, 'unknown_command');
});

test('E2E: Result for another device is refused', async () => {
  // Given a request where verifyDeviceRequest returns d1 but posting to d2
  const table = new FakeTable();
  const now = () => 1000;

  const resultBody = JSON.stringify({
    status: 'succeeded',
    exitCode: 0,
    output: 'output',
    finishedAt: 1000,
  });

  const handler = createResultHandler({
    table,
    now,
    verifyDevice: createFakeVerifier('d1'),
  });

  const response = await handler({
    method: 'POST',
    path: '/api/v1/devices/d2/commands/cmd1/result',
    params: { deviceId: 'd2', commandId: 'cmd1' },
    query: {},
    headers: {},
    body: resultBody,
  });

  // Then the status is 403 and the error is device_mismatch
  assert.strictEqual(response.statusCode, 403);
  assert.strictEqual(response.body.error, 'device_mismatch');
});

test('E2E: Out-of-range max is refused', async () => {
  // When the agent polls with max=99
  const table = new FakeTable();
  const now = () => 1000;

  const handler = createLeaseHandler({
    table,
    now,
    verifyDevice: createFakeVerifier('dev1'),
  });

  const response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev1/commands',
    params: { deviceId: 'dev1' },
    query: { max: '99' },
    headers: {},
    body: null,
  });

  // Then the status is 400 and the error is invalid_request
  assert.strictEqual(response.statusCode, 400);
  assert.strictEqual(response.body.error, 'invalid_request');
});

test('E2E: Unknown result status is refused', async () => {
  // When a result is posted with status "cancelled"
  const table = new FakeTable();
  const now = () => 1000;

  const resultBody = JSON.stringify({
    status: 'cancelled',
    exitCode: 0,
    output: 'output',
    finishedAt: 1000,
  });

  const handler = createResultHandler({
    table,
    now,
    verifyDevice: createFakeVerifier('dev1'),
  });

  const response = await handler({
    method: 'POST',
    path: '/api/v1/devices/dev1/commands/cmd1/result',
    params: { deviceId: 'dev1', commandId: 'cmd1' },
    query: {},
    headers: {},
    body: resultBody,
  });

  // Then the status is 400 and the error is invalid_request
  assert.strictEqual(response.statusCode, 400);
  assert.strictEqual(response.body.error, 'invalid_request');
});

test('E2E: Missing exitCode is refused with the offending field named', async () => {
  // Given a leased command c1
  const table = new FakeTable();
  const now = () => 1000;

  table.setItem('DEVICE#dev1', 'CMD#c1', {
    commandId: 'c1',
    status: 'leased',
    leaseExpiresAt: 1500,
  });

  const resultBody = JSON.stringify({
    status: 'succeeded',
    output: '',
    finishedAt: 1500,
    // missing exitCode
  });

  const handler = createResultHandler({
    table,
    now,
    verifyDevice: createFakeVerifier('dev1'),
  });

  // When a result is posted with no exitCode
  const response = await handler({
    method: 'POST',
    path: '/api/v1/devices/dev1/commands/c1/result',
    params: { deviceId: 'dev1', commandId: 'c1' },
    query: {},
    headers: {},
    body: resultBody,
  });

  // Then the status is 400, the error is invalid_request, fields contains "exitCode" and the stored item is unchanged
  assert.strictEqual(response.statusCode, 400);
  assert.strictEqual(response.body.error, 'invalid_request');
  assert.ok(Array.isArray(response.body.fields), 'fields should be an array');
  assert.ok(response.body.fields.includes('exitCode'), 'fields should include exitCode');

  const item = table.items.get('DEVICE#dev1#CMD#c1');
  assert.strictEqual(item.status, 'leased', 'stored item should be unchanged');
});

test('E2E: Wrong-typed output and finishedAt are both named', async () => {
  // Given a leased command c1
  const table = new FakeTable();
  const now = () => 1000;

  table.setItem('DEVICE#dev1', 'CMD#c1', {
    commandId: 'c1',
    status: 'leased',
    leaseExpiresAt: 1500,
  });

  const resultBody = JSON.stringify({
    status: 'succeeded',
    exitCode: 0,
    output: 42, // wrong type
    finishedAt: 'soon', // wrong type
  });

  const handler = createResultHandler({
    table,
    now,
    verifyDevice: createFakeVerifier('dev1'),
  });

  // When a result is posted with output 42 and finishedAt "soon"
  const response = await handler({
    method: 'POST',
    path: '/api/v1/devices/dev1/commands/c1/result',
    params: { deviceId: 'dev1', commandId: 'c1' },
    query: {},
    headers: {},
    body: resultBody,
  });

  // Then the status is 400, fields contains "output" and "finishedAt" and the stored item is unchanged
  assert.strictEqual(response.statusCode, 400);
  assert.ok(Array.isArray(response.body.fields), 'fields should be an array');
  assert.ok(response.body.fields.includes('output'), 'fields should include output');
  assert.ok(response.body.fields.includes('finishedAt'), 'fields should include finishedAt');

  const item = table.items.get('DEVICE#dev1#CMD#c1');
  assert.strictEqual(item.status, 'leased', 'stored item should be unchanged');
});

test('E2E: Body validation runs before the command lookup', async () => {
  // When a result with no exitCode is posted for commandId "nope"
  const table = new FakeTable();
  const now = () => 1000;

  const resultBody = JSON.stringify({
    status: 'succeeded',
    output: 'output',
    finishedAt: 1000,
    // missing exitCode
  });

  const handler = createResultHandler({
    table,
    now,
    verifyDevice: createFakeVerifier('dev1'),
  });

  const response = await handler({
    method: 'POST',
    path: '/api/v1/devices/dev1/commands/nope/result',
    params: { deviceId: 'dev1', commandId: 'nope' },
    query: {},
    headers: {},
    body: resultBody,
  });

  // Then the status is 400 and the error is invalid_request, not 404
  assert.strictEqual(response.statusCode, 400, 'body validation should come before lookup');
  assert.strictEqual(response.body.error, 'invalid_request');
});

test('E2E: Result for a never-leased command is refused', async () => {
  // Given command c1 is stored with status pending
  const table = new FakeTable();
  const now = () => 1000;

  table.setItem('DEVICE#dev1', 'CMD#c1', {
    commandId: 'c1',
    status: 'pending',
  });

  const resultBody = JSON.stringify({
    status: 'succeeded',
    exitCode: 0,
    output: 'output',
    finishedAt: 1500,
  });

  const handler = createResultHandler({
    table,
    now,
    verifyDevice: createFakeVerifier('dev1'),
  });

  // When a valid result is posted for c1
  const response = await handler({
    method: 'POST',
    path: '/api/v1/devices/dev1/commands/c1/result',
    params: { deviceId: 'dev1', commandId: 'c1' },
    query: {},
    headers: {},
    body: resultBody,
  });

  // Then the status is 409, the error is command_not_leased and the stored item is unchanged
  assert.strictEqual(response.statusCode, 409);
  assert.strictEqual(response.body.error, 'command_not_leased');

  const item = table.items.get('DEVICE#dev1#CMD#c1');
  assert.strictEqual(item.status, 'pending', 'stored item should be unchanged');
});

// ===== Unit Tests for Individual Functions =====

test('Unit: parseMax validates max parameter correctly', async () => {
  const table = new FakeTable();
  const now = () => 1000;

  const handler = createLeaseHandler({
    table,
    now,
    verifyDevice: createFakeVerifier('dev1'),
  });

  // Default (undefined)
  let response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev1/commands',
    params: { deviceId: 'dev1' },
    query: {},
    headers: {},
    body: null,
  });
  assert.strictEqual(response.statusCode, 200);

  // Min value (1)
  response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev1/commands',
    params: { deviceId: 'dev1' },
    query: { max: '1' },
    headers: {},
    body: null,
  });
  assert.strictEqual(response.statusCode, 200);

  // Max value (25)
  response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev1/commands',
    params: { deviceId: 'dev1' },
    query: { max: '25' },
    headers: {},
    body: null,
  });
  assert.strictEqual(response.statusCode, 200);

  // Below min (0)
  response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev1/commands',
    params: { deviceId: 'dev1' },
    query: { max: '0' },
    headers: {},
    body: null,
  });
  assert.strictEqual(response.statusCode, 400);
  assert.strictEqual(response.body.error, 'invalid_request');

  // Above max (26)
  response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev1/commands',
    params: { deviceId: 'dev1' },
    query: { max: '26' },
    headers: {},
    body: null,
  });
  assert.strictEqual(response.statusCode, 400);
  assert.strictEqual(response.body.error, 'invalid_request');
});

test('Unit: Result validation checks all required fields', async () => {
  const table = new FakeTable();
  const now = () => 1000;

  const handler = createResultHandler({
    table,
    now,
    verifyDevice: createFakeVerifier('dev1'),
  });

  // Missing all three fields
  let response = await handler({
    method: 'POST',
    path: '/api/v1/devices/dev1/commands/cmd1/result',
    params: { deviceId: 'dev1', commandId: 'cmd1' },
    query: {},
    headers: {},
    body: JSON.stringify({ status: 'succeeded' }),
  });

  assert.strictEqual(response.statusCode, 400);
  assert.ok(response.body.fields.includes('exitCode'));
  assert.ok(response.body.fields.includes('output'));
  assert.ok(response.body.fields.includes('finishedAt'));

  // Valid fields
  table.setItem('DEVICE#dev1', 'CMD#cmd1', { status: 'leased', leaseExpiresAt: 1500 });
  response = await handler({
    method: 'POST',
    path: '/api/v1/devices/dev1/commands/cmd1/result',
    params: { deviceId: 'dev1', commandId: 'cmd1' },
    query: {},
    headers: {},
    body: JSON.stringify({
      status: 'succeeded',
      exitCode: 0,
      output: 'output',
      finishedAt: 1000,
    }),
  });
  assert.strictEqual(response.statusCode, 200);
});

test('Unit: Output truncation respects UTF-8 boundaries', async () => {
  const table = new FakeTable();
  const now = () => 1000;

  table.setItem('DEVICE#dev1', 'CMD#cmd1', { status: 'leased', leaseExpiresAt: 1500 });

  const handler = createResultHandler({
    table,
    now,
    verifyDevice: createFakeVerifier('dev1'),
  });

  // Create output with multi-byte UTF-8 character
  const emoji = '😀'; // 4 bytes in UTF-8
  const output = 'x'.repeat(8191) + emoji;

  const response = await handler({
    method: 'POST',
    path: '/api/v1/devices/dev1/commands/cmd1/result',
    params: { deviceId: 'dev1', commandId: 'cmd1' },
    query: {},
    headers: {},
    body: JSON.stringify({
      status: 'succeeded',
      exitCode: 0,
      output,
      finishedAt: 1000,
    }),
  });

  assert.strictEqual(response.statusCode, 200);

  const item = table.items.get('DEVICE#dev1#CMD#cmd1');
  const truncatedBytes = Buffer.byteLength(item.output, 'utf8');
  assert.ok(truncatedBytes <= 8192, `output bytes ${truncatedBytes} should be <= 8192`);
});

test('Unit: Device mismatch prevents any database operation', async () => {
  const table = new FakeTable();
  const now = () => 1000;

  table.setItem('DEVICE#dev1', 'CMD#cmd1', {
    commandId: 'cmd1',
    status: 'pending',
    issuedAt: 900000,
    expiresAt: 2000000,
    type: 'execute',
    payload: {},
  });

  const handler = createLeaseHandler({
    table,
    now,
    verifyDevice: createFakeVerifier('dev1'),
  });

  // Try to access dev2's commands with dev1's auth
  const response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev2/commands',
    params: { deviceId: 'dev2' },
    query: {},
    headers: {},
    body: null,
  });

  assert.strictEqual(response.statusCode, 403);
  assert.strictEqual(response.body.error, 'device_mismatch');

  // Verify no query was made
  const queryOps = table.operations.filter(op => op.op === 'query');
  assert.strictEqual(queryOps.length, 0, 'no query should have occurred due to device mismatch');
});

test('Unit: registerCommandRoutes adds both routes to router', async () => {
  const table = new FakeTable();
  const now = () => 1000;

  const router = createRouter();
  registerCommandRoutes(router, {
    table,
    now,
    verifyDevice: createFakeVerifier('dev1'),
  });

  // Test GET route
  let response = await router.handle({
    method: 'GET',
    path: '/api/v1/devices/dev1/commands',
    params: { deviceId: 'dev1' },
    query: {},
    headers: {},
    body: null,
  });
  assert.strictEqual(response.statusCode, 200);

  // Test POST route
  table.setItem('DEVICE#dev1', 'CMD#cmd1', { status: 'leased', leaseExpiresAt: 1500 });
  response = await router.handle({
    method: 'POST',
    path: '/api/v1/devices/dev1/commands/cmd1/result',
    params: { deviceId: 'dev1', commandId: 'cmd1' },
    query: {},
    headers: {},
    body: JSON.stringify({
      status: 'succeeded',
      exitCode: 0,
      output: 'output',
      finishedAt: 1000,
    }),
  });
  assert.strictEqual(response.statusCode, 200);
});

test('Unit: Lazy dependency resolution with function source', async () => {
  let callCount = 0;
  const depsFunction = () => {
    callCount++;
    return {
      table: new FakeTable(),
      now: () => 1000,
      verifyDevice: createFakeVerifier('dev1'),
    };
  };

  const handler = createLeaseHandler(depsFunction);

  // First call
  let response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev1/commands',
    params: { deviceId: 'dev1' },
    query: {},
    headers: {},
    body: null,
  });
  assert.strictEqual(response.statusCode, 200);
  assert.strictEqual(callCount, 1);

  // Second call
  response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev1/commands',
    params: { deviceId: 'dev1' },
    query: {},
    headers: {},
    body: null,
  });
  assert.strictEqual(response.statusCode, 200);
  assert.strictEqual(callCount, 2);
});

// ============================================================================
// TASK-045: Ordered queues -- lease (LS1-LS6) and the on-failure setting
// (OF3-OF6, backend half). Uses the real createTableClient over an in-memory
// documentClient (test/helpers/fakeDynamo.js), so conditional updates, the
// ADD counter and query pagination all run through production code. No real
// database connection is made.
// ============================================================================

test('Scenario: LS1 Lease reads every query page', async () => {
  const { table, documentClient } = createFakeTable();
  // Force the fake to paginate like a 1 MB DynamoDB response would, without a
  // multi-megabyte fixture: three terminal items on page one, the pending
  // item alone on page two.
  documentClient.pageSize = 3;
  const now = () => 1000;

  for (let i = 1; i <= 3; i += 1) {
    await table.put({
      ...deviceCommand('dev-1', `t${i}`),
      commandId: `t${i}`,
      type: 'run_script',
      status: 'succeeded',
      issuedAt: 100,
      expiresAt: 999999999,
    });
  }
  await table.put({
    ...deviceCommand('dev-1', 'z-pending'),
    commandId: 'z-pending',
    type: 'run_script',
    status: 'pending',
    issuedAt: 200,
    expiresAt: 999999999,
    payload: { interpreter: 'cmd', script: 'echo' },
  });

  const handler = createLeaseHandler({ table, now, verifyDevice: createFakeVerifier('dev-1') });
  const response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev-1/commands',
    params: { deviceId: 'dev-1' },
    query: { max: '5' },
    headers: {},
    body: null,
  });

  assert.strictEqual(response.statusCode, 200);
  assert.strictEqual(response.body.commands.length, 1);
  assert.strictEqual(response.body.commands[0].commandId, 'z-pending');

  const stored = await table.get(deviceCommand('dev-1', 'z-pending'));
  assert.strictEqual(stored.status, 'leased');
});

test('Scenario: LS2 Lease order is legacy first, then by seq', async () => {
  const { table } = createFakeTable();
  const now = () => 1000;

  await table.put({ ...deviceCommand('dev-1', 'S3'), commandId: 'S3', type: 'run_script', status: 'pending', seq: 3, issuedAt: 50, payload: { interpreter: 'cmd', script: 'a' } });
  await table.put({ ...deviceCommand('dev-1', 'L1'), commandId: 'L1', type: 'run_script', status: 'pending', issuedAt: 200, payload: { interpreter: 'cmd', script: 'b' } });
  await table.put({ ...deviceCommand('dev-1', 'S1'), commandId: 'S1', type: 'run_script', status: 'pending', seq: 1, issuedAt: 60, payload: { interpreter: 'cmd', script: 'c' } });
  await table.put({ ...deviceCommand('dev-1', 'L0'), commandId: 'L0', type: 'run_script', status: 'pending', issuedAt: 100, payload: { interpreter: 'cmd', script: 'd' } });

  const handler = createLeaseHandler({ table, now, verifyDevice: createFakeVerifier('dev-1') });
  const response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev-1/commands',
    params: { deviceId: 'dev-1' },
    query: { max: '3' },
    headers: {},
    body: null,
  });

  assert.strictEqual(response.statusCode, 200);
  assert.deepStrictEqual(response.body.commands.map((c) => c.commandId), ['L0', 'L1', 'S1']);

  const s3 = await table.get(deviceCommand('dev-1', 'S3'));
  assert.strictEqual(s3.status, 'pending');
});

test('Scenario: LS3 An unexpired earlier lease blocks later commands', async () => {
  const { table } = createFakeTable();
  const now = () => 1000;

  await table.put({ ...deviceCommand('dev-1', 'L0'), commandId: 'L0', type: 'run_script', status: 'pending', issuedAt: 50, payload: { interpreter: 'cmd', script: 'a' } });
  await table.put({ ...deviceCommand('dev-1', 'S1'), commandId: 'S1', type: 'run_script', status: 'leased', seq: 1, issuedAt: 60, leaseExpiresAt: 1100, payload: { interpreter: 'cmd', script: 'b' } });
  await table.put({ ...deviceCommand('dev-1', 'S2'), commandId: 'S2', type: 'run_script', status: 'pending', seq: 2, issuedAt: 70, payload: { interpreter: 'cmd', script: 'c' } });

  const handler = createLeaseHandler({ table, now, verifyDevice: createFakeVerifier('dev-1') });
  const response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev-1/commands',
    params: { deviceId: 'dev-1' },
    query: {},
    headers: {},
    body: null,
  });

  assert.strictEqual(response.statusCode, 200);
  assert.deepStrictEqual(response.body.commands.map((c) => c.commandId), ['L0']);

  const s2 = await table.get(deviceCommand('dev-1', 'S2'));
  assert.strictEqual(s2.status, 'pending');
});

test('Scenario: LS4 Terminal commands are never leased and never block', async () => {
  const { table } = createFakeTable();
  const now = () => 1000;
  const terminal = ['cancelled', 'skipped', 'failed', 'expired', 'succeeded'];
  for (let i = 0; i < terminal.length; i += 1) {
    await table.put({
      ...deviceCommand('dev-1', `c${i + 1}`),
      commandId: `c${i + 1}`,
      type: 'run_script',
      status: terminal[i],
      seq: i + 1,
      issuedAt: 10 * (i + 1),
      payload: { interpreter: 'cmd', script: 'x' },
    });
  }
  await table.put({ ...deviceCommand('dev-1', 'c6'), commandId: 'c6', type: 'run_script', status: 'pending', seq: 6, issuedAt: 70, payload: { interpreter: 'cmd', script: 'y' } });

  const handler = createLeaseHandler({ table, now, verifyDevice: createFakeVerifier('dev-1') });
  const response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev-1/commands',
    params: { deviceId: 'dev-1' },
    query: {},
    headers: {},
    body: null,
  });

  assert.deepStrictEqual(response.body.commands.map((c) => c.commandId), ['c6']);
});

test('Scenario: LS5 A lapsed lease is re-leased in position', async () => {
  const { table } = createFakeTable();
  const now = () => 1000;

  await table.put({ ...deviceCommand('dev-1', 'S1'), commandId: 'S1', type: 'run_script', status: 'leased', seq: 1, issuedAt: 50, leaseExpiresAt: 999, payload: { interpreter: 'cmd', script: 'a' } });
  await table.put({ ...deviceCommand('dev-1', 'S2'), commandId: 'S2', type: 'run_script', status: 'pending', seq: 2, issuedAt: 60, payload: { interpreter: 'cmd', script: 'b' } });

  const handler = createLeaseHandler({ table, now, verifyDevice: createFakeVerifier('dev-1') });
  const response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev-1/commands',
    params: { deviceId: 'dev-1' },
    query: {},
    headers: {},
    body: null,
  });

  assert.deepStrictEqual(response.body.commands.map((c) => c.commandId), ['S1', 'S2']);
});

test('Scenario: LS6 Commands without expiry never expire and get a far wire expiry', async () => {
  const { table } = createFakeTable();
  const now = () => 1000; // epoch seconds

  // No expiresAt at all: a library command.
  await table.put({ ...deviceCommand('dev-1', 'S1'), commandId: 'S1', type: 'run_script', status: 'pending', seq: 1, issuedAt: 1000, payload: { interpreter: 'cmd', script: 'a' } });
  // Legacy command whose expiresAt has already passed.
  await table.put({ ...deviceCommand('dev-1', 'X'), commandId: 'X', type: 'run_script', status: 'pending', issuedAt: 500, expiresAt: 1, payload: { interpreter: 'cmd', script: 'b' } });

  const handler = createLeaseHandler({ table, now, verifyDevice: createFakeVerifier('dev-1') });
  const response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev-1/commands',
    params: { deviceId: 'dev-1' },
    query: {},
    headers: {},
    body: null,
  });

  assert.deepStrictEqual(response.body.commands.map((c) => c.commandId), ['S1']);
  assert.strictEqual(response.body.commands[0].expiresAt, 1000 + NO_EXPIRY_WIRE_MILLIS);
  assert.strictEqual(NO_EXPIRY_WIRE_MILLIS, 315360000000);

  const x = await table.get(deviceCommand('dev-1', 'X'));
  assert.strictEqual(x.status, 'expired');
});

test('Scenario: OF3 Stop mode flags sequenced commands at lease', async () => {
  const { table } = createFakeTable();
  const now = () => 1000;
  await table.put({ ...commandSettings(), onFailure: 'stop' });
  await table.put({ ...deviceCommand('dev-1', 'L0'), commandId: 'L0', type: 'run_script', status: 'pending', issuedAt: 50, payload: { interpreter: 'cmd', script: 'a' } });
  await table.put({ ...deviceCommand('dev-1', 'S1'), commandId: 'S1', type: 'run_script', status: 'pending', seq: 1, issuedAt: 60, payload: { interpreter: 'cmd', script: 'b' } });

  const handler = createLeaseHandler({ table, now, verifyDevice: createFakeVerifier('dev-1') });
  const response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev-1/commands',
    params: { deviceId: 'dev-1' },
    query: {},
    headers: {},
    body: null,
  });

  const byId = Object.fromEntries(response.body.commands.map((c) => [c.commandId, c]));
  assert.strictEqual(byId.S1.payload.stopOnFailure, true);
  assert.strictEqual(byId.L0.payload.stopOnFailure, undefined);

  const storedS1 = await table.get(deviceCommand('dev-1', 'S1'));
  assert.strictEqual(storedS1.payload.stopOnFailure, true);
});

test('Scenario: OF3 Continue mode does not flag', async () => {
  const { table } = createFakeTable();
  const now = () => 1000;
  // No CONFIG/COMMANDS item at all: defaults to continue.
  await table.put({ ...deviceCommand('dev-1', 'S1'), commandId: 'S1', type: 'run_script', status: 'pending', seq: 1, issuedAt: 60, payload: { interpreter: 'cmd', script: 'b' } });

  const handler = createLeaseHandler({ table, now, verifyDevice: createFakeVerifier('dev-1') });
  const response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev-1/commands',
    params: { deviceId: 'dev-1' },
    query: {},
    headers: {},
    body: null,
  });

  for (const c of response.body.commands) {
    assert.notStrictEqual(c.payload.stopOnFailure, true);
  }
});

test('Scenario: OF4 A flagged failure skips later commands', async () => {
  const { table } = createFakeTable();

  await table.put({ ...deviceCommand('dev-1', 'S0'), commandId: 'S0', type: 'run_script', status: 'succeeded', seq: 0, issuedAt: 10, payload: { interpreter: 'cmd', script: 'z' } });
  await table.put({ ...deviceCommand('dev-1', 'S1'), commandId: 'S1', type: 'run_script', status: 'leased', seq: 1, issuedAt: 20, leaseExpiresAt: 2000, payload: { interpreter: 'cmd', script: 'a', stopOnFailure: true } });
  await table.put({ ...deviceCommand('dev-1', 'S2'), commandId: 'S2', type: 'run_script', status: 'leased', seq: 2, issuedAt: 30, leaseExpiresAt: 2000, payload: { interpreter: 'cmd', script: 'b' } });
  await table.put({ ...deviceCommand('dev-1', 'S3'), commandId: 'S3', type: 'run_script', status: 'pending', seq: 3, issuedAt: 40, payload: { interpreter: 'cmd', script: 'c' } });
  await table.put({ ...deviceCommand('dev-2', 'T1'), commandId: 'T1', type: 'run_script', status: 'pending', seq: 2, issuedAt: 40, payload: { interpreter: 'cmd', script: 'd' } });

  const resultHandler = createResultHandler({ table, now: () => 1000, verifyDevice: createFakeVerifier('dev-1') });
  const response = await resultHandler({
    method: 'POST',
    path: '/api/v1/devices/dev-1/commands/S1/result',
    params: { deviceId: 'dev-1', commandId: 'S1' },
    query: {},
    headers: {},
    body: JSON.stringify({ status: 'failed', exitCode: 1, output: 'bad', finishedAt: 1000 }),
  });
  assert.strictEqual(response.statusCode, 200);

  const s2 = await table.get(deviceCommand('dev-1', 'S2'));
  const s3 = await table.get(deviceCommand('dev-1', 'S3'));
  const s0 = await table.get(deviceCommand('dev-1', 'S0'));
  const t1 = await table.get(deviceCommand('dev-2', 'T1'));
  assert.strictEqual(s2.status, 'skipped');
  assert.strictEqual(s2.skippedBecause, 'S1');
  assert.strictEqual(s3.status, 'skipped');
  assert.strictEqual(s3.skippedBecause, 'S1');
  assert.strictEqual(s0.status, 'succeeded');
  assert.strictEqual(t1.status, 'pending');

  // The two skipped commands are never offered again.
  const leaseHandler = createLeaseHandler({ table, now: () => 1000, verifyDevice: createFakeVerifier('dev-1') });
  const leaseResp = await leaseHandler({
    method: 'GET',
    path: '/api/v1/devices/dev-1/commands',
    params: { deviceId: 'dev-1' },
    query: {},
    headers: {},
    body: null,
  });
  const ids = leaseResp.body.commands.map((c) => c.commandId);
  assert.ok(!ids.includes('S2'));
  assert.ok(!ids.includes('S3'));
});

test('Scenario Outline: OF5 Results that do not trigger skipping', async () => {
  const cases = [
    { state: 'leased without stopOnFailure', payload: { interpreter: 'cmd', script: 'a' }, status: 'leased', result: 'failed' },
    { state: 'leased with stopOnFailure', payload: { interpreter: 'cmd', script: 'a', stopOnFailure: true }, status: 'leased', result: 'succeeded' },
    { state: 'already failed with stopOnFailure (repeat)', payload: { interpreter: 'cmd', script: 'a', stopOnFailure: true }, status: 'failed', result: 'failed' },
  ];
  for (const c of cases) {
    const { table } = createFakeTable();
    await table.put({ ...deviceCommand('dev-1', 'S1'), commandId: 'S1', type: 'run_script', status: c.status, seq: 1, issuedAt: 10, leaseExpiresAt: 5000, payload: c.payload });
    await table.put({ ...deviceCommand('dev-1', 'S2'), commandId: 'S2', type: 'run_script', status: 'pending', seq: 2, issuedAt: 20, payload: { interpreter: 'cmd', script: 'b' } });

    const handler = createResultHandler({ table, now: () => 1000, verifyDevice: createFakeVerifier('dev-1') });
    const response = await handler({
      method: 'POST',
      path: '/api/v1/devices/dev-1/commands/S1/result',
      params: { deviceId: 'dev-1', commandId: 'S1' },
      query: {},
      headers: {},
      body: JSON.stringify({ status: c.result, exitCode: c.result === 'failed' ? 1 : 0, output: 'x', finishedAt: 1000 }),
    });
    assert.strictEqual(response.statusCode, 200, c.state);

    const s2 = await table.get(deviceCommand('dev-1', 'S2'));
    assert.strictEqual(s2.status, 'pending', c.state);
  }
});

test('Unit: byRunOrder sorts legacy commands before sequenced ones, by issuedAt then by seq', () => {
  const items = [
    { commandId: 'S2', seq: 2, issuedAt: 5 },
    { commandId: 'L2', issuedAt: 20 },
    { commandId: 'S1', seq: 1, issuedAt: 999 },
    { commandId: 'L1', issuedAt: 10 },
  ];
  const sorted = [...items].sort(byRunOrder);
  assert.deepStrictEqual(sorted.map((i) => i.commandId), ['L1', 'L2', 'S1', 'S2']);
});

test('Unit: LEASE_TERMINAL_STATUSES covers every status the lease must never offer', () => {
  for (const status of ['succeeded', 'failed', 'expired', 'cancelled', 'skipped']) {
    assert.ok(LEASE_TERMINAL_STATUSES.includes(status), status);
  }
  assert.ok(!LEASE_TERMINAL_STATUSES.includes('pending'));
  assert.ok(!LEASE_TERMINAL_STATUSES.includes('leased'));
});

// ============================================================================
// TASK-049 AC8: an install_application item is leased like a library command
// ============================================================================

test('Scenario: The install is delivered at the next check-in\'s poll in queue order', async () => {
  // Given dev-1 has a pending run_script with seq 3 and a pending
  // install_application with seq 5
  const table = new FakeTable();
  const now = () => 1000000; // ms
  table.setItem('DEVICE#dev-1', 'CMD#run-1', {
    commandId: 'run-1',
    type: 'run_script',
    payload: { interpreter: 'cmd', script: 'ipconfig' },
    status: 'pending',
    seq: 3,
    issuedAt: 500,
    expiresAt: 500 + NO_EXPIRY_WIRE_MILLIS,
  });
  table.setItem('DEVICE#dev-1', 'CMD#install-1', {
    commandId: 'install-1',
    type: 'install_application',
    payload: { applicationId: 'app-1', applicationName: '7-Zip', timeoutSeconds: 3600 },
    status: 'pending',
    seq: 5,
    issuedAt: 600,
    expiresAt: 600 + NO_EXPIRY_WIRE_MILLIS,
  });

  const handler = createLeaseHandler({ table, now, verifyDevice: createFakeVerifier('dev-1') });

  // When the device leases its commands
  const response = await handler({
    method: 'GET',
    path: '/api/v1/devices/dev-1/commands',
    params: { deviceId: 'dev-1' },
    query: {},
    headers: {},
    body: null,
  });

  // Then the run_script comes before the install_application, whose
  // expiresAt is issuedAt + NO_EXPIRY_WIRE_MILLIS and payload is unchanged
  assert.strictEqual(response.statusCode, 200);
  const body = response.body;
  assert.strictEqual(body.commands.length, 2);
  assert.strictEqual(body.commands[0].commandId, 'run-1');
  assert.strictEqual(body.commands[1].commandId, 'install-1');
  assert.strictEqual(body.commands[1].type, 'install_application');
  assert.deepStrictEqual(body.commands[1].payload, { applicationId: 'app-1', applicationName: '7-Zip', timeoutSeconds: 3600 });
  assert.strictEqual(body.commands[1].expiresAt, 600 + NO_EXPIRY_WIRE_MILLIS);
});
