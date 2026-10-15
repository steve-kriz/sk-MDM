/**
 * Unit tests for the device contact (last-seen update) helper module (TASK-033).
 * These tests verify the recordDeviceContact function and its error handling.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const {
  recordDeviceContact,
  LAST_SEEN_UPDATE_EXPRESSION,
  LAST_SEEN_CONDITION,
} = await import(`file://${join(__dirname, '../../dist/routes/deviceContact.js')}`);

const {
  deviceProfile,
} = await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);

const { isoUtc } = await import(`file://${join(__dirname, '../../dist/audit.js')}`);

// ============================================================================
// Mock Table Client
// ============================================================================

class FakeTable {
  constructor() {
    this.updateCalls = [];
    this.shouldThrowConditionalCheckFailure = false;
    this.shouldThrowOtherError = null;
  }

  async update(key, fields) {
    this.updateCalls.push({ key, fields });

    if (this.shouldThrowConditionalCheckFailure) {
      const err = new Error('ConditionalCheckFailedException');
      err.name = 'ConditionalCheckFailedException';
      throw err;
    }

    if (this.shouldThrowOtherError) {
      throw this.shouldThrowOtherError;
    }

    return {};
  }

  getUpdateCalls() {
    return this.updateCalls;
  }

  getLastUpdateCall() {
    return this.updateCalls.length > 0 ? this.updateCalls[this.updateCalls.length - 1] : null;
  }
}

// ============================================================================
// Unit Tests for recordDeviceContact
// ============================================================================

test('Unit: recordDeviceContact issues exactly one update call', async (t) => {
  const table = new FakeTable();
  const deviceId = 'device-123';
  const at = new Date('2026-10-02T12:00:00Z');

  await recordDeviceContact(table, deviceId, at);

  assert.strictEqual(table.updateCalls.length, 1);
});

test('Unit: recordDeviceContact calls update on the correct device profile key', async (t) => {
  const table = new FakeTable();
  const deviceId = 'device-456';
  const at = new Date('2026-10-02T12:00:00Z');

  await recordDeviceContact(table, deviceId, at);

  const call = table.getLastUpdateCall();
  const expectedKey = deviceProfile(deviceId);
  assert.deepStrictEqual(call.key, expectedKey);
});

test('Unit: recordDeviceContact uses the fixed UpdateExpression', async (t) => {
  const table = new FakeTable();
  const deviceId = 'device-789';
  const at = new Date('2026-10-02T12:00:00Z');

  await recordDeviceContact(table, deviceId, at);

  const call = table.getLastUpdateCall();
  assert.strictEqual(call.fields.UpdateExpression, LAST_SEEN_UPDATE_EXPRESSION);
  assert.strictEqual(
    call.fields.UpdateExpression,
    'SET lastSeenAt = :lastSeenAt, gsi1pk = :gsi1pk, gsi1sk = :gsi1sk'
  );
});

test('Unit: recordDeviceContact uses the fixed ConditionExpression', async (t) => {
  const table = new FakeTable();
  const deviceId = 'device-abc';
  const at = new Date('2026-10-02T12:00:00Z');

  await recordDeviceContact(table, deviceId, at);

  const call = table.getLastUpdateCall();
  assert.strictEqual(call.fields.ConditionExpression, LAST_SEEN_CONDITION);
  assert.strictEqual(
    call.fields.ConditionExpression,
    'attribute_exists(pk) AND (attribute_not_exists(lastSeenAt) OR lastSeenAt <= :lastSeenAt)'
  );
});

test('Unit: recordDeviceContact sets lastSeenAt to isoUtc formatted string', async (t) => {
  const table = new FakeTable();
  const deviceId = 'device-def';
  const at = new Date('2026-10-02T12:00:00Z');

  await recordDeviceContact(table, deviceId, at);

  const call = table.getLastUpdateCall();
  const values = call.fields.ExpressionAttributeValues;

  const expectedIsoUtc = isoUtc(at);
  assert.strictEqual(values[':lastSeenAt'], expectedIsoUtc);
  assert.strictEqual(values[':lastSeenAt'], '2026-10-02T12:00:00Z');
});

test('Unit: recordDeviceContact sets gsi1pk to DEVICE', async (t) => {
  const table = new FakeTable();
  const deviceId = 'device-ghi';
  const at = new Date('2026-10-02T12:00:00Z');

  await recordDeviceContact(table, deviceId, at);

  const call = table.getLastUpdateCall();
  const values = call.fields.ExpressionAttributeValues;
  assert.strictEqual(values[':gsi1pk'], 'DEVICE');
});

test('Unit: recordDeviceContact sets gsi1sk to lastSeenAt', async (t) => {
  const table = new FakeTable();
  const deviceId = 'device-jkl';
  const at = new Date('2026-10-02T12:00:00Z');

  await recordDeviceContact(table, deviceId, at);

  const call = table.getLastUpdateCall();
  const values = call.fields.ExpressionAttributeValues;

  const expectedIsoUtc = isoUtc(at);
  assert.strictEqual(values[':gsi1sk'], expectedIsoUtc);
  assert.strictEqual(values[':lastSeenAt'], values[':gsi1sk']);
});

test('Unit: recordDeviceContact converts Date to isoUtc format (epoch seconds)', async (t) => {
  const table = new FakeTable();
  const deviceId = 'device-mno';
  // 1790942400 epoch seconds = 2026-10-02T12:00:00Z
  const at = new Date(1790942400 * 1000);

  await recordDeviceContact(table, deviceId, at);

  const call = table.getLastUpdateCall();
  const values = call.fields.ExpressionAttributeValues;
  assert.strictEqual(values[':lastSeenAt'], '2026-10-02T12:00:00Z');
});

test('Unit: recordDeviceContact never throws on ConditionalCheckFailedException', async (t) => {
  const table = new FakeTable();
  table.shouldThrowConditionalCheckFailure = true;

  const deviceId = 'device-pqr';
  const at = new Date('2026-10-02T12:00:00Z');

  // Should not throw
  await recordDeviceContact(table, deviceId, at);
});

test('Unit: recordDeviceContact calls console.warn once on other errors', async (t) => {
  const table = new FakeTable();
  const error = new Error('table connection failed');
  table.shouldThrowOtherError = error;

  const warnCalls = [];
  const originalWarn = console.warn;
  console.warn = (...args) => {
    warnCalls.push(args);
  };

  try {
    const deviceId = 'device-stu';
    const at = new Date('2026-10-02T12:00:00Z');

    // Should not throw, but should warn
    await recordDeviceContact(table, deviceId, at);

    assert.strictEqual(warnCalls.length, 1);
    const warnMessage = warnCalls[0][0];
    const parsed = JSON.parse(warnMessage);
    assert.strictEqual(parsed.msg, 'last-seen update failed');
    assert.strictEqual(parsed.deviceId, 'device-stu');
  } finally {
    console.warn = originalWarn;
  }
});

test('Unit: recordDeviceContact logs JSON with correct deviceId', async (t) => {
  const table = new FakeTable();
  const error = new Error('something went wrong');
  table.shouldThrowOtherError = error;

  const warnCalls = [];
  const originalWarn = console.warn;
  console.warn = (...args) => {
    warnCalls.push(args);
  };

  try {
    const deviceId = 'my-special-device';
    const at = new Date('2026-10-02T12:00:00Z');

    await recordDeviceContact(table, deviceId, at);

    assert.strictEqual(warnCalls.length, 1);
    const warnMessage = warnCalls[0][0];
    const parsed = JSON.parse(warnMessage);
    assert.strictEqual(parsed.deviceId, 'my-special-device');
  } finally {
    console.warn = originalWarn;
  }
});

test('Unit: recordDeviceContact is an async function', async (t) => {
  const table = new FakeTable();
  const promise = recordDeviceContact(table, 'device-vwx', new Date());
  assert.ok(promise instanceof Promise);
  await promise;
});

test('Unit: recordDeviceContact handles Date constructor with ISO string', async (t) => {
  const table = new FakeTable();
  const deviceId = 'device-yz1';
  const at = new Date('2026-10-02T12:34:56.789Z');

  await recordDeviceContact(table, deviceId, at);

  const call = table.getLastUpdateCall();
  const values = call.fields.ExpressionAttributeValues;
  // isoUtc should strip milliseconds
  assert.ok(values[':lastSeenAt'].includes('2026-10-02T12:34:56Z'));
});

test('Unit: recordDeviceContact handles leap second edge cases', async (t) => {
  const table = new FakeTable();
  const deviceId = 'device-leap';
  // 2012-06-30T23:59:60Z was a leap second, but JS Date doesn't really handle them
  // Test a time near a historical leap second
  const at = new Date('2012-06-30T23:59:59Z');

  await recordDeviceContact(table, deviceId, at);

  const call = table.getLastUpdateCall();
  const values = call.fields.ExpressionAttributeValues;
  assert.ok(values[':lastSeenAt']);
  assert.ok(typeof values[':lastSeenAt'] === 'string');
});

test('Unit: LAST_SEEN_UPDATE_EXPRESSION constant is correct', async (t) => {
  assert.strictEqual(
    LAST_SEEN_UPDATE_EXPRESSION,
    'SET lastSeenAt = :lastSeenAt, gsi1pk = :gsi1pk, gsi1sk = :gsi1sk'
  );
});

test('Unit: LAST_SEEN_CONDITION constant is correct', async (t) => {
  assert.strictEqual(
    LAST_SEEN_CONDITION,
    'attribute_exists(pk) AND (attribute_not_exists(lastSeenAt) OR lastSeenAt <= :lastSeenAt)'
  );
});

test('Unit: recordDeviceContact with table lacking update method throws', async (t) => {
  const invalidTable = {}; // No update method

  const warnCalls = [];
  const originalWarn = console.warn;
  console.warn = (...args) => {
    warnCalls.push(args);
  };

  try {
    const deviceId = 'device-nomethod';
    const at = new Date('2026-10-02T12:00:00Z');

    // Should not throw, but should warn about the error
    await recordDeviceContact(invalidTable, deviceId, at);

    assert.ok(warnCalls.length >= 1, 'Should warn about missing update method');
    const warnMessage = warnCalls[0][0];
    const parsed = JSON.parse(warnMessage);
    assert.strictEqual(parsed.msg, 'last-seen update failed');
  } finally {
    console.warn = originalWarn;
  }
});

test('Unit: ConditionalCheckFailedException is identified by name property', async (t) => {
  const table = new FakeTable();
  table.shouldThrowConditionalCheckFailure = true;

  const warnCalls = [];
  const originalWarn = console.warn;
  console.warn = (...args) => {
    warnCalls.push(args);
  };

  try {
    const deviceId = 'device-conditional';
    const at = new Date('2026-10-02T12:00:00Z');

    // Should silently ignore ConditionalCheckFailedException
    await recordDeviceContact(table, deviceId, at);

    // No warn should be called
    assert.strictEqual(warnCalls.length, 0, 'ConditionalCheckFailedException should be silently swallowed');
  } finally {
    console.warn = originalWarn;
  }
});

test('Unit: recordDeviceContact only swallows ConditionalCheckFailedException, not other errors', async (t) => {
  const table = new FakeTable();

  const warnCalls = [];
  const originalWarn = console.warn;
  console.warn = (...args) => {
    warnCalls.push(args);
  };

  try {
    // Test with TypeError
    table.shouldThrowOtherError = new TypeError('something is not a function');
    const deviceId = 'device-typeerror';
    const at = new Date('2026-10-02T12:00:00Z');

    await recordDeviceContact(table, deviceId, at);

    assert.ok(warnCalls.length >= 1, 'Should warn about TypeError');
    const warnMessage = warnCalls[0][0];
    const parsed = JSON.parse(warnMessage);
    assert.strictEqual(parsed.msg, 'last-seen update failed');
  } finally {
    console.warn = originalWarn;
  }
});
