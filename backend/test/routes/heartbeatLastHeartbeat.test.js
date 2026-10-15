/**
 * E2E cucumber-style tests and unit tests for TASK-054's heartbeat
 * diagnostics in `backend/src/routes/heartbeat.ts` and
 * `backend/src/admin/heartbeat.ts`: recording `lastHeartbeatAt` on a stored
 * heartbeat (AC1, AC2), never failing the heartbeat when that update rejects
 * (AC3), and naming the AWS error on a CloudWatch failure (AC4).
 *
 * New file per TASK-054 instructions: backend/test/routes/heartbeat.test.js
 * and backend/test/admin/heartbeat.test.js (AC16) must pass unchanged.
 *
 * All database calls and the CloudWatch heartbeat log are in-process fakes;
 * no real connection of either kind is ever opened.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const {
  createHeartbeatHandler,
  LAST_HEARTBEAT_UPDATE_EXPRESSION,
} = await import(`file://${join(__dirname, '../../dist/routes/heartbeat.js')}`);
const { handleHeartbeatHistory } = await import(`file://${join(__dirname, '../../dist/admin/heartbeat.js')}`);
const { deviceProfile, deviceHeartbeatSettings } = await import(
  `file://${join(__dirname, '../../dist/db/keys.js')}`
);
const { CONDITIONAL_CHECK_FAILED } = await import(`file://${join(__dirname, '../../dist/db/table.js')}`);

// ============================================================================
// Fakes
// ============================================================================

/**
 * A table fake that can selectively reject one update call, matched by its
 * exact `UpdateExpression`, while every other update (e.g. deviceContact's
 * `lastSeenAt` refresh) succeeds normally. This is required because the
 * heartbeat route issues the `lastSeenAt` update first and the
 * `lastHeartbeatAt` update second (AC1): rejecting indiscriminately would
 * make the first update fail too, masking what AC3 tests.
 */
class FakeTable {
  constructor({ rejectUpdateExpression = null, rejectError = null } = {}) {
    this.items = new Map();
    this.updateCalls = [];
    this.rejectUpdateExpression = rejectUpdateExpression;
    this.rejectError = rejectError;
  }

  keyStr(key) {
    return JSON.stringify({ pk: key.pk, sk: key.sk });
  }

  async get(key) {
    return this.items.get(this.keyStr(key));
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
    this.updateCalls.push({ key, fields });
    if (this.rejectUpdateExpression !== null && fields?.UpdateExpression === this.rejectUpdateExpression) {
      throw this.rejectError;
    }
    const existing = this.items.get(this.keyStr(key)) ?? { ...key };
    const updated = { ...existing };
    if (fields?.ExpressionAttributeValues?.[':lastSeenAt'] !== undefined) {
      updated.lastSeenAt = fields.ExpressionAttributeValues[':lastSeenAt'];
    }
    if (fields?.ExpressionAttributeValues?.[':lastHeartbeatAt'] !== undefined) {
      updated.lastHeartbeatAt = fields.ExpressionAttributeValues[':lastHeartbeatAt'];
    }
    this.items.set(this.keyStr(key), updated);
    return updated;
  }

  seedItem(item) {
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  getStoredItem(key) {
    return this.items.get(this.keyStr(key));
  }
}

function seedDevice(table, deviceId = 'd1') {
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });
}

function seedHeartbeatOn(table, deviceId = 'd1', intervalSeconds = 300) {
  table.seedItem({ ...deviceHeartbeatSettings(deviceId), deviceId, heartbeatEnabled: true, intervalSeconds });
}

function createFakeVerifier(deviceId = 'd1', ok = true, status = 401, error = 'bad_signature') {
  return async () => (ok ? { ok: true, deviceId } : { ok: false, status, body: { error } });
}

function fakeHeartbeatLog({ writeError = null, readResult = [], readError = null } = {}) {
  const writeCalls = [];
  const readCalls = [];
  return {
    writeCalls,
    readCalls,
    async write(deviceId, event) {
      writeCalls.push({ deviceId, event });
      if (writeError !== null) {
        throw writeError;
      }
    },
    async read(deviceId, limit) {
      readCalls.push({ deviceId, limit });
      if (readError !== null) {
        throw readError;
      }
      return readResult;
    },
  };
}

function heartbeatRequest({
  deviceId = 'd1',
  body = { collectedAt: '2026-10-11T11:59:58Z', performance: {} },
} = {}) {
  return {
    method: 'POST',
    path: `/api/v1/devices/${deviceId}/heartbeat`,
    query: {},
    headers: {},
    params: { deviceId },
    body: JSON.stringify(body),
  };
}

const NOW = () => new Date('2026-10-11T12:00:00Z');

/** Captures console.warn lines for the duration of `fn`, then restores it. */
async function captureWarnings(fn) {
  const lines = [];
  const original = console.warn;
  console.warn = (line) => lines.push(line);
  try {
    await fn();
  } finally {
    console.warn = original;
  }
  return lines;
}

// ============================================================================
// Scenario: A stored heartbeat records lastHeartbeatAt after last-seen (AC1)
// ============================================================================

test('Scenario: A stored heartbeat records lastHeartbeatAt after last-seen', async () => {
  // Given a device "d1" with a PROFILE item, heartbeat on at 300, and a
  // heartbeatLog whose write resolves
  const table = new FakeTable();
  seedDevice(table);
  seedHeartbeatOn(table, 'd1', 300);
  const heartbeatLog = fakeHeartbeatLog();
  const handler = createHeartbeatHandler({ table, now: NOW, heartbeatLog, verifyDevice: createFakeVerifier('d1') });

  // When "d1" posts a valid signed heartbeat
  const result = await handler(heartbeatRequest());

  // Then the response is 200 {"heartbeatIntervalSeconds": 300}
  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body, { heartbeatIntervalSeconds: 300 });

  // And exactly two PROFILE updates were issued: lastSeenAt first...
  const profileUpdates = table.updateCalls.filter((u) => u.key.sk === 'PROFILE');
  assert.strictEqual(profileUpdates.length, 2);
  assert.strictEqual(profileUpdates[0].fields.ExpressionAttributeValues[':lastSeenAt'], '2026-10-11T12:00:00Z');

  // ...then the lastHeartbeatAt update, whose shape is exact.
  const second = profileUpdates[1];
  assert.strictEqual(second.fields.UpdateExpression, LAST_HEARTBEAT_UPDATE_EXPRESSION);
  assert.strictEqual(second.fields.UpdateExpression, 'SET lastHeartbeatAt = :lastHeartbeatAt');
  assert.strictEqual(second.fields.ExpressionAttributeValues[':lastHeartbeatAt'], '2026-10-11T12:00:00Z');
  assert.strictEqual(second.fields.ConditionExpression, 'attribute_exists(pk)');
});

// ============================================================================
// Scenario Outline: No lastHeartbeatAt when the heartbeat is off or not
// stored (AC2)
// ============================================================================

test('Scenario Outline: No lastHeartbeatAt when the heartbeat is off or not stored', async () => {
  const cases = [
    {
      description: 'no HEARTBEAT item for d1',
      setup: (table) => {},
      status: 200,
      body: { heartbeatIntervalSeconds: 0 },
    },
    {
      description: 'HEARTBEAT item on but no heartbeatLog',
      setup: (table) => seedHeartbeatOn(table, 'd1', 300),
      noLog: true,
      status: 503,
      body: { error: 'heartbeat_not_configured' },
    },
    {
      description: 'HEARTBEAT on at 300 and heartbeatLog.write rejects',
      setup: (table) => seedHeartbeatOn(table, 'd1', 300),
      writeError: new Error('boom'),
      status: 503,
      body: { error: 'heartbeat_store_unavailable' },
    },
  ];

  for (const tc of cases) {
    const table = new FakeTable();
    seedDevice(table);
    tc.setup(table);
    const heartbeatLog = tc.noLog ? undefined : fakeHeartbeatLog({ writeError: tc.writeError ?? null });
    const handler = createHeartbeatHandler({ table, now: NOW, heartbeatLog, verifyDevice: createFakeVerifier('d1') });

    const result = await handler(heartbeatRequest());

    assert.strictEqual(result.statusCode, tc.status, tc.description);
    assert.deepStrictEqual(result.body, tc.body, tc.description);

    // No update anywhere carries :lastHeartbeatAt.
    const anyLastHeartbeat = table.updateCalls.some(
      (u) => u.fields?.ExpressionAttributeValues?.[':lastHeartbeatAt'] !== undefined,
    );
    assert.strictEqual(anyLastHeartbeat, false, tc.description);
  }
});

// ============================================================================
// Scenario: A failed CloudWatch write touches no profile (AC2, failure)
// ============================================================================

test('Scenario: A failed CloudWatch write touches no profile', async () => {
  // Given the HEARTBEAT item of "d1" is {heartbeatEnabled: true, intervalSeconds: 300}
  // And heartbeatLog.write rejects with an error named "AccessDeniedException"
  const table = new FakeTable();
  seedDevice(table);
  seedHeartbeatOn(table, 'd1', 300);
  const error = new Error('denied');
  error.name = 'AccessDeniedException';
  const heartbeatLog = fakeHeartbeatLog({ writeError: error });
  const handler = createHeartbeatHandler({ table, now: NOW, heartbeatLog, verifyDevice: createFakeVerifier('d1') });

  // When "d1" posts a valid signed heartbeat
  await handler(heartbeatRequest());

  // Then no update is issued on the PROFILE key at all.
  const profileUpdates = table.updateCalls.filter((u) => u.key.sk === 'PROFILE');
  assert.strictEqual(profileUpdates.length, 0);
});

// ============================================================================
// Scenario Outline: A failing lastHeartbeatAt update never fails the
// heartbeat (AC3)
// ============================================================================

test('Scenario Outline: A failing lastHeartbeatAt update never fails the heartbeat', async () => {
  const cases = [
    { name: CONDITIONAL_CHECK_FAILED, count: 0 },
    { name: 'ProvisionedThroughputExceeded', count: 1 },
  ];

  for (const tc of cases) {
    // Given the HEARTBEAT item of "d1" is on at 300 and write resolves
    // And the lastHeartbeatAt update rejects with an error named "<name>"
    const error = new Error('fail');
    error.name = tc.name;
    const table = new FakeTable({ rejectUpdateExpression: LAST_HEARTBEAT_UPDATE_EXPRESSION, rejectError: error });
    seedDevice(table);
    seedHeartbeatOn(table, 'd1', 300);
    const heartbeatLog = fakeHeartbeatLog();
    const handler = createHeartbeatHandler({ table, now: NOW, heartbeatLog, verifyDevice: createFakeVerifier('d1') });

    // When "d1" posts a valid signed heartbeat
    const warnings = [];
    const original = console.warn;
    console.warn = (line) => warnings.push(line);
    let result;
    try {
      result = await handler(heartbeatRequest());
    } finally {
      console.warn = original;
    }

    // Then the response is 200 {"heartbeatIntervalSeconds": 300}
    assert.strictEqual(result.statusCode, 200, tc.name);
    assert.deepStrictEqual(result.body, { heartbeatIntervalSeconds: 300 }, tc.name);

    // And console.warn was called <count> times with the expected JSON line.
    const matching = warnings.filter((line) => {
      try {
        const parsed = JSON.parse(line);
        return parsed.msg === 'last-heartbeat update failed' && parsed.deviceId === 'd1';
      } catch {
        return false;
      }
    });
    assert.strictEqual(matching.length, tc.count, tc.name);
  }
});

// ============================================================================
// Scenario Outline: CloudWatch failures name the AWS error (AC4)
// ============================================================================

test('Scenario: heartbeat write rejects named AccessDeniedException', async () => {
  const table = new FakeTable();
  seedDevice(table);
  seedHeartbeatOn(table, 'd1', 300);
  const error = new Error('denied');
  error.name = 'AccessDeniedException';
  const heartbeatLog = fakeHeartbeatLog({ writeError: error });
  const handler = createHeartbeatHandler({ table, now: NOW, heartbeatLog, verifyDevice: createFakeVerifier('d1') });

  const warnings = await captureWarnings(async () => {
    const result = await handler(heartbeatRequest());
    assert.strictEqual(result.statusCode, 503);
    assert.deepStrictEqual(result.body, { error: 'heartbeat_store_unavailable' });
  });

  assert.strictEqual(warnings.length, 1);
  assert.deepStrictEqual(JSON.parse(warnings[0]), {
    msg: 'heartbeat write failed',
    deviceId: 'd1',
    error: 'AccessDeniedException',
  });
});

test('Scenario: heartbeat history read rejects named AccessDeniedException', async () => {
  const table = new FakeTable();
  seedDevice(table);
  const error = new Error('denied');
  error.name = 'AccessDeniedException';
  const heartbeatLog = fakeHeartbeatLog({ readError: error });

  const warnings = await captureWarnings(async () => {
    const result = await handleHeartbeatHistory(
      { params: { deviceId: 'd1' }, query: {}, headers: {} },
      { table, heartbeatLog },
    );
    assert.strictEqual(result.statusCode, 503);
    assert.deepStrictEqual(result.body, { error: 'heartbeat_store_unavailable' });
  });

  assert.strictEqual(warnings.length, 1);
  assert.deepStrictEqual(JSON.parse(warnings[0]), {
    msg: 'heartbeat history read failed',
    deviceId: 'd1',
    error: 'AccessDeniedException',
  });
});

test('Scenario: heartbeat write rejects with a plain string names the error unknown', async () => {
  const table = new FakeTable();
  seedDevice(table);
  seedHeartbeatOn(table, 'd1', 300);
  const heartbeatLog = fakeHeartbeatLog({ writeError: 'a plain string, not an Error' });
  const handler = createHeartbeatHandler({ table, now: NOW, heartbeatLog, verifyDevice: createFakeVerifier('d1') });

  const warnings = await captureWarnings(async () => {
    const result = await handler(heartbeatRequest());
    assert.strictEqual(result.statusCode, 503);
    assert.deepStrictEqual(result.body, { error: 'heartbeat_store_unavailable' });
  });

  assert.strictEqual(warnings.length, 1);
  assert.deepStrictEqual(JSON.parse(warnings[0]), {
    msg: 'heartbeat write failed',
    deviceId: 'd1',
    error: 'unknown',
  });
});

test('Edge: a thrown write error with no string name logs "unknown"', async () => {
  const table = new FakeTable();
  seedDevice(table);
  seedHeartbeatOn(table, 'd1', 300);
  const heartbeatLog = fakeHeartbeatLog({ writeError: { message: 'no name field at all' } });
  const handler = createHeartbeatHandler({ table, now: NOW, heartbeatLog, verifyDevice: createFakeVerifier('d1') });

  const warnings = await captureWarnings(async () => {
    await handler(heartbeatRequest());
  });

  assert.strictEqual(warnings.length, 1);
  assert.strictEqual(JSON.parse(warnings[0]).error, 'unknown');
});
