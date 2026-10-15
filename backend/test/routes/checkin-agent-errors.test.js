/**
 * E2E and unit tests for TASK-063: the agent's `agentErrors` array is stored
 * as one DynamoDB item per distinct (level, component, message) per device.
 * Tests implement the Gherkin scenarios for AC12-AC15. Mock all database
 * calls -- no real DB connections.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { randomBytes, createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const { createCheckInHandler, MAX_AGENT_ERRORS, MAX_AGENT_ERROR_COUNT, AGENT_ERROR_RETENTION_SECONDS } = await import(
  `file://${join(__dirname, '../../dist/routes/checkin.js')}`
);
const { deviceProfile, deviceAgentError, AGENT_ERROR_SK_PREFIX } = await import(
  `file://${join(__dirname, '../../dist/db/keys.js')}`
);
const { assertValidDynamoExpressions } = await import('../helpers/dynamoExpressions.js');

const randomHex = (bytes = 32) => randomBytes(bytes).toString('hex');

/** A minimal in-memory table: get/put/query, every write validated like DynamoDB would. */
class FakeTable {
  constructor() {
    this.items = new Map();
  }
  keyOf(key) {
    return `${key.pk}|${key.sk}`;
  }
  seed(item) {
    this.items.set(this.keyOf(item), { ...item });
  }
  async get(key) {
    return this.items.get(this.keyOf(key));
  }
  async put(item, fields) {
    assertValidDynamoExpressions(fields);
    this.items.set(this.keyOf(item), { ...item });
  }
  async putIfAbsent(item) {
    if (this.items.has(this.keyOf(item))) return { written: false };
    this.items.set(this.keyOf(item), { ...item });
    return { written: true };
  }
  async update(key, fields) {
    assertValidDynamoExpressions(fields);
    const updated = { ...(this.items.get(this.keyOf(key)) ?? {}), ...key };
    this.items.set(this.keyOf(key), updated);
    return updated;
  }
  async query(request) {
    assertValidDynamoExpressions(request);
    return { items: [], cursor: null };
  }
  async delete(key) {
    this.items.delete(this.keyOf(key));
  }
  agentErrorItems(deviceId) {
    const { pk } = deviceProfile(deviceId);
    return [...this.items.values()].filter((item) => item.pk === pk && item.sk.startsWith(AGENT_ERROR_SK_PREFIX));
  }
}

const fullBody = {
  collectedAt: '2026-10-11T08:00:00Z',
  agentVersion: '1.0.7',
  inventory: {
    hardware: { manufacturer: 'Dell', model: 'OptiPlex', serialNumber: 'S1', cpu: 'i7', ramBytes: 1, diskBytes: 1 },
    os: { name: 'Windows', version: '11', build: '22621', architecture: 'x86_64' },
    software: [],
    warnings: [],
  },
  posture: {
    diskEncryption: { enabled: true, method: 'bitlocker' },
    firewall: { enabled: true },
    antivirus: { name: 'Microsoft Defender', enabled: true, definitionsAgeDays: 1 },
    screenLock: { enabled: true, timeoutSeconds: 300 },
    osUpdates: { pendingCount: 0, lastInstalledAt: null },
    warnings: [],
  },
};

function checkInRequest(deviceId, body) {
  return {
    method: 'POST',
    path: `/api/v1/devices/${deviceId}/checkin`,
    query: {},
    headers: {
      'x-mdm-device-id': deviceId,
      'x-mdm-timestamp': Math.floor(Date.now() / 1000).toString(),
      'x-mdm-nonce': randomHex(16),
      'x-mdm-signature': randomHex(32),
    },
    params: { deviceId },
    body: JSON.stringify(body),
  };
}

function handlerFor(table, now) {
  return createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => now,
    verifyDevice: async (req) => ({ ok: true, deviceId: req.params.deviceId }),
  });
}

function withAgentErrors(agentErrors) {
  return { ...fullBody, agentErrors };
}

function agentError(overrides = {}) {
  return {
    level: 'warn',
    component: 'enforce',
    message: 'policy enforcement failed',
    fields: { error: 'exit status 1' },
    count: 1,
    firstAt: '2026-10-11T08:00:00.000Z',
    lastAt: '2026-10-11T08:00:00.000Z',
    ...overrides,
  };
}

// ============================================================================
// Scenario: A new error is stored and a repeat is accumulated (AC12)
// ============================================================================

test('Scenario: A new error is stored and a repeat is accumulated (AC12)', async () => {
  const table = new FakeTable();
  table.seed({ ...deviceProfile('dev-1'), deviceId: 'dev-1', platform: 'windows' });
  const now = new Date('2026-10-11T09:00:00Z');

  // Timestamps are given with milliseconds, as the agent sends them, but
  // normalisedInstant stores them without (isoUtc strips ".000"); T1..T4
  // below are already in that stored form so the later equality checks are
  // exact.
  const T1 = '2026-10-11T08:00:00Z';
  const T2 = '2026-10-11T08:05:00Z';
  const T3 = '2026-10-11T08:10:00Z';
  const T4 = '2026-10-11T08:15:00Z';

  // Given no AGENTERROR item exists for "dev-1"
  assert.deepStrictEqual(table.agentErrorItems('dev-1'), []);

  // When a check-in arrives with an entry count 2 firstAt T1 lastAt T2
  const first = await handlerFor(table, now)(
    checkInRequest('dev-1', withAgentErrors([agentError({ count: 2, firstAt: T1, lastAt: T2 })])),
  );
  assert.strictEqual(first.statusCode, 200, JSON.stringify(first.body));

  // And a later check-in arrives with the same entry count 3 firstAt T3 lastAt T4
  const second = await handlerFor(table, now)(
    checkInRequest('dev-1', withAgentErrors([agentError({ count: 3, firstAt: T3, lastAt: T4 })])),
  );
  assert.strictEqual(second.statusCode, 200, JSON.stringify(second.body));

  // Then the item AGENTERROR#<signature> has count 5, firstSeenAt T1, lastSeenAt T4
  const items = table.agentErrorItems('dev-1');
  assert.strictEqual(items.length, 1, `expected exactly one AGENTERROR item, got ${JSON.stringify(items)}`);
  const item = items[0];
  assert.strictEqual(item.count, 5);
  assert.strictEqual(item.firstSeenAt, T1);
  assert.strictEqual(item.lastSeenAt, T4);
  assert.strictEqual(item.ttl, Math.floor(Date.parse(T4) / 1000) + AGENT_ERROR_RETENTION_SECONDS);

  // The signature matches sha256(level\ncomponent\nmessage).slice(0, 32)
  const expectedSignature = createHash('sha256')
    .update('warn\nenforce\npolicy enforcement failed', 'utf8')
    .digest('hex')
    .slice(0, 32);
  assert.strictEqual(item.signature, expectedSignature);
  assert.strictEqual(item.sk, `${AGENT_ERROR_SK_PREFIX}${expectedSignature}`);
});

// ============================================================================
// Scenario: An older batch does not move lastSeenAt back (AC12)
// ============================================================================

test('Scenario: An older batch does not move lastSeenAt back (AC12)', async () => {
  const table = new FakeTable();
  table.seed({ ...deviceProfile('dev-1'), deviceId: 'dev-1', platform: 'windows' });
  const now = new Date('2026-10-11T09:00:00Z');

  const T2 = '2026-10-11T08:05:00Z';
  const T4 = '2026-10-11T08:15:00Z';

  // Given the stored item has lastSeenAt T4
  await handlerFor(table, now)(checkInRequest('dev-1', withAgentErrors([agentError({ count: 4, firstAt: T2, lastAt: T4 })])));
  const before = table.agentErrorItems('dev-1')[0];
  assert.strictEqual(before.lastSeenAt, T4);
  assert.strictEqual(before.count, 4);

  // When a check-in arrives with the same entry lastAt T2 (earlier than T4) and count 1
  const result = await handlerFor(table, now)(
    checkInRequest('dev-1', withAgentErrors([agentError({ count: 1, firstAt: T2, lastAt: T2 })])),
  );
  assert.strictEqual(result.statusCode, 200);

  // Then lastSeenAt stays T4 and count increases by 1
  const after = table.agentErrorItems('dev-1')[0];
  assert.strictEqual(after.lastSeenAt, T4);
  assert.strictEqual(after.count, 5);
});

// ============================================================================
// Scenario Outline: Malformed entries are dropped without refusing the
// check-in (AC13)
// ============================================================================

test('Scenario Outline: Malformed entries are dropped without refusing the check-in (AC13)', async () => {
  const now = new Date('2026-10-11T09:00:00Z');
  const futureAt = new Date(now.getTime() + 2 * 24 * 60 * 60 * 1000).toISOString();
  const tooOldAt = new Date(now.getTime() - 31 * 24 * 60 * 60 * 1000).toISOString();

  const cases = [
    { name: 'a non-array value', value: 'not-an-array', stored: 0 },
    { name: 'wrong level', value: [agentError({ level: 'info' })], stored: 0 },
    { name: 'empty message', value: [agentError({ message: '' })], stored: 0 },
    { name: 'unparseable lastAt', value: [agentError({ lastAt: 'yesterday' })], stored: 0 },
    { name: 'lastAt too far in the future', value: [agentError({ lastAt: futureAt })], stored: 0 },
    { name: 'lastAt too far in the past', value: [agentError({ lastAt: tooOldAt })], stored: 0 },
    {
      name: '60 distinct valid entries, only 50 stored',
      value: Array.from({ length: 60 }, (_, i) =>
        agentError({ message: `distinct message ${i}`, firstAt: '2026-10-11T08:00:00.000Z', lastAt: '2026-10-11T08:00:00.000Z' }),
      ),
      stored: MAX_AGENT_ERRORS,
    },
  ];

  for (const { name, value, stored } of cases) {
    await test(name, async () => {
      const table = new FakeTable();
      table.seed({ ...deviceProfile('dev-1'), deviceId: 'dev-1', platform: 'windows' });

      const result = await handlerFor(table, now)(checkInRequest('dev-1', withAgentErrors(value)));

      // Then the response is 200
      assert.strictEqual(result.statusCode, 200, `expected 200 for ${name}, got ${JSON.stringify(result.body)}`);

      // And <stored> AGENTERROR items are written
      assert.strictEqual(table.agentErrorItems('dev-1').length, stored, `expected ${stored} stored items for ${name}`);
    });
  }
});

// A non-object entry and an entry whose firstAt is unparseable are dropped
// the same way: documented edge cases alongside the outline above.
test('Edge: a non-object entry and an unparseable firstAt are both dropped (AC13)', async () => {
  const table = new FakeTable();
  table.seed({ ...deviceProfile('dev-1'), deviceId: 'dev-1', platform: 'windows' });
  const now = new Date('2026-10-11T09:00:00Z');

  const result = await handlerFor(table, now)(
    checkInRequest('dev-1', withAgentErrors(['not-an-object', agentError({ firstAt: 'not-a-date' })])),
  );
  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(table.agentErrorItems('dev-1').length, 0);
});

// ============================================================================
// Scenario: Out-of-range counts are clamped (AC13)
// ============================================================================

test('Scenario: Out-of-range counts are clamped (AC13)', async () => {
  const table = new FakeTable();
  table.seed({ ...deviceProfile('dev-1'), deviceId: 'dev-1', platform: 'windows' });
  const now = new Date('2026-10-11T09:00:00Z');

  const result = await handlerFor(table, now)(
    checkInRequest(
      'dev-1',
      withAgentErrors([
        agentError({ message: 'zero count', count: 0 }),
        agentError({ message: 'fractional count', count: 2.5 }),
        agentError({ message: 'huge count', count: 5000000 }),
      ]),
    ),
  );
  assert.strictEqual(result.statusCode, 200, JSON.stringify(result.body));

  const items = table.agentErrorItems('dev-1');
  const byMessage = Object.fromEntries(items.map((item) => [item.message, item.count]));
  assert.strictEqual(byMessage['zero count'], 1);
  assert.strictEqual(byMessage['fractional count'], 1);
  assert.strictEqual(byMessage['huge count'], MAX_AGENT_ERROR_COUNT);
});

// ============================================================================
// Scenario: Expressions pass the DynamoDB reserved-word validator (AC14)
// ============================================================================

test('Scenario: Expressions pass the DynamoDB reserved-word validator (AC14)', async () => {
  // Given the ValidatingTable from checkin-dynamo-expressions.test.js (a
  // plain assertValidDynamoExpressions check on every put/update/query --
  // "count" is a reserved word DynamoDB would refuse used bare).
  const table = new FakeTable();
  table.seed({ ...deviceProfile('dev-1'), deviceId: 'dev-1', platform: 'windows' });
  const now = new Date('2026-10-11T09:00:00Z');

  // When a check-in with two agentErrors entries is handled
  const result = await handlerFor(table, now)(
    checkInRequest(
      'dev-1',
      withAgentErrors([agentError({ message: 'first' }), agentError({ message: 'second', level: 'error' })]),
    ),
  );

  // Then no ValidationException is raised and the response is 200
  assert.strictEqual(result.statusCode, 200, JSON.stringify(result.body));
  assert.strictEqual(table.agentErrorItems('dev-1').length, 2);
});

// ============================================================================
// Scenario: A check-in without agentErrors writes nothing new (AC15)
// ============================================================================

test('Scenario: A check-in without agentErrors writes nothing new (AC15)', async () => {
  const table = new FakeTable();
  table.seed({ ...deviceProfile('dev-1'), deviceId: 'dev-1', platform: 'windows' });
  const now = new Date('2026-10-11T09:00:00Z');

  // Baseline: the same body, without agentErrors, run once to capture the
  // "before this change" response shape.
  const before = await handlerFor(table, now)(checkInRequest('dev-1', fullBody));
  const beforeAgentErrorCount = table.agentErrorItems('dev-1').length;

  // When a check-in without agentErrors is handled
  const after = await handlerFor(table, now)(checkInRequest('dev-1', fullBody));

  // Then no item with an sk starting "AGENTERROR#" is written
  assert.strictEqual(table.agentErrorItems('dev-1').length, beforeAgentErrorCount);
  assert.strictEqual(table.agentErrorItems('dev-1').length, 0);

  // And the response body equals the response body before this change
  assert.strictEqual(after.statusCode, before.statusCode);
  assert.deepStrictEqual(after.body, before.body);
});
