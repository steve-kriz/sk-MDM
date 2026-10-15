/**
 * Regression test: a check-in's DynamoDB expressions must be ones the real
 * service accepts. Production check-ins failed with
 *   ValidationException: Invalid UpdateExpression: Attribute name is a reserved
 *   keyword; reserved keyword: timeZone
 * because the profile update wrote `timeZone = :timeZone` bare. The in-memory
 * fakes elsewhere accept any expression, so this file uses a table that
 * validates expressions like DynamoDB. All database calls are mocked.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { assertValidDynamoExpressions } from '../helpers/dynamoExpressions.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const { createCheckInHandler } = await import(`file://${join(__dirname, '../../dist/routes/checkin.js')}`);
const { deviceProfile } = await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);

const randomHex = (bytes = 32) => randomBytes(bytes).toString('hex');

/** A fake table that refuses expressions DynamoDB would refuse. */
class ValidatingTable {
  constructor() {
    this.items = new Map();
    this.updates = [];
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
    this.updates.push({ key: { ...key }, fields });
    const updated = { ...(this.items.get(this.keyOf(key)) ?? {}), ...key };
    this.items.set(this.keyOf(key), updated);
    return updated;
  }
  async query(request) {
    assertValidDynamoExpressions(request);
    return { items: [], cursor: null };
  }
  async delete() {}
}

function checkInRequest(body) {
  return {
    method: 'POST',
    path: '/api/v1/devices/dev-1/checkin',
    query: {},
    headers: {
      'x-mdm-device-id': 'dev-1',
      'x-mdm-timestamp': Math.floor(Date.now() / 1000).toString(),
      'x-mdm-nonce': randomHex(16),
      'x-mdm-signature': randomHex(32),
    },
    params: { deviceId: 'dev-1' },
    body: JSON.stringify(body),
  };
}

const fullBody = {
  collectedAt: '2026-10-11T08:00:00Z',
  agentVersion: '1.0.7',
  timeZone: 'Australia/Sydney',
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

function handlerFor(table) {
  return createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-11T08:00:00Z'),
    verifyDevice: async () => ({ ok: true, deviceId: 'dev-1' }),
  });
}

test('Unit: the expression validator refuses a bare reserved word, as DynamoDB does', () => {
  assert.throws(
    () => assertValidDynamoExpressions({
      UpdateExpression: 'SET lastSeenAt = :lastSeenAt, timeZone = :timeZone',
      ExpressionAttributeValues: { ':lastSeenAt': 'x', ':timeZone': 'Australia/Sydney' },
    }),
    (error) => error.name === 'ValidationException' && /reserved keyword: timeZone/.test(error.message),
  );
  assert.doesNotThrow(() => assertValidDynamoExpressions({
    UpdateExpression: 'SET lastSeenAt = :lastSeenAt, #timeZone = :timeZone',
    ExpressionAttributeNames: { '#timeZone': 'timeZone' },
    ExpressionAttributeValues: { ':lastSeenAt': 'x', ':timeZone': 'Australia/Sydney' },
  }));
});

test('Scenario: A check-in that reports a time zone is accepted by a DynamoDB-validating table', async () => {
  // Given device "dev-1" exists
  const table = new ValidatingTable();
  table.seed({ ...deviceProfile('dev-1'), deviceId: 'dev-1', platform: 'windows' });

  // When it checks in with timeZone "Australia/Sydney" and an agent version
  const result = await handlerFor(table)(checkInRequest(fullBody));

  // Then the check-in is accepted
  assert.strictEqual(result.statusCode, 200, JSON.stringify(result.body));

  // And the profile update stores the zone through a #name placeholder
  const profile = table.updates.find((u) => u.key.sk === 'PROFILE' && u.fields.ExpressionAttributeValues?.[':timeZone']);
  assert.ok(profile, 'expected a profile update carrying :timeZone');
  assert.strictEqual(profile.fields.ExpressionAttributeValues[':timeZone'], 'Australia/Sydney');
  const placeholder = Object.entries(profile.fields.ExpressionAttributeNames ?? {}).find(([, name]) => name === 'timeZone')?.[0];
  assert.ok(placeholder, 'timeZone must be written through an ExpressionAttributeNames placeholder');
  assert.ok(profile.fields.UpdateExpression.includes(`${placeholder} = :timeZone`));
});

test('Scenario: A check-in without a time zone is also accepted by a DynamoDB-validating table', async () => {
  const table = new ValidatingTable();
  table.seed({ ...deviceProfile('dev-1'), deviceId: 'dev-1', platform: 'windows' });
  const { timeZone, ...withoutZone } = fullBody;
  const result = await handlerFor(table)(checkInRequest(withoutZone));
  assert.strictEqual(result.statusCode, 200, JSON.stringify(result.body));
});

// ============================================================================
// TASK-059: the profile update also gains a conditional `osDisplay = :osDisplay`
// clause. "osDisplay" is not a DynamoDB reserved word, but this regression
// test exists precisely because a bare reserved word slipped through before
// (see file header): every check-in shape must keep producing an
// UpdateExpression the real service accepts.
// ============================================================================

const bodyWithDeviceDetails = {
  ...fullBody,
  inventory: {
    ...fullBody.inventory,
    os: { name: 'Microsoft Windows 11 Enterprise', version: '10.0.22631', build: '22631', architecture: 'amd64' },
  },
};

test('Scenario: A check-in that derives an osDisplay is accepted by a DynamoDB-validating table, with timeZone', async () => {
  // Given device "dev-1" exists
  const table = new ValidatingTable();
  table.seed({ ...deviceProfile('dev-1'), deviceId: 'dev-1', platform: 'windows' });

  // When it checks in with both timeZone and an inventory.os that yields an osDisplay
  const result = await handlerFor(table)(checkInRequest(bodyWithDeviceDetails));

  // Then the check-in is accepted (the ValidatingTable would throw on a bad expression)
  assert.strictEqual(result.statusCode, 200, JSON.stringify(result.body));

  // And the profile update carries osDisplay alongside timeZone, both through
  // expressions the validator accepts.
  const profile = table.updates.find((u) => u.key.sk === 'PROFILE' && u.fields.ExpressionAttributeValues?.[':osDisplay']);
  assert.ok(profile, 'expected a profile update carrying :osDisplay');
  assert.strictEqual(profile.fields.ExpressionAttributeValues[':osDisplay'], 'Windows 11 Enterprise (build 22631)');
  assert.ok(profile.fields.UpdateExpression.includes('osDisplay = :osDisplay'));
  assert.ok(profile.fields.ExpressionAttributeValues[':timeZone']);
  assertValidDynamoExpressions(profile.fields);
});

test('Scenario: A check-in that derives an osDisplay is accepted without a time zone', async () => {
  const table = new ValidatingTable();
  table.seed({ ...deviceProfile('dev-1'), deviceId: 'dev-1', platform: 'windows' });
  const { timeZone, ...withoutZone } = bodyWithDeviceDetails;

  const result = await handlerFor(table)(checkInRequest(withoutZone));
  assert.strictEqual(result.statusCode, 200, JSON.stringify(result.body));

  const profile = table.updates.find((u) => u.key.sk === 'PROFILE' && u.fields.ExpressionAttributeValues?.[':osDisplay']);
  assert.ok(profile, 'expected a profile update carrying :osDisplay');
  assert.ok(!profile.fields.UpdateExpression.includes('timeZone = :timeZone'));
  assertValidDynamoExpressions(profile.fields);
});

test('Scenario: A check-in with neither osDisplay nor timeZone is still accepted', async () => {
  // Given an inventory.os with no name (osDisplayName returns null)
  const table = new ValidatingTable();
  table.seed({ ...deviceProfile('dev-1'), deviceId: 'dev-1', platform: 'windows' });
  const { timeZone, ...withoutZone } = {
    ...fullBody,
    inventory: { ...fullBody.inventory, os: { ...fullBody.inventory.os, name: '' } },
  };

  const result = await handlerFor(table)(checkInRequest(withoutZone));
  assert.strictEqual(result.statusCode, 200, JSON.stringify(result.body));

  const profile = table.updates.find((u) => u.key.sk === 'PROFILE');
  assert.ok(profile, 'expected a profile update');
  assert.strictEqual(profile.fields.ExpressionAttributeValues[':osDisplay'], undefined);
  assert.ok(!profile.fields.UpdateExpression.includes('osDisplay = :osDisplay'));
  assertValidDynamoExpressions(profile.fields);
});

// ============================================================================
// TASK-070 AC21: recordAgentActions uses no DynamoDB expression of its own --
// "source", "type" and "ttl" (all reserved words) are written only through a
// plain put, never through an expression.
// ============================================================================

test('Scenario: Expressions pass the reserved-word validator (AC21)', async () => {
  // Given the ValidatingTable from checkin-dynamo-expressions.test.js
  const table = new ValidatingTable();
  table.seed({ ...deviceProfile('dev-1'), deviceId: 'dev-1', platform: 'windows' });

  // When a check-in carrying all four action types is handled
  const bodyWithAllActions = {
    ...fullBody,
    agentActions: [
      { type: 'enforce.firewall_enabled', occurredAt: '2026-10-12T00:59:00Z', details: {} },
      { type: 'enforce.antivirus_enabled', occurredAt: '2026-10-12T00:59:01Z', details: {} },
      { type: 'enforce.domains_updated', occurredAt: '2026-10-12T00:59:02Z', details: { blockedCount: '4' } },
      {
        type: 'agent.update_rolled_back',
        occurredAt: '2026-10-12T00:59:03Z',
        details: { installedVersion: '1.5.0', runningVersion: '1.4.9' },
      },
    ],
  };

  const result = await handlerFor(table)(checkInRequest(bodyWithAllActions));

  // Then no ValidationException is raised (the ValidatingTable would have
  // thrown) and the response is 200
  assert.strictEqual(result.statusCode, 200, JSON.stringify(result.body));

  const events = [...table.items.values()].filter((item) => item.pk === 'DEVICE#dev-1' && item.sk.startsWith('EVENT#') && item.source === 'agent');
  assert.strictEqual(events.length, 4, `expected 4 agent events, got ${JSON.stringify(events)}`);
});
