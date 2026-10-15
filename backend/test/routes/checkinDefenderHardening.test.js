/**
 * E2E cucumber-style tests for TASK-060's `defenderHardening` check-in block
 * (`recordDefenderHardening` in `src/routes/checkin.ts`) and the Defender
 * compliance violation flow (AC121-AC124). The table is the real
 * `TableClient` wired to the in-memory fake document client
 * (`test/helpers/fakeDynamo.js`), so group/policy assignment resolution runs
 * through the production query code. No real database connection is opened.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { createCheckInHandler } = await import(`file://${join(__dirname, '../../dist/routes/checkin.js')}`);
const {
  deviceProfile,
  deviceDefenderHardening,
  deviceCompliance,
  group,
  groupListIndex,
  groupMember,
  groupIndex,
  policy: policyKey,
  policyAssignment,
  policyAssignmentIndex,
} = await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);
const { createFakeTable } = await import(`file://${join(__dirname, '../helpers/fakeDynamo.js')}`);

function createFakeVerifier(deviceIdToReturn, ok = true) {
  return async () => (ok ? { ok: true, deviceId: deviceIdToReturn } : { ok: false, status: 401, body: { error: 'bad_signature' } });
}

function createCheckInRequest(deviceId, bodyOverrides = {}) {
  const body = {
    collectedAt: '2026-10-11T00:00:00Z',
    inventory: {
      hardware: { manufacturer: 'Dell', model: 'X', serialNumber: 'S1', cpu: 'Intel', ramBytes: 1, diskBytes: 1 },
      os: { name: 'Windows', version: '11', build: '1', architecture: 'x86_64' },
      software: [],
      warnings: [],
    },
    posture: {
      diskEncryption: { enabled: true, method: 'bitlocker' },
      firewall: { enabled: true },
      antivirus: { name: 'Defender', enabled: true, definitionsAgeDays: 1 },
      osUpdate: { lastCheckedAt: '2026-10-11T00:00:00Z', pendingCount: 0, rebootRequired: false },
      localAdmins: [],
      warnings: [],
    },
    ...bodyOverrides,
  };
  return {
    method: 'POST',
    path: `/api/v1/devices/${deviceId}/checkin`,
    query: {},
    headers: {
      'x-mdm-device-id': deviceId,
      'x-mdm-timestamp': '1234567890',
      'x-mdm-nonce': 'nonce-value',
      'x-mdm-signature': 'signature-value',
    },
    params: { deviceId },
    body: JSON.stringify(body),
  };
}

async function seedDevice(table, deviceId, overrides = {}) {
  await table.put({ ...deviceProfile(deviceId), deviceId, hostname: 'host-1', ...overrides });
}

async function seedAssignedPolicy(table, { groupId, policyId, deviceId, settings = {} }) {
  await table.put({ ...group(groupId), ...groupListIndex(`Group ${groupId}`), groupId, name: `Group ${groupId}` });
  await table.put({ ...groupMember(groupId, deviceId), ...groupIndex(groupId, deviceId), groupId, deviceId });
  await table.put({
    ...policyAssignment(policyId, groupId),
    ...policyAssignmentIndex(groupId, policyId),
    policyId,
    groupId,
  });
  await table.put({ ...policyKey(policyId), policyId, version: 1, settings });
}

function handlerFor(table, now, verifyDevice) {
  return createCheckInHandler({ table, pepper: 'a'.repeat(64), now: () => now, verifyDevice });
}

// ============================================================================
// AC124: recordDefenderHardening -- storage and sanitisation
// ============================================================================

test('Scenario: Backend stores and sanitises the block', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-1';
  await seedDevice(table, deviceId, { complianceState: 'compliant' });

  const at = new Date('2026-10-11T10:00:00Z');
  const handler = handlerFor(table, at, createFakeVerifier(deviceId));

  const longDetail = 'x'.repeat(300);
  const request = createCheckInRequest(deviceId, {
    defenderHardening: {
      evaluatedAt: '2026-10-11T10:00:00Z',
      items: [
        { item: 'realTimeMonitoring', state: 'applied', detail: longDetail },
        { item: 'bogusItem', state: 'ok' },
        { item: 'networkProtection', state: 'weird' },
        { item: 'realTimeMonitoring', state: 'failed' },
      ],
    },
  });

  // When it checks in with that block
  const result = await handler(request);

  // Then the check-in succeeds
  assert.strictEqual(result.statusCode, 200);

  // And DEVICE#<id>/DEFENDERHARDENING holds one item realTimeMonitoring
  // "applied" with a 256-character detail
  const stored = await table.get(deviceDefenderHardening(deviceId));
  assert.ok(stored, 'expected a stored defenderHardening item');
  assert.strictEqual(stored.items.length, 1);
  assert.strictEqual(stored.items[0].item, 'realTimeMonitoring');
  assert.strictEqual(stored.items[0].state, 'applied');
  assert.strictEqual(stored.items[0].detail.length, 256);
  assert.strictEqual(stored.evaluatedAt, '2026-10-11T10:00:00Z');
  assert.ok(typeof stored.reportedAt === 'string' && stored.reportedAt.length > 0);

  // And complianceState is still "compliant" -- the block never moves it
  const profile = await table.get(deviceProfile(deviceId));
  assert.strictEqual(profile.complianceState, 'compliant');

  // When it checks in with no policyCompliance and defenderHardening
  // items [networkProtection failed]
  const secondRequest = createCheckInRequest(deviceId, {
    defenderHardening: { evaluatedAt: '2026-10-11T11:00:00Z', items: [{ item: 'networkProtection', state: 'failed' }] },
  });
  const secondResult = await handler(secondRequest);
  assert.strictEqual(secondResult.statusCode, 200);

  // Then complianceState is still "compliant"
  const profileAfter = await table.get(deviceProfile(deviceId));
  assert.strictEqual(profileAfter.complianceState, 'compliant');
});

test('Scenario: Backend keeps the stored block when the value is not an object', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-2';
  await seedDevice(table, deviceId);

  const existing = {
    ...deviceDefenderHardening(deviceId),
    deviceId,
    evaluatedAt: '2026-10-11T09:00:00Z',
    reportedAt: '2026-10-11T09:00:01Z',
    items: [{ item: 'networkProtection', state: 'ok' }],
  };
  await table.put(existing);

  const handler = handlerFor(table, new Date('2026-10-11T10:00:00Z'), createFakeVerifier(deviceId));
  const request = createCheckInRequest(deviceId, { defenderHardening: 'garbage' });

  // When the device checks in with defenderHardening "garbage"
  const result = await handler(request);

  // Then the check-in succeeds and the stored item is unchanged
  assert.strictEqual(result.statusCode, 200);
  const stored = await table.get(deviceDefenderHardening(deviceId));
  assert.deepStrictEqual(stored, existing);
});

test('Scenario (edge): A non-ISO evaluatedAt is stored as null', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-3';
  await seedDevice(table, deviceId);

  const handler = handlerFor(table, new Date('2026-10-11T10:00:00Z'), createFakeVerifier(deviceId));
  const request = createCheckInRequest(deviceId, {
    defenderHardening: { evaluatedAt: 'not-a-date', items: [] },
  });
  const result = await handler(request);
  assert.strictEqual(result.statusCode, 200);

  const stored = await table.get(deviceDefenderHardening(deviceId));
  assert.strictEqual(stored.evaluatedAt, null);
  assert.deepStrictEqual(stored.items, []);
});

// ============================================================================
// AC122: a Defender violation moves complianceState, independent of the block
// ============================================================================

test('Scenario: The backend makes the device non-compliant on a Defender violation', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-4';
  await seedDevice(table, deviceId, { complianceState: 'compliant' });
  await seedAssignedPolicy(table, {
    groupId: 'grp-1',
    policyId: 'p1',
    deviceId,
    settings: { defenderNetworkProtection: true },
  });

  const handler = handlerFor(table, new Date('2026-10-11T10:00:00Z'), createFakeVerifier(deviceId));

  // When it checks in with policyCompliance [{policyId "p1", compliant false,
  // violations ["defender_protection_failed:defenderNetworkProtection:networkProtection"]}]
  const violation = 'defender_protection_failed:defenderNetworkProtection:networkProtection';
  const request = createCheckInRequest(deviceId, {
    policyCompliance: [{ policyId: 'p1', version: 1, compliant: false, violations: [violation] }],
  });
  const result = await handler(request);
  assert.strictEqual(result.statusCode, 200);

  // Then COMPLIANCE#p1 stores that violation string unchanged
  const stored = await table.get(deviceCompliance(deviceId, 'p1'));
  assert.deepStrictEqual(stored.violations, [violation]);
  assert.strictEqual(stored.compliant, false);

  // And complianceState is "noncompliant"
  let profile = await table.get(deviceProfile(deviceId));
  assert.strictEqual(profile.complianceState, 'noncompliant');

  // When it checks in with policyCompliance [{policyId "p1", compliant true, violations []}]
  const secondRequest = createCheckInRequest(deviceId, {
    policyCompliance: [{ policyId: 'p1', version: 1, compliant: true, violations: [] }],
  });
  const secondResult = await handler(secondRequest);
  assert.strictEqual(secondResult.statusCode, 200);

  // Then complianceState is "compliant"
  profile = await table.get(deviceProfile(deviceId));
  assert.strictEqual(profile.complianceState, 'compliant');
});

test('Scenario (edge): complianceState is identical with and without the defenderHardening block', async () => {
  // The backend never reads the block to compute complianceState: with the
  // same policyCompliance, complianceState is identical with and without the
  // block, even when the block lists failed items.
  const violation = 'defender_protection_failed:defenderNetworkProtection:networkProtection';

  async function checkInAndGetComplianceState(deviceId, includeHardening) {
    const { table } = createFakeTable();
    await seedDevice(table, deviceId, { complianceState: 'compliant' });
    await seedAssignedPolicy(table, {
      groupId: 'grp-1',
      policyId: 'p1',
      deviceId,
      settings: { defenderNetworkProtection: true },
    });
    const handler = handlerFor(table, new Date('2026-10-11T10:00:00Z'), createFakeVerifier(deviceId));
    const overrides = {
      policyCompliance: [{ policyId: 'p1', version: 1, compliant: false, violations: [violation] }],
    };
    if (includeHardening) {
      overrides.defenderHardening = {
        evaluatedAt: '2026-10-11T10:00:00Z',
        items: [{ item: 'networkProtection', state: 'failed', detail: 'boom' }],
      };
    }
    await handler(createCheckInRequest(deviceId, overrides));
    const profile = await table.get(deviceProfile(deviceId));
    return profile.complianceState;
  }

  const withBlock = await checkInAndGetComplianceState('dev-5', true);
  const withoutBlock = await checkInAndGetComplianceState('dev-6', false);
  assert.strictEqual(withBlock, 'noncompliant');
  assert.strictEqual(withBlock, withoutBlock);
});
