/**
 * E2E test for TASK-060 AC125: GET /admin/api/v1/devices/{deviceId} returns
 * defenderHardening as the stored item (via publicItem), or null when none is
 * stored. Modelled on the AC22 antivirusStatus tests in
 * backend/test/admin/devices.test.js. No real database connection is opened.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { handleDeviceDetail } from '../../dist/admin/devices.js';
import { deviceProfile, deviceDefenderHardening } from '../../dist/db/keys.js';
import { createFakeTable } from '../helpers/fakeDynamo.js';

function adminDeps(table) {
  return { table, claims: { sub: 'admin-1', upn: 'admin@example.com' } };
}

async function seedDevice(table, deviceId) {
  await table.put({ ...deviceProfile(deviceId), deviceId, hostname: `host-${deviceId}` });
}

function detail(table, deviceId) {
  return handleDeviceDetail({ params: { deviceId }, query: {}, headers: {}, body: null }, adminDeps(table));
}

test('Scenario: Device detail API returns the block', async () => {
  const { table } = createFakeTable();
  await seedDevice(table, 'dev-1');

  // Given a stored DEFENDERHARDENING item for the device
  const stored = {
    ...deviceDefenderHardening('dev-1'),
    deviceId: 'dev-1',
    evaluatedAt: '2026-10-11T10:00:00Z',
    reportedAt: '2026-10-11T10:00:05Z',
    items: [{ item: 'networkProtection', state: 'failed', detail: 'boom' }],
  };
  await table.put(stored);

  // When the admin GETs the device detail
  const response = await detail(table, 'dev-1');
  assert.strictEqual(response.statusCode, 200);

  // Then the body has defenderHardening equal to the stored item without key attributes
  assert.ok(response.body.defenderHardening, 'expected defenderHardening to be present');
  assert.strictEqual(response.body.defenderHardening.deviceId, 'dev-1');
  assert.strictEqual(response.body.defenderHardening.evaluatedAt, '2026-10-11T10:00:00Z');
  assert.deepStrictEqual(response.body.defenderHardening.items, [
    { item: 'networkProtection', state: 'failed', detail: 'boom' },
  ]);
  assert.strictEqual(response.body.defenderHardening.pk, undefined);
  assert.strictEqual(response.body.defenderHardening.sk, undefined);
});

test('Scenario: Device detail with no stored item is null', async () => {
  const { table } = createFakeTable();
  // And for a device with no stored item defenderHardening is null
  await seedDevice(table, 'dev-2');

  const response = await detail(table, 'dev-2');
  assert.strictEqual(response.statusCode, 200);
  assert.strictEqual(response.body.defenderHardening, null);
});
