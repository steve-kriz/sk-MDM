/**
 * E2E cucumber-style tests for TASK-056: `GET /admin/api/v1/devices/{deviceId}`
 * gains `location` and `locationTracking` (`handleDeviceDetail` in
 * `src/admin/devices.ts`).
 *
 * Every call goes through the real admin route handlers over an in-memory
 * documentClient (`test/helpers/fakeDynamo.js`); no real database connection
 * is ever opened.
 */

import test from 'node:test';
import assert from 'node:assert';
import { handleDeviceDetail } from '../../dist/admin/devices.js';
import { handleGroupCreate, handleGroupMembersAdd } from '../../dist/admin/groups.js';
import { handlePolicyCreate, handlePolicyAssign } from '../../dist/admin/policies.js';
import { deviceProfile, deviceLocation } from '../../dist/db/keys.js';
import { createFakeTable } from '../helpers/fakeDynamo.js';

function adminDeps(table, overrides = {}) {
  return { table, claims: { sub: 'admin-1', upn: 'admin@example.com' }, ...overrides };
}

async function seedDevice(table, deviceId, extra = {}) {
  await table.put({ ...deviceProfile(deviceId), deviceId, hostname: `host-${deviceId}`, platform: 'windows', ...extra });
}

async function createGroup(table, name) {
  const result = await handleGroupCreate(
    { params: {}, query: {}, headers: {}, body: JSON.stringify({ name }), claims: {} },
    adminDeps(table),
  );
  assert.strictEqual(result.statusCode, 201);
  return result.body.groupId;
}

async function addMember(table, groupId, deviceId) {
  const result = await handleGroupMembersAdd(
    { params: { groupId }, query: {}, headers: {}, body: JSON.stringify({ deviceIds: [deviceId] }), claims: {} },
    adminDeps(table),
  );
  assert.strictEqual(result.statusCode, 200);
}

async function createPolicy(table, name, settings) {
  const result = await handlePolicyCreate(
    { params: {}, query: {}, headers: {}, body: JSON.stringify({ name, settings }), claims: {} },
    adminDeps(table),
  );
  assert.strictEqual(result.statusCode, 201, JSON.stringify(result.body));
  return result.body.policyId;
}

async function assignPolicy(table, policyId, groupId) {
  const result = await handlePolicyAssign(
    { params: { policyId }, query: {}, headers: {}, body: JSON.stringify({ groupId }), claims: {} },
    adminDeps(table),
  );
  assert.strictEqual(result.statusCode, 200);
}

async function detail(table, deviceId) {
  return handleDeviceDetail({ params: { deviceId }, query: {}, headers: {}, body: null }, adminDeps(table));
}

// ============================================================================
// Scenario: Admin device detail returns location and tracking state
// ============================================================================

test('Scenario: Admin device detail returns location and tracking state', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-1';
  await seedDevice(table, deviceId);
  const groupId = await createGroup(table, 'Office fleet');
  await addMember(table, groupId, deviceId);
  const policyId = await createPolicy(table, 'Tracking on', { locationTracking: true });
  await assignPolicy(table, policyId, groupId);

  await table.put({
    ...deviceLocation(deviceId),
    deviceId,
    latitude: -33.8688,
    longitude: 151.2093,
    city: 'Sydney',
    region: 'New South Wales',
    country: 'AU',
    source: 'ip',
    accuracyMeters: null,
    capturedAt: '2026-10-11T00:00:00Z',
    history: [
      { latitude: -33.8688, longitude: 151.2093, city: 'Sydney', region: 'New South Wales', country: 'AU', source: 'ip', accuracyMeters: null, capturedAt: '2026-10-11T00:00:00Z' },
      { latitude: 1, longitude: 1, city: null, region: null, country: null, source: 'ip', accuracyMeters: null, capturedAt: '2026-10-10T00:00:00Z' },
    ],
  });

  const result = await detail(table, deviceId);
  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(result.body.location.latest.latitude, -33.8688);
  assert.strictEqual(result.body.location.latest.city, 'Sydney');
  assert.strictEqual(result.body.location.history.length, 2);
  assert.strictEqual(result.body.locationTracking, true);
});

// ============================================================================
// Scenario: Admin device detail with no location
// ============================================================================

test('Scenario: Admin device detail with no location and no policy', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-1';
  await seedDevice(table, deviceId);

  const result = await detail(table, deviceId);
  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body.location, { latest: null, history: [] });
  assert.strictEqual(result.body.locationTracking, false);
});

test('Scenario: Admin device detail locationTracking is false when the assigned policy does not enable it', async () => {
  const { table } = createFakeTable();
  const deviceId = 'dev-1';
  await seedDevice(table, deviceId);
  const groupId = await createGroup(table, 'Office fleet');
  await addMember(table, groupId, deviceId);
  const policyId = await createPolicy(table, 'Tracking off', { locationTracking: false });
  await assignPolicy(table, policyId, groupId);

  const result = await detail(table, deviceId);
  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(result.body.locationTracking, false);
  assert.deepStrictEqual(result.body.location, { latest: null, history: [] });
});
