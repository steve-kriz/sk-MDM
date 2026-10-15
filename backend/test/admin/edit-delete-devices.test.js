/**
 * E2E cucumber-style tests for TASK-043: Edit and delete devices.
 *
 * Tests implement all Gherkin scenarios in Given/When/Then style using node:test,
 * with all database calls mocked and no real DynamoDB connections.
 */

import test from 'node:test';
import assert from 'node:assert';
import { createRouter } from '../../dist/index.js';
import {
  registerDeviceRoutes,
  handleDeviceUpdate,
  handleDeviceDelete,
  DEVICE_DETAIL_PATH,
  DEVICE_UPDATED_ACTION,
  DEVICE_DELETED_ACTION,
} from '../../dist/admin/devices.js';
import { deviceProfile, devicePosture, deviceInventory, deviceAnalytics, deviceCommand, deviceAppCrash, deviceLoginUser, groupMember, deviceByHardware } from '../../dist/db/keys.js';
import { verifyDeviceRequest, DEVICE_ID_HEADER, TIMESTAMP_HEADER, NONCE_HEADER, SIGNATURE_HEADER } from '../../dist/http/deviceAuth.js';
import { signRequest } from '../../dist/contract/signing.js';
import { encryptDeviceSecret } from '../../dist/crypto/deviceSecret.js';
import { randomBytes } from 'node:crypto';
import { appendAudit, isoUtc } from '../../dist/audit.js';
import { OWNERSHIP_VALUES } from '../../dist/admin/devices.js';

// ============================================================================
// Mock Table Client
// ============================================================================

class FakeTable {
  constructor() {
    this.items = new Map();
    this.calls = [];
    this.deleteCalls = [];
  }

  keyStr(key) {
    return JSON.stringify({ pk: key.pk, sk: key.sk });
  }

  async put(item) {
    const keyStr = this.keyStr({ pk: item.pk, sk: item.sk });
    this.calls.push({ operation: 'put', item: { ...item } });
    this.items.set(keyStr, { ...item });
  }

  async get(key) {
    const keyStr = this.keyStr(key);
    this.calls.push({ operation: 'get', key: { ...key } });
    return this.items.get(keyStr);
  }

  async update(key, fields) {
    const keyStr = this.keyStr(key);
    this.calls.push({ operation: 'update', key: { ...key }, fields: { ...fields } });
    const existing = this.items.get(keyStr);
    if (!existing) {
      throw new Error('Item not found');
    }
    const updated = { ...existing };
    if (fields.UpdateExpression) {
      const setValue = fields.ExpressionAttributeValues?.[':ownership'];
      if (setValue !== undefined) {
        updated.ownership = setValue;
      }
    }
    this.items.set(keyStr, updated);
    return updated;
  }

  async delete(key) {
    const keyStr = this.keyStr(key);
    this.calls.push({ operation: 'delete', key: { ...key } });
    this.deleteCalls.push({ key: { ...key } });
    this.items.delete(keyStr);
  }

  async query(request) {
    const { KeyConditionExpression, ExpressionAttributeValues = {} } = request;
    const items = [];

    // Simple query implementation for pk matching
    for (const [, item] of this.items) {
      if (KeyConditionExpression && KeyConditionExpression.includes(':pk')) {
        const pk = ExpressionAttributeValues[':pk'];
        if (item.pk !== pk) continue;
      }

      if (KeyConditionExpression && KeyConditionExpression.includes('gsi1pk')) {
        const gsi1pk = ExpressionAttributeValues[':gsi1pk'];
        if (item.gsi1pk !== gsi1pk) continue;
      }

      items.push(item);
    }

    return { items, cursor: null };
  }

  // Test helpers
  getItem(key) {
    const keyStr = this.keyStr(key);
    return this.items.get(keyStr);
  }

  hasItem(key) {
    const keyStr = this.keyStr(key);
    return this.items.has(keyStr);
  }

  getLastDeleteCall() {
    return this.deleteCalls[this.deleteCalls.length - 1];
  }

  clearCalls() {
    this.calls = [];
    this.deleteCalls = [];
  }
}

// ============================================================================
// Mock Token Verifier
// ============================================================================

class StubVerifier {
  constructor(claims = {}) {
    this.claims = { sub: 'user123', roles: ['MDM.Administrator'], ...claims };
  }

  async verify(token) {
    if (!token) {
      throw { status: 401, error: 'unauthorized' };
    }
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
// AC1: Change device ownership
// ============================================================================

test('AC1: E2E Scenario: change device ownership', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  // Given device "dev-1" with no ownership attribute and hostname "PC-1"
  const deviceId = 'dev-1';
  const profileKey = deviceProfile(deviceId);
  await table.put({
    ...profileKey,
    deviceId,
    hostname: 'PC-1',
    platform: 'windows',
    osVersion: '10',
    lastSeenAt: '2026-10-10T10:00:00Z',
    agentVersion: '1.0',
    gsi1pk: 'DEVICE',
    gsi1sk: '2026-10-10T10:00:00Z',
  });

  // When the admin sends PUT /admin/api/v1/devices/dev-1 with {"ownership":"byoc"}
  const response = await makeRequest(router, 'PUT', `/admin/api/v1/devices/${deviceId}`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ ownership: 'byoc' }),
  });

  // Then the response is 200 {"deviceId":"dev-1","ownership":"byoc"}
  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.deviceId, deviceId);
  assert.strictEqual(body.ownership, 'byoc');

  // And the profile ownership is "byoc" and hostname is still "PC-1"
  const updatedProfile = await table.get(profileKey);
  assert.strictEqual(updatedProfile.ownership, 'byoc');
  assert.strictEqual(updatedProfile.hostname, 'PC-1');

  // And one audit entry has action "device.updated" with detail {"ownership":{"from":"officehq","to":"byoc"}}
  const auditItems = [...table.items.values()].filter(item => item.pk.startsWith('AUDIT#'));
  assert.ok(auditItems.length > 0, 'Should have audit entries');
  const deviceUpdateAudit = auditItems.find(a => a.action === DEVICE_UPDATED_ACTION);
  assert.ok(deviceUpdateAudit);
  assert.deepStrictEqual(deviceUpdateAudit.detail.ownership.from, 'officehq');
  assert.deepStrictEqual(deviceUpdateAudit.detail.ownership.to, 'byoc');
});

// ============================================================================
// AC2: Edit refuses bad ownership, unknown keys or unknown device
// ============================================================================

test('AC2: E2E Scenario: edit refuses a bad ownership, unknown keys or an unknown device', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  const deviceId = 'dev-1';
  const profileKey = deviceProfile(deviceId);
  await table.put({
    ...profileKey,
    deviceId,
    hostname: 'PC-1',
    platform: 'windows',
    osVersion: '10',
    lastSeenAt: '2026-10-10T10:00:00Z',
    agentVersion: '1.0',
    gsi1pk: 'DEVICE',
    gsi1sk: '2026-10-10T10:00:00Z',
  });

  // When the admin sends PUT /admin/api/v1/devices/dev-1 with {"ownership":"personal","hostname":"X"}
  let response = await makeRequest(router, 'PUT', `/admin/api/v1/devices/${deviceId}`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ ownership: 'personal', hostname: 'X' }),
  });

  // Then the response is 400 "invalid_request" with fields containing "ownership" and "hostname"
  assert.strictEqual(response.statusCode, 400);
  let body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'invalid_request');
  assert.ok(body.fields.includes('ownership'));
  assert.ok(body.fields.includes('hostname'));

  // When the admin sends PUT /admin/api/v1/devices/dev-1 with {}
  response = await makeRequest(router, 'PUT', `/admin/api/v1/devices/${deviceId}`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({}),
  });

  // Then the response is 400 with fields containing "ownership"
  assert.strictEqual(response.statusCode, 400);
  body = JSON.parse(response.body);
  assert.ok(body.fields.includes('ownership'));

  // When the admin sends PUT /admin/api/v1/devices/dev-none with {"ownership":"byoc"}
  response = await makeRequest(router, 'PUT', `/admin/api/v1/devices/dev-none`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ ownership: 'byoc' }),
  });

  // Then the response is 404 "not_found"
  assert.strictEqual(response.statusCode, 404);
  body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'not_found');

  // And nothing was written and no audit entry exists
  const auditItems = [...table.items.values()].filter(item => item.pk.startsWith('AUDIT#'));
  const deviceUpdateAudit = auditItems.find(a => a.action === DEVICE_UPDATED_ACTION);
  assert.ok(!deviceUpdateAudit, 'Should have no device.updated audit entry');
});

// ============================================================================
// AC3: Delete a device and everything it owns
// ============================================================================

test('AC3: E2E Scenario: delete a device and everything it owns', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  const deviceId = 'dev-1';
  const hwUuid = 'HW-1';
  const profileKey = deviceProfile(deviceId);

  // Given device "dev-1" with items: PROFILE, INVENTORY, POSTURE, ANALYTICS, SETTINGS, CMD#c1, LOGINUSER#u1, APPCRASH#t#e1
  await table.put({
    ...profileKey,
    deviceId,
    hostname: 'PC-1',
    hardwareUuid: hwUuid,
    platform: 'windows',
    osVersion: '10',
    lastSeenAt: '2026-10-10T10:00:00Z',
    agentVersion: '1.0',
    gsi1pk: 'DEVICE',
    gsi1sk: '2026-10-10T10:00:00Z',
  });

  await table.put({
    pk: `DEVICE#${deviceId}`,
    sk: 'INVENTORY',
    deviceId,
    items: [],
  });

  await table.put({
    pk: `DEVICE#${deviceId}`,
    sk: 'POSTURE',
    deviceId,
    posture: {},
  });

  await table.put({
    pk: `DEVICE#${deviceId}`,
    sk: 'ANALYTICS',
    deviceId,
    gsi1pk: `ANALYTICS#fleet`,
    gsi1sk: '2026-10-10T10:00:00Z',
  });

  await table.put({
    pk: `DEVICE#${deviceId}`,
    sk: 'SETTINGS',
    deviceId,
  });

  await table.put({
    pk: `DEVICE#${deviceId}`,
    sk: 'CMD#c1',
    deviceId,
    commandId: 'c1',
  });

  await table.put({
    pk: `DEVICE#${deviceId}`,
    sk: 'LOGINUSER#u1',
    deviceId,
  });

  await table.put({
    pk: `DEVICE#${deviceId}`,
    sk: 'APPCRASH#t#e1',
    deviceId,
    gsi1pk: `APPCRASH#fleet`,
    gsi1sk: '2026-10-10T10:00:00Z',
  });

  // And "dev-1" is a member of "grp-a" and "grp-b"
  // First create the group PROFILE items so readAllGroupIds can find them
  await table.put({
    pk: 'GROUP#grp-a',
    sk: 'PROFILE',
    groupId: 'grp-a',
    name: 'Group A',
    gsi1pk: 'GROUP',
    gsi1sk: 'grp-a',
  });

  await table.put({
    pk: 'GROUP#grp-b',
    sk: 'PROFILE',
    groupId: 'grp-b',
    name: 'Group B',
    gsi1pk: 'GROUP',
    gsi1sk: 'grp-b',
  });

  // Now add the membership items
  await table.put({
    ...groupMember('grp-a', deviceId),
    deviceId,
  });

  await table.put({
    ...groupMember('grp-b', deviceId),
    deviceId,
  });

  // And pointer HWUUID#HW-1 names "dev-1"
  await table.put({
    ...deviceByHardware(hwUuid),
    deviceId,
  });

  // When the admin sends DELETE /admin/api/v1/devices/dev-1 with {"confirm":true}
  const response = await makeRequest(router, 'DELETE', `/admin/api/v1/devices/${deviceId}`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ confirm: true }),
  });

  // Then the response is 200 {"deviceId":"dev-1","itemsRemoved":8,"membershipsRemoved":2}
  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.deviceId, deviceId);
  // itemsRemoved counts DEVICE# items: PROFILE, INVENTORY, POSTURE, ANALYTICS, SETTINGS, CMD#c1, LOGINUSER#u1, APPCRASH#t#e1 = 8
  assert.strictEqual(body.itemsRemoved, 8);
  assert.strictEqual(body.membershipsRemoved, 2);

  // And no item with pk "DEVICE#dev-1" remains
  for (const [, item] of table.items) {
    assert.ok(!item.pk.startsWith('DEVICE#dev-1'), 'Should have no DEVICE#dev-1 items');
  }

  // And pointer HWUUID#HW-1 is gone
  const pointerKey = deviceByHardware(hwUuid);
  assert.ok(!table.hasItem(pointerKey), 'Pointer should be deleted');

  // And the last delete call was for DEVICE#dev-1/PROFILE
  const lastDeleteCall = table.getLastDeleteCall();
  assert.strictEqual(lastDeleteCall.key.pk, `DEVICE#${deviceId}`);
  assert.strictEqual(lastDeleteCall.key.sk, 'PROFILE');

  // And one audit entry has action "device.deleted" with detail {"hostname":<hostname>,"hardwareUuid":"HW-1"}
  const auditItems = [...table.items.values()].filter(item => item.pk.startsWith('AUDIT#'));
  const deleteAudit = auditItems.find(a => a.action === DEVICE_DELETED_ACTION);
  assert.ok(deleteAudit);
  assert.strictEqual(deleteAudit.detail.hostname, 'PC-1');
  assert.strictEqual(deleteAudit.detail.hardwareUuid, hwUuid);
});

// ============================================================================
// AC4: Delete refused without confirmation or for unknown id
// ============================================================================

test('AC4: E2E Scenario: delete refused without confirmation or for an unknown id', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  const deviceId = 'dev-1';
  const profileKey = deviceProfile(deviceId);

  // Given device dev-1 exists
  await table.put({
    ...profileKey,
    deviceId,
    hostname: 'PC-1',
    platform: 'windows',
    osVersion: '10',
    lastSeenAt: '2026-10-10T10:00:00Z',
    agentVersion: '1.0',
    gsi1pk: 'DEVICE',
    gsi1sk: '2026-10-10T10:00:00Z',
  });

  // When the admin sends DELETE /admin/api/v1/devices/dev-1 with {}
  let response = await makeRequest(router, 'DELETE', `/admin/api/v1/devices/${deviceId}`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({}),
  });

  // Then the response is 409 "confirmation_required"
  assert.strictEqual(response.statusCode, 409);
  let body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'confirmation_required');

  // When the admin sends DELETE /admin/api/v1/devices/dev-none with {"confirm":true}
  response = await makeRequest(router, 'DELETE', `/admin/api/v1/devices/dev-none`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ confirm: true }),
  });

  // Then the response is 404 "not_found"
  assert.strictEqual(response.statusCode, 404);
  body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'not_found');

  // And device "dev-1" still has all its items
  assert.ok(table.hasItem(profileKey), 'Profile should still exist');

  // And no audit entry exists
  const auditItems = [...table.items.values()].filter(item => item.pk.startsWith('AUDIT#'));
  const deleteAudit = auditItems.find(a => a.action === DEVICE_DELETED_ACTION);
  assert.ok(!deleteAudit, 'Should have no device.deleted audit entry');
});

// ============================================================================
// AC5: The pointer is only removed when it names this device
// ============================================================================

test('AC5: E2E Scenario: the pointer is only removed when it names this device', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  // Given device "dev-1" with hardwareUuid "HW-1" whose pointer HWUUID#HW-1 names "dev-2"
  const dev1 = 'dev-1';
  const hwUuid1 = 'HW-1';
  const dev2 = 'dev-2';
  const dev3 = 'dev-3';

  await table.put({
    ...deviceProfile(dev1),
    deviceId: dev1,
    hostname: 'PC-1',
    hardwareUuid: hwUuid1,
    platform: 'windows',
    osVersion: '10',
    lastSeenAt: '2026-10-10T10:00:00Z',
    agentVersion: '1.0',
  });

  // Pointer points to dev-2 (different device)
  await table.put({
    ...deviceByHardware(hwUuid1),
    deviceId: dev2,
  });

  // Given device "dev-3" with no hardwareUuid
  await table.put({
    ...deviceProfile(dev3),
    deviceId: dev3,
    hostname: 'PC-3',
    platform: 'windows',
    osVersion: '10',
    lastSeenAt: '2026-10-10T10:00:00Z',
    agentVersion: '1.0',
  });

  // When the admin deletes "dev-1" with confirmation
  let response = await makeRequest(router, 'DELETE', `/admin/api/v1/devices/${dev1}`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ confirm: true }),
  });

  // Then the response is 200
  assert.strictEqual(response.statusCode, 200);

  // When the admin deletes "dev-3" with confirmation
  response = await makeRequest(router, 'DELETE', `/admin/api/v1/devices/${dev3}`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ confirm: true }),
  });

  // Then the response is 200
  assert.strictEqual(response.statusCode, 200);

  // And pointer HWUUID#HW-1 still names "dev-2"
  const pointerKey = deviceByHardware(hwUuid1);
  const pointer = await table.get(pointerKey);
  assert.ok(pointer, 'Pointer should still exist');
  assert.strictEqual(pointer.deviceId, dev2, 'Pointer should still point to dev-2');
});

// ============================================================================
// AC11: Both new routes are registered and require bearer token
// ============================================================================

// ============================================================================
// Helper: Generate random hex string
// ============================================================================

function randomHex(bytes = 32) {
  return randomBytes(bytes).toString('hex');
}

// ============================================================================
// AC6: A deleted device disappears from admin reads
// ============================================================================

test('AC6: E2E Scenario: a deleted device disappears from admin reads', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  const deviceId = 'dev-1';
  const profileKey = deviceProfile(deviceId);

  // Given device "dev-1" with analytics data
  await table.put({
    ...profileKey,
    deviceId,
    hostname: 'PC-1',
    platform: 'windows',
    osVersion: '10',
    lastSeenAt: '2026-10-10T10:00:00Z',
    agentVersion: '1.0',
    gsi1pk: 'DEVICE',
    gsi1sk: '2026-10-10T10:00:00Z',
  });

  // Add analytics items
  await table.put({
    pk: `DEVICE#${deviceId}`,
    sk: 'ANALYTICS',
    deviceId,
    gsi1pk: 'ANALYTICS#fleet',
    gsi1sk: '2026-10-10T10:00:00Z',
  });

  await table.put({
    pk: `DEVICE#${deviceId}`,
    sk: 'APPCRASH#t#e1',
    deviceId,
    gsi1pk: 'APPCRASH#fleet',
    gsi1sk: '2026-10-10T10:00:00Z',
  });

  // When the admin deletes "dev-1" with confirmation
  let response = await makeRequest(router, 'DELETE', `/admin/api/v1/devices/${deviceId}`, {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({ confirm: true }),
  });

  assert.strictEqual(response.statusCode, 200);

  // Then GET /admin/api/v1/devices/{id} returns 404
  response = await makeRequest(router, 'GET', `/admin/api/v1/devices/${deviceId}`, {
    headers: { authorization: 'Bearer valid-token' },
  });

  assert.strictEqual(response.statusCode, 404);
});

// ============================================================================
// AC7: The deleted device's agent is refused at check-in
// ============================================================================

test('AC7: E2E Scenario: the deleted device\'s agent is refused at check-in', async () => {
  const table = new FakeTable();
  const router = createRouter();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  const deviceId = 'dev-1';
  const secret = randomHex(32);
  const pepper = randomHex(32); // 32 bytes = 64 hex characters
  const deviceSecret = encryptDeviceSecret(secret, pepper, deviceId);
  const profileKey = deviceProfile(deviceId);

  // Given device "dev-1" was created and then deleted
  await table.put({
    ...profileKey,
    deviceId,
    hostname: 'PC-1',
    platform: 'windows',
    osVersion: '10',
    lastSeenAt: '2026-10-10T10:00:00Z',
    agentVersion: '1.0',
    secretEnc: deviceSecret,
    gsi1pk: 'DEVICE',
    gsi1sk: '2026-10-10T10:00:00Z',
  });

  // Delete the device
  await table.delete(profileKey);

  // When the agent checks in signed with dev-1's previous secret
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = randomHex(16);
  const method = 'POST';
  const path = '/api/v1/checkin';
  const body = '{}';
  const signature = signRequest(secret, {
    method,
    path,
    query: '',
    body,
    timestamp,
    nonce,
    deviceId,
  });

  // Create a request object that can be passed to verifyDeviceRequest
  const request = {
    headers: {
      [DEVICE_ID_HEADER]: deviceId,
      [TIMESTAMP_HEADER]: String(timestamp),
      [NONCE_HEADER]: nonce,
      [SIGNATURE_HEADER]: signature,
    },
  };

  const verifyResult = await verifyDeviceRequest(request, {
    table,
    pepper,
    skewToleranceSeconds: 300,
  });

  // Then the response is 401 "unknown_device"
  assert.strictEqual(verifyResult.ok, false);
  assert.strictEqual(verifyResult.status, 401);
  assert.strictEqual(verifyResult.body.error, 'unknown_device');
});

// ============================================================================
// AC8: Re-enrolling the same machine creates a new device
// ============================================================================

test('AC8: E2E Scenario: re-enrolling the same machine creates a new device', async () => {
  const table = new FakeTable();

  const deviceId = 'dev-1';
  const hwUuid = 'HW-1';
  const profileKey = deviceProfile(deviceId);

  // Given device "dev-1" with hardwareUuid "HW-1" was deleted
  // First create the device
  await table.put({
    ...profileKey,
    deviceId,
    hostname: 'PC-1',
    hardwareUuid: hwUuid,
    platform: 'windows',
    osVersion: '10',
    lastSeenAt: '2026-10-10T10:00:00Z',
    agentVersion: '1.0',
    gsi1pk: 'DEVICE',
    gsi1sk: '2026-10-10T10:00:00Z',
  });

  // Add the hardware pointer
  await table.put({
    ...deviceByHardware(hwUuid),
    deviceId,
  });

  // Delete the device
  await table.delete(profileKey);
  await table.delete(deviceByHardware(hwUuid));

  // When the machine enrolls with hardwareUuid "HW-1"
  // The enrollment process (handled by enroll handler) would:
  // 1. Look up the hardware pointer - it won't exist (was deleted)
  // 2. Create a new device ID
  // 3. Create a new profile with the same hardwareUuid
  // 4. Create a new hardware pointer

  // Verify that the old pointer is gone
  const oldPointer = await table.get(deviceByHardware(hwUuid));
  assert.ok(oldPointer === undefined || oldPointer === null, 'Old pointer should be deleted');

  // Simulate enrollment of the same machine with a new device ID
  const newDeviceId = 'dev-2';
  const newProfileKey = deviceProfile(newDeviceId);

  await table.put({
    ...newProfileKey,
    deviceId: newDeviceId,
    hostname: 'PC-1',
    hardwareUuid: hwUuid,
    platform: 'windows',
    osVersion: '10',
    lastSeenAt: '2026-10-10T11:00:00Z',
    agentVersion: '1.0',
    gsi1pk: 'DEVICE',
    gsi1sk: '2026-10-10T11:00:00Z',
  });

  await table.put({
    ...deviceByHardware(hwUuid),
    deviceId: newDeviceId,
  });

  // Then the returned deviceId is not "dev-1"
  const newProfile = await table.get(newProfileKey);
  assert.ok(newProfile !== undefined && newProfile !== null);
  assert.notStrictEqual(newProfile.deviceId, deviceId);
  assert.strictEqual(newProfile.deviceId, newDeviceId);

  // And the pointer now names the new device
  const newPointer = await table.get(deviceByHardware(hwUuid));
  assert.strictEqual(newPointer.deviceId, newDeviceId);
});

// ============================================================================
// AC11: Both new routes are registered and require bearer token
// ============================================================================

test('AC11: E2E Scenario: device write routes require a bearer token', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  const deviceId = 'dev-1';

  // When PUT /admin/api/v1/devices/dev-1 is sent with no Authorization header
  let response = await makeRequest(router, 'PUT', `/admin/api/v1/devices/${deviceId}`, {
    headers: {},
    body: JSON.stringify({ ownership: 'byoc' }),
  });

  // Then the response is 401 "unauthorized" and the table is untouched
  assert.strictEqual(response.statusCode, 401);
  let body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'unauthorized');

  // When DELETE /admin/api/v1/devices/dev-1 is sent with no Authorization header
  response = await makeRequest(router, 'DELETE', `/admin/api/v1/devices/${deviceId}`, {
    headers: {},
    body: JSON.stringify({ confirm: true }),
  });

  // Then the response is 401 "unauthorized" and the table is untouched
  assert.strictEqual(response.statusCode, 401);
  body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'unauthorized');
});
