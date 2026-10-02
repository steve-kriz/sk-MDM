/**
 * E2E cucumber-style tests and unit tests for the check-in endpoint (TASK-007).
 * Tests implement all Gherkin scenarios without a cucumber package.
 * Mock all database calls — no real DB connections.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const {
  createCheckInHandler,
  registerCheckInRoute,
  CHECKIN_PATH,
  MAX_BODY_BYTES,
  MAX_SOFTWARE_ENTRIES,
} = await import(`file://${join(__dirname, '../../dist/routes/checkin.js')}`);

const { DEFAULT_CHECKIN_INTERVAL_SECONDS } = await import(
  `file://${join(__dirname, '../../dist/config/intervals.js')}`
);

const { agentRelease, deviceProfile, deviceInventory, devicePosture, deviceCommand } = await import(
  `file://${join(__dirname, '../../dist/db/keys.js')}`
);

const { isoUtc } = await import(`file://${join(__dirname, '../../dist/audit.js')}`);

// ============================================================================
// Test Helpers
// ============================================================================

class FakeTable {
  constructor() {
    this.calls = [];
    this.items = new Map();
    this.queryResponses = [];
  }

  keyStr(key) {
    return JSON.stringify({ pk: key.pk, sk: key.sk });
  }

  async get(key) {
    this.calls.push({ operation: 'get', key: { ...key } });
    return this.items.get(this.keyStr(key));
  }

  async put(item) {
    this.calls.push({ operation: 'put', item: { ...item } });
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  async putIfAbsent(item) {
    const keyStr = this.keyStr({ pk: item.pk, sk: item.sk });
    this.calls.push({ operation: 'putIfAbsent', item: { ...item } });
    if (this.items.has(keyStr)) {
      return { written: false };
    }
    this.items.set(keyStr, { ...item });
    return { written: true };
  }

  async update(key, fields) {
    this.calls.push({ operation: 'update', key: { ...key }, fields: { ...fields } });
    const existing = this.items.get(this.keyStr(key)) || {};
    const updated = { ...existing, ...key };
    this.items.set(this.keyStr(key), updated);
    return updated;
  }

  async query(request) {
    this.calls.push({ operation: 'query', request: { ...request } });
    // Pop the next queued response, or return empty
    if (this.queryResponses.length > 0) {
      return this.queryResponses.shift();
    }
    return { items: [], cursor: null };
  }

  // Test helpers
  seedItem(item) {
    this.calls = [];
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  getStoredItem(key) {
    return this.items.get(this.keyStr(key));
  }

  recordedOperations() {
    return this.calls.map((c) => c.operation);
  }

  recordedPutCalls() {
    return this.calls.filter((c) => c.operation === 'put').map((c) => c.item);
  }

  recordedUpdateCalls() {
    return this.calls.filter((c) => c.operation === 'update');
  }

  recordedQueryCalls() {
    return this.calls.filter((c) => c.operation === 'query');
  }

  recordedInventoryPut() {
    return this.recordedPutCalls().find(
      (item) => item.sk === 'INVENTORY'
    );
  }

  recordedPosturePut() {
    return this.recordedPutCalls().find(
      (item) => item.sk === 'POSTURE'
    );
  }

  recordedProfileUpdate() {
    return this.recordedUpdateCalls().find(
      (call) => call.key.sk === 'PROFILE'
    );
  }

  noCalls() {
    return this.calls.length === 0;
  }

  seedQueryResponses(responses) {
    this.queryResponses = [...responses];
  }
}

function randomHex(bytes = 32) {
  return randomBytes(bytes).toString('hex');
}

function createValidCheckInRequest(overrides = {}) {
  const baseRequest = {
    method: 'POST',
    path: '/api/v1/devices/test-device-id/checkin',
    query: {},
    headers: {
      'x-mdm-device-id': 'test-device-id',
      'x-mdm-timestamp': Math.floor(Date.now() / 1000).toString(),
      'x-mdm-nonce': randomHex(16),
      'x-mdm-signature': randomHex(32),
    },
    params: { deviceId: 'test-device-id' },
    body: null,
  };

  const defaultBody = {
    collectedAt: '2026-10-02T11:00:00Z',
    inventory: {
      hardware: {
        manufacturer: 'Dell',
        model: 'OptiPlex 7090',
        serialNumber: 'ABC123',
        cpu: 'Intel Core i7',
        ramBytes: 16000000000,
        diskBytes: 500000000000,
      },
      os: {
        name: 'Windows',
        version: '11',
        build: '22621',
        architecture: 'x86_64',
      },
      software: [
        {
          name: 'Node.js',
          version: '22.0.0',
          publisher: 'OpenJS',
          installedAt: '2026-01-01T00:00:00Z',
        },
      ],
      warnings: ['warning_1'],
    },
    posture: {
      diskEncryption: {
        enabled: true,
        method: 'bitlocker',
      },
      firewall: {
        enabled: true,
      },
      antivirus: {
        name: 'Windows Defender',
        enabled: true,
        definitionsAgeDays: 1,
      },
      osUpdate: {
        lastCheckedAt: '2026-10-02T10:00:00Z',
        pendingCount: 2,
        rebootRequired: false,
      },
      localAdmins: ['admin1', 'admin2'],
      warnings: ['posture_warning_1'],
    },
  };

  const body = { ...defaultBody, ...overrides };
  return {
    ...baseRequest,
    body: JSON.stringify(body),
    ...overrides.requestOverride,
  };
}

function createFakeVerifier(deviceIdToReturn = 'test-device-id', authOk = true, authStatus = 401) {
  return async (req, options) => {
    if (!authOk) {
      return { ok: false, status: authStatus, body: { error: 'replayed_nonce' } };
    }
    return { ok: true, deviceId: deviceIdToReturn };
  };
}

// ============================================================================
// E2E Cucumber-Style Tests
// ============================================================================

test('Scenario: Check-in returns the polling contract', async (t) => {
  // Given an authenticated device with no pending commands
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  // When it posts a valid check-in
  const request = createValidCheckInRequest();
  const result = await handler(request);

  // Then the status is 200
  assert.strictEqual(result.statusCode, 200);

  // And the body keys are exactly checkInIntervalSeconds and pendingCommandCount
  const keys = Object.keys(result.body).sort();
  assert.deepStrictEqual(keys, ['checkInIntervalSeconds', 'pendingCommandCount']);

  // And pendingCommandCount is 0
  assert.strictEqual(result.body.pendingCommandCount, 0);
});

test('Scenario: Polling interval comes from the shared constant', async (t) => {
  // Given DEFAULT_CHECKIN_INTERVAL_SECONDS is 900
  assert.strictEqual(DEFAULT_CHECKIN_INTERVAL_SECONDS, 900);

  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  // When a device posts a valid check-in
  const request = createValidCheckInRequest();
  const result = await handler(request);

  // Then checkInIntervalSeconds is 900
  assert.strictEqual(result.body.checkInIntervalSeconds, 900);

  // And backend/src/routes/checkin.ts contains no other numeric literal for that field
  const checkinSource = readFileSync(
    join(__dirname, '../../src/routes/checkin.ts'),
    'utf-8'
  );
  // The route should import DEFAULT_CHECKIN_INTERVAL_SECONDS and use it, not define 900 as a literal
  assert.ok(checkinSource.includes('DEFAULT_CHECKIN_INTERVAL_SECONDS'), 'Should import DEFAULT_CHECKIN_INTERVAL_SECONDS');
  // Should not have a literal 900 assignment for the checkInIntervalSeconds field
  const literalAssignments = checkinSource.match(/checkInIntervalSeconds\s*:\s*900\b/g);
  assert.ok(literalAssignments === null || literalAssignments.length === 0, 'Should not have literal 900 for checkInIntervalSeconds');
});

test('Scenario: Response carries no policy information', async (t) => {
  // Given an authenticated device with policies assigned (in this case, the response shouldn't have policies)
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  // When it posts a valid check-in
  const request = createValidCheckInRequest();
  const result = await handler(request);

  // Then the response body has no "policies" key
  assert.ok(!('policies' in result.body), 'Response should not contain policies key');
});

test('Scenario: Route runs device auth first', async (t) => {
  // Given verifyDeviceRequest resolves {ok:false, status:401, body:{error:"replayed_nonce"}}
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', false, 401),
  });

  // When a request hits POST /api/v1/devices/d1/checkin
  const request = createValidCheckInRequest({
    requestOverride: {
      path: '/api/v1/devices/d1/checkin',
      params: { deviceId: 'd1' },
      headers: {
        'x-mdm-device-id': 'd1',
        'x-mdm-timestamp': Math.floor(Date.now() / 1000).toString(),
        'x-mdm-nonce': randomHex(16),
        'x-mdm-signature': randomHex(32),
      },
    },
  });
  const result = await handler(request);

  // Then the status is 401
  assert.strictEqual(result.statusCode, 401);
  // And the body is {"error":"replayed_nonce"}
  assert.deepStrictEqual(result.body, { error: 'replayed_nonce' });
  // And no inventory, posture, profile or command item was touched
  assert.ok(table.noCalls(), 'Table should not be called when auth fails');
});

test('Scenario: Route is reachable through the entry point', async (t) => {
  // When I inspect the routes registered by backend/src/index.ts
  const indexSource = readFileSync(
    join(__dirname, '../../src/index.ts'),
    'utf-8'
  );
  // Then POST /api/v1/devices/{deviceId}/checkin is present
  assert.ok(
    indexSource.includes('registerCheckInRoute'),
    'index.ts should register the check-in route'
  );
  assert.ok(
    indexSource.includes(CHECKIN_PATH) || indexSource.includes('{deviceId}/checkin'),
    'index.ts should reference the check-in path'
  );
});

test('Scenario: Oversized body is rejected before authentication', async (t) => {
  // Given a body of 300000 bytes and a fake verifyDeviceRequest that records its calls
  const table = new FakeTable();
  let verifyDeviceCalled = false;
  const fakeVerify = async () => {
    verifyDeviceCalled = true;
    return { ok: true, deviceId: 'test-device-id' };
  };

  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: fakeVerify,
  });

  const request = createValidCheckInRequest();
  request.body = 'x'.repeat(300000);

  // When the request is handled
  const result = await handler(request);

  // Then the status is 413
  assert.strictEqual(result.statusCode, 413);
  // And the error is payload_too_large
  assert.deepStrictEqual(result.body, { error: 'payload_too_large' });
  // And verifyDeviceRequest was never called
  assert.ok(!verifyDeviceCalled, 'verifyDevice should not be called for oversized body');
});

test('Scenario: Mismatch is checked before body validation', async (t) => {
  // Given a request authenticated as d1 posting to /devices/d2/checkin with collectedAt "yesterday"
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('d1', true),
  });

  const request = createValidCheckInRequest(
    { collectedAt: 'yesterday' },
    {
      requestOverride: {
        path: '/api/v1/devices/d2/checkin',
        params: { deviceId: 'd2' },
        headers: {
          'x-mdm-device-id': 'd1',
          'x-mdm-timestamp': Math.floor(Date.now() / 1000).toString(),
          'x-mdm-nonce': randomHex(16),
          'x-mdm-signature': randomHex(32),
        },
      },
    }
  );
  request.path = '/api/v1/devices/d2/checkin';
  request.params = { deviceId: 'd2' };

  // When the request is handled
  const result = await handler(request);

  // Then the status is 403 and the error is device_mismatch, not invalid_request
  assert.strictEqual(result.statusCode, 403);
  assert.deepStrictEqual(result.body, { error: 'device_mismatch' });
});

test('Scenario: Inventory snapshot is stored under the frozen field names', async (t) => {
  // Given a check-in whose inventory carries hardware, os and one software entry
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const request = createValidCheckInRequest();
  // When the check-in is stored
  const result = await handler(request);

  // Then the INVENTORY item holds hardware with manufacturer, model, serialNumber, cpu, ramBytes and diskBytes
  const inventoryItem = table.recordedInventoryPut();
  assert.ok(inventoryItem, 'Inventory item should be put');
  assert.ok(inventoryItem.hardware, 'Inventory should have hardware');
  assert.strictEqual(inventoryItem.hardware.manufacturer, 'Dell');
  assert.strictEqual(inventoryItem.hardware.model, 'OptiPlex 7090');
  assert.strictEqual(inventoryItem.hardware.serialNumber, 'ABC123');
  assert.strictEqual(inventoryItem.hardware.cpu, 'Intel Core i7');
  assert.strictEqual(inventoryItem.hardware.ramBytes, 16000000000);
  assert.strictEqual(inventoryItem.hardware.diskBytes, 500000000000);

  // And os with name, version, build and architecture
  assert.ok(inventoryItem.os, 'Inventory should have os');
  assert.strictEqual(inventoryItem.os.name, 'Windows');
  assert.strictEqual(inventoryItem.os.version, '11');
  assert.strictEqual(inventoryItem.os.build, '22621');
  assert.strictEqual(inventoryItem.os.architecture, 'x86_64');

  // And software[0] with name, version, publisher and installedAt
  assert.ok(Array.isArray(inventoryItem.software), 'Inventory should have software array');
  assert.strictEqual(inventoryItem.software.length, 1);
  assert.strictEqual(inventoryItem.software[0].name, 'Node.js');
  assert.strictEqual(inventoryItem.software[0].version, '22.0.0');
  assert.strictEqual(inventoryItem.software[0].publisher, 'OpenJS');
  assert.strictEqual(inventoryItem.software[0].installedAt, '2026-01-01T00:00:00Z');
});

test('Scenario: Posture snapshot is stored under the frozen field names', async (t) => {
  // Given a check-in whose posture carries every field
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const request = createValidCheckInRequest();
  // When the check-in is stored
  const result = await handler(request);

  // Then the POSTURE item holds diskEncryption with enabled and method
  const postureItem = table.recordedPosturePut();
  assert.ok(postureItem, 'Posture item should be put');
  assert.ok(postureItem.diskEncryption, 'Posture should have diskEncryption');
  assert.strictEqual(postureItem.diskEncryption.enabled, true);
  assert.strictEqual(postureItem.diskEncryption.method, 'bitlocker');

  // And firewall with enabled
  assert.ok(postureItem.firewall, 'Posture should have firewall');
  assert.strictEqual(postureItem.firewall.enabled, true);

  // And antivirus with name, enabled and definitionsAgeDays
  assert.ok(postureItem.antivirus, 'Posture should have antivirus');
  assert.strictEqual(postureItem.antivirus.name, 'Windows Defender');
  assert.strictEqual(postureItem.antivirus.enabled, true);
  assert.strictEqual(postureItem.antivirus.definitionsAgeDays, 1);

  // And osUpdate with lastCheckedAt, pendingCount and rebootRequired
  assert.ok(postureItem.osUpdate, 'Posture should have osUpdate');
  assert.strictEqual(postureItem.osUpdate.lastCheckedAt, '2026-10-02T10:00:00Z');
  assert.strictEqual(postureItem.osUpdate.pendingCount, 2);
  assert.strictEqual(postureItem.osUpdate.rebootRequired, false);

  // And localAdmins
  assert.ok(Array.isArray(postureItem.localAdmins), 'Posture should have localAdmins array');
  assert.strictEqual(postureItem.localAdmins.length, 2);
  assert.strictEqual(postureItem.localAdmins[0], 'admin1');
  assert.strictEqual(postureItem.localAdmins[1], 'admin2');
});

test('Scenario: collectedAt is copied to both snapshots', async (t) => {
  // Given a check-in with collectedAt "2026-10-02T11:59:00Z"
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const request = createValidCheckInRequest({ collectedAt: '2026-10-02T11:59:00Z' });
  // When the check-in is stored
  const result = await handler(request);

  // Then the INVENTORY item carries collectedAt "2026-10-02T11:59:00Z"
  const inventoryItem = table.recordedInventoryPut();
  assert.strictEqual(inventoryItem.collectedAt, '2026-10-02T11:59:00Z');

  // And the POSTURE item carries collectedAt "2026-10-02T11:59:00Z"
  const postureItem = table.recordedPosturePut();
  assert.strictEqual(postureItem.collectedAt, '2026-10-02T11:59:00Z');
});

test('Scenario: Absent warnings keys are accepted', async (t) => {
  // Given a check-in whose inventory and posture carry no warnings key
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const inventoryWithoutWarnings = {
    hardware: { manufacturer: 'Dell', model: 'OptiPlex', serialNumber: 'ABC123', cpu: 'Intel', ramBytes: 16000000000, diskBytes: 500000000000 },
    os: { name: 'Windows', version: '11', build: '22621', architecture: 'x86_64' },
    software: [],
    // no warnings
  };

  const postureWithoutWarnings = {
    diskEncryption: { enabled: true, method: 'bitlocker' },
    firewall: { enabled: true },
    antivirus: { name: 'Defender', enabled: true, definitionsAgeDays: 1 },
    osUpdate: { lastCheckedAt: '2026-10-02T10:00:00Z', pendingCount: 0, rebootRequired: false },
    localAdmins: [],
    // no warnings
  };

  const request = createValidCheckInRequest({
    inventory: inventoryWithoutWarnings,
    posture: postureWithoutWarnings,
  });

  // When the check-in is stored
  const result = await handler(request);

  // Then the status is 200
  assert.strictEqual(result.statusCode, 200);
  // And neither written item has a warnings attribute
  const inventoryItem = table.recordedInventoryPut();
  assert.ok(!('warnings' in inventoryItem) || inventoryItem.warnings === undefined, 'Inventory should not have warnings attribute');
  const postureItem = table.recordedPosturePut();
  assert.ok(!('warnings' in postureItem) || postureItem.warnings === undefined, 'Posture should not have warnings attribute');
});

test('Scenario: policyCompliance is accepted and not persisted', async (t) => {
  // Given a check-in carrying policyCompliance
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const request = createValidCheckInRequest({
    policyCompliance: [{ policyId: 'p1', version: 1, compliant: false, violations: ['firewall_disabled'] }],
  });

  // When the check-in is handled
  const result = await handler(request);

  // Then the status is 200
  assert.strictEqual(result.statusCode, 200);
  // And no written item carries any policyCompliance data
  const inventoryItem = table.recordedInventoryPut();
  assert.ok(!('policyCompliance' in inventoryItem), 'Inventory should not have policyCompliance');
  const postureItem = table.recordedPosturePut();
  assert.ok(!('policyCompliance' in postureItem), 'Posture should not have policyCompliance');
  const updateCall = table.recordedProfileUpdate();
  if (updateCall) {
    assert.ok(!('policyCompliance' in updateCall.fields.ExpressionAttributeValues), 'Profile update should not include policyCompliance');
  }
});

test('Scenario: Last-seen uses server time', async (t) => {
  // Given the server clock is 2026-10-02T12:00:00Z and the agent sends collectedAt 2026-01-01T00:00:00Z
  const table = new FakeTable();
  const serverTime = new Date('2026-10-02T12:00:00Z');
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => serverTime,
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const request = createValidCheckInRequest({ collectedAt: '2026-01-01T00:00:00Z' });
  // When the check-in is stored
  const result = await handler(request);

  // Then the device profile lastSeenAt and gsi1sk are both 2026-10-02T12:00:00Z
  const updateCall = table.recordedProfileUpdate();
  assert.ok(updateCall, 'Profile should be updated');
  const expValue = updateCall.fields.ExpressionAttributeValues[':lastSeenAt'];
  assert.strictEqual(expValue, isoUtc(serverTime));
});

test('Scenario: Device id mismatch is refused', async (t) => {
  // Given a request authenticated as d1 posting to /devices/d2/checkin
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('d1', true),
  });

  const request = createValidCheckInRequest({
    requestOverride: {
      path: '/api/v1/devices/d2/checkin',
      params: { deviceId: 'd2' },
      headers: {
        'x-mdm-device-id': 'd1',
        'x-mdm-timestamp': Math.floor(Date.now() / 1000).toString(),
        'x-mdm-nonce': randomHex(16),
        'x-mdm-signature': randomHex(32),
      },
    },
  });
  request.path = '/api/v1/devices/d2/checkin';
  request.params = { deviceId: 'd2' };

  // Then the status is 403, the error is device_mismatch and nothing was written
  const result = await handler(request);
  assert.strictEqual(result.statusCode, 403);
  assert.deepStrictEqual(result.body, { error: 'device_mismatch' });
  assert.ok(table.noCalls(), 'No database operations should occur on device mismatch');
});

test('Scenario: Oversized payload is refused', async (t) => {
  // Given a body of 300000 bytes
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const request = createValidCheckInRequest();
  request.body = 'x'.repeat(300000);

  // Then the status is 413, the error is payload_too_large and nothing was written
  const result = await handler(request);
  assert.strictEqual(result.statusCode, 413);
  assert.deepStrictEqual(result.body, { error: 'payload_too_large' });
  assert.ok(table.noCalls(), 'No database operations should occur for oversized payload');
});

test('Scenario: Malformed timestamp is refused', async (t) => {
  // Given collectedAt is "yesterday"
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const request = createValidCheckInRequest({ collectedAt: 'yesterday' });
  // Then the status is 400 and fields contains "collectedAt"
  const result = await handler(request);
  assert.strictEqual(result.statusCode, 400);
  assert.deepStrictEqual(result.body.error, 'invalid_request');
  assert.ok(Array.isArray(result.body.fields), 'Response should include fields array');
  assert.ok(result.body.fields.includes('collectedAt'), 'Fields should include collectedAt');
});

test('Scenario: Software entry without a version is refused', async (t) => {
  // Given inventory.software[0] is {name:"Foo", publisher:"Acme", installedAt:"2026-01-01T00:00:00Z"}
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const request = createValidCheckInRequest({
    inventory: {
      hardware: { manufacturer: 'Dell', model: 'OptiPlex', serialNumber: 'ABC123', cpu: 'Intel', ramBytes: 16000000000, diskBytes: 500000000000 },
      os: { name: 'Windows', version: '11', build: '22621', architecture: 'x86_64' },
      software: [{ name: 'Foo', publisher: 'Acme', installedAt: '2026-01-01T00:00:00Z' }],
    },
    posture: {
      diskEncryption: { enabled: true, method: 'bitlocker' },
      firewall: { enabled: true },
      antivirus: { name: 'Defender', enabled: true, definitionsAgeDays: 1 },
      osUpdate: { lastCheckedAt: '2026-10-02T10:00:00Z', pendingCount: 0, rebootRequired: false },
      localAdmins: [],
    },
  });

  // Then the status is 400 and fields contains "inventory.software[0].version"
  const result = await handler(request);
  assert.strictEqual(result.statusCode, 400);
  assert.deepStrictEqual(result.body.error, 'invalid_request');
  assert.ok(result.body.fields.includes('inventory.software[0].version'), 'Fields should include inventory.software[0].version');
});

test('Scenario: Too many software entries are refused', async (t) => {
  // Given inventory.software holds 2001 entries
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const software = Array.from({ length: 2001 }, (_, i) => ({
    name: `Software${i}`,
    version: '1.0.0',
    publisher: 'Publisher',
    installedAt: '2026-01-01T00:00:00Z',
  }));

  const request = createValidCheckInRequest({
    inventory: {
      hardware: { manufacturer: 'Dell', model: 'OptiPlex', serialNumber: 'ABC123', cpu: 'Intel', ramBytes: 16000000000, diskBytes: 500000000000 },
      os: { name: 'Windows', version: '11', build: '22621', architecture: 'x86_64' },
      software,
    },
    posture: {
      diskEncryption: { enabled: true, method: 'bitlocker' },
      firewall: { enabled: true },
      antivirus: { name: 'Defender', enabled: true, definitionsAgeDays: 1 },
      osUpdate: { lastCheckedAt: '2026-10-02T10:00:00Z', pendingCount: 0, rebootRequired: false },
      localAdmins: [],
    },
  });

  // Then the status is 400 and fields contains "inventory.software"
  const result = await handler(request);
  assert.strictEqual(result.statusCode, 400);
  assert.deepStrictEqual(result.body.error, 'invalid_request');
  assert.ok(result.body.fields.includes('inventory.software'), 'Fields should include inventory.software');
});

test('Scenario: Pending commands are counted', async (t) => {
  // Given the device has two command items with status pending and one with status completed
  const table = new FakeTable();
  table.seedQueryResponses([
    {
      items: [
        { pk: 'DEVICE#test-device-id', sk: 'CMD#cmd1', status: 'pending' },
        { pk: 'DEVICE#test-device-id', sk: 'CMD#cmd2', status: 'pending' },
        { pk: 'DEVICE#test-device-id', sk: 'CMD#cmd3', status: 'completed' },
      ],
      cursor: null,
    },
  ]);

  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const request = createValidCheckInRequest();
  // When it checks in
  const result = await handler(request);

  // Then pendingCommandCount is 2
  assert.strictEqual(result.body.pendingCommandCount, 2);
  // And the query used pk "DEVICE#test-device-id" with sk begins_with "CMD#"
  const queryCalls = table.recordedQueryCalls();
  assert.ok(queryCalls.length > 0, 'Should have query calls');
  const queryCall = queryCalls[0];
  assert.strictEqual(queryCall.request.ExpressionAttributeValues[':pk'], 'DEVICE#test-device-id');
  assert.strictEqual(queryCall.request.ExpressionAttributeValues[':commandPrefix'], 'CMD#');
});

test('Scenario: Pending count spans every page', async (t) => {
  // Given the command query returns one pending item plus a non-null cursor, then two pending items and a null cursor
  const table = new FakeTable();
  table.seedQueryResponses([
    {
      items: [{ pk: 'DEVICE#test-device-id', sk: 'CMD#cmd1', status: 'pending' }],
      cursor: 'page2-cursor',
    },
    {
      items: [
        { pk: 'DEVICE#test-device-id', sk: 'CMD#cmd2', status: 'pending' },
        { pk: 'DEVICE#test-device-id', sk: 'CMD#cmd3', status: 'pending' },
      ],
      cursor: null,
    },
  ]);

  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const request = createValidCheckInRequest();
  // When the device checks in
  const result = await handler(request);

  // Then pendingCommandCount is 3
  assert.strictEqual(result.body.pendingCommandCount, 3);
  // And no scan was issued
  const queryCalls = table.recordedQueryCalls();
  for (const call of queryCalls) {
    assert.ok(!call.request.Scan, 'Should use query, not scan');
    assert.ok(call.request.KeyConditionExpression, 'Should have key condition expression');
  }
});

// ============================================================================
// Unit Tests
// ============================================================================

test('Unit: MAX_BODY_BYTES is 262144', async (t) => {
  assert.strictEqual(MAX_BODY_BYTES, 262144);
});

test('Unit: MAX_SOFTWARE_ENTRIES is 2000', async (t) => {
  assert.strictEqual(MAX_SOFTWARE_ENTRIES, 2000);
});

test('Unit: Exact body size at limit is accepted', async (t) => {
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const request = createValidCheckInRequest();
  // Create a body exactly at the limit
  const baseBody = {
    collectedAt: '2026-10-02T11:00:00Z',
    inventory: {
      hardware: { manufacturer: 'a', model: 'b', serialNumber: 'c', cpu: 'd', ramBytes: 1, diskBytes: 1 },
      os: { name: 'a', version: 'b', build: 'c', architecture: 'd' },
      software: [],
    },
    posture: {
      diskEncryption: { enabled: true, method: 'bitlocker' },
      firewall: { enabled: true },
      antivirus: { name: 'a', enabled: true, definitionsAgeDays: 1 },
      osUpdate: { lastCheckedAt: '2026-01-01T00:00:00Z', pendingCount: 1, rebootRequired: false },
      localAdmins: [],
    },
  };

  let bodyStr = JSON.stringify(baseBody);
  // Pad to exactly MAX_BODY_BYTES
  while (Buffer.byteLength(bodyStr, 'utf8') < MAX_BODY_BYTES) {
    baseBody.inventory.software.push({
      name: 'x',
      version: 'y',
      publisher: 'z',
      installedAt: '2026-01-01T00:00:00Z',
    });
    bodyStr = JSON.stringify(baseBody);
  }

  request.body = bodyStr.substring(0, bodyStr.length - (Buffer.byteLength(bodyStr, 'utf8') - MAX_BODY_BYTES));

  const result = await handler(request);
  assert.notStrictEqual(result.statusCode, 413);
});

test('Unit: Handler with static dependencies', async (t) => {
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: 'static-pepper',
    now: () => 1696270800, // epoch seconds
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const request = createValidCheckInRequest();
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);
  assert.ok(result.body.checkInIntervalSeconds, 'Should include checkInIntervalSeconds');
  assert.ok(typeof result.body.pendingCommandCount === 'number', 'Should include pendingCommandCount');
});

test('Unit: Empty software array is stored', async (t) => {
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const request = createValidCheckInRequest({
    inventory: {
      hardware: { manufacturer: 'a', model: 'b', serialNumber: 'c', cpu: 'd', ramBytes: 1, diskBytes: 1 },
      os: { name: 'a', version: 'b', build: 'c', architecture: 'd' },
      software: [],
    },
    posture: {
      diskEncryption: { enabled: true, method: 'bitlocker' },
      firewall: { enabled: true },
      antivirus: { name: 'a', enabled: true, definitionsAgeDays: 1 },
      osUpdate: { lastCheckedAt: '2026-01-01T00:00:00Z', pendingCount: 1, rebootRequired: false },
      localAdmins: [],
    },
  });

  const result = await handler(request);
  assert.strictEqual(result.statusCode, 200);
  const inventoryItem = table.recordedInventoryPut();
  assert.deepStrictEqual(inventoryItem.software, []);
});

test('Unit: Software with name but no version fails validation', async (t) => {
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const request = createValidCheckInRequest({
    inventory: {
      hardware: { manufacturer: 'a', model: 'b', serialNumber: 'c', cpu: 'd', ramBytes: 1, diskBytes: 1 },
      os: { name: 'a', version: 'b', build: 'c', architecture: 'd' },
      software: [{ name: 'Foo', publisher: 'Bar' }],
    },
    posture: {
      diskEncryption: { enabled: true, method: 'bitlocker' },
      firewall: { enabled: true },
      antivirus: { name: 'a', enabled: true, definitionsAgeDays: 1 },
      osUpdate: { lastCheckedAt: '2026-01-01T00:00:00Z', pendingCount: 1, rebootRequired: false },
      localAdmins: [],
    },
  });

  const result = await handler(request);
  assert.strictEqual(result.statusCode, 400);
  assert.ok(result.body.fields.includes('inventory.software[0].version'));
});

test('Unit: Missing inventory object fails validation', async (t) => {
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const baseRequest = createValidCheckInRequest();
  const body = JSON.parse(baseRequest.body);
  delete body.inventory;
  baseRequest.body = JSON.stringify(body);

  const result = await handler(baseRequest);
  assert.strictEqual(result.statusCode, 400);
  assert.ok(result.body.fields.includes('inventory'));
});

test('Unit: Missing posture object fails validation', async (t) => {
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const baseRequest = createValidCheckInRequest();
  const body = JSON.parse(baseRequest.body);
  delete body.posture;
  baseRequest.body = JSON.stringify(body);

  const result = await handler(baseRequest);
  assert.strictEqual(result.statusCode, 400);
  assert.ok(result.body.fields.includes('posture'));
});

test('Unit: CheckInResponse has exactly two keys when no release is advertised', async (t) => {
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const request = createValidCheckInRequest();
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);
  const bodyKeys = Object.keys(result.body).sort();
  assert.deepStrictEqual(bodyKeys, ['checkInIntervalSeconds', 'pendingCommandCount']);
});

test('Unit: CheckInResponse carries agentRelease as its only extra key', async (t) => {
  const table = new FakeTable();
  table.seedItem({
    ...deviceProfile('test-device-id'),
    deviceId: 'test-device-id',
    platform: 'windows',
    agentVersion: '1.2.0',
  });
  table.seedItem({
    ...agentRelease('windows-amd64'),
    platform: 'windows-amd64',
    version: '1.3.0',
    url: 'https://releases.example.com/mdmagent/1.3.0/windows-amd64/mdmagent.exe',
    sha256: 'a'.repeat(64),
    publishedAt: '2026-10-02T12:00:00Z',
  });

  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const result = await handler(createValidCheckInRequest());

  assert.strictEqual(result.statusCode, 200);
  const bodyKeys = Object.keys(result.body).sort();
  assert.deepStrictEqual(bodyKeys, ['agentRelease', 'checkInIntervalSeconds', 'pendingCommandCount']);
  assert.deepStrictEqual(result.body.agentRelease, {
    version: '1.3.0',
    url: 'https://releases.example.com/mdmagent/1.3.0/windows-amd64/mdmagent.exe',
    sha256: 'a'.repeat(64),
  });
});

test('Unit: Authentication failure prevents storage', async (t) => {
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: async () => ({ ok: false, status: 401, body: { error: 'unauthorized' } }),
  });

  const request = createValidCheckInRequest();
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 401);
  // No put or update operations
  const calls = table.recordedOperations();
  assert.ok(!calls.includes('put') && !calls.includes('update'), 'No storage on auth failure');
});

test('Unit: gsi1pk and gsi1sk are updated', async (t) => {
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const request = createValidCheckInRequest();
  const result = await handler(request);

  const updateCall = table.recordedProfileUpdate();
  assert.ok(updateCall);
  const values = updateCall.fields.ExpressionAttributeValues;
  assert.ok(':gsi1pk' in values, 'gsi1pk should be in update');
  assert.ok(':gsi1sk' in values, 'gsi1sk should be in update');
});

test('Unit: Pending commands query uses pagination cursor', async (t) => {
  const table = new FakeTable();
  table.seedQueryResponses([
    {
      items: [{ pk: 'DEVICE#test-device-id', sk: 'CMD#cmd1', status: 'pending' }],
      cursor: 'next-page',
    },
    {
      items: [{ pk: 'DEVICE#test-device-id', sk: 'CMD#cmd2', status: 'pending' }],
      cursor: null,
    },
  ]);

  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const request = createValidCheckInRequest();
  const result = await handler(request);

  const queryCalls = table.recordedQueryCalls();
  assert.strictEqual(queryCalls.length, 2, 'Should make two query calls for pagination');
  assert.strictEqual(queryCalls[1].request.cursor, 'next-page', 'Second query should use cursor from first');
});

// ============================================================================
// TASK-022: Agent Release Check-in Scenarios
// ============================================================================

test('Scenario: Check-in advertises an update', async (t) => {
  // Given the device profile has platform "windows" and agentVersion "1.2.0"
  // And the check-in body has inventory.os.architecture "x86_64"
  // And AGENTRELEASE/windows-amd64 holds version 1.3.0
  const table = new FakeTable();
  table.seedItem({
    ...deviceProfile('test-device-id'),
    deviceId: 'test-device-id',
    platform: 'windows',
    agentVersion: '1.2.0',
  });
  table.seedItem({
    ...agentRelease('windows-amd64'),
    platform: 'windows-amd64',
    version: '1.3.0',
    url: 'https://releases.example.com/mdmagent.exe',
    sha256: 'a'.repeat(64),
  });

  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  // When the device checks in
  const result = await handler(createValidCheckInRequest());

  // Then the body keys are exactly checkInIntervalSeconds, pendingCommandCount and agentRelease
  assert.strictEqual(result.statusCode, 200);
  const bodyKeys = Object.keys(result.body).sort();
  assert.deepStrictEqual(bodyKeys, ['agentRelease', 'checkInIntervalSeconds', 'pendingCommandCount']);

  // And agentRelease has version 1.3.0 with the stored url and sha256
  assert.strictEqual(result.body.agentRelease.version, '1.3.0');
  assert.strictEqual(result.body.agentRelease.url, 'https://releases.example.com/mdmagent.exe');
  assert.strictEqual(result.body.agentRelease.sha256, 'a'.repeat(64));
});

test('Scenario: Posted agent version wins and refreshes the profile', async (t) => {
  // Given the device profile agentVersion is "1.2.0" and AGENTRELEASE/windows-amd64 holds 1.3.0
  const table = new FakeTable();
  table.seedItem({
    ...deviceProfile('test-device-id'),
    deviceId: 'test-device-id',
    platform: 'windows',
    agentVersion: '1.2.0',
  });
  table.seedItem({
    ...agentRelease('windows-amd64'),
    version: '1.3.0',
    url: 'https://releases.example.com/mdmagent.exe',
    sha256: 'a'.repeat(64),
  });

  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  // When the device checks in posting agentVersion "1.3.0"
  const result = await handler(createValidCheckInRequest({
    agentVersion: '1.3.0',
  }));

  // Then the body has no agentRelease key
  assert.strictEqual(result.statusCode, 200);
  const bodyKeys = Object.keys(result.body).sort();
  assert.deepStrictEqual(bodyKeys, ['checkInIntervalSeconds', 'pendingCommandCount']);

  // And the device profile agentVersion is "1.3.0"
  const profileUpdate = table.recordedProfileUpdate();
  assert(profileUpdate);
  assert.strictEqual(
    profileUpdate.fields.ExpressionAttributeValues[':agentVersion'],
    '1.3.0',
  );
});

test('Scenario: No update when versions match', async (t) => {
  // Given the device profile agentVersion is 1.3.0 and AGENTRELEASE/windows-amd64 holds 1.3.0
  const table = new FakeTable();
  table.seedItem({
    ...deviceProfile('test-device-id'),
    deviceId: 'test-device-id',
    platform: 'windows',
    agentVersion: '1.3.0',
  });
  table.seedItem({
    ...agentRelease('windows-amd64'),
    version: '1.3.0',
    url: 'https://releases.example.com/mdmagent.exe',
    sha256: 'a'.repeat(64),
  });

  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  // When the device checks in
  const result = await handler(createValidCheckInRequest());

  // Then the body keys are exactly checkInIntervalSeconds and pendingCommandCount
  assert.strictEqual(result.statusCode, 200);
  const bodyKeys = Object.keys(result.body).sort();
  assert.deepStrictEqual(bodyKeys, ['checkInIntervalSeconds', 'pendingCommandCount']);
});

test('Scenario: No release stored for the platform', async (t) => {
  // Given no item exists at AGENTRELEASE/darwin-arm64
  const table = new FakeTable();
  table.seedItem({
    ...deviceProfile('test-device-id'),
    deviceId: 'test-device-id',
    platform: 'darwin',
    agentVersion: '1.2.0',
  });

  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  // When a darwin arm64 device checks in
  const result = await handler(createValidCheckInRequest({
    requestOverride: {
      params: { deviceId: 'test-device-id' },
    },
    inventory: {
      hardware: {
        manufacturer: 'Apple',
        model: 'MacBook Pro',
        serialNumber: 'FVFX0',
        cpu: 'Apple M1',
        ramBytes: 16000000000,
        diskBytes: 500000000000,
      },
      os: {
        name: 'macOS',
        version: '14.5',
        build: '23F79',
        architecture: 'aarch64',
      },
      software: [],
    },
  }));

  // Then the body has no agentRelease key
  assert.strictEqual(result.statusCode, 200);
  assert.ok(!result.body.agentRelease);
});

test('Scenario: Unmappable architecture advertises nothing', async (t) => {
  // Given inventory.os.architecture is "ppc64"
  const table = new FakeTable();
  table.seedItem({
    ...deviceProfile('test-device-id'),
    deviceId: 'test-device-id',
    platform: 'windows',
    agentVersion: '1.2.0',
  });
  table.seedItem({
    ...agentRelease('windows-amd64'),
    version: '1.3.0',
    url: 'https://releases.example.com/mdmagent.exe',
    sha256: 'a'.repeat(64),
  });

  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  // When the device checks in
  const result = await handler(createValidCheckInRequest({
    inventory: {
      hardware: {
        manufacturer: 'Dell',
        model: 'OptiPlex 7090',
        serialNumber: 'ABC123',
        cpu: 'Intel Core i7',
        ramBytes: 16000000000,
        diskBytes: 500000000000,
      },
      os: {
        name: 'Windows',
        version: '11',
        build: '22621',
        architecture: 'ppc64',
      },
      software: [],
    },
  }));

  // Then the body has no agentRelease key and no release item was read
  assert.strictEqual(result.statusCode, 200);
  assert.ok(!result.body.agentRelease);

  // Verify that the agentRelease was not queried
  const getCalls = table.calls.filter((c) => c.operation === 'get');
  const releaseGets = getCalls.filter((c) => c.key?.pk === 'AGENTRELEASE');
  assert.strictEqual(releaseGets.length, 0, 'Should not attempt to get release for unmappable architecture');
});
