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
  osDisplayName,
  MAX_DETAIL_STRING_LENGTH,
} = await import(`file://${join(__dirname, '../../dist/routes/checkin.js')}`);

const { DEFAULT_CHECKIN_INTERVAL_SECONDS } = await import(
  `file://${join(__dirname, '../../dist/config/intervals.js')}`
);

const { agentRelease, deviceProfile, deviceInventory, devicePosture, deviceCommand } = await import(
  `file://${join(__dirname, '../../dist/db/keys.js')}`
);

const { AGENT_BUILD_URL_TTL_SECONDS } = await import(`file://${join(__dirname, '../../dist/routes/checkin.js')}`);
const { agentBuildKey } = await import(`file://${join(__dirname, '../../dist/routes/downloads.js')}`);

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

/** A fake InstallerStore exposing only `agentBuild`/`presignGet`, recording every call. */
class FakeInstallers {
  constructor() {
    this.agentBuildCalls = [];
    this.presignCalls = [];
    this.builds = new Map();
    this.agentBuildError = null;
    this.presignError = null;
    this.presignedUrl = 'https://bucket.s3.example/presigned';
  }

  setBuild(key, build) {
    this.builds.set(key, build);
  }

  async agentBuild(key) {
    this.agentBuildCalls.push(key);
    if (this.agentBuildError) {
      throw this.agentBuildError;
    }
    return this.builds.has(key) ? this.builds.get(key) : null;
  }

  async presignGet(key, ttlSeconds) {
    this.presignCalls.push({ key, ttlSeconds });
    if (this.presignError) {
      throw this.presignError;
    }
    return this.presignedUrl;
  }
}

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

// ============================================================================
// TASK-046: device time zone on check-in (AC6, AC7)
// ============================================================================

test('Scenario: A valid reported zone is stored on the profile (AC6)', async (t) => {
  // When "dev-1" checks in with timeZone "Australia/Sydney"
  const table = new FakeTable();
  table.seedItem({ ...deviceProfile('test-device-id'), deviceId: 'test-device-id', platform: 'windows' });

  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const result = await handler(createValidCheckInRequest({ timeZone: 'Australia/Sydney' }));

  // Then the response status is 200
  assert.strictEqual(result.statusCode, 200);

  // And the profile of "dev-1" has timeZone "Australia/Sydney", written in the
  // same profile update as lastSeenAt
  const profileUpdate = table.recordedProfileUpdate();
  assert(profileUpdate, 'expected a profile update');
  assert.strictEqual(profileUpdate.fields.ExpressionAttributeValues[':timeZone'], 'Australia/Sydney');
  assert.ok(profileUpdate.fields.UpdateExpression.includes('timeZone = :timeZone'));
  assert.ok(profileUpdate.fields.UpdateExpression.includes('lastSeenAt = :lastSeenAt'));
  assert.ok(profileUpdate.fields.ExpressionAttributeValues[':lastSeenAt']);
});

test('Scenario Outline: An unusable reported zone is ignored (AC7)', async (t) => {
  const cases = [
    { label: 'absent', overrides: {} },
    { label: 'the number 10', overrides: { timeZone: 10 } },
    { label: '""', overrides: { timeZone: '' } },
    { label: 'a 65-character string', overrides: { timeZone: 'A'.repeat(65) } },
    { label: '"Mars/Olympus"', overrides: { timeZone: 'Mars/Olympus' } },
  ];

  for (const { label, overrides } of cases) {
    await t.test(label, async () => {
      // Given the profile of "dev-1" has timeZone "Europe/London"
      const table = new FakeTable();
      table.seedItem({
        ...deviceProfile('test-device-id'),
        deviceId: 'test-device-id',
        platform: 'windows',
        timeZone: 'Europe/London',
      });

      const handler = createCheckInHandler({
        table,
        pepper: randomHex(32),
        now: () => new Date('2026-10-02T12:00:00Z'),
        verifyDevice: createFakeVerifier('test-device-id', true),
      });

      // When "dev-1" checks in with the unusable timeZone
      const result = await handler(createValidCheckInRequest(overrides));

      // Then the response status is 200
      assert.strictEqual(result.statusCode, 200);
      assert.notStrictEqual(result.body.error, 'invalid_request');

      // And the stored profile timeZone is left as it was: no ':timeZone'
      // value is sent and the UpdateExpression carries no 'timeZone' clause.
      const profileUpdate = table.recordedProfileUpdate();
      assert(profileUpdate, 'expected a profile update');
      assert.strictEqual(profileUpdate.fields.ExpressionAttributeValues[':timeZone'], undefined);
      assert.ok(!profileUpdate.fields.UpdateExpression.includes('timeZone = :timeZone'));
    });
  }
});

// ============================================================================
// TASK-052: diagnostics for a rejected time zone (AC11, AC12)
// ============================================================================

test('Scenario Outline: A rejected zone is ignored and logged once (AC11)', async (t) => {
  const cases = [
    { label: '"Mars/Olympus"', value: 'Mars/Olympus', logged: 'Mars/Olympus' },
    { label: 'the number 10', value: 10, logged: 'number' },
    { label: '""', value: '', logged: '' },
    { label: 'a 65-character string', value: 'B'.repeat(65), logged: 'B'.repeat(64) },
  ];

  for (const { label, value, logged } of cases) {
    await t.test(label, async () => {
      // Given the profile of "dev-1" has timeZone "Europe/London"
      const table = new FakeTable();
      table.seedItem({
        ...deviceProfile('test-device-id'),
        deviceId: 'test-device-id',
        platform: 'windows',
        timeZone: 'Europe/London',
      });

      const handler = createCheckInHandler({
        table,
        pepper: randomHex(32),
        now: () => new Date('2026-10-02T12:00:00Z'),
        verifyDevice: createFakeVerifier('test-device-id', true),
      });

      // When "dev-1" checks in with timeZone <value>
      let result;
      const warnings = await captureWarnings(async () => {
        result = await handler(createValidCheckInRequest({ timeZone: value }));
      });

      // Then the response status is 200
      assert.strictEqual(result.statusCode, 200);

      // And the profile of "dev-1" still has timeZone "Europe/London"
      const profileUpdate = table.recordedProfileUpdate();
      assert(profileUpdate, 'expected a profile update');
      assert.strictEqual(profileUpdate.fields.ExpressionAttributeValues[':timeZone'], undefined);
      assert.ok(!profileUpdate.fields.UpdateExpression.includes('timeZone = :timeZone'));

      // And console.warn was called exactly once with msg "check-in time zone
      // ignored", deviceId "dev-1" and timeZone <logged>
      const ignored = warnings.filter((line) => {
        try {
          return JSON.parse(line).msg === 'check-in time zone ignored';
        } catch {
          return false;
        }
      });
      assert.strictEqual(ignored.length, 1, `expected exactly one ignore warning, got: ${JSON.stringify(warnings)}`);
      const parsed = JSON.parse(ignored[0]);
      assert.strictEqual(parsed.deviceId, 'test-device-id');
      assert.strictEqual(parsed.timeZone, logged);
    });
  }
});

test('Scenario Outline: A valid or absent zone writes no ignore warning (AC12)', async (t) => {
  const cases = [
    { label: '"Australia/Sydney"', overrides: { timeZone: 'Australia/Sydney' } },
    { label: 'absent', overrides: {} },
  ];

  for (const { label, overrides } of cases) {
    await t.test(label, async () => {
      const table = new FakeTable();
      table.seedItem({ ...deviceProfile('test-device-id'), deviceId: 'test-device-id', platform: 'windows' });

      const handler = createCheckInHandler({
        table,
        pepper: randomHex(32),
        now: () => new Date('2026-10-02T12:00:00Z'),
        verifyDevice: createFakeVerifier('test-device-id', true),
      });

      // When "dev-1" checks in with timeZone <value>
      let result;
      const warnings = await captureWarnings(async () => {
        result = await handler(createValidCheckInRequest(overrides));
      });

      // Then the response status is 200
      assert.strictEqual(result.statusCode, 200);

      // And no console.warn call has msg "check-in time zone ignored"
      const ignored = warnings.filter((line) => {
        try {
          return JSON.parse(line).msg === 'check-in time zone ignored';
        } catch {
          return false;
        }
      });
      assert.strictEqual(ignored.length, 0, `expected no ignore warning, got: ${JSON.stringify(warnings)}`);
    });
  }
});

test('Edge: a 400 for an unrelated reason never names timeZone as an offending field', async (t) => {
  // Given an otherwise-invalid body (missing posture) carrying an unusable timeZone
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const request = createValidCheckInRequest({ timeZone: 'Mars/Olympus', posture: undefined });
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 400);
  assert.ok(!result.body.fields.includes('timeZone'), 'fields should never name timeZone');
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

// ============================================================================
// TASK-048: self-update -- the published S3 agent build and the strictly-newer rule
// ============================================================================

test('Scenario: Check-in advertises the published S3 build with a presigned URL (AC10)', async (t) => {
  // Given a windows device posting agentVersion "1.3.0" and inventory.os.architecture "x86_64"
  const table = new FakeTable();
  table.seedItem({
    ...deviceProfile('test-device-id'),
    deviceId: 'test-device-id',
    platform: 'windows',
  });
  // And no AGENTRELEASE/windows-amd64 item exists
  // And agentBuild("agent/windows-amd64/mdmagent.exe") returns {version:"1.4.0", sha256:"c..c"}
  const installers = new FakeInstallers();
  installers.setBuild(agentBuildKey('windows-amd64'), { version: '1.4.0', sha256: 'c'.repeat(64) });
  // And presignGet returns "https://bucket.s3.example/presigned"

  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
    installers,
  });

  // When the device checks in
  const result = await handler(createValidCheckInRequest({ agentVersion: '1.3.0' }));

  assert.strictEqual(result.statusCode, 200);
  // Then presignGet was called with ("agent/windows-amd64/mdmagent.exe", 900)
  assert.strictEqual(installers.presignCalls.length, 1);
  assert.deepStrictEqual(installers.presignCalls[0], {
    key: 'agent/windows-amd64/mdmagent.exe',
    ttlSeconds: 900,
  });
  assert.strictEqual(AGENT_BUILD_URL_TTL_SECONDS, 900);

  // And agentRelease is {version:"1.4.0", url:"https://bucket.s3.example/presigned", sha256:"c..c"}
  assert.deepStrictEqual(result.body.agentRelease, {
    version: '1.4.0',
    url: 'https://bucket.s3.example/presigned',
    sha256: 'c'.repeat(64),
  });
});

test('Scenario: A higher manual release record wins over the S3 build (AC11)', async (t) => {
  // Given AGENTRELEASE/windows-amd64 holds version 1.5.0 with url U and sha256 S
  const table = new FakeTable();
  table.seedItem({
    ...deviceProfile('test-device-id'),
    deviceId: 'test-device-id',
    platform: 'windows',
  });
  table.seedItem({
    ...agentRelease('windows-amd64'),
    version: '1.5.0',
    url: 'https://releases.example.com/1.5.0',
    sha256: 'd'.repeat(64),
  });
  // And the S3 build for windows-amd64 is 1.4.0
  const installers = new FakeInstallers();
  installers.setBuild(agentBuildKey('windows-amd64'), { version: '1.4.0', sha256: 'c'.repeat(64) });

  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
    installers,
  });

  // And the device posts agentVersion "1.3.0"
  // When the device checks in
  const result = await handler(createValidCheckInRequest({ agentVersion: '1.3.0' }));

  // Then agentRelease is {version:"1.5.0", url:U, sha256:S} and presignGet was not called
  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body.agentRelease, {
    version: '1.5.0',
    url: 'https://releases.example.com/1.5.0',
    sha256: 'd'.repeat(64),
  });
  assert.strictEqual(installers.presignCalls.length, 0);
});

test('Scenario: The S3 build wins a tie with the manual record (AC11 edge)', async (t) => {
  // Given AGENTRELEASE/windows-amd64 and the S3 build both hold version 1.4.0
  const table = new FakeTable();
  table.seedItem({
    ...deviceProfile('test-device-id'),
    deviceId: 'test-device-id',
    platform: 'windows',
  });
  table.seedItem({
    ...agentRelease('windows-amd64'),
    version: '1.4.0',
    url: 'https://releases.example.com/record-1.4.0',
    sha256: 'e'.repeat(64),
  });
  const installers = new FakeInstallers();
  installers.setBuild(agentBuildKey('windows-amd64'), { version: '1.4.0', sha256: 'c'.repeat(64) });

  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
    installers,
  });

  // And the device posts agentVersion "1.3.0"
  // When the device checks in
  const result = await handler(createValidCheckInRequest({ agentVersion: '1.3.0' }));

  // Then agentRelease.url is the presigned URL and agentRelease.sha256 is the S3 metadata sha256
  assert.strictEqual(result.body.agentRelease.version, '1.4.0');
  assert.strictEqual(result.body.agentRelease.url, installers.presignedUrl);
  assert.strictEqual(result.body.agentRelease.sha256, 'c'.repeat(64));
  assert.strictEqual(installers.presignCalls.length, 1);
});

// ----------------------------------------------------------------------------
// AC12: Only a strictly newer build is advertised
// ----------------------------------------------------------------------------
// TASK-061/AC15: a Windows device below MIN_WINDOWS_SELF_UPDATE_VERSION
// (1.0.8) is never advertised an update, however new the candidate is. The
// two rows that used to exercise "device reports an unusable version" on
// windows-amd64 now run on darwin-amd64 instead (darwin is never gated, at
// any version -- AC16), so they still test the strictly-newer rule in
// isolation; AC15's own gating is covered by the scenarios below.
const strictlyNewerExamples = [
  { candidate: '1.9.0', device: '1.10.0', platform: 'windows', advertised: false },
  { candidate: '1.3.0', device: '1.3.0', platform: 'windows', advertised: false },
  { candidate: '1.0.0', device: '0.0.0-dev', platform: 'darwin', advertised: true },
  { candidate: '1.0.0', device: undefined, platform: 'darwin', advertised: true },
];

for (const { candidate, device, platform, advertised } of strictlyNewerExamples) {
  test(`Scenario Outline: Only a strictly newer build is advertised (candidate ${candidate}, device ${device ?? '(none at all)'}, platform ${platform})`, async (t) => {
    // Given the selected candidate version is "<candidate>"
    const table = new FakeTable();
    table.seedItem({
      ...deviceProfile('test-device-id'),
      deviceId: 'test-device-id',
      platform,
    });
    const installers = new FakeInstallers();
    installers.setBuild(agentBuildKey(`${platform}-amd64`), { version: candidate, sha256: 'f'.repeat(64) });

    const handler = createCheckInHandler({
      table,
      pepper: randomHex(32),
      now: () => new Date('2026-10-02T12:00:00Z'),
      verifyDevice: createFakeVerifier('test-device-id', true),
      installers,
    });

    // And the device's current version is "<device>" (posted agentVersion, or none at all)
    const overrides = device === undefined ? {} : { agentVersion: device };
    // When the device checks in
    const result = await handler(createValidCheckInRequest(overrides));

    assert.strictEqual(result.statusCode, 200);
    if (advertised) {
      // Then the response carries agentRelease 1.0.0
      assert.ok(result.body.agentRelease, 'expected an agentRelease');
      assert.strictEqual(result.body.agentRelease.version, candidate);
    } else {
      // Then the response has no agentRelease key
      assert.strictEqual('agentRelease' in result.body, false);
    }
  });
}

// ----------------------------------------------------------------------------
// TASK-061 AC15/AC16: a Windows device below MIN_WINDOWS_SELF_UPDATE_VERSION
// (1.0.8) restarts itself with the broken sc.exe stop/start sequence when it
// applies a self-update, which leaves the service stopped; the backend stops
// advertising a build to it until it is reinstalled from a fixed MSI. macOS
// is never gated, at any version.
// ----------------------------------------------------------------------------

test('Scenario: An old Windows agent is not advertised an update (AC15)', async (t) => {
  // Given a windows-amd64 device whose check-in reports agentVersion "1.0.7"
  const table = new FakeTable();
  table.seedItem({
    ...deviceProfile('test-device-id'),
    deviceId: 'test-device-id',
    platform: 'windows',
  });
  // And a published build "1.0.9" for windows-amd64
  const installers = new FakeInstallers();
  installers.setBuild(agentBuildKey('windows-amd64'), { version: '1.0.9', sha256: 'f'.repeat(64) });

  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
    installers,
  });

  // A device already on the minimum version gets the same response shape,
  // minus agentRelease, so every other field can be compared against it.
  const ungatedResult = await handler(createValidCheckInRequest({ agentVersion: '1.0.8' }));

  // When the device checks in
  const result = await handler(createValidCheckInRequest({ agentVersion: '1.0.7' }));

  // Then the response status is 200
  assert.strictEqual(result.statusCode, 200);
  // And the response has no agentRelease
  assert.strictEqual('agentRelease' in result.body, false);
  // And every other response field equals what it would be without the gate
  const { agentRelease: _gatedRelease, ...gatedRest } = result.body;
  const { agentRelease: _ungatedRelease, ...ungatedRest } = ungatedResult.body;
  assert.deepStrictEqual(gatedRest, ungatedRest);
});

const ac15EdgeExamples = [
  { reported: undefined, profileVersion: undefined },
  { reported: 'garbage', profileVersion: undefined },
  { reported: undefined, profileVersion: '1.0.6' },
];

for (const { reported, profileVersion } of ac15EdgeExamples) {
  test(`Scenario Outline: Windows agents with no usable version are gated (reported ${reported ?? '(absent)'}, profile ${profileVersion ?? '(absent)'})`, async (t) => {
    // Given a windows-amd64 device reporting agentVersion <reported> and a
    // profile agentVersion <profile>
    const table = new FakeTable();
    table.seedItem({
      ...deviceProfile('test-device-id'),
      deviceId: 'test-device-id',
      platform: 'windows',
      ...(profileVersion !== undefined ? { agentVersion: profileVersion } : {}),
    });
    // And a published build "1.0.9"
    const installers = new FakeInstallers();
    installers.setBuild(agentBuildKey('windows-amd64'), { version: '1.0.9', sha256: 'f'.repeat(64) });

    const handler = createCheckInHandler({
      table,
      pepper: randomHex(32),
      now: () => new Date('2026-10-02T12:00:00Z'),
      verifyDevice: createFakeVerifier('test-device-id', true),
      installers,
    });

    const overrides = reported !== undefined ? { agentVersion: reported } : {};
    // When the device checks in
    const result = await handler(createValidCheckInRequest(overrides));

    // Then the response has no agentRelease key
    assert.strictEqual(result.statusCode, 200);
    assert.strictEqual('agentRelease' in result.body, false);
  });
}

const ac16Examples = [
  { platform: 'windows', version: '1.0.8' },
  { platform: 'darwin', version: '1.0.6' },
];

for (const { platform, version } of ac16Examples) {
  test(`Scenario Outline: Fixed Windows agents and all macOS agents are advertised as before (platform ${platform}, version ${version})`, async (t) => {
    // Given a <platform>-amd64 device reporting agentVersion "<version>"
    const table = new FakeTable();
    table.seedItem({
      ...deviceProfile('test-device-id'),
      deviceId: 'test-device-id',
      platform,
    });
    // And a published build "1.0.9" for <platform>-amd64
    const installers = new FakeInstallers();
    installers.setBuild(agentBuildKey(`${platform}-amd64`), { version: '1.0.9', sha256: 'f'.repeat(64) });

    const handler = createCheckInHandler({
      table,
      pepper: randomHex(32),
      now: () => new Date('2026-10-02T12:00:00Z'),
      verifyDevice: createFakeVerifier('test-device-id', true),
      installers,
    });

    // When the device checks in
    const result = await handler(createValidCheckInRequest({ agentVersion: version }));

    // Then the response agentRelease version is "1.0.9"
    assert.strictEqual(result.statusCode, 200);
    assert.ok(result.body.agentRelease, 'expected an agentRelease');
    assert.strictEqual(result.body.agentRelease.version, '1.0.9');
  });
}

// ----------------------------------------------------------------------------
// AC13: an S3 lookup or presign failure never fails the check-in
// ----------------------------------------------------------------------------
test('Scenario: S3 lookup failure never fails the check-in (AC13)', async (t) => {
  // Given agentBuild throws "network down"
  const table = new FakeTable();
  table.seedItem({
    ...deviceProfile('test-device-id'),
    deviceId: 'test-device-id',
    platform: 'windows',
  });
  // And AGENTRELEASE/windows-amd64 holds 1.4.0 and the device posts "1.3.0"
  table.seedItem({
    ...agentRelease('windows-amd64'),
    version: '1.4.0',
    url: 'https://releases.example.com/1.4.0',
    sha256: 'a'.repeat(64),
  });
  const installers = new FakeInstallers();
  installers.agentBuildError = new Error('network down');

  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
    installers,
  });

  let result;
  // When the device checks in
  const warnings = await captureWarnings(async () => {
    result = await handler(createValidCheckInRequest({ agentVersion: '1.3.0' }));
  });

  // Then the status is 200 and agentRelease is the AGENTRELEASE record
  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body.agentRelease, {
    version: '1.4.0',
    url: 'https://releases.example.com/1.4.0',
    sha256: 'a'.repeat(64),
  });

  // And the inventory, posture and profile items were written
  assert.ok(table.recordedInventoryPut());
  assert.ok(table.recordedPosturePut());
  assert.ok(table.recordedProfileUpdate());

  // And exactly one console.warn line has msg "agent build lookup failed" and the deviceId
  assert.strictEqual(warnings.length, 1);
  const parsed = JSON.parse(warnings[0]);
  assert.strictEqual(parsed.msg, 'agent build lookup failed');
  assert.strictEqual(parsed.deviceId, 'test-device-id');
});

test('Scenario: Presign failure falls back without the S3 build (AC13)', async (t) => {
  // Given the S3 build is 1.4.0, presignGet throws and no AGENTRELEASE item exists
  const table = new FakeTable();
  table.seedItem({
    ...deviceProfile('test-device-id'),
    deviceId: 'test-device-id',
    platform: 'windows',
  });
  const installers = new FakeInstallers();
  installers.setBuild(agentBuildKey('windows-amd64'), { version: '1.4.0', sha256: 'c'.repeat(64) });
  installers.presignError = new Error('presign failed');

  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
    installers,
  });

  let result;
  // When the device checks in
  const warnings = await captureWarnings(async () => {
    result = await handler(createValidCheckInRequest({ agentVersion: '1.3.0' }));
  });

  // Then the status is 200, the body has no agentRelease key
  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual('agentRelease' in result.body, false);

  // and exactly one "agent build lookup failed" warning was logged
  assert.strictEqual(warnings.length, 1);
  const parsed = JSON.parse(warnings[0]);
  assert.strictEqual(parsed.msg, 'agent build lookup failed');
  assert.strictEqual(parsed.deviceId, 'test-device-id');
});

// ----------------------------------------------------------------------------
// AC14: no installer store, or an unmappable architecture
// ----------------------------------------------------------------------------
test('Scenario: No installer store keeps the manual-record behaviour (AC14)', async (t) => {
  // Given the check-in route is configured without installers
  const table = new FakeTable();
  table.seedItem({
    ...deviceProfile('test-device-id'),
    deviceId: 'test-device-id',
    platform: 'windows',
  });
  // And AGENTRELEASE/windows-amd64 holds 1.4.0 and the device posts "1.3.0"
  table.seedItem({
    ...agentRelease('windows-amd64'),
    version: '1.4.0',
    url: 'https://releases.example.com/1.4.0',
    sha256: 'a'.repeat(64),
  });

  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
    // no installers field at all
  });

  // When the device checks in
  const result = await handler(createValidCheckInRequest({ agentVersion: '1.3.0' }));

  // Then agentRelease is the AGENTRELEASE record and no S3 read was made
  assert.deepStrictEqual(result.body.agentRelease, {
    version: '1.4.0',
    url: 'https://releases.example.com/1.4.0',
    sha256: 'a'.repeat(64),
  });
});

test('Scenario: Unmappable architecture reads nothing, even with installers configured (AC14 edge)', async (t) => {
  // Given inventory.os.architecture is "ppc64"
  const table = new FakeTable();
  table.seedItem({
    ...deviceProfile('test-device-id'),
    deviceId: 'test-device-id',
    platform: 'windows',
  });
  table.seedItem({
    ...agentRelease('windows-amd64'),
    version: '1.4.0',
    url: 'https://releases.example.com/1.4.0',
    sha256: 'a'.repeat(64),
  });
  const installers = new FakeInstallers();
  installers.setBuild(agentBuildKey('windows-amd64'), { version: '1.4.0', sha256: 'c'.repeat(64) });

  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
    installers,
  });

  // When the device checks in
  const result = await handler(createValidCheckInRequest({
    agentVersion: '1.3.0',
    inventory: {
      hardware: {
        manufacturer: 'Dell',
        model: 'OptiPlex 7090',
        serialNumber: 'ABC123',
        cpu: 'Intel Core i7',
        ramBytes: 16000000000,
        diskBytes: 500000000000,
      },
      os: { name: 'Windows', version: '11', build: '22621', architecture: 'ppc64' },
      software: [],
    },
  }));

  // Then agentBuild and presignGet were not called, no AGENTRELEASE item was read
  // and the body has no agentRelease key
  assert.strictEqual(installers.agentBuildCalls.length, 0);
  assert.strictEqual(installers.presignCalls.length, 0);
  const releaseGets = table.calls.filter((c) => c.operation === 'get' && c.key?.pk === 'AGENTRELEASE');
  assert.strictEqual(releaseGets.length, 0);
  assert.strictEqual('agentRelease' in result.body, false);
});

// ============================================================================
// TASK-038: Check-in writes INVENTORY with gsi1 attributes (AC2)
// ============================================================================

test('Scenario: Accepted check-in writes INVENTORY item with gsi1pk and gsi1sk (AC2)', async (t) => {
  // Given an authenticated device
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('dev-7', true),
  });

  // When it posts a valid check-in with 3 software entries
  const request = createValidCheckInRequest({
    requestOverride: { params: { deviceId: 'dev-7' }, headers: { 'x-mdm-device-id': 'dev-7' } },
    inventory: {
      hardware: { manufacturer: 'Dell', model: 'OptiPlex', serialNumber: 'SN1' },
      os: { name: 'Windows', version: '11' },
      software: [
        { name: 'App1', version: '1.0' },
        { name: 'App2', version: '2.0' },
        { name: 'App3', version: '3.0' },
      ],
    },
  });
  const result = await handler(request);

  // Then the response is 200
  assert.strictEqual(result.statusCode, 200);

  // And the INVENTORY item was written with gsi1pk and gsi1sk
  const inventoryItem = table.recordedInventoryPut();
  assert.ok(inventoryItem, 'INVENTORY item should be written');
  assert.strictEqual(inventoryItem.gsi1pk, 'INVENTORY', 'gsi1pk should be INVENTORY');
  assert.strictEqual(inventoryItem.gsi1sk, 'dev-7', 'gsi1sk should be deviceId');
  assert.strictEqual(Array.isArray(inventoryItem.software), true, 'should have software array');
  assert.strictEqual(inventoryItem.software.length, 3, 'should have 3 software entries');
});

test('Scenario: Rejected check-in (empty version) returns 400 and writes nothing (AC2, failure)', async (t) => {
  // Given an authenticated device
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier('dev-7', true),
  });

  // When it posts a check-in with empty version in software[0]
  const request = createValidCheckInRequest({
    requestOverride: { params: { deviceId: 'dev-7' }, headers: { 'x-mdm-device-id': 'dev-7' } },
    inventory: {
      hardware: { manufacturer: 'Dell', model: 'OptiPlex', serialNumber: 'SN1' },
      os: { name: 'Windows', version: '11' },
      software: [
        { name: 'App1', version: '' },
      ],
    },
  });
  const result = await handler(request);

  // Then the response is 400
  assert.strictEqual(result.statusCode, 400);
  const body = typeof result.body === 'string' ? JSON.parse(result.body) : result.body;
  assert.strictEqual(body.error, 'invalid_request');

  // And no INVENTORY item was written
  const inventoryItem = table.recordedInventoryPut();
  assert.strictEqual(inventoryItem, undefined, 'INVENTORY item should not be written on rejection');
});

// ============================================================================
// TASK-059: full Windows device details + friendly OS display
// E2E cucumber-style tests (AC15-AC19) and osDisplayName unit tests (AC18).
// All database calls are mocked through FakeTable; no network, no real DB.
// ============================================================================

/** A full device-details inventory, matching the golden contract fixture. */
function fullDeviceDetailsInventory(overrides = {}) {
  return {
    hardware: {
      manufacturer: 'LENOVO',
      model: '20XW004PUS',
      serialNumber: 'PF2K8R3C',
      cpu: '11th Gen Intel(R) Core(TM) i7-1185G7',
      ramBytes: 34072571904,
      diskBytes: 1023303839744,
      systemFamily: 'ThinkPad X1 Carbon Gen 9',
      systemSku: 'LENOVO_MT_20XW',
      cpuCores: 4,
      cpuLogicalProcessors: 8,
    },
    os: {
      name: 'Microsoft Windows 11 Enterprise',
      version: '10.0.22631',
      build: '22631',
      architecture: 'amd64',
      edition: 'Enterprise',
      displayVersion: '23H2',
      ubr: 4317,
      installDate: '2024-03-12T02:18:44Z',
      lastBootAt: '2026-10-10T21:04:37Z',
      locale: 'en-AU',
    },
    software: [],
    firmware: {
      type: 'uefi',
      biosVersion: 'N32ET91W (1.67 )',
      biosReleaseDate: '2024-06-20T00:00:00Z',
      secureBootEnabled: true,
      tpmPresent: true,
      tpmReady: true,
      tpmVersion: '2.0',
    },
    disks: [{ deviceId: 'C:', fileSystem: 'NTFS', sizeBytes: 1023303839744, freeBytes: 412876075008 }],
    physicalDisks: [{ model: 'SAMSUNG MZVL21T0HCLR', mediaType: 'ssd', sizeBytes: 1024209543168 }],
    network: [
      {
        description: 'Intel(R) Wi-Fi 6 AX201',
        macAddress: 'A4:C3:F0:85:7B:21',
        ipv4: ['192.168.1.47'],
        ipv6: ['fe80::8d2c:41a7:3b1e:9f02'],
        dhcpEnabled: true,
        dnsServers: ['192.168.1.1'],
        gateways: ['192.168.1.1'],
      },
    ],
    join: {
      azureAdJoined: true,
      domainJoined: true,
      domain: 'contoso.local',
      tenantName: 'OfficeHQ',
      tenantId: '3e1c9a7b-2f4d-4b8e-9c6a-1d5f8e2b4c70',
      entraDeviceId: '5b7f2d1e-8c4a-4e9b-a1d3-6f0e2c9b7a45',
    },
    ...overrides,
  };
}

test('Scenario: Backend stores the full device details (AC15)', async (t) => {
  // Given a signed check-in with the device-details fixture body
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-11T08:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  // When it is posted to the check-in route
  const result = await handler(createValidCheckInRequest({ inventory: fullDeviceDetailsInventory() }));

  // Then the response is 200
  assert.strictEqual(result.statusCode, 200, JSON.stringify(result.body));

  // And the stored INVENTORY item carries os.edition, os.displayVersion,
  // os.ubr, hardware.systemFamily, firmware, disks, physicalDisks, network
  // and join as posted
  const item = table.recordedInventoryPut();
  assert.ok(item, 'expected an INVENTORY item to be written');
  assert.strictEqual(item.os.edition, 'Enterprise');
  assert.strictEqual(item.os.displayVersion, '23H2');
  assert.strictEqual(item.os.ubr, 4317);
  assert.strictEqual(item.hardware.systemFamily, 'ThinkPad X1 Carbon Gen 9');
  assert.deepStrictEqual(item.firmware, {
    type: 'uefi',
    biosVersion: 'N32ET91W (1.67 )',
    biosReleaseDate: '2024-06-20T00:00:00Z',
    secureBootEnabled: true,
    tpmPresent: true,
    tpmReady: true,
    tpmVersion: '2.0',
  });
  assert.strictEqual(item.disks.length, 1);
  assert.strictEqual(item.disks[0].deviceId, 'C:');
  assert.strictEqual(item.disks[0].sizeBytes, 1023303839744);
  assert.strictEqual(item.physicalDisks.length, 1);
  assert.strictEqual(item.physicalDisks[0].mediaType, 'ssd');
  assert.strictEqual(item.network.length, 1);
  assert.strictEqual(item.network[0].macAddress, 'A4:C3:F0:85:7B:21');
  assert.deepStrictEqual(item.network[0].ipv4, ['192.168.1.47']);
  assert.deepStrictEqual(item.join, {
    azureAdJoined: true,
    domainJoined: true,
    domain: 'contoso.local',
    tenantName: 'OfficeHQ',
    tenantId: '3e1c9a7b-2f4d-4b8e-9c6a-1d5f8e2b4c70',
    entraDeviceId: '5b7f2d1e-8c4a-4e9b-a1d3-6f0e2c9b7a45',
  });
});

test('Scenario: Old agent check-in keeps working (AC16)', async (t) => {
  // Given a check-in whose inventory has only the existing hardware and os fields
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-11T08:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const oldHardware = { manufacturer: 'Dell', model: 'OptiPlex 7090', serialNumber: 'ABC123', cpu: 'Intel Core i7', ramBytes: 16000000000, diskBytes: 500000000000 };
  const oldOS = { name: 'Windows', version: '11', build: '22621', architecture: 'x86_64' };

  // When it is posted
  const result = await handler(createValidCheckInRequest({
    inventory: { hardware: oldHardware, os: oldOS, software: [] },
  }));

  // Then the response is 200
  assert.strictEqual(result.statusCode, 200, JSON.stringify(result.body));

  // And the stored item has no firmware, disks, physicalDisks, network or join attribute
  const item = table.recordedInventoryPut();
  assert.ok(item);
  for (const key of ['firmware', 'disks', 'physicalDisks', 'network', 'join']) {
    assert.ok(!(key in item), `stored item should not carry ${key}`);
  }
  // And the stored hardware and os equal the posted ones
  assert.deepStrictEqual(item.hardware, oldHardware);
  assert.deepStrictEqual(item.os, oldOS);
});

test('Scenario: Malformed device details never fail the check-in (AC17)', async (t) => {
  // Given a check-in with firmware.secureBootEnabled "yes", os.ubr -1,
  // firmware.type "efi", os.installDate "yesterday", disks as a string and
  // join as an array
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-11T08:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const inventory = fullDeviceDetailsInventory({
    os: { ...fullDeviceDetailsInventory().os, ubr: -1, installDate: 'yesterday' },
    firmware: { ...fullDeviceDetailsInventory().firmware, secureBootEnabled: 'yes', type: 'efi' },
    disks: 'not-an-array',
    join: ['not', 'an', 'object'],
  });

  // When it is posted
  const result = await handler(createValidCheckInRequest({ inventory }));

  // Then the response is 200 and no new field is named in any fields list
  assert.strictEqual(result.statusCode, 200, JSON.stringify(result.body));
  assert.strictEqual(result.body.fields, undefined);

  // And none of those values are stored
  const item = table.recordedInventoryPut();
  assert.ok(item);
  assert.strictEqual(item.os.ubr, undefined);
  assert.strictEqual(item.os.installDate, undefined);
  assert.ok(!('disks' in item));
  assert.ok(!('join' in item));
  // firmware.type "efi" and secureBootEnabled "yes" are both dropped, but
  // firmware still carries its other valid fields (biosVersion etc.).
  assert.strictEqual(item.firmware.type, undefined);
  assert.strictEqual(item.firmware.secureBootEnabled, undefined);
  assert.strictEqual(item.firmware.biosVersion, 'N32ET91W (1.67 )');
});

test('Scenario: Oversized device details are bounded (AC17)', async (t) => {
  // Given a check-in with a 300 character firmware.biosVersion, 20 network
  // adapters, 40 disks, 20 physicalDisks and an adapter with 30 ipv4 entries
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-11T08:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const longBiosVersion = 'V'.repeat(300);
  const disks = Array.from({ length: 40 }, (_, i) => ({ deviceId: `D${i}:`, sizeBytes: 1 }));
  const physicalDisks = Array.from({ length: 20 }, (_, i) => ({ model: `Disk${i}`, mediaType: 'ssd', sizeBytes: 1 }));
  const network = Array.from({ length: 20 }, (_, i) => ({
    description: `Adapter${i}`,
    macAddress: `AA:BB:CC:DD:EE:${String(i).padStart(2, '0')}`,
    ipv4: i === 0 ? Array.from({ length: 30 }, (_, j) => `10.0.0.${j}`) : [],
  }));

  const inventory = fullDeviceDetailsInventory({
    firmware: { ...fullDeviceDetailsInventory().firmware, biosVersion: longBiosVersion },
    disks,
    physicalDisks,
    network,
  });

  // When it is posted
  const result = await handler(createValidCheckInRequest({ inventory }));

  // Then the response is 200
  assert.strictEqual(result.statusCode, 200, JSON.stringify(result.body));

  // And the stored biosVersion is 256 characters
  const item = table.recordedInventoryPut();
  assert.ok(item);
  assert.strictEqual(item.firmware.biosVersion.length, MAX_DETAIL_STRING_LENGTH);
  assert.strictEqual(item.firmware.biosVersion, 'V'.repeat(256));

  // And 16 network entries, 32 disks, 16 physicalDisks and 16 ipv4 entries are stored
  assert.strictEqual(item.network.length, 16);
  assert.strictEqual(item.disks.length, 32);
  assert.strictEqual(item.physicalDisks.length, 16);
  assert.strictEqual(item.network[0].ipv4.length, 16);
});

test('Scenario: Fractional UBR is dropped (AC17)', async (t) => {
  // Given a check-in with os.ubr 1.5
  const table = new FakeTable();
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-11T08:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  const inventory = fullDeviceDetailsInventory({ os: { ...fullDeviceDetailsInventory().os, ubr: 1.5 } });

  // When it is posted
  const result = await handler(createValidCheckInRequest({ inventory }));

  // Then the response is 200 and os.ubr is not stored
  assert.strictEqual(result.statusCode, 200, JSON.stringify(result.body));
  const item = table.recordedInventoryPut();
  assert.ok(item);
  assert.strictEqual(item.os.ubr, undefined);
});

test('Scenario Outline: OS display name (AC18)', () => {
  const cases = [
    {
      os: { name: 'Microsoft Windows 11 Enterprise', version: '10.0.22631', build: '22631', displayVersion: '23H2', ubr: 4317 },
      display: 'Windows 11 Enterprise 23H2 (build 22631.4317)',
    },
    {
      os: { name: 'Microsoft Windows 11 Enterprise', build: '22631' },
      display: 'Windows 11 Enterprise (build 22631)',
    },
    {
      os: { name: 'Windows 10 Pro', build: '22631', displayVersion: '23H2', ubr: 4317 },
      display: 'Windows 11 Pro 23H2 (build 22631.4317)',
    },
    {
      os: { name: 'Windows 10 Pro', build: '19045', displayVersion: '22H2', ubr: 5011 },
      display: 'Windows 10 Pro 22H2 (build 19045.5011)',
    },
    {
      os: { name: 'Windows 11 Enterprise', build: '22631.4317', ubr: 4317 },
      display: 'Windows 11 Enterprise (build 22631.4317)',
    },
    {
      os: { name: 'macOS', version: '14.5', build: '23F79' },
      display: 'macOS 14.5 (build 23F79)',
    },
    { os: { name: '' }, display: null },
    { os: {}, display: null },
  ];

  for (const { os, display } of cases) {
    // Given inventory.os <os>
    // When osDisplayName is computed
    // Then the result is <display>
    assert.strictEqual(osDisplayName(os), display, `osDisplayName(${JSON.stringify(os)})`);
  }
});

test('Scenario: Check-in records the OS display name on the profile (AC19)', async (t) => {
  // Given a check-in whose inventory.os is the Windows 11 23H2 fixture
  const table = new FakeTable();
  table.seedItem({ ...deviceProfile('test-device-id'), deviceId: 'test-device-id', platform: 'windows' });
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-11T08:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  // When it is posted
  const result = await handler(createValidCheckInRequest({ inventory: fullDeviceDetailsInventory() }));
  assert.strictEqual(result.statusCode, 200, JSON.stringify(result.body));

  // Then the profile osDisplay is "Windows 11 Enterprise 23H2 (build 22631.4317)"
  const profileUpdate = table.recordedProfileUpdate();
  assert.ok(profileUpdate, 'expected a profile update');
  assert.strictEqual(profileUpdate.fields.ExpressionAttributeValues[':osDisplay'], 'Windows 11 Enterprise 23H2 (build 22631.4317)');
  assert.ok(profileUpdate.fields.UpdateExpression.includes('osDisplay = :osDisplay'));
});

test('Scenario: Missing OS name leaves the stored display name alone (AC19)', async (t) => {
  // Given a profile with osDisplay "Windows 11 Enterprise (build 22631)"
  const table = new FakeTable();
  table.seedItem({
    ...deviceProfile('test-device-id'),
    deviceId: 'test-device-id',
    platform: 'windows',
    osDisplay: 'Windows 11 Enterprise (build 22631)',
  });
  const handler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => new Date('2026-10-11T08:00:00Z'),
    verifyDevice: createFakeVerifier('test-device-id', true),
  });

  // And a check-in whose inventory.os.name is empty
  const inventory = fullDeviceDetailsInventory({ os: { ...fullDeviceDetailsInventory().os, name: '' } });

  // When it is posted
  const result = await handler(createValidCheckInRequest({ inventory }));

  // Then the response is 200
  assert.strictEqual(result.statusCode, 200, JSON.stringify(result.body));

  // And the profile osDisplay is still "Windows 11 Enterprise (build 22631)":
  // the profile update carries no osDisplay clause at all, so the stored
  // attribute is left untouched.
  const profileUpdate = table.recordedProfileUpdate();
  assert.ok(profileUpdate, 'expected a profile update');
  assert.strictEqual(profileUpdate.fields.ExpressionAttributeValues[':osDisplay'], undefined);
  assert.ok(!profileUpdate.fields.UpdateExpression.includes('osDisplay = :osDisplay'));
});
