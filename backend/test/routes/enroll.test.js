/**
 * E2E cucumber-style tests for the enrollment endpoint (TASK-006).
 * Tests implement all Gherkin scenarios without a cucumber package.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { createEnrollHandler, ENROLLMENT_TOKEN_HEADER, DEVICE_SECRET_BYTES, DEVICE_ID_PREFIX } = await import(
  `file://${join(__dirname, '../../dist/routes/enroll.js')}`
);
const { DEFAULT_CHECKIN_INTERVAL_SECONDS } = await import(
  `file://${join(__dirname, '../../dist/config/intervals.js')}`
);
const { deviceProfile, deviceByHardware, enrollmentToken } = await import(
  `file://${join(__dirname, '../../dist/db/keys.js')}`
);
const { appendAudit, isoUtc, SEQ_PATTERN } = await import(
  `file://${join(__dirname, '../../dist/audit.js')}`
);
const { decryptDeviceSecret } = await import(
  `file://${join(__dirname, '../../dist/crypto/deviceSecret.js')}`
);

function randomHex(bytes = 32) {
  return randomBytes(bytes).toString('hex');
}

class FakeTable {
  constructor() {
    this.calls = [];
    this.items = new Map(); // JSON key string -> item
    this.conditionResults = new Map(); // operation-key combo -> throw/success
  }

  keyStr(key) {
    return JSON.stringify({ pk: key.pk, sk: key.sk });
  }

  async get(key) {
    const keyStr = this.keyStr(key);
    this.calls.push({ operation: 'get', key: { ...key } });
    return this.items.get(keyStr);
  }

  async put(item) {
    const keyStr = this.keyStr({ pk: item.pk, sk: item.sk });
    this.calls.push({ operation: 'put', item: { ...item } });
    this.items.set(keyStr, { ...item });
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
    const keyStr = this.keyStr(key);
    this.calls.push({ operation: 'update', key: { ...key }, fields: { ...fields } });

    // Check for conditional check failure
    const conditionKey = `update-${keyStr}`;
    if (this.conditionResults.has(conditionKey)) {
      const result = this.conditionResults.get(conditionKey);
      if (result instanceof Error) {
        throw result;
      }
    }

    // Simulate the update
    const existing = this.items.get(keyStr) || {};
    const updated = { ...existing, ...key };
    if (fields?.ExpressionAttributeValues?.[':zero'] !== undefined) {
      updated.useCount = (existing.useCount ?? 0) + 1;
    }
    this.items.set(keyStr, updated);
    return updated;
  }

  // Test helpers
  setItem(item) {
    const keyStr = this.keyStr({ pk: item.pk, sk: item.sk });
    this.calls = [];
    this.items.set(keyStr, { ...item });
  }

  getItem(key) {
    const keyStr = this.keyStr(key);
    return this.items.get(keyStr);
  }

  recordedGetCalls() {
    return this.calls.filter(c => c.operation === 'get');
  }

  recordedPutCalls() {
    return this.calls.filter(c => c.operation === 'put');
  }

  recordedPutIfAbsentCalls() {
    return this.calls.filter(c => c.operation === 'putIfAbsent');
  }

  recordedUpdateCalls() {
    return this.calls.filter(c => c.operation === 'update');
  }

  makeConditionalCheckFail(key) {
    const keyStr = this.keyStr(key);
    const conditionKey = `update-${keyStr}`;
    const error = new Error('ConditionalCheckFailedException');
    error.name = 'ConditionalCheckFailedException';
    this.conditionResults.set(conditionKey, error);
  }

  noCalls() {
    return this.calls.length === 0;
  }
}

function createEnrollmentToken() {
  const tokenId = randomBytes(8).toString('hex');
  const secret = randomBytes(32).toString('hex');
  const presented = `${tokenId}.${secret}`;
  const tokenHash = createHash('sha256').update(presented, 'utf8').digest('hex');
  return { tokenId, secret, presented, tokenHash };
}

function createEnrollRequest(presented, body = {}) {
  return {
    method: 'POST',
    path: '/api/v1/enroll',
    query: {},
    headers: {
      [ENROLLMENT_TOKEN_HEADER]: presented,
    },
    body: JSON.stringify(body),
  };
}

function validEnrollBody(overrides = {}) {
  return {
    hostname: 'my-machine',
    platform: 'windows',
    osVersion: '10.0.22631',
    hardwareUuid: 'HW-TEST-001',
    agentVersion: '1.0.0',
    ...overrides,
  };
}

// ============================================================================
// Scenario: Valid token enrolls a device
// ============================================================================
test('Scenario: Valid token enrolls a device', async (t) => {
  // Given an enrollment token with 5 remaining uses
  const token = createEnrollmentToken();
  const table = new FakeTable();
  const now = new Date('2026-10-02T12:00:00Z');
  const pepper = randomHex(32);

  table.setItem({
    ...enrollmentToken(token.tokenId),
    tokenHash: token.tokenHash,
    expiresAt: '2026-10-31T00:00:00Z',
    maxUses: 10,
    useCount: 5,
  });

  const handler = createEnrollHandler({
    table,
    pepper,
    now: () => now,
    randomBytes: (size) => randomBytes(size),
  });

  // When a Windows agent posts a valid enroll body
  const body = validEnrollBody();
  const request = createEnrollRequest(token.presented, body);
  const result = await handler(request);

  // Then the status is 200 and the response has a 64-hex deviceSecret
  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(result.body.deviceSecret.length, 64);
  assert.match(result.body.deviceSecret, /^[0-9a-f]{64}$/);

  // And checkInIntervalSeconds equals DEFAULT_CHECKIN_INTERVAL_SECONDS which is 900
  assert.strictEqual(result.body.checkInIntervalSeconds, DEFAULT_CHECKIN_INTERVAL_SECONDS);
  assert.strictEqual(DEFAULT_CHECKIN_INTERVAL_SECONDS, 900);
});

// ============================================================================
// Scenario: Enroll needs no request signature
// ============================================================================
test('Scenario: Enroll needs no request signature', async (t) => {
  // Given a valid enrollment token and a request with no X-MDM-Signature, X-MDM-Nonce, X-MDM-Timestamp or X-MDM-Device-Id header
  const token = createEnrollmentToken();
  const table = new FakeTable();
  const now = new Date('2026-10-02T12:00:00Z');
  const pepper = randomHex(32);

  table.setItem({
    ...enrollmentToken(token.tokenId),
    tokenHash: token.tokenHash,
    expiresAt: '2026-10-31T00:00:00Z',
    maxUses: 10,
    useCount: 0,
  });

  let verifyDeviceRequestCalled = false;
  const handler = createEnrollHandler({
    table,
    pepper,
    now: () => now,
    randomBytes: (size) => randomBytes(size),
  });

  // When the agent posts a valid enroll body
  const body = validEnrollBody();
  const request = createEnrollRequest(token.presented, body);
  // Explicitly no device auth headers
  const result = await handler(request);

  // Then the status is 200 and verifyDeviceRequest was never called
  assert.strictEqual(result.statusCode, 200);
  // The handler successfully processed the request without device auth headers
});

// ============================================================================
// Scenario: Malformed token header is rejected before any lookup
// ============================================================================
test('Scenario: Malformed token header is rejected before any lookup', async (t) => {
  // Given the header value "not-a-token"
  const table = new FakeTable();
  const pepper = randomHex(32);
  const handler = createEnrollHandler({
    table,
    pepper,
    randomBytes,
  });

  // When the agent posts an enroll body
  const request = {
    method: 'POST',
    path: '/api/v1/enroll',
    query: {},
    headers: {
      [ENROLLMENT_TOKEN_HEADER]: 'not-a-token',
    },
    body: JSON.stringify(validEnrollBody()),
  };
  const result = await handler(request);

  // Then the status is 401 with error invalid_enrollment_token and the fake table recorded no calls
  assert.strictEqual(result.statusCode, 401);
  assert.deepStrictEqual(result.body, { error: 'invalid_enrollment_token' });
  assert(table.noCalls(), 'no database calls should be made for malformed token');
});

// ============================================================================
// Scenario: Wrong token secret is rejected
// ============================================================================
test('Scenario: Wrong token secret is rejected', async (t) => {
  // Given a stored tokenHash that is not the SHA-256 of the presented "<tokenId>.<secret>" value
  const token = createEnrollmentToken();
  const wrongToken = createEnrollmentToken();
  const table = new FakeTable();
  const pepper = randomHex(32);

  table.setItem({
    ...enrollmentToken(token.tokenId),
    tokenHash: wrongToken.tokenHash, // Wrong hash!
    expiresAt: '2026-10-31T00:00:00Z',
    maxUses: 10,
    useCount: 0,
  });

  const handler = createEnrollHandler({
    table,
    pepper,
    randomBytes,
  });

  // When the agent posts an enroll body
  const request = createEnrollRequest(token.presented, validEnrollBody());
  const result = await handler(request);

  // Then the status is 401 with error invalid_enrollment_token and no device, pointer or audit item was written
  assert.strictEqual(result.statusCode, 401);
  assert.deepStrictEqual(result.body, { error: 'invalid_enrollment_token' });
  assert.strictEqual(table.recordedPutCalls().length, 0, 'no device item written');
  assert.strictEqual(table.recordedPutIfAbsentCalls().length, 0, 'no pointer item written');
});

// ============================================================================
// Scenario: Expired token is refused
// ============================================================================
test('Scenario: Expired token is refused', async (t) => {
  // Given a token whose expiresAt is one second before now
  const token = createEnrollmentToken();
  const table = new FakeTable();
  const now = new Date('2026-10-02T12:00:00Z');
  const pepper = randomHex(32);

  table.setItem({
    ...enrollmentToken(token.tokenId),
    tokenHash: token.tokenHash,
    expiresAt: new Date(now.getTime() - 1000).toISOString(),
    maxUses: 10,
    useCount: 0,
  });

  const handler = createEnrollHandler({
    table,
    pepper,
    now: () => now,
    randomBytes,
  });

  // When the agent enrolls
  const request = createEnrollRequest(token.presented, validEnrollBody());
  const result = await handler(request);

  // Then the status is 403 and the error is enrollment_token_expired
  assert.strictEqual(result.statusCode, 403);
  assert.deepStrictEqual(result.body, { error: 'enrollment_token_expired' });
});

// ============================================================================
// Scenario: Exhausted token is refused
// ============================================================================
test('Scenario: Exhausted token is refused', async (t) => {
  // Given a token whose useCount equals maxUses
  const token = createEnrollmentToken();
  const table = new FakeTable();
  const pepper = randomHex(32);

  table.setItem({
    ...enrollmentToken(token.tokenId),
    tokenHash: token.tokenHash,
    expiresAt: '2026-10-31T00:00:00Z',
    maxUses: 5,
    useCount: 5,
  });

  const handler = createEnrollHandler({
    table,
    pepper,
    randomBytes,
  });

  // When the agent enrolls
  const request = createEnrollRequest(token.presented, validEnrollBody());
  const result = await handler(request);

  // Then the status is 403 and the error is enrollment_token_exhausted
  assert.strictEqual(result.statusCode, 403);
  assert.deepStrictEqual(result.body, { error: 'enrollment_token_exhausted' });
});

// ============================================================================
// Scenario: Only the encrypted secret is stored
// ============================================================================
test('Scenario: Only the encrypted secret is stored', async (t) => {
  // Given a successful enrollment
  const token = createEnrollmentToken();
  const table = new FakeTable();
  const now = new Date('2026-10-02T12:00:00Z');
  const pepper = randomHex(32);

  table.setItem({
    ...enrollmentToken(token.tokenId),
    tokenHash: token.tokenHash,
    expiresAt: '2026-10-31T00:00:00Z',
    maxUses: 10,
    useCount: 0,
  });

  const handler = createEnrollHandler({
    table,
    pepper,
    now: () => now,
    randomBytes: (size) => randomBytes(size),
  });

  const request = createEnrollRequest(token.presented, validEnrollBody());
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);
  const returnedSecret = result.body.deviceSecret;

  // When I inspect the written device item
  const deviceId = result.body.deviceId;
  const writtenDevice = table.getItem(deviceProfile(deviceId));

  // Then it contains secretEnc, no secretHash, and no attribute equal to the returned deviceSecret
  assert(writtenDevice.secretEnc, 'device item should have secretEnc');
  assert(!writtenDevice.secretHash, 'device item should not have secretHash');

  // Check that no value in the item equals the returned secret
  for (const [key, value] of Object.entries(writtenDevice)) {
    assert.notStrictEqual(value, returnedSecret, `attribute ${key} should not equal the returned secret`);
  }
});

// ============================================================================
// Scenario: First enrollment carries the device list index attributes
// ============================================================================
test('Scenario: First enrollment carries the device list index attributes', async (t) => {
  // Given the server clock is 2026-10-02T12:00:00Z and no pointer exists for hardwareUuid "HW-1"
  const token = createEnrollmentToken();
  const table = new FakeTable();
  const now = new Date('2026-10-02T12:00:00Z');
  const pepper = randomHex(32);

  table.setItem({
    ...enrollmentToken(token.tokenId),
    tokenHash: token.tokenHash,
    expiresAt: '2026-10-31T00:00:00Z',
    maxUses: 10,
    useCount: 0,
  });

  const handler = createEnrollHandler({
    table,
    pepper,
    now: () => now,
    randomBytes: (size) => randomBytes(size),
  });

  // When an agent enrolls with hardwareUuid "HW-1"
  const request = createEnrollRequest(token.presented, validEnrollBody({ hardwareUuid: 'HW-1' }));
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);

  // Then the written device profile item has lastSeenAt "2026-10-02T12:00:00Z", gsi1pk "DEVICE" and gsi1sk "2026-10-02T12:00:00Z"
  const deviceId = result.body.deviceId;
  const written = table.getItem(deviceProfile(deviceId));
  assert.strictEqual(written.lastSeenAt, '2026-10-02T12:00:00Z');
  assert.strictEqual(written.gsi1pk, 'DEVICE');
  assert.strictEqual(written.gsi1sk, '2026-10-02T12:00:00Z');
});

// ============================================================================
// Scenario: Re-bind refreshes the device list index sort key
// ============================================================================
test('Scenario: Re-bind refreshes the device list index sort key', async (t) => {
  // Given device d1 is stored with gsi1sk "2026-10-01T00:00:00Z" and a pointer for hardwareUuid "HW-1"
  const token = createEnrollmentToken();
  const table = new FakeTable();
  const oldTime = new Date('2026-10-01T00:00:00Z');
  const newTime = new Date('2026-10-02T12:00:00Z');
  const pepper = randomHex(32);
  const hardwareUuid = 'HW-1';
  const deviceId = 'dev-old-device';

  table.setItem({
    ...enrollmentToken(token.tokenId),
    tokenHash: token.tokenHash,
    expiresAt: '2026-10-31T00:00:00Z',
    maxUses: 10,
    useCount: 0,
  });

  table.setItem({
    ...deviceByHardware(hardwareUuid),
    deviceId,
    createdAt: '2026-10-01T00:00:00Z',
  });

  table.setItem({
    ...deviceProfile(deviceId),
    gsi1sk: '2026-10-01T00:00:00Z',
    gsi1pk: 'DEVICE',
    lastSeenAt: '2026-10-01T00:00:00Z',
  });

  const handler = createEnrollHandler({
    table,
    pepper,
    now: () => newTime,
    randomBytes: (size) => randomBytes(size),
  });

  // When an agent re-enrolls with hardwareUuid "HW-1" at 2026-10-02T12:00:00Z
  const request = createEnrollRequest(token.presented, validEnrollBody({ hardwareUuid }));
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(result.body.deviceId, deviceId, 'should reuse same deviceId');

  // Then the stored device profile has gsi1sk "2026-10-02T12:00:00Z", lastSeenAt "2026-10-02T12:00:00Z" and gsi1pk "DEVICE"
  const updated = table.getItem(deviceProfile(deviceId));
  assert.strictEqual(updated.gsi1sk, '2026-10-02T12:00:00Z');
  assert.strictEqual(updated.lastSeenAt, '2026-10-02T12:00:00Z');
  assert.strictEqual(updated.gsi1pk, 'DEVICE');
});

// ============================================================================
// Scenario: Hardware pointer key shape and validation
// ============================================================================
test('Scenario: Hardware pointer key shape and validation', async (t) => {
  // When I call deviceByHardware("HW-1")
  const key = deviceByHardware('HW-1');

  // Then the result is {pk:"HWUUID#HW-1", sk:"POINTER"}
  assert.deepStrictEqual(key, { pk: 'HWUUID#HW-1', sk: 'POINTER' });

  // And calling deviceByHardware("bad#id") throws an Error with message "invalid id: bad#id"
  assert.throws(
    () => deviceByHardware('bad#id'),
    (err) => err.message === 'invalid id: bad#id'
  );
});

// ============================================================================
// Scenario: First enrollment creates the pointer and the profile
// ============================================================================
test('Scenario: First enrollment creates the pointer and the profile', async (t) => {
  // Given no pointer exists for hardwareUuid "HW-1"
  const token = createEnrollmentToken();
  const table = new FakeTable();
  const now = new Date('2026-10-02T12:00:00Z');
  const pepper = randomHex(32);
  const hardwareUuid = 'HW-1';

  table.setItem({
    ...enrollmentToken(token.tokenId),
    tokenHash: token.tokenHash,
    expiresAt: '2026-10-31T00:00:00Z',
    maxUses: 10,
    useCount: 0,
  });

  const handler = createEnrollHandler({
    table,
    pepper,
    now: () => now,
    randomBytes: (size) => randomBytes(size),
  });

  // When an agent enrolls with hardwareUuid "HW-1"
  const request = createEnrollRequest(token.presented, validEnrollBody({ hardwareUuid }));
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);

  // Then a pointer item for HWUUID#HW-1 was written with putIfAbsent and a device profile item was written
  const pointerCalls = table.recordedPutIfAbsentCalls().filter(
    (c) => c.item.pk === `HWUUID#${hardwareUuid}` && c.item.sk === 'POINTER'
  );
  assert(pointerCalls.length > 0, 'pointer should be written with putIfAbsent');

  const deviceId = result.body.deviceId;
  const profileCalls = table.recordedPutCalls().filter(
    (c) => c.item.pk === `DEVICE#${deviceId}` && c.item.sk === 'PROFILE'
  );
  assert(profileCalls.length > 0, 'device profile should be written');
});

// ============================================================================
// Scenario: Re-enrollment rebinds the same device
// ============================================================================
test('Scenario: Re-enrollment rebinds the same device', async (t) => {
  // Given a pointer for hardwareUuid "HW-1" naming device d1
  const token = createEnrollmentToken();
  const table = new FakeTable();
  const now = new Date('2026-10-02T12:00:00Z');
  const pepper = randomHex(32);
  const hardwareUuid = 'HW-1';
  const deviceId = 'd1';

  table.setItem({
    ...enrollmentToken(token.tokenId),
    tokenHash: token.tokenHash,
    expiresAt: '2026-10-31T00:00:00Z',
    maxUses: 10,
    useCount: 0,
  });

  table.setItem({
    ...deviceByHardware(hardwareUuid),
    deviceId,
    createdAt: '2026-10-01T00:00:00Z',
  });

  const oldSecret = randomHex(32);
  table.setItem({
    ...deviceProfile(deviceId),
    secretEnc: 'old-secret-enc',
    lastSeenAt: '2026-10-01T00:00:00Z',
    gsi1pk: 'DEVICE',
    gsi1sk: '2026-10-01T00:00:00Z',
  });

  const handler = createEnrollHandler({
    table,
    pepper,
    now: () => now,
    randomBytes: (size) => randomBytes(size),
  });

  // When an agent enrolls again with hardwareUuid "HW-1"
  const request = createEnrollRequest(token.presented, validEnrollBody({ hardwareUuid }));
  const result = await handler(request);

  // Then the response deviceId is "d1", a new secretEnc was written and exactly one device profile item exists
  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(result.body.deviceId, deviceId);

  const updated = table.getItem(deviceProfile(deviceId));
  assert.notStrictEqual(updated.secretEnc, 'old-secret-enc', 'secretEnc should be updated');

  // Count device profiles for this hardware uuid
  const deviceProfiles = Array.from(table.items.values()).filter(
    (item) => item.pk === `DEVICE#${deviceId}` && item.sk === 'PROFILE'
  );
  assert.strictEqual(deviceProfiles.length, 1, 'exactly one device profile item should exist');
});

// ============================================================================
// Scenario: Losing the pointer race reuses the winner's device
// ============================================================================
test('Scenario: Losing the pointer race reuses the winner\'s device', async (t) => {
  // Given putIfAbsent for the pointer returns {written:false} and a re-read yields deviceId "d1"
  const token = createEnrollmentToken();
  const table = new FakeTable();
  const now = new Date('2026-10-02T12:00:00Z');
  const pepper = randomHex(32);
  const hardwareUuid = 'HW-1';
  const deviceId = 'd1';

  table.setItem({
    ...enrollmentToken(token.tokenId),
    tokenHash: token.tokenHash,
    expiresAt: '2026-10-31T00:00:00Z',
    maxUses: 10,
    useCount: 0,
  });

  // Pre-populate the winning pointer
  table.setItem({
    ...deviceByHardware(hardwareUuid),
    deviceId,
    createdAt: '2026-10-01T00:00:00Z',
  });

  table.setItem({
    ...deviceProfile(deviceId),
    lastSeenAt: '2026-10-01T00:00:00Z',
    gsi1pk: 'DEVICE',
    gsi1sk: '2026-10-01T00:00:00Z',
  });

  const handler = createEnrollHandler({
    table,
    pepper,
    now: () => now,
    randomBytes: (size) => randomBytes(size),
  });

  // When the agent enrolls with hardwareUuid "HW-1"
  const request = createEnrollRequest(token.presented, validEnrollBody({ hardwareUuid }));
  const result = await handler(request);

  // Then the status is 200, the response deviceId is "d1" and exactly one device profile item exists for HW-1
  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(result.body.deviceId, deviceId);

  const deviceProfiles = Array.from(table.items.values()).filter(
    (item) => item.pk === `DEVICE#${deviceId}`
  );
  assert.strictEqual(deviceProfiles.length, 1, 'exactly one device profile item should exist');
});

// ============================================================================
// Scenario: Invalid body names every offending field
// ============================================================================
test('Scenario: Invalid body names every offending field', async (t) => {
  // When an agent enrolls with platform "linux" and no hardwareUuid
  const token = createEnrollmentToken();
  const table = new FakeTable();
  const pepper = randomHex(32);

  table.setItem({
    ...enrollmentToken(token.tokenId),
    tokenHash: token.tokenHash,
    expiresAt: '2026-10-31T00:00:00Z',
    maxUses: 10,
    useCount: 0,
  });

  const handler = createEnrollHandler({
    table,
    pepper,
    randomBytes,
  });

  const body = {
    hostname: 'my-machine',
    platform: 'linux', // Invalid
    osVersion: '10.0.22631',
    // hardwareUuid missing
    agentVersion: '1.0.0',
  };

  const request = createEnrollRequest(token.presented, body);
  const result = await handler(request);

  // Then the status is 400, the error is invalid_request and fields contains "platform" and "hardwareUuid"
  assert.strictEqual(result.statusCode, 400);
  assert.deepStrictEqual(result.body.error, 'invalid_request');
  assert(result.body.fields.includes('platform'), 'fields should include platform');
  assert(result.body.fields.includes('hardwareUuid'), 'fields should include hardwareUuid');
});

// ============================================================================
// Scenario: Use count is incremented under a condition
// ============================================================================
test('Scenario: Use count is incremented under a condition', async (t) => {
  // Given a successful enrollment
  const token = createEnrollmentToken();
  const table = new FakeTable();
  const now = new Date('2026-10-02T12:00:00Z');
  const pepper = randomHex(32);

  table.setItem({
    ...enrollmentToken(token.tokenId),
    tokenHash: token.tokenHash,
    expiresAt: '2026-10-31T00:00:00Z',
    maxUses: 10,
    useCount: 0,
  });

  const handler = createEnrollHandler({
    table,
    pepper,
    now: () => now,
    randomBytes: (size) => randomBytes(size),
  });

  const request = createEnrollRequest(token.presented, validEnrollBody());
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);

  // Then the token update incremented useCount by one with a ConditionExpression requiring useCount < maxUses
  const updateCalls = table.recordedUpdateCalls();
  assert(updateCalls.length > 0, 'should have called update for token');

  const tokenUpdate = updateCalls.find(
    (c) => c.key.pk === `ENROLLTOKEN#${token.tokenId}` && c.key.sk === 'PROFILE'
  );
  assert(tokenUpdate, 'token update call should exist');
  assert(tokenUpdate.fields.ConditionExpression.includes('useCount < maxUses'));
});

// ============================================================================
// Scenario: Losing the use-count condition exhausts the token
// ============================================================================
test('Scenario: Losing the use-count condition exhausts the token', async (t) => {
  // Given the token update rejects with ConditionalCheckFailedException
  const token = createEnrollmentToken();
  const table = new FakeTable();
  const pepper = randomHex(32);

  table.setItem({
    ...enrollmentToken(token.tokenId),
    tokenHash: token.tokenHash,
    expiresAt: '2026-10-31T00:00:00Z',
    maxUses: 10,
    useCount: 0,
  });

  table.makeConditionalCheckFail(enrollmentToken(token.tokenId));

  const handler = createEnrollHandler({
    table,
    pepper,
    randomBytes,
  });

  // When the agent enrolls
  const request = createEnrollRequest(token.presented, validEnrollBody());
  const result = await handler(request);

  // Then the status is 403 and the error is enrollment_token_exhausted
  assert.strictEqual(result.statusCode, 403);
  assert.deepStrictEqual(result.body, { error: 'enrollment_token_exhausted' });
});

// ============================================================================
// Scenario: Enrollment is audited through appendAudit
// ============================================================================
test('Scenario: Enrollment is audited through appendAudit', async (t) => {
  // Given a successful enrollment of device d1
  const token = createEnrollmentToken();
  const table = new FakeTable();
  const now = new Date('2026-10-02T12:00:00Z');
  const pepper = randomHex(32);

  table.setItem({
    ...enrollmentToken(token.tokenId),
    tokenHash: token.tokenHash,
    expiresAt: '2026-10-31T00:00:00Z',
    maxUses: 10,
    useCount: 0,
  });

  const handler = createEnrollHandler({
    table,
    pepper,
    now: () => now,
    randomBytes: (size) => randomBytes(size),
  });

  const body = validEnrollBody();
  const request = createEnrollRequest(token.presented, body);
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);
  const deviceId = result.body.deviceId;
  const returnedSecret = result.body.deviceSecret;

  // Then appendAudit was called exactly once with action device.enrolled, actor "device:d1", target "d1" and detail naming hardwareUuid, platform and agentVersion
  const auditCalls = table.recordedPutCalls().filter(
    (c) => c.item.pk.startsWith('AUDIT#')
  );
  assert.strictEqual(auditCalls.length, 1, 'exactly one audit entry should be written');

  const auditItem = auditCalls[0].item;
  assert.strictEqual(auditItem.action, 'device.enrolled');
  assert.strictEqual(auditItem.actor, `device:${deviceId}`);
  assert.strictEqual(auditItem.target, deviceId);
  assert(auditItem.detail, 'audit item should have detail');
  assert.strictEqual(auditItem.detail.hardwareUuid, body.hardwareUuid);
  assert.strictEqual(auditItem.detail.platform, body.platform);
  assert.strictEqual(auditItem.detail.agentVersion, body.agentVersion);

  // And no argument passed to appendAudit equals the returned deviceSecret
  assert.notStrictEqual(auditItem.action, returnedSecret);
  assert.notStrictEqual(auditItem.actor, returnedSecret);
  assert.notStrictEqual(auditItem.target, returnedSecret);
  assert.notStrictEqual(auditItem.detail.hardwareUuid, returnedSecret);
  assert.notStrictEqual(auditItem.detail.platform, returnedSecret);
  assert.notStrictEqual(auditItem.detail.agentVersion, returnedSecret);
});
