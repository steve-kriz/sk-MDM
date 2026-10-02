/**
 * Cross-ticket integration tests for TASK-011 contracts with TASK-006 and TASK-008.
 *
 * Verifies that:
 * 1. Tokens minted by TASK-011 are correctly verified by TASK-006's enroll handler
 * 2. Commands queued by TASK-011 are correctly leased by TASK-008's lease handler
 */

import test from 'node:test';
import assert from 'node:assert';
import { createRouter } from '../../dist/index.js';
import { registerEnrollmentTokenRoutes } from '../../dist/admin/enrollmentTokens.js';
import { registerCommandDispatchRoutes } from '../../dist/admin/commandDispatch.js';
import { createEnrollHandler } from '../../dist/routes/enroll.js';
import { createLeaseHandler } from '../../dist/routes/commands.js';
import { deviceProfile } from '../../dist/db/keys.js';

// ============================================================================
// Enhanced Fake Table with update() and condition support
// ============================================================================

class IntegrationFakeTable {
  constructor() {
    this.items = new Map();
  }

  async put(item) {
    const key = `${item.pk}#${item.sk}`;
    this.items.set(key, { ...item });
  }

  async get(keyObj) {
    const fullKey = `${keyObj.pk}#${keyObj.sk}`;
    return this.items.get(fullKey);
  }

  async putIfAbsent(item) {
    const key = `${item.pk}#${item.sk}`;
    if (this.items.has(key)) {
      return { ok: false };
    }
    this.items.set(key, { ...item });
    return { ok: true };
  }

  async update(keyObj, fields) {
    const fullKey = `${keyObj.pk}#${keyObj.sk}`;
    const item = this.items.get(fullKey);

    if (!item) {
      const error = new Error('Item not found');
      error.name = 'ConditionalCheckFailedException';
      throw error;
    }

    // Handle ConditionExpression for useCount < maxUses
    if (fields?.ConditionExpression === 'useCount < maxUses') {
      const useCount = item.useCount ?? 0;
      const maxUses = item.maxUses ?? 0;
      if (useCount >= maxUses) {
        const error = new Error('Condition failed');
        error.name = 'ConditionalCheckFailedException';
        throw error;
      }
    }

    // Handle UpdateExpression for useCount increment
    if (fields?.UpdateExpression?.includes('SET useCount')) {
      item.useCount = (item.useCount ?? 0) + 1;
    }

    // Handle LEASE_CONDITION: status = 'pending' OR (status = 'leased' AND leaseExpiresAt <= :now)
    if (fields?.ConditionExpression?.includes('#status = :pending')) {
      const now = fields.ExpressionAttributeValues[':now'];
      const status = item.status;
      const leaseExpiresAt = item.leaseExpiresAt;

      const isPending = status === 'pending';
      const isExpiredLease = status === 'leased' && leaseExpiresAt <= now;

      if (!isPending && !isExpiredLease) {
        const error = new Error('Condition failed');
        error.name = 'ConditionalCheckFailedException';
        throw error;
      }
    }

    // Apply update
    if (fields?.UpdateExpression?.includes('SET #status = :leased')) {
      item.status = 'leased';
      item.leaseExpiresAt = fields.ExpressionAttributeValues[':leaseExpiresAt'];
    }

    return item;
  }

  async query(request) {
    const items = [];
    const { KeyConditionExpression, ExpressionAttributeValues } = request;

    const pk = ExpressionAttributeValues[':pk'];
    for (const [, item] of this.items) {
      if (item.pk !== pk) continue;
      if (KeyConditionExpression?.includes('begins_with')) {
        const prefix = ExpressionAttributeValues[':commandPrefix'];
        if (!item.sk.startsWith(prefix)) continue;
      }
      items.push(item);
    }

    const sorted = items.sort((a, b) => (a.sk < b.sk ? 1 : -1));
    return { items: sorted, cursor: null };
  }
}

// ============================================================================
// Stub Verifiers
// ============================================================================

class AdminVerifier {
  constructor(claims = {}) {
    this.claims = { sub: 'user123', preferred_username: 'admin@example.com', ...claims };
  }

  async verify(token) {
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
// Helper: Deterministic random bytes
// ============================================================================

let seed = 0;
function deterministicRandomBytes(n) {
  const buf = Buffer.alloc(n);
  for (let i = 0; i < n; i++) {
    buf[i] = (seed + i) % 256;
  }
  seed += n;
  return buf;
}

// ============================================================================
// Contract Test 1: Token minted by TASK-011 → verified by TASK-006
// ============================================================================

test('Contract: Token minted by TASK-011 is verified by TASK-006 enroll handler', async (t) => {
  const table = new IntegrationFakeTable();
  const adminVerifier = new AdminVerifier();
  const pepper = 'a'.repeat(64); // 64-char hex pepper
  const now = new Date('2026-10-02T10:00:00Z');
  const tomorrow = new Date(now.getTime() + 86400000);

  // Reset seed for deterministic output
  seed = 0;

  // Step 1: Mint a token through TASK-011's admin API
  const adminRouter = createRouter();
  registerEnrollmentTokenRoutes(adminRouter, {
    verifier: adminVerifier,
    table,
    now: () => now,
    randomBytes: deterministicRandomBytes,
  });

  const mintResponse = await makeRequest(adminRouter, 'POST', '/admin/api/v1/enrollment-tokens', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      label: 'integration-test',
      maxUses: 10,
      expiresAt: tomorrow.toISOString(),
    }),
  });

  assert.strictEqual(mintResponse.statusCode, 201);
  const mintBody = typeof mintResponse.body === 'string' ? JSON.parse(mintResponse.body) : mintResponse.body;
  const token = mintBody.token;
  const tokenId = mintBody.tokenId;

  // Verify token format
  const [returnedTokenId, secret] = token.split('.');
  assert.strictEqual(returnedTokenId.length, 16);
  assert.strictEqual(secret.length, 64);
  assert(/^[0-9a-f]{16}$/.test(returnedTokenId));
  assert(/^[0-9a-f]{64}$/.test(secret));

  // Step 2: Use the token to enroll through TASK-006's enroll handler
  const enrollHandler = createEnrollHandler({
    table,
    pepper,
    now: () => now,
    randomBytes: deterministicRandomBytes,
  });

  const enrollRequest = {
    method: 'POST',
    path: '/api/v1/enroll',
    headers: {
      'x-mdm-enrollment-token': token,
    },
    query: {},
    body: JSON.stringify({
      hostname: 'test-machine',
      platform: 'windows',
      osVersion: '11',
      hardwareUuid: 'hw-uuid-001',
      agentVersion: '1.0.0',
    }),
  };

  const enrollResponse = await enrollHandler(enrollRequest);

  // Then the enrollment succeeds with 200 and a 64-hex deviceSecret
  assert.strictEqual(enrollResponse.statusCode, 200, `Enroll failed: ${JSON.stringify(enrollResponse.body)}`);
  const enrollBody = typeof enrollResponse.body === 'string' ? JSON.parse(enrollResponse.body) : enrollResponse.body;
  assert(enrollBody.deviceSecret);
  assert.strictEqual(enrollBody.deviceSecret.length, 64);
  assert(/^[0-9a-f]{64}$/.test(enrollBody.deviceSecret));
});

// ============================================================================
// Contract Test 2: Command queued by TASK-011 → leased by TASK-008
// ============================================================================

test('Contract: Command queued by TASK-011 is correctly leased by TASK-008', async (t) => {
  const table = new IntegrationFakeTable();
  const adminVerifier = new AdminVerifier();
  const pepper = 'b'.repeat(64);
  const nowDate = new Date('2026-10-02T12:30:00Z');
  const nowSeconds = Math.floor(nowDate.getTime() / 1000); // epoch seconds

  // Reset seed for deterministic output
  seed = 0;

  // Setup: Create a device profile
  await table.put({
    pk: 'DEVICE#d1',
    sk: 'PROFILE',
    deviceId: 'd1',
    hostname: 'test-device',
    platform: 'windows',
  });

  // Step 1: Queue a command through TASK-011's admin API
  const adminRouter = createRouter();
  registerCommandDispatchRoutes(adminRouter, {
    verifier: adminVerifier,
    table,
    now: () => nowDate,
    randomBytes: deterministicRandomBytes,
  });

  const queueResponse = await makeRequest(adminRouter, 'POST', '/admin/api/v1/devices/d1/commands', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      type: 'lock',
      payload: {},
    }),
  });

  assert.strictEqual(queueResponse.statusCode, 202);
  const queueBody = typeof queueResponse.body === 'string' ? JSON.parse(queueResponse.body) : queueResponse.body;
  const commandId = queueBody.commandId;
  assert(commandId);

  // Step 2: Lease the command through TASK-008's lease handler
  const leaseHandler = createLeaseHandler({
    table,
    now: () => nowSeconds,
    pepper,
    verifyDevice: async (req, options) => {
      // Stubbed verifier: the device in the path is always authorized
      return {
        ok: true,
        deviceId: 'd1',
      };
    },
  });

  const leaseRequest = {
    method: 'GET',
    path: '/api/v1/devices/d1/commands',
    headers: {},
    query: { max: '5' },
    params: { deviceId: 'd1' },
    body: null,
  };

  const leaseResponse = await leaseHandler(leaseRequest);

  // Then the command is leased with 200 and the same commandId, type, issuedAt, expiresAt
  assert.strictEqual(leaseResponse.statusCode, 200);
  const leaseBody = typeof leaseResponse.body === 'string' ? JSON.parse(leaseResponse.body) : leaseResponse.body;
  assert(Array.isArray(leaseBody.commands));
  assert.strictEqual(leaseBody.commands.length, 1);

  const leasedCommand = leaseBody.commands[0];
  assert.strictEqual(leasedCommand.commandId, commandId);
  assert.strictEqual(leasedCommand.type, 'lock');

  // issuedAt and expiresAt must match what was queued (epoch milliseconds)
  const expectedIssuedAt = nowDate.getTime(); // epoch milliseconds
  const expectedExpiresAt = expectedIssuedAt + 86400000; // +24 hours

  assert.strictEqual(leasedCommand.issuedAt, expectedIssuedAt);
  assert.strictEqual(leasedCommand.expiresAt, expectedExpiresAt);
});

// ============================================================================
// Contract Test 3: Token cannot be used more than maxUses times
// ============================================================================

test('Contract: Token use count enforcement between TASK-011 and TASK-006', async (t) => {
  const table = new IntegrationFakeTable();
  const adminVerifier = new AdminVerifier();
  const pepper = 'c'.repeat(64);
  const now = new Date('2026-10-02T10:00:00Z');
  const tomorrow = new Date(now.getTime() + 86400000);

  seed = 0;

  // Mint a token with maxUses = 1
  const adminRouter = createRouter();
  registerEnrollmentTokenRoutes(adminRouter, {
    verifier: adminVerifier,
    table,
    now: () => now,
    randomBytes: deterministicRandomBytes,
  });

  const mintResponse = await makeRequest(adminRouter, 'POST', '/admin/api/v1/enrollment-tokens', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      label: 'single-use',
      maxUses: 1,
      expiresAt: tomorrow.toISOString(),
    }),
  });

  const token = (typeof mintResponse.body === 'string' ? JSON.parse(mintResponse.body) : mintResponse.body).token;

  // First enrollment should succeed
  const enrollHandler = createEnrollHandler({
    table,
    pepper,
    now: () => now,
    randomBytes: deterministicRandomBytes,
  });

  const enrollRequest1 = {
    method: 'POST',
    path: '/api/v1/enroll',
    headers: { 'x-mdm-enrollment-token': token },
    query: {},
    body: JSON.stringify({
      hostname: 'machine1',
      platform: 'windows',
      osVersion: '11',
      hardwareUuid: 'hw-001',
      agentVersion: '1.0.0',
    }),
  };

  const response1 = await enrollHandler(enrollRequest1);
  assert.strictEqual(response1.statusCode, 200);

  // Second enrollment should fail with exhausted token
  const enrollRequest2 = {
    method: 'POST',
    path: '/api/v1/enroll',
    headers: { 'x-mdm-enrollment-token': token },
    query: {},
    body: JSON.stringify({
      hostname: 'machine2',
      platform: 'windows',
      osVersion: '11',
      hardwareUuid: 'hw-002',
      agentVersion: '1.0.0',
    }),
  };

  const response2 = await enrollHandler(enrollRequest2);
  assert.strictEqual(response2.statusCode, 403);
  const body2 = typeof response2.body === 'string' ? JSON.parse(response2.body) : response2.body;
  assert.strictEqual(body2.error, 'enrollment_token_exhausted');
});
