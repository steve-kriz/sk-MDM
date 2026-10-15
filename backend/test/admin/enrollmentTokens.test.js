/**
 * E2E and unit tests for TASK-011: Admin API enrollment tokens.
 *
 * Tests implement the Gherkin scenarios in Given/When/Then style using node:test,
 * with all database calls mocked and deterministic clock injection.
 */

import test from 'node:test';
import assert from 'node:assert';
import { createHash } from 'node:crypto';
import { createRouter } from '../../dist/index.js';
import { registerEnrollmentTokenRoutes } from '../../dist/admin/enrollmentTokens.js';

// ============================================================================
// Mock Table Client
// ============================================================================

class FakeTable {
  constructor() {
    this.items = new Map();
    this.audits = [];
  }

  async put(item) {
    const key = `${item.pk}#${item.sk}`;
    this.items.set(key, { ...item });
    if (String(item.pk).startsWith('AUDIT#')) {
      this.audits.push(item);
    }
  }

  async get(keyObj) {
    const fullKey = `${keyObj.pk}#${keyObj.sk}`;
    return this.items.get(fullKey);
  }

  async update(key, fields) {
    const fullKey = `${key.pk}#${key.sk}`;
    const existing = this.items.get(fullKey) || { pk: key.pk, sk: key.sk };
    const updated = { ...existing };

    // Handle SET operations
    if (fields?.UpdateExpression) {
      const values = fields.ExpressionAttributeValues || {};
      const names = fields.ExpressionAttributeNames || {};

      // Simple SET operation handling
      if (fields.UpdateExpression.includes('SET')) {
        // Handle revokedAt/revokedBy for revoke
        if (values[':revokedAt'] !== undefined) {
          updated.revokedAt = values[':revokedAt'];
        }
        if (values[':revokedBy'] !== undefined) {
          updated.revokedBy = values[':revokedBy'];
        }
        // Handle useCount increment for claim
        if (values[':zero'] !== undefined && values[':one'] !== undefined) {
          updated.useCount = (existing.useCount ?? 0) + 1;
        }
        // Handle status/disabledAt/disabledBy for device disable
        if (values[':status'] !== undefined) {
          updated.status = values[':status'];
        }
        if (values[':disabledAt'] !== undefined) {
          updated.disabledAt = values[':disabledAt'];
        }
        if (values[':disabledBy'] !== undefined) {
          updated.disabledBy = values[':disabledBy'];
        }
      }

      // Handle list_append for deviceIds
      if (fields.UpdateExpression.includes('list_append')) {
        const deviceIdList = values[':deviceIdList'];
        if (deviceIdList && Array.isArray(deviceIdList)) {
          const existing_deviceIds = existing.deviceIds || [];
          updated.deviceIds = [...existing_deviceIds, ...deviceIdList];
        }
      }
    }

    this.items.set(fullKey, updated);
    return updated;
  }

  async query(request) {
    // GSI1 query for ENROLLTOKEN list
    if (request.KeyConditionExpression?.includes('gsi1pk') && request.IndexName === 'gsi1') {
      const items = [];
      for (const [key, item] of this.items.entries()) {
        if (item.gsi1pk === 'ENROLLTOKEN') {
          items.push(item);
        }
      }
      // Sort by gsi1sk descending (newest first)
      items.sort((a, b) => String(b.gsi1sk || '').localeCompare(String(a.gsi1sk || '')));
      return { items: items.slice(0, request.Limit || 100), cursor: null };
    }
    return { items: [], cursor: null };
  }

  getAllAudits() {
    return this.audits;
  }
}

// ============================================================================
// Mock Token Verifier
// ============================================================================

class StubVerifier {
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
// Helper: Deterministic random bytes for testing
// ============================================================================

let deterministicSeed = 0;
function deterministicRandomBytes(n) {
  const buf = Buffer.alloc(n);
  for (let i = 0; i < n; i++) {
    buf[i] = (deterministicSeed + i) % 256;
  }
  deterministicSeed += n;
  return buf;
}

// ============================================================================
// Scenario: Enrollment token is minted as tokenId dot secret and stored hashed
// ============================================================================

test('Scenario: Enrollment token is minted as tokenId dot secret and stored hashed', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');
  const tomorrow = new Date(now.getTime() + 86400000); // +24 hours

  registerEnrollmentTokenRoutes(router, { verifier, table, now: () => now, randomBytes: deterministicRandomBytes });

  // When an admin creates a token with maxUses 10 expiring tomorrow
  const response = await makeRequest(router, 'POST', '/admin/api/v1/enrollment-tokens', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      label: 'test-token',
      maxUses: 10,
      expiresAt: tomorrow.toISOString(),
    }),
  });

  assert.strictEqual(response.statusCode, 201);
  const body = JSON.parse(response.body);
  const token = body.token;
  const tokenId = body.tokenId;

  // Then the response token splits on "." into a 16-hex tokenId and a 64-hex secret
  assert(token.includes('.'));
  const [returnedTokenId, secret] = token.split('.');
  assert.strictEqual(returnedTokenId.length, 16);
  assert.strictEqual(secret.length, 64);
  assert(/^[0-9a-f]{16}$/.test(returnedTokenId));
  assert(/^[0-9a-f]{64}$/.test(secret));

  // And the item stored at ENROLLTOKEN#<tokenId> holds tokenHash equal to SHA-256 hex of full token
  const storedKey = `ENROLLTOKEN#${tokenId}#PROFILE`;
  const stored = table.items.get(storedKey);
  assert(stored);
  const expectedHash = createHash('sha256').update(token, 'utf8').digest('hex');
  assert.strictEqual(stored.tokenHash, expectedHash);

  // And no attribute of that item equals the returned token or its secret portion
  assert.notStrictEqual(stored.token, token);
  assert.notStrictEqual(stored.secret, secret);
  for (const [key, value] of Object.entries(stored)) {
    if (key !== 'pk' && key !== 'sk') {
      assert.notStrictEqual(value, token, `Attribute ${key} should not equal token`);
      assert.notStrictEqual(value, secret, `Attribute ${key} should not equal secret`);
    }
  }
});

// ============================================================================
// Scenario: Invalid token parameters are refused
// ============================================================================

test('Scenario: Invalid token parameters (maxUses 0) are refused', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');
  const tomorrow = new Date(now.getTime() + 86400000);

  registerEnrollmentTokenRoutes(router, { verifier, table, now: () => now });

  // When an admin creates a token with maxUses 0
  const response = await makeRequest(router, 'POST', '/admin/api/v1/enrollment-tokens', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      label: 'test-token',
      maxUses: 0,
      expiresAt: tomorrow.toISOString(),
    }),
  });

  // Then the status is 400 and the error is invalid_request
  assert.strictEqual(response.statusCode, 400);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'invalid_request');
});

// ============================================================================
// Unit: Token with negative maxUses is refused
// ============================================================================

test('Unit: Token with negative maxUses is refused', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');
  const tomorrow = new Date(now.getTime() + 86400000);

  registerEnrollmentTokenRoutes(router, { verifier, table, now: () => now });

  const response = await makeRequest(router, 'POST', '/admin/api/v1/enrollment-tokens', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      label: 'test-token',
      maxUses: -5,
      expiresAt: tomorrow.toISOString(),
    }),
  });

  assert.strictEqual(response.statusCode, 400);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'invalid_request');
});

// ============================================================================
// Unit: Token with expiry at or before now is refused
// ============================================================================

test('Unit: Token with expiry before now is refused', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');
  const yesterday = new Date(now.getTime() - 86400000);

  registerEnrollmentTokenRoutes(router, { verifier, table, now: () => now });

  const response = await makeRequest(router, 'POST', '/admin/api/v1/enrollment-tokens', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      label: 'test-token',
      maxUses: 10,
      expiresAt: yesterday.toISOString(),
    }),
  });

  assert.strictEqual(response.statusCode, 400);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'invalid_request');
});

// ============================================================================
// Unit: Token with expiry equal to now is refused
// ============================================================================

test('Unit: Token with expiry equal to now is refused', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');

  registerEnrollmentTokenRoutes(router, { verifier, table, now: () => now });

  const response = await makeRequest(router, 'POST', '/admin/api/v1/enrollment-tokens', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      label: 'test-token',
      maxUses: 10,
      expiresAt: now.toISOString(),
    }),
  });

  assert.strictEqual(response.statusCode, 400);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'invalid_request');
});

// ============================================================================
// Unit: Token with epoch milliseconds expiry works
// ============================================================================

test('Unit: Token with epoch milliseconds expiry works', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');
  const tomorrow = new Date(now.getTime() + 86400000);

  registerEnrollmentTokenRoutes(router, { verifier, table, now: () => now });

  const response = await makeRequest(router, 'POST', '/admin/api/v1/enrollment-tokens', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      label: 'test-token',
      maxUses: 10,
      expiresAt: tomorrow.getTime(), // epoch milliseconds
    }),
  });

  assert.strictEqual(response.statusCode, 201);
});

// ============================================================================
// Unit: Token stored with useCount 0 and label
// ============================================================================

test('Unit: Token stored with useCount 0 and label', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');
  const tomorrow = new Date(now.getTime() + 86400000);

  registerEnrollmentTokenRoutes(router, { verifier, table, now: () => now });

  const response = await makeRequest(router, 'POST', '/admin/api/v1/enrollment-tokens', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      label: 'installer-001',
      maxUses: 5,
      expiresAt: tomorrow.toISOString(),
    }),
  });

  const body = JSON.parse(response.body);
  const tokenId = body.tokenId;

  const stored = table.items.get(`ENROLLTOKEN#${tokenId}#PROFILE`);
  assert.strictEqual(stored.useCount, 0);
  assert.strictEqual(stored.label, 'installer-001');
  assert.strictEqual(stored.maxUses, 5);
  assert(stored.expiresAt);
});

// ============================================================================
// Unit: Token response includes tokenId, token, label, maxUses, expiresAt
// ============================================================================

test('Unit: Token response includes required fields', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');
  const tomorrow = new Date(now.getTime() + 86400000);

  registerEnrollmentTokenRoutes(router, { verifier, table, now: () => now });

  const response = await makeRequest(router, 'POST', '/admin/api/v1/enrollment-tokens', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      label: 'test-token',
      maxUses: 10,
      expiresAt: tomorrow.toISOString(),
    }),
  });

  const body = JSON.parse(response.body);
  assert(body.tokenId);
  assert(body.token);
  assert.strictEqual(body.label, 'test-token');
  assert.strictEqual(body.maxUses, 10);
  assert(body.expiresAt);
});

// ============================================================================
// AC1: Minted tokens carry gsi1pk and gsi1sk attributes for listing
// ============================================================================

test('AC1 E2E: Minted tokens carry gsi1pk "ENROLLTOKEN" and gsi1sk with createdAt and tokenId', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');
  const tomorrow = new Date(now.getTime() + 86400000);

  registerEnrollmentTokenRoutes(router, { verifier, table, now: () => now, randomBytes: deterministicRandomBytes });

  // Create a token
  const response = await makeRequest(router, 'POST', '/admin/api/v1/enrollment-tokens', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      label: 'test-token',
      maxUses: 5,
      expiresAt: tomorrow.toISOString(),
    }),
  });

  assert.strictEqual(response.statusCode, 201);
  const body = JSON.parse(response.body);
  const tokenId = body.tokenId;

  // Check the stored record has gsi1pk and gsi1sk
  const stored = table.items.get(`ENROLLTOKEN#${tokenId}#PROFILE`);
  assert(stored);
  assert.strictEqual(stored.gsi1pk, 'ENROLLTOKEN');
  assert(stored.gsi1sk, 'gsi1sk should be set');
  assert(stored.gsi1sk.includes(tokenId), 'gsi1sk should include tokenId');
});

// ============================================================================
// AC5: GET /admin/api/v1/enrollment-tokens lists tokens with correct shape
// ============================================================================

test('AC5 E2E: List endpoint returns tokens newest first with exactly the required fields', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');
  const tomorrow = new Date(now.getTime() + 86400000);

  registerEnrollmentTokenRoutes(router, { verifier, table, now: () => now, randomBytes: deterministicRandomBytes });

  // Create two tokens
  for (let i = 0; i < 2; i++) {
    await makeRequest(router, 'POST', '/admin/api/v1/enrollment-tokens', {
      headers: { authorization: 'Bearer valid-token' },
      body: JSON.stringify({
        label: `token-${i}`,
        maxUses: 5,
        expiresAt: tomorrow.toISOString(),
      }),
    });
  }

  // List tokens
  const listResponse = await makeRequest(router, 'GET', '/admin/api/v1/enrollment-tokens', {
    headers: { authorization: 'Bearer valid-token' },
  });

  assert.strictEqual(listResponse.statusCode, 200);
  const listBody = JSON.parse(listResponse.body);
  assert(Array.isArray(listBody.items));
  assert(listBody.items.length >= 2);

  // Check the first item has exactly the required fields
  const item = listBody.items[0];
  const requiredFields = ['tokenId', 'label', 'createdBy', 'createdAt', 'maxUses', 'useCount', 'expiresAt', 'status', 'deviceIds', 'revokedAt'];
  const itemKeys = Object.keys(item).sort();
  const expectedKeys = requiredFields.sort();
  assert.deepStrictEqual(itemKeys, expectedKeys, `Item keys should match: ${JSON.stringify(itemKeys)} vs ${JSON.stringify(expectedKeys)}`);

  // Ensure no token or tokenHash in the response
  assert.strictEqual(item.token, undefined, 'token should not be in list');
  assert.strictEqual(item.tokenHash, undefined, 'tokenHash should not be in list');
});

test('AC5 Edge: Invalid limit parameter returns 400 invalid_request', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerEnrollmentTokenRoutes(router, { verifier, table });

  const response = await makeRequest(router, 'GET', '/admin/api/v1/enrollment-tokens', {
    headers: { authorization: 'Bearer valid-token' },
    query: { limit: 'abc' },
  });

  assert.strictEqual(response.statusCode, 400);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'invalid_request');
});

// ============================================================================
// AC6: Status derivation for tokens
// ============================================================================

test('AC6 Unit: Status is "revoked" when revokedAt is set', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');
  const tomorrow = new Date(now.getTime() + 86400000);

  registerEnrollmentTokenRoutes(router, { verifier, table, now: () => now, randomBytes: deterministicRandomBytes });

  // Create a token
  const mintResponse = await makeRequest(router, 'POST', '/admin/api/v1/enrollment-tokens', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      label: 'token-to-revoke',
      maxUses: 5,
      expiresAt: tomorrow.toISOString(),
    }),
  });

  const tokenId = JSON.parse(mintResponse.body).tokenId;

  // Revoke it
  const revokeResponse = await makeRequest(router, 'POST', `/admin/api/v1/enrollment-tokens/${tokenId}/revoke`, {
    headers: { authorization: 'Bearer valid-token' },
  });

  assert.strictEqual(revokeResponse.statusCode, 200);

  // List and check status
  const listResponse = await makeRequest(router, 'GET', '/admin/api/v1/enrollment-tokens', {
    headers: { authorization: 'Bearer valid-token' },
  });

  const items = JSON.parse(listResponse.body).items;
  const revokedItem = items.find((i) => i.tokenId === tokenId);
  assert.strictEqual(revokedItem.status, 'revoked');
});

test('AC6 Unit: Status is "expired" when expiresAt is in past', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');
  const yesterday = new Date(now.getTime() - 86400000);

  // Seed an expired token record directly
  await table.put({
    pk: 'ENROLLTOKEN#expired-token',
    sk: 'PROFILE',
    gsi1pk: 'ENROLLTOKEN',
    gsi1sk: '2026-10-01T10:00:00Z#expired-token',
    tokenId: 'expired-token',
    label: 'expired',
    createdBy: 'admin',
    createdAt: '2026-10-01T10:00:00Z',
    maxUses: 5,
    useCount: 0,
    expiresAt: yesterday.toISOString(),
  });

  registerEnrollmentTokenRoutes(router, { verifier, table, now: () => now });

  const listResponse = await makeRequest(router, 'GET', '/admin/api/v1/enrollment-tokens', {
    headers: { authorization: 'Bearer valid-token' },
  });

  const items = JSON.parse(listResponse.body).items;
  const expiredItem = items.find((i) => i.tokenId === 'expired-token');
  assert.strictEqual(expiredItem.status, 'expired');
});

test('AC6 Unit: Status is "used" when useCount equals maxUses', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');
  const tomorrow = new Date(now.getTime() + 86400000);

  // Seed a used token
  await table.put({
    pk: 'ENROLLTOKEN#used-token',
    sk: 'PROFILE',
    gsi1pk: 'ENROLLTOKEN',
    gsi1sk: '2026-10-02T10:00:00Z#used-token',
    tokenId: 'used-token',
    label: 'used',
    createdBy: 'admin',
    createdAt: '2026-10-02T10:00:00Z',
    maxUses: 1,
    useCount: 1,
    expiresAt: tomorrow.toISOString(),
  });

  registerEnrollmentTokenRoutes(router, { verifier, table, now: () => now });

  const listResponse = await makeRequest(router, 'GET', '/admin/api/v1/enrollment-tokens', {
    headers: { authorization: 'Bearer valid-token' },
  });

  const items = JSON.parse(listResponse.body).items;
  const usedItem = items.find((i) => i.tokenId === 'used-token');
  assert.strictEqual(usedItem.status, 'used');
});

test('AC6 Unit: Status is "active" when uses left and not expired', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');
  const tomorrow = new Date(now.getTime() + 86400000);

  registerEnrollmentTokenRoutes(router, { verifier, table, now: () => now, randomBytes: deterministicRandomBytes });

  const response = await makeRequest(router, 'POST', '/admin/api/v1/enrollment-tokens', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      label: 'active-token',
      maxUses: 5,
      expiresAt: tomorrow.toISOString(),
    }),
  });

  const tokenId = JSON.parse(response.body).tokenId;

  const listResponse = await makeRequest(router, 'GET', '/admin/api/v1/enrollment-tokens', {
    headers: { authorization: 'Bearer valid-token' },
  });

  const items = JSON.parse(listResponse.body).items;
  const activeItem = items.find((i) => i.tokenId === tokenId);
  assert.strictEqual(activeItem.status, 'active');
});

// ============================================================================
// AC7, AC8, AC9, AC10: Revoke functionality
// ============================================================================

test('AC7 AC8 AC10 E2E: Revoke returns correct shape, sets revokedAt/revokedBy, and audits', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');
  const tomorrow = new Date(now.getTime() + 86400000);

  registerEnrollmentTokenRoutes(router, { verifier, table, now: () => now, randomBytes: deterministicRandomBytes });

  // Create a token
  const mintResponse = await makeRequest(router, 'POST', '/admin/api/v1/enrollment-tokens', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      label: 'token-to-revoke',
      maxUses: 5,
      expiresAt: tomorrow.toISOString(),
    }),
  });

  const tokenId = JSON.parse(mintResponse.body).tokenId;

  // Revoke it
  const revokeResponse = await makeRequest(router, 'POST', `/admin/api/v1/enrollment-tokens/${tokenId}/revoke`, {
    headers: { authorization: 'Bearer valid-token' },
  });

  assert.strictEqual(revokeResponse.statusCode, 200);
  const revokeBody = JSON.parse(revokeResponse.body);

  // Check response shape
  assert.strictEqual(revokeBody.tokenId, tokenId);
  assert.strictEqual(revokeBody.status, 'revoked');
  assert(revokeBody.revokedAt);
  const responseKeys = Object.keys(revokeBody).sort();
  assert.deepStrictEqual(responseKeys, ['revokedAt', 'status', 'tokenId']);

  // Check record was updated
  const stored = table.items.get(`ENROLLTOKEN#${tokenId}#PROFILE`);
  assert(stored.revokedAt);
  assert(stored.revokedBy);

  // Check audit entry
  const audits = table.getAllAudits();
  const revokeAudit = audits.find((a) => a.action === 'enrollment_token.revoked');
  assert(revokeAudit);
  assert.strictEqual(revokeAudit.target, tokenId);
  assert.deepStrictEqual(revokeAudit.detail, {});
});

test('AC9 Edge: Revoke unknown tokenId returns 404', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerEnrollmentTokenRoutes(router, { verifier, table });

  const response = await makeRequest(router, 'POST', '/admin/api/v1/enrollment-tokens/unknown-id/revoke', {
    headers: { authorization: 'Bearer valid-token' },
  });

  assert.strictEqual(response.statusCode, 404);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'not_found');
});

test('AC9 Edge: Revoke already-revoked token returns 409 already_revoked', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();
  const now = new Date('2026-10-02T10:00:00Z');
  const tomorrow = new Date(now.getTime() + 86400000);

  registerEnrollmentTokenRoutes(router, { verifier, table, now: () => now, randomBytes: deterministicRandomBytes });

  // Create and revoke a token
  const mintResponse = await makeRequest(router, 'POST', '/admin/api/v1/enrollment-tokens', {
    headers: { authorization: 'Bearer valid-token' },
    body: JSON.stringify({
      label: 'token',
      maxUses: 5,
      expiresAt: tomorrow.toISOString(),
    }),
  });

  const tokenId = JSON.parse(mintResponse.body).tokenId;

  // First revoke
  const firstRevoke = await makeRequest(router, 'POST', `/admin/api/v1/enrollment-tokens/${tokenId}/revoke`, {
    headers: { authorization: 'Bearer valid-token' },
  });
  assert.strictEqual(firstRevoke.statusCode, 200);

  // Second revoke should fail
  const secondRevoke = await makeRequest(router, 'POST', `/admin/api/v1/enrollment-tokens/${tokenId}/revoke`, {
    headers: { authorization: 'Bearer valid-token' },
  });

  assert.strictEqual(secondRevoke.statusCode, 409);
  const body = JSON.parse(secondRevoke.body);
  assert.strictEqual(body.error, 'already_revoked');
});
