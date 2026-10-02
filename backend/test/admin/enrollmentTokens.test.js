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
  }

  async put(item) {
    const key = `${item.pk}#${item.sk}`;
    this.items.set(key, { ...item });
  }

  async get(keyObj) {
    const fullKey = `${keyObj.pk}#${keyObj.sk}`;
    return this.items.get(fullKey);
  }

  async query(request) {
    return { items: [], cursor: null };
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
