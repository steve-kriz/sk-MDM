/**
 * E2E and unit tests for TASK-009: Entra ID OIDC token validation.
 *
 * These tests implement the Gherkin scenarios in Given/When/Then style
 * using node:test, with all JWKS calls mocked and deterministic clock injection.
 */

import test from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { createTokenVerifier, isVerifyFailure, ADMIN_ROLE, CLOCK_SKEW_SECONDS } from '../dist/auth/entra.js';

const TENANT_ID = 'tenant-123';
const CLIENT_ID = 'client-456';
const ADMIN_GROUP_ID = 'g-admin';

/**
 * Helper: Generate an RSA key pair for test signing.
 */
function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  return { publicKey, privateKey };
}

/**
 * Helper: Export a public key as JWK format for JWKS.
 */
function exportPublicKeyAsJwk(publicKey, kid) {
  const jwk = publicKey.export({ format: 'jwk' });
  return { ...jwk, kid, alg: 'RS256', use: 'sig' };
}

/**
 * Helper: Sign a JWT with RS256.
 */
function signJwt(header, payload, privateKey) {
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const message = `${encodedHeader}.${encodedPayload}`;

  const signature = crypto.sign('RSA-SHA256', Buffer.from(message), privateKey);
  const encodedSignature = signature.toString('base64url');

  return `${message}.${encodedSignature}`;
}

/**
 * Helper: Create a base token with standard claims.
 */
function createBaseToken(now, overrides = {}) {
  return {
    iss: `https://login.microsoftonline.com/${TENANT_ID}/v2.0`,
    aud: CLIENT_ID,
    exp: now + 3600,
    nbf: now - 60,
    roles: ['MDM.Administrator'],
    oid: 'object-123',
    ...overrides,
  };
}

/**
 * Helper: Create a mock jwksFetcher that tracks call count.
 */
function createMockFetcher(jwks) {
  let callCount = 0;
  return {
    fetcher: async () => {
      callCount++;
      return jwks;
    },
    getCallCount: () => callCount,
    resetCallCount: () => {
      callCount = 0;
    },
  };
}

// ==================== E2E / INTEGRATION TESTS ====================

test('Scenario: Valid admin token is accepted', async (t) => {
  // Given a token signed with a key in the JWKS and roles containing MDM.Administrator
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'key-1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createBaseToken(now);
  const token = signJwt(header, payload, privateKey);

  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  // When verify runs
  const claims = await verifier.verify(token);

  // Then it resolves with the decoded claims
  assert.strictEqual(claims.iss, payload.iss);
  assert.strictEqual(claims.aud, payload.aud);
  assert.deepStrictEqual(claims.roles, payload.roles);
});

test('Scenario: Non-RS256 token is refused', async (t) => {
  // Given a token whose header alg is "none"
  const mockFetcher = createMockFetcher({ keys: [] });
  const now = 1000000;
  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  const header = { alg: 'none' };
  const payload = createBaseToken(now);
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const token = `${encodedHeader}.${encodedPayload}.invalid`;

  // Then verify rejects with 401 invalid_token
  try {
    await verifier.verify(token);
    assert.fail('Expected rejection');
  } catch (error) {
    assert.ok(isVerifyFailure(error));
    assert.strictEqual(error.status, 401);
    assert.strictEqual(error.error, 'invalid_token');
  }
});

test('Scenario: Foreign issuer is refused', async (t) => {
  // Given a token issued by another tenant
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'key-1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createBaseToken(now, {
    iss: 'https://login.microsoftonline.com/other-tenant/v2.0',
  });
  const token = signJwt(header, payload, privateKey);

  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  // Then verify rejects with 401 invalid_issuer
  try {
    await verifier.verify(token);
    assert.fail('Expected rejection');
  } catch (error) {
    assert.ok(isVerifyFailure(error));
    assert.strictEqual(error.status, 401);
    assert.strictEqual(error.error, 'invalid_issuer');
  }
});

test('Scenario: Wrong audience is refused', async (t) => {
  // Given a token whose aud is another client id
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'key-1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createBaseToken(now, { aud: 'wrong-client-id' });
  const token = signJwt(header, payload, privateKey);

  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  // Then verify rejects with 401 invalid_audience
  try {
    await verifier.verify(token);
    assert.fail('Expected rejection');
  } catch (error) {
    assert.ok(isVerifyFailure(error));
    assert.strictEqual(error.status, 401);
    assert.strictEqual(error.error, 'invalid_audience');
  }
});

test('Scenario: Expired token is refused, but boundary case passes', async (t) => {
  // Given now() returns epoch seconds
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'key-1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;

  // And a token whose exp is 120 seconds before now
  const header = { alg: 'RS256', kid };
  const payloadExpired = createBaseToken(now, { exp: now - 120 });
  const tokenExpired = signJwt(header, payloadExpired, privateKey);

  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  // Then verify rejects with 401 token_expired
  try {
    await verifier.verify(tokenExpired);
    assert.fail('Expected rejection for expired token');
  } catch (error) {
    assert.ok(isVerifyFailure(error));
    assert.strictEqual(error.status, 401);
    assert.strictEqual(error.error, 'token_expired');
  }

  // And a token whose exp is exactly 60 seconds before now resolves
  const payloadBoundary = createBaseToken(now, { exp: now - CLOCK_SKEW_SECONDS });
  const tokenBoundary = signJwt(header, payloadBoundary, privateKey);

  // Reset mock fetcher since we're making another call
  mockFetcher.resetCallCount();

  const claims = await verifier.verify(tokenBoundary);
  assert.strictEqual(claims.exp, now - CLOCK_SKEW_SECONDS);
});

test('Scenario: Future token (nbf) is refused', async (t) => {
  // Given a token whose nbf is 120 seconds after now
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'key-1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createBaseToken(now, { nbf: now + 120 });
  const token = signJwt(header, payload, privateKey);

  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  // Then verify rejects with 401 token_not_yet_valid
  try {
    await verifier.verify(token);
    assert.fail('Expected rejection');
  } catch (error) {
    assert.ok(isVerifyFailure(error));
    assert.strictEqual(error.status, 401);
    assert.strictEqual(error.error, 'token_not_yet_valid');
  }
});

test('Scenario: Group membership grants admin', async (t) => {
  // Given a verifier constructed with adminGroupId "g-123"
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'key-1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;

  // And a valid token with no roles claim and groups ["g-999","g-123"]
  const header = { alg: 'RS256', kid };
  const payload = createBaseToken(now, {
    roles: undefined,
    groups: ['g-999', 'g-123'],
  });
  delete payload.roles;
  const token = signJwt(header, payload, privateKey);

  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    adminGroupId: 'g-123',
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  // Then verify resolves with the decoded claims
  const claims = await verifier.verify(token);
  assert.strictEqual(claims.aud, CLIENT_ID);
  assert.deepStrictEqual(claims.groups, ['g-999', 'g-123']);
});

test('Scenario: Group membership without configured adminGroupId grants nothing', async (t) => {
  // Given a verifier constructed without adminGroupId
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'key-1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;

  // And a valid token with no MDM.Administrator role and groups ["g-123"]
  const header = { alg: 'RS256', kid };
  const payload = createBaseToken(now, {
    roles: [],
    groups: ['g-123'],
  });
  const token = signJwt(header, payload, privateKey);

  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    // adminGroupId not set (defaults to '')
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  // Then verify rejects with 403 not_admin
  try {
    await verifier.verify(token);
    assert.fail('Expected rejection');
  } catch (error) {
    assert.ok(isVerifyFailure(error));
    assert.strictEqual(error.status, 403);
    assert.strictEqual(error.error, 'not_admin');
  }
});

test('Scenario: Non-admin token is refused', async (t) => {
  // Given a verifier with adminGroupId "g-123"
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'key-1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;

  // And a valid token with roles ["MDM.Reader"] and groups ["g-999"]
  const header = { alg: 'RS256', kid };
  const payload = createBaseToken(now, {
    roles: ['MDM.Reader'],
    groups: ['g-999'],
  });
  const token = signJwt(header, payload, privateKey);

  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    adminGroupId: 'g-123',
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  // Then verify rejects with 403 not_admin
  try {
    await verifier.verify(token);
    assert.fail('Expected rejection');
  } catch (error) {
    assert.ok(isVerifyFailure(error));
    assert.strictEqual(error.status, 403);
    assert.strictEqual(error.error, 'not_admin');
  }
});

test('Scenario: Token with neither roles nor groups claim is refused without throwing', async (t) => {
  // Given a valid token carrying no roles and no groups claim
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'key-1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createBaseToken(now);
  delete payload.roles;
  delete payload.groups;
  const token = signJwt(header, payload, privateKey);

  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  // Then verify rejects with 403 not_admin and no TypeError is raised
  try {
    await verifier.verify(token);
    assert.fail('Expected rejection');
  } catch (error) {
    assert.ok(isVerifyFailure(error), 'Should be a VerifyFailure, not a TypeError');
    assert.strictEqual(error.status, 403);
    assert.strictEqual(error.error, 'not_admin');
  }
});

test('Scenario: Key rotation triggers one refetch', async (t) => {
  // Given a cached JWKS without the token's kid
  const { publicKey: pk1, privateKey: priv1 } = generateKeyPair();
  const { publicKey: pk2, privateKey: priv2 } = generateKeyPair();

  const kid1 = 'key-1';
  const kid2 = 'key-2';
  const jwk1 = exportPublicKeyAsJwk(pk1, kid1);
  const jwk2 = exportPublicKeyAsJwk(pk2, kid2);

  let jwksState = { keys: [jwk1] };
  let fetchCount = 0;
  const fetcher = async () => {
    fetchCount++;
    return jwksState;
  };

  const now = 1000000;

  // First token signed with key-1, should succeed
  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: fetcher,
    now: () => now,
    cacheTtlSeconds: 3600,
  });

  const header1 = { alg: 'RS256', kid: kid1 };
  const payload1 = createBaseToken(now);
  const token1 = signJwt(header1, payload1, priv1);
  const claims1 = await verifier.verify(token1);
  assert.ok(claims1);
  assert.strictEqual(fetchCount, 1); // First fetch

  // Now update JWKS to have key-2 instead of key-1 (simulating key rotation)
  jwksState = { keys: [jwk2] };

  // And a fetcher returning it on the next call
  // When verify runs with a token signed by key-2
  const header2 = { alg: 'RS256', kid: kid2 };
  const payload2 = createBaseToken(now);
  const token2 = signJwt(header2, payload2, priv2);

  const claims2 = await verifier.verify(token2);
  assert.ok(claims2);

  // Then the fetcher was called exactly twice across the two verifications
  assert.strictEqual(fetchCount, 2, `Expected 2 fetches (1 initial + 1 refetch for unknown kid), got ${fetchCount}`);
});

test('Scenario: Still-unknown key stops after one refetch', async (t) => {
  // Given a fetcher that never returns the token's kid
  const { publicKey, privateKey } = generateKeyPair();

  const kid1 = 'key-1';
  const kid2 = 'key-unknown';
  const jwk1 = exportPublicKeyAsJwk(publicKey, kid1);

  let fetchCount = 0;
  const fetcher = async () => {
    fetchCount++;
    return { keys: [jwk1] }; // Always returns key-1, never key-unknown
  };

  const now = 1000000;
  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: fetcher,
    now: () => now,
    cacheTtlSeconds: 3600,
  });

  const header = { alg: 'RS256', kid: kid2 };
  const payload = createBaseToken(now);
  const token = signJwt(header, payload, privateKey);

  // Then verify rejects with 401 unknown_key and the fetcher was called exactly twice
  try {
    await verifier.verify(token);
    assert.fail('Expected rejection');
  } catch (error) {
    assert.ok(isVerifyFailure(error));
    assert.strictEqual(error.status, 401);
    assert.strictEqual(error.error, 'unknown_key');
    assert.strictEqual(fetchCount, 2, `Expected 2 fetches (1 initial + 1 refetch), got ${fetchCount}`);
  }
});

test('Scenario: JWKS endpoint failure surfaces as unavailable', async (t) => {
  // Given a jwksFetcher that rejects
  const fetcher = async () => {
    throw new Error('Network error');
  };

  const now = 1000000;
  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: fetcher,
    now: () => now,
  });

  const { publicKey, privateKey } = generateKeyPair();
  const header = { alg: 'RS256', kid: 'key-1' };
  const payload = createBaseToken(now);
  const token = signJwt(header, payload, privateKey);

  // Then verify rejects with 503 jwks_unavailable
  try {
    await verifier.verify(token);
    assert.fail('Expected rejection');
  } catch (error) {
    assert.ok(isVerifyFailure(error));
    assert.strictEqual(error.status, 503);
    assert.strictEqual(error.error, 'jwks_unavailable');
  }
});

// ==================== UNIT TESTS (Edge Cases) ====================

test('Unit: Invalid token format (not three segments)', async (t) => {
  // Two segments instead of three
  const mockFetcher = createMockFetcher({ keys: [] });
  const now = 1000000;
  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  try {
    await verifier.verify('header.payload');
    assert.fail('Expected rejection');
  } catch (error) {
    assert.ok(isVerifyFailure(error));
    assert.strictEqual(error.status, 401);
    assert.strictEqual(error.error, 'invalid_token');
  }
});

test('Unit: Token with invalid base64url segments', async (t) => {
  const mockFetcher = createMockFetcher({ keys: [] });
  const now = 1000000;
  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  try {
    await verifier.verify('!!!invalid!!!.!!!invalid!!!.!!!invalid!!!');
    assert.fail('Expected rejection');
  } catch (error) {
    assert.ok(isVerifyFailure(error));
    assert.strictEqual(error.status, 401);
    assert.strictEqual(error.error, 'invalid_token');
  }
});

test('Unit: Token with invalid signature', async (t) => {
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'key-1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createBaseToken(now);
  let token = signJwt(header, payload, privateKey);

  // Corrupt the signature. Flip a middle character: the last base64url char of a
  // 256-byte signature carries padding bits, so changing it can leave the bytes intact.
  const parts = token.split('.');
  const mid = Math.floor(parts[2].length / 2);
  parts[2] = parts[2].substring(0, mid) + (parts[2][mid] === 'A' ? 'B' : 'A') + parts[2].substring(mid + 1);
  token = parts.join('.');

  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  try {
    await verifier.verify(token);
    assert.fail('Expected rejection');
  } catch (error) {
    assert.ok(isVerifyFailure(error));
    assert.strictEqual(error.status, 401);
    assert.strictEqual(error.error, 'invalid_token');
  }
});

test('Unit: Token with malformed JSON header', async (t) => {
  const mockFetcher = createMockFetcher({ keys: [] });
  const now = 1000000;
  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  // Create a token with an invalid JSON header
  const invalidHeader = Buffer.from('not json').toString('base64url');
  const payload = Buffer.from(JSON.stringify(createBaseToken(now))).toString('base64url');
  const signature = Buffer.from('sig').toString('base64url');

  try {
    await verifier.verify(`${invalidHeader}.${payload}.${signature}`);
    assert.fail('Expected rejection');
  } catch (error) {
    assert.ok(isVerifyFailure(error));
    assert.strictEqual(error.status, 401);
    assert.strictEqual(error.error, 'invalid_token');
  }
});

test('Unit: Token missing exp claim', async (t) => {
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'key-1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createBaseToken(now);
  delete payload.exp;
  const token = signJwt(header, payload, privateKey);

  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  try {
    await verifier.verify(token);
    assert.fail('Expected rejection for missing exp');
  } catch (error) {
    assert.ok(isVerifyFailure(error));
    assert.strictEqual(error.status, 401);
    assert.strictEqual(error.error, 'token_expired');
  }
});

test('Unit: Token with non-numeric exp', async (t) => {
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'key-1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createBaseToken(now, { exp: 'not a number' });
  const token = signJwt(header, payload, privateKey);

  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  try {
    await verifier.verify(token);
    assert.fail('Expected rejection');
  } catch (error) {
    assert.ok(isVerifyFailure(error));
    assert.strictEqual(error.status, 401);
    assert.strictEqual(error.error, 'token_expired');
  }
});

test('Unit: Token with both roles and groups, only groups grants admin', async (t) => {
  // A token carrying both roles and groups where only one grants admin must resolve
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'key-1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createBaseToken(now, {
    roles: ['MDM.Reader'], // Not admin
    groups: ['g-admin'], // Admin
  });
  const token = signJwt(header, payload, privateKey);

  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    adminGroupId: 'g-admin',
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  const claims = await verifier.verify(token);
  assert.ok(claims);
});

test('Unit: Token with both roles and groups, only roles grants admin', async (t) => {
  // Opposite case: only roles grants admin
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'key-1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createBaseToken(now, {
    roles: ['MDM.Administrator'], // Admin
    groups: ['g-users'], // Not admin
  });
  const token = signJwt(header, payload, privateKey);

  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    adminGroupId: 'g-admin',
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  const claims = await verifier.verify(token);
  assert.ok(claims);
});

test('Unit: Empty signature segment rejects', async (t) => {
  const { publicKey } = generateKeyPair();
  const mockFetcher = createMockFetcher({ keys: [] });

  const now = 1000000;
  const header = { alg: 'RS256', kid: 'key-1' };
  const payload = createBaseToken(now);
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');

  const token = `${encodedHeader}.${encodedPayload}.`;

  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  try {
    await verifier.verify(token);
    assert.fail('Expected rejection');
  } catch (error) {
    assert.ok(isVerifyFailure(error));
    assert.strictEqual(error.status, 401);
    assert.strictEqual(error.error, 'invalid_token');
  }
});

test('Unit: nbf exactly 60 seconds in future is accepted', async (t) => {
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'key-1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createBaseToken(now, { nbf: now + CLOCK_SKEW_SECONDS }); // Exactly at boundary
  const token = signJwt(header, payload, privateKey);

  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  const claims = await verifier.verify(token);
  assert.strictEqual(claims.nbf, now + CLOCK_SKEW_SECONDS);
});

test('Unit: isVerifyFailure type guard works correctly', async (t) => {
  const validFailure = { status: 401, error: 'invalid_token' };
  assert.ok(isVerifyFailure(validFailure));

  const invalidFailure1 = { status: '401', error: 'invalid_token' };
  assert.ok(!isVerifyFailure(invalidFailure1));

  const invalidFailure2 = { error: 'invalid_token' };
  assert.ok(!isVerifyFailure(invalidFailure2));

  const invalidFailure3 = null;
  assert.ok(!isVerifyFailure(invalidFailure3));

  const invalidFailure4 = 'not an object';
  assert.ok(!isVerifyFailure(invalidFailure4));
});

test('Unit: JWKS as bare array is accepted', async (t) => {
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'key-1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);

  // Return bare array instead of { keys: [...] }
  const mockFetcher = createMockFetcher([jwk]);

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createBaseToken(now);
  const token = signJwt(header, payload, privateKey);

  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  const claims = await verifier.verify(token);
  assert.ok(claims);
});

test('Unit: Cache TTL prevents refetch', async (t) => {
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'key-1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);

  let callCount = 0;
  const fetcher = async () => {
    callCount++;
    return { keys: [jwk] };
  };

  let currentTime = 1000000;
  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: fetcher,
    now: () => currentTime,
    cacheTtlSeconds: 3600,
  });

  // First verify triggers fetch
  const header = { alg: 'RS256', kid };
  const payload1 = createBaseToken(currentTime);
  const token1 = signJwt(header, payload1, privateKey);
  await verifier.verify(token1);
  assert.strictEqual(callCount, 1);

  // Second verify within TTL should reuse cache
  currentTime += 1800; // 30 minutes later
  const payload2 = createBaseToken(currentTime);
  const token2 = signJwt(header, payload2, privateKey);
  await verifier.verify(token2);
  assert.strictEqual(callCount, 1, 'Should not refetch within TTL');

  // Third verify after TTL should refetch
  currentTime += 3600; // 1 hour later (past TTL)
  const payload3 = createBaseToken(currentTime);
  const token3 = signJwt(header, payload3, privateKey);
  await verifier.verify(token3);
  assert.strictEqual(callCount, 2, 'Should refetch after TTL expires');
});

test('Unit: Roles as non-array is handled safely', async (t) => {
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'key-1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createBaseToken(now, {
    roles: 'MDM.Administrator', // Not an array
  });
  const token = signJwt(header, payload, privateKey);

  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  try {
    await verifier.verify(token);
    assert.fail('Expected rejection (no admin)');
  } catch (error) {
    assert.ok(isVerifyFailure(error));
    assert.strictEqual(error.status, 403);
    assert.strictEqual(error.error, 'not_admin');
  }
});

test('Unit: Groups containing non-string entries is filtered', async (t) => {
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'key-1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createBaseToken(now, {
    roles: [],
    groups: ['g-admin', 123, null, 'g-users'], // Mixed types
  });
  const token = signJwt(header, payload, privateKey);

  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    adminGroupId: 'g-admin',
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  const claims = await verifier.verify(token);
  assert.ok(claims); // Should resolve because g-admin is in the filtered list
});

test('Unit: ADMIN_ROLE is MDM.Administrator, distinct from the MDM.Admin scope', async (t) => {
  // Entra keeps app-role and exposed-scope values in one namespace, so the
  // admin role cannot reuse the console's sign-in scope name.
  assert.strictEqual(ADMIN_ROLE, 'MDM.Administrator');
});

test('Scenario: A token whose only role is the scope name MDM.Admin is not an admin', async (t) => {
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'key-1';
  const mockFetcher = createMockFetcher({ keys: [exportPublicKeyAsJwk(publicKey, kid)] });
  const now = 1000000;
  const token = signJwt({ alg: 'RS256', kid }, createBaseToken(now, { roles: ['MDM.Admin'] }), privateKey);
  const verifier = createTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  await assert.rejects(verifier.verify(token), (error) => {
    assert.ok(isVerifyFailure(error));
    assert.strictEqual(error.status, 403);
    assert.strictEqual(error.error, 'not_admin');
    return true;
  });
});
