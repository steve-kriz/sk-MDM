/**
 * E2E and unit tests for TASK-031: Entra ID user token validation for the agent.
 *
 * These tests implement the Gherkin scenarios (B2, B3, B4) in Given/When/Then style
 * using node:test, with all JWKS calls mocked and deterministic clock injection.
 */

import test from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { createUserTokenVerifier, createAppUserTokenVerifier, AGENT_SCOPE_NAME, APP_USER_SCOPE_NAME } = await import(
  `file://${join(__dirname, '../../dist/auth/userToken.js')}`
);

const { isVerifyFailure } = await import(
  `file://${join(__dirname, '../../dist/auth/jwtCore.js')}`
);

const TENANT_ID = 'tenant-001';
const CLIENT_ID = 'client-001';

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
 * Helper: Create a base token with standard agent-scoped claims.
 */
function createAgentToken(now, overrides = {}) {
  return {
    iss: `https://login.microsoftonline.com/${TENANT_ID}/v2.0`,
    aud: CLIENT_ID,
    exp: now + 3600,
    nbf: now - 60,
    scp: `openid MDM.Agent profile`,
    tid: TENANT_ID,
    oid: 'object-agent-001',
    ...overrides,
  };
}

/**
 * Helper: Create a mock jwksFetcher.
 */
function createMockFetcher(jwks) {
  let callCount = 0;
  return {
    fetcher: async () => {
      callCount++;
      return jwks;
    },
    getCallCount: () => callCount,
  };
}

// ==================== B2 SCENARIO TESTS ====================

test('B2: Valid agent-scoped token without roles verifies', async (t) => {
  // Given a token signed by k1 with agent scope, no roles
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'k1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createAgentToken(now, {
    scp: 'openid MDM.Agent',
    oid: 'o-1',
  });
  const token = signJwt(header, payload, privateKey);

  const verifier = createUserTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  // When verify runs
  const claims = await verifier.verify(token);

  // Then it resolves with oid "o-1"
  assert.strictEqual(claims.oid, 'o-1');
  assert.strictEqual(claims.tid, TENANT_ID);
  assert.ok(claims.scp.includes('MDM.Agent'));
});

// ==================== B3 FAILURE SCENARIO TESTS ====================

test('B3: Token with 2 segments (not 3) is rejected', async (t) => {
  const mockFetcher = createMockFetcher({ keys: [] });
  const now = 1000000;
  const verifier = createUserTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  const token = 'header.payload'; // Missing signature

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

test('B3: HS256-headed token is rejected', async (t) => {
  const mockFetcher = createMockFetcher({ keys: [] });
  const now = 1000000;
  const verifier = createUserTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  const encodedHeader = Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify({ exp: now + 3600 })).toString('base64url');
  const token = `${encodedHeader}.${encodedPayload}.signature`;

  try {
    await verifier.verify(token);
    assert.fail('Expected rejection');
  } catch (error) {
    assert.ok(isVerifyFailure(error));
    assert.strictEqual(error.status, 401);
    assert.strictEqual(error.error, 'invalid_token');
  }
});

test('B3: Tampered payload is rejected', async (t) => {
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'k1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createAgentToken(now, { oid: 'o-1' });
  let token = signJwt(header, payload, privateKey);

  // Tamper with the payload
  const parts = token.split('.');
  const tamperedPayload = Buffer.from(JSON.stringify({ ...payload, oid: 'o-2' })).toString('base64url');
  token = parts[0] + '.' + tamperedPayload + '.' + parts[2];

  const verifier = createUserTokenVerifier({
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

test('B3: Unknown kid after refetch is rejected with unknown_key', async (t) => {
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'k9'; // Not in JWKS
  const header = { alg: 'RS256', kid };
  const now = 1000000;
  const payload = createAgentToken(now);
  const token = signJwt(header, payload, privateKey);

  const mockFetcher = createMockFetcher({ keys: [] }); // No keys
  const verifier = createUserTokenVerifier({
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
    assert.strictEqual(error.error, 'unknown_key');
  }
});

test('B3: Wrong issuer (different tenant) is rejected', async (t) => {
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'k1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createAgentToken(now, {
    iss: 'https://login.microsoftonline.com/t-2/v2.0',
  });
  const token = signJwt(header, payload, privateKey);

  const verifier = createUserTokenVerifier({
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
    assert.strictEqual(error.error, 'invalid_issuer');
  }
});

test('B3: Wrong audience is rejected', async (t) => {
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'k1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createAgentToken(now, { aud: 'other-client' });
  const token = signJwt(header, payload, privateKey);

  const verifier = createUserTokenVerifier({
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
    assert.strictEqual(error.error, 'invalid_audience');
  }
});

test('B3: Expired token (61 seconds ago) is rejected', async (t) => {
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'k1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createAgentToken(now, { exp: now - 61 });
  const token = signJwt(header, payload, privateKey);

  const verifier = createUserTokenVerifier({
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

test('B3: Token with nbf 61 seconds in future is rejected', async (t) => {
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'k1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createAgentToken(now, { nbf: now + 61 });
  const token = signJwt(header, payload, privateKey);

  const verifier = createUserTokenVerifier({
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
    assert.strictEqual(error.error, 'token_not_yet_valid');
  }
});

test('B3: Missing scope (scp absent) is rejected', async (t) => {
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'k1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createAgentToken(now);
  delete payload.scp;
  const token = signJwt(header, payload, privateKey);

  const verifier = createUserTokenVerifier({
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
    assert.strictEqual(error.error, 'missing_scope');
  }
});

test('B3: Scope MDM.Admin (not MDM.Agent) is rejected', async (t) => {
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'k1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createAgentToken(now, { scp: 'MDM.Admin' });
  const token = signJwt(header, payload, privateKey);

  const verifier = createUserTokenVerifier({
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
    assert.strictEqual(error.error, 'missing_scope');
  }
});

test('B3: Scope MDM.AgentX (partial match) is rejected', async (t) => {
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'k1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createAgentToken(now, { scp: 'MDM.AgentX' });
  const token = signJwt(header, payload, privateKey);

  const verifier = createUserTokenVerifier({
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
    assert.strictEqual(error.error, 'missing_scope');
  }
});

test('B3: Missing oid is rejected with invalid_subject', async (t) => {
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'k1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  const payload = createAgentToken(now);
  delete payload.oid;
  const token = signJwt(header, payload, privateKey);

  const verifier = createUserTokenVerifier({
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
    assert.strictEqual(error.error, 'invalid_subject');
  }
});

test('B3: Wrong tid (different tenant) is rejected with invalid_subject', async (t) => {
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'k1';
  const jwk = exportPublicKeyAsJwk(publicKey, kid);
  const mockFetcher = createMockFetcher({ keys: [jwk] });

  const now = 1000000;
  const header = { alg: 'RS256', kid };
  // Create token with correct iss for TENANT_ID but wrong tid claim
  const payload = createAgentToken(now, {
    iss: `https://login.microsoftonline.com/${TENANT_ID}/v2.0`,
    tid: 't-2' // Wrong tenant id
  });
  const token = signJwt(header, payload, privateKey);

  const verifier = createUserTokenVerifier({
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
    assert.strictEqual(error.error, 'invalid_subject');
  }
});

test('B3: JWKS fetcher rejection is 503 jwks_unavailable', async (t) => {
  const mockFetcher = {
    fetcher: async () => {
      throw new Error('Network error');
    },
  };

  const now = 1000000;
  const header = { alg: 'RS256', kid: 'k1' };
  const payload = createAgentToken(now);
  const { publicKey, privateKey } = generateKeyPair();
  const token = signJwt(header, payload, privateKey);

  const verifier = createUserTokenVerifier({
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
    assert.strictEqual(error.status, 503);
    assert.strictEqual(error.error, 'jwks_unavailable');
  }
});

// ==================== B4 REGRESSION TEST ====================

test('B4: AGENT_SCOPE_NAME constant equals MDM.Agent', async (t) => {
  assert.strictEqual(AGENT_SCOPE_NAME, 'MDM.Agent');
});

// ==================== TASK-049 AC9: createAppUserTokenVerifier (MDM.User) ====================

function createAppToken(now, overrides = {}) {
  return {
    iss: `https://login.microsoftonline.com/${TENANT_ID}/v2.0`,
    aud: CLIENT_ID,
    exp: now + 3600,
    nbf: now - 60,
    scp: 'openid MDM.User',
    tid: TENANT_ID,
    oid: 'u-1',
    ...overrides,
  };
}

function signedAppToken(now, privateKey, kid, overrides = {}) {
  return signJwt({ alg: 'RS256', kid }, createAppToken(now, overrides), privateKey);
}

test('Scenario: User token with MDM.User is accepted', async () => {
  // Given a valid token for the configured tenant and audience with
  // scp "openid MDM.User" and oid "u-1"
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'k1';
  const mockFetcher = createMockFetcher({ keys: [exportPublicKeyAsJwk(publicKey, kid)] });
  const now = 1000000;
  const token = signedAppToken(now, privateKey, kid);

  const verifier = createAppUserTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  // When createAppUserTokenVerifier verifies it
  const claims = await verifier.verify(token);

  // Then the claims are returned
  assert.strictEqual(claims.oid, 'u-1');
  assert.strictEqual(claims.tid, TENANT_ID);
});

const appUserRejections = [
  { label: 'with scp "MDM.Admin" only', overrides: { scp: 'MDM.Admin' }, status: 403, error: 'missing_scope' },
  { label: 'with scp "MDM.Users"', overrides: { scp: 'MDM.Users' }, status: 403, error: 'missing_scope' },
  {
    label: "with scp \"MDM.User\" and another tenant's tid",
    overrides: { tid: 'other-tenant' },
    status: 401,
    error: 'invalid_subject',
  },
  { label: 'with scp "MDM.User" and no oid', overrides: { oid: '' }, status: 401, error: 'invalid_subject' },
  { label: 'with the wrong audience', overrides: { aud: 'someone-else' }, status: 401, error: 'invalid_audience' },
];

for (const { label, overrides, status, error } of appUserRejections) {
  test(`Scenario Outline: User token rejected -- ${label}`, async () => {
    const { publicKey, privateKey } = generateKeyPair();
    const kid = 'k1';
    const mockFetcher = createMockFetcher({ keys: [exportPublicKeyAsJwk(publicKey, kid)] });
    const now = 1000000;
    const token = signedAppToken(now, privateKey, kid, overrides);

    const verifier = createAppUserTokenVerifier({
      tenantId: TENANT_ID,
      clientId: CLIENT_ID,
      jwksFetcher: mockFetcher.fetcher,
      now: () => now,
    });

    await assert.rejects(
      () => verifier.verify(token),
      (err) => {
        assert.ok(isVerifyFailure(err));
        assert.strictEqual(err.status, status, label);
        assert.strictEqual(err.error, error, label);
        return true;
      },
    );
  });
}

test('Scenario Outline: User token rejected -- that has expired', async () => {
  const { publicKey, privateKey } = generateKeyPair();
  const kid = 'k1';
  const mockFetcher = createMockFetcher({ keys: [exportPublicKeyAsJwk(publicKey, kid)] });
  const now = 1000000;
  const token = signJwt({ alg: 'RS256', kid }, createAppToken(now, { exp: now - 1000 }), privateKey);

  const verifier = createAppUserTokenVerifier({
    tenantId: TENANT_ID,
    clientId: CLIENT_ID,
    jwksFetcher: mockFetcher.fetcher,
    now: () => now,
  });

  await assert.rejects(
    () => verifier.verify(token),
    (err) => {
      assert.ok(isVerifyFailure(err));
      assert.strictEqual(err.status, 401);
      assert.strictEqual(err.error, 'token_expired');
      return true;
    },
  );
});

test('Unit: APP_USER_SCOPE_NAME is MDM.User and createUserTokenVerifier (MDM.Agent) is unaffected', () => {
  assert.strictEqual(APP_USER_SCOPE_NAME, 'MDM.User');
  assert.strictEqual(AGENT_SCOPE_NAME, 'MDM.Agent');
});
