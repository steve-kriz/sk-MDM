import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { createHash } from 'node:crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Import compiled contract functions
const contractPath = join(__dirname, '../../dist/contract/signing.js');
const { canonicalString, canonicalQuery, bodyHash, signRequest, verifySignature } = await import(`file://${contractPath}`);

// Load signing vectors
const vectorsPath = join(__dirname, '../../../contract/testdata/signing-vectors.json');
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf-8'));

test('Canonical string is built from the seven parts', async (t) => {
  // Given a GET request for /api/v1/devices/d1/commands with query max=5, timestamp and empty body
  const parts = {
    method: 'get',
    path: '/api/v1/devices/d1/commands',
    query: 'max=5',
    body: '',
    timestamp: 1760000000,
    nonce: 'nonce-value',
    deviceId: 'd1'
  };

  // When canonicalString runs
  const result = canonicalString(parts);
  const lines = result.split('\n');

  // Then the result's fourth line is the SHA-256 hex of zero bytes
  const expectedBodyHash = createHash('sha256').update(Buffer.alloc(0)).digest('hex');
  assert.equal(lines[3], expectedBodyHash, 'body hash line should be SHA-256 of zero bytes');

  // And the fifth line is "1760000000" and the last line is "d1"
  assert.equal(lines[4], '1760000000', 'timestamp line should be 1760000000');
  assert.equal(lines[6], 'd1', 'last line should be d1 (deviceId)');

  // And METHOD is upper-cased
  assert.equal(lines[0], 'GET', 'method should be upper-cased');
  assert.equal(lines[1], '/api/v1/devices/d1/commands', 'path should be exact');
});

test('Query pairs are ordered', async (t) => {
  // Given a query of "b=2&a=1&a=0"
  const query = 'b=2&a=1&a=0';

  // When canonicalQuery runs
  const result = canonicalQuery(query);

  // Then the canonicalQuery line is "a=0&a=1&b=2"
  assert.equal(result, 'a=0&a=1&b=2', 'query should be sorted by key then by value');
});

test('Signature carries the v1 prefix', async (t) => {
  // Given a known secret and parts
  const secretHex = 'deadbeefcafef00dfeedfacebadc0ffee1d0c0de5afe1dea0123456789abcdef';
  const parts = {
    method: 'GET',
    path: '/api/v1/devices/dev-001/commands',
    query: '',
    body: '',
    timestamp: 1760000000,
    nonce: 'nonce-value',
    deviceId: 'dev-001'
  };

  // When signRequest runs
  const signature = signRequest(secretHex, parts);

  // Then the output starts with "v1=" and has 64 hex characters after it
  assert.ok(signature.startsWith('v1='), 'signature should start with v1=');
  const hexPart = signature.slice(3);
  assert.equal(hexPart.length, 64, 'signature should have 64 hex characters after v1=');
  assert.match(hexPart, /^[0-9a-f]{64}$/, 'signature hex part should be lowercase hex');
});

test('Go and Node agree on every vector', async (t) => {
  // Given contract/testdata/signing-vectors.json
  for (const vector of vectors) {
    // When the Node test signs the vector
    const parts = {
      method: vector.method,
      path: vector.path,
      query: vector.query,
      body: vector.body,
      timestamp: vector.timestamp,
      nonce: vector.nonce,
      deviceId: vector.deviceId
    };

    const canonical = canonicalString(parts);
    const signature = signRequest(vector.secretHex, parts);

    // Then the produced canonical string and signature equal the vector's expected values
    assert.equal(canonical, vector.canonical, `canonical string mismatch for vector: ${vector.name}`);
    assert.equal(signature, vector.signature, `signature mismatch for vector: ${vector.name}`);
  }
});

test('Vectors cover only signed device operations', async (t) => {
  // When I read every vector in contract/testdata/signing-vectors.json
  for (const vector of vectors) {
    // Then every path starts with "/api/v1/devices/" and none equals "/api/v1/enroll"
    assert.ok(
      vector.path.startsWith('/api/v1/devices/'),
      `vector ${vector.name} path ${vector.path} should start with /api/v1/devices/`
    );
    assert.notEqual(
      vector.path,
      '/api/v1/enroll',
      `vector ${vector.name} should not be /api/v1/enroll`
    );
  }
});

test('Unicode body hashes as UTF-8', async (t) => {
  // Given the vector whose body contains "naïve-日本"
  const unicodeVector = vectors.find(v => v.body.includes('naïve-日本'));
  assert.ok(unicodeVector, 'should have a vector with unicode content');

  // When both implementations sign it
  const parts = {
    method: unicodeVector.method,
    path: unicodeVector.path,
    query: unicodeVector.query,
    body: unicodeVector.body,
    timestamp: unicodeVector.timestamp,
    nonce: unicodeVector.nonce,
    deviceId: unicodeVector.deviceId
  };

  const signature = signRequest(unicodeVector.secretHex, parts);

  // Then the signature matches the vector's expected value
  assert.equal(signature, unicodeVector.signature, 'unicode vector signature should match');
});

test('Wrong secret fails verification', async (t) => {
  // Given a signature produced with secret A
  const secretA = 'deadbeefcafef00dfeedfacebadc0ffee1d0c0de5afe1dea0123456789abcdef';
  const secretB = '11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff';

  const parts = {
    method: 'GET',
    path: '/api/v1/devices/dev-001/commands',
    query: '',
    body: '',
    timestamp: 1760000000,
    nonce: 'nonce-value',
    deviceId: 'dev-001'
  };

  const signatureWithA = signRequest(secretA, parts);

  // When verifySignature runs with secret B
  const verified = verifySignature(secretB, parts, signatureWithA);

  // Then it returns false
  assert.equal(verified, false, 'verification with wrong secret should fail');
});

test('Signature without the v1 prefix is refused', async (t) => {
  // Given the header value "v2=00112233"
  const header = 'v2=00112233';

  const parts = {
    method: 'GET',
    path: '/api/v1/devices/dev-001/commands',
    query: '',
    body: '',
    timestamp: 1760000000,
    nonce: 'nonce-value',
    deviceId: 'dev-001'
  };

  // When verifySignature runs
  const result = verifySignature('deadbeefcafef00dfeedfacebadc0ffee1d0c0de5afe1dea0123456789abcdef', parts, header);

  // Then it returns false and no exception is thrown
  assert.equal(result, false, 'verification should return false for wrong prefix');
});

test('Empty body edge case', async (t) => {
  // Given a signing vector whose body is empty
  const emptyBodyVector = vectors.find(v => v.body === '');
  assert.ok(emptyBodyVector, 'should have a vector with empty body');

  // The body hash line is the SHA-256 of zero bytes, not an empty string
  const parts = {
    method: emptyBodyVector.method,
    path: emptyBodyVector.path,
    query: emptyBodyVector.query,
    body: '',
    timestamp: emptyBodyVector.timestamp,
    nonce: emptyBodyVector.nonce,
    deviceId: emptyBodyVector.deviceId
  };

  const canonical = canonicalString(parts);
  const lines = canonical.split('\n');
  const expectedBodyHash = createHash('sha256').update(Buffer.alloc(0)).digest('hex');
  assert.equal(lines[3], expectedBodyHash, 'empty body should hash to SHA-256 of zero bytes');
});

test('Timestamp is rendered without padding or sign', async (t) => {
  // Given various timestamps
  const testCases = [
    { ts: 1760000000, expected: '1760000000' },
    { ts: 1, expected: '1' },
    { ts: 999, expected: '999' }
  ];

  for (const testCase of testCases) {
    const parts = {
      method: 'GET',
      path: '/api/v1/devices/dev-001/commands',
      query: '',
      body: '',
      timestamp: testCase.ts,
      nonce: 'nonce-value',
      deviceId: 'dev-001'
    };

    const canonical = canonicalString(parts);
    const lines = canonical.split('\n');
    assert.equal(lines[4], testCase.expected, `timestamp ${testCase.ts} should render as ${testCase.expected}`);
  }
});

test('Query with leading question mark is handled', async (t) => {
  // Given a query with a leading ?
  const result1 = canonicalQuery('?a=1&b=2');
  const result2 = canonicalQuery('a=1&b=2');

  // Both should produce the same canonical form
  assert.equal(result1, result2, 'leading ? should be stripped');
});

test('Body hash with null and undefined', async (t) => {
  // Given parts with null and undefined bodies
  const expectedZeroHash = createHash('sha256').update(Buffer.alloc(0)).digest('hex');

  const parts1 = {
    method: 'POST',
    path: '/api/v1/devices/dev-001/checkin',
    query: '',
    body: null,
    timestamp: 1760000000,
    nonce: 'nonce-value',
    deviceId: 'dev-001'
  };

  const parts2 = {
    method: 'POST',
    path: '/api/v1/devices/dev-001/checkin',
    query: '',
    body: undefined,
    timestamp: 1760000000,
    nonce: 'nonce-value',
    deviceId: 'dev-001'
  };

  const canonical1 = canonicalString(parts1);
  const canonical2 = canonicalString(parts2);

  const lines1 = canonical1.split('\n');
  const lines2 = canonical2.split('\n');

  assert.equal(lines1[3], expectedZeroHash, 'null body should hash to zero bytes');
  assert.equal(lines2[3], expectedZeroHash, 'undefined body should hash to zero bytes');
});

test('Constant time comparison in verifySignature', async (t) => {
  // Given a valid signature
  const secretHex = 'deadbeefcafef00dfeedfacebadc0ffee1d0c0de5afe1dea0123456789abcdef';
  const parts = {
    method: 'GET',
    path: '/api/v1/devices/dev-001/commands',
    query: '',
    body: '',
    timestamp: 1760000000,
    nonce: 'nonce-value',
    deviceId: 'dev-001'
  };

  const validSignature = signRequest(secretHex, parts);

  // When we verify with a slightly different signature (different last char)
  const wrongSignature = validSignature.slice(0, -1) + (validSignature[validSignature.length - 1] === '0' ? '1' : '0');

  // Then verification should still fail (constant time doesn't affect the result, just prevents timing attacks)
  const result = verifySignature(secretHex, parts, wrongSignature);
  assert.equal(result, false, 'different signature should not verify');
});

test('Non-hex secret in signRequest', async (t) => {
  // Given a secret with non-hex characters
  const invalidSecret = 'not-hex-characters!!';
  const parts = {
    method: 'GET',
    path: '/api/v1/devices/dev-001/commands',
    query: '',
    body: '',
    timestamp: 1760000000,
    nonce: 'nonce-value',
    deviceId: 'dev-001'
  };

  // When signRequest is called with invalid hex
  // It should throw an error (in TypeScript) or return false in verify
  try {
    signRequest(invalidSecret, parts);
    assert.fail('should throw on invalid hex');
  } catch (e) {
    // Expected to throw
    assert.ok(e);
  }
});

test('Query object format with repeated keys', async (t) => {
  // Given query as an object with repeated keys
  const query = {
    'a': ['0', '1'],
    'b': '2'
  };

  const canonical = canonicalQuery(query);
  assert.equal(canonical, 'a=0&a=1&b=2', 'object with array values should handle repeated keys');
});
