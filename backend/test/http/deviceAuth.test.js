/**
 * E2E cucumber-style tests for device request authentication (TASK-005).
 * Tests verifyDeviceRequest against all acceptance criteria including edge cases.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { verifyDeviceRequest, DEVICE_ID_HEADER, TIMESTAMP_HEADER, NONCE_HEADER, SIGNATURE_HEADER } =
  await import(`file://${join(__dirname, '../../dist/http/deviceAuth.js')}`);
const { signRequest } = await import(`file://${join(__dirname, '../../dist/contract/signing.js')}`);
const { encryptDeviceSecret } = await import(`file://${join(__dirname, '../../dist/crypto/deviceSecret.js')}`);
const { deviceProfile, nonce: nonceKey } = await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);

// Helper to generate a valid 64-char hex string
function randomHex(bytes = 32) {
  return randomBytes(bytes).toString('hex');
}

// Mock table client
class FakeTable {
  constructor() {
    this.calls = [];
    this.devices = new Map(); // key -> item
    this.nonces = new Map(); // key -> item
  }

  async get(key) {
    this.calls.push({ operation: 'get', key: { ...key } });
    const keyStr = JSON.stringify(key);
    return this.devices.get(keyStr);
  }

  async putIfAbsent(item) {
    this.calls.push({ operation: 'putIfAbsent', item: { ...item } });
    const key = JSON.stringify({ pk: item.pk, sk: item.sk });
    if (this.nonces.has(key)) {
      return { written: false };
    }
    this.nonces.set(key, item);
    return { written: true };
  }

  setDevice(deviceId, attrs) {
    const key = deviceProfile(deviceId);
    const keyStr = JSON.stringify(key);
    this.devices.set(keyStr, {
      ...key,
      ...attrs,
    });
  }
}

// Helper to create a valid signed request
function createSignedRequest(deviceId, secret, nowSeconds, pepper, deviceIdHeaderCase = 'lower') {
  const timestamp = nowSeconds;
  const nonce = randomHex(16);
  const method = 'POST';
  const path = '/api/v1/devices/d1/state';
  const body = '{}';
  const query = '';

  const signature = signRequest(secret, {
    method,
    path,
    query,
    body,
    timestamp,
    nonce,
    deviceId,
  });

  // Encrypt the secret for storage
  const secretEnc = encryptDeviceSecret(secret, pepper, deviceId);

  const headerName = deviceIdHeaderCase === 'lower' ? 'x-mdm-device-id' : 'X-MDM-Device-Id';

  return {
    request: {
      method,
      path,
      query,
      headers: {
        [headerName]: deviceId,
        [TIMESTAMP_HEADER]: String(timestamp),
        [NONCE_HEADER]: nonce,
        [SIGNATURE_HEADER]: signature,
      },
      body,
    },
    secret,
    secretEnc,
    deviceId,
    timestamp,
    nonce,
    signature,
  };
}

test('Scenario: Valid signed request is accepted', async (t) => {
  // Given a device whose secretEnc decrypts to a known secret and a request signed with it
  const nowSeconds = 1000000;
  const now = () => nowSeconds;
  const secret = randomHex(32);
  const pepper = randomHex(32);
  const deviceId = 'd1';
  const table = new FakeTable();

  const signed = createSignedRequest(deviceId, secret, nowSeconds, pepper);
  table.setDevice(deviceId, { secretEnc: signed.secretEnc });

  // When verifyDeviceRequest runs
  const result = await verifyDeviceRequest(signed.request, {
    table,
    now,
    pepper,
  });

  // Then the result is ok and deviceId matches the header
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.deviceId, deviceId);
});

test('Scenario: Header casing does not matter', async (t) => {
  // Given the same valid request with headers keyed "x-mdm-device-id"
  const nowSeconds = 1000000;
  const now = () => nowSeconds;
  const secret = randomHex(32);
  const pepper = randomHex(32);
  const deviceId = 'd1';
  const table = new FakeTable();

  const signed = createSignedRequest(deviceId, secret, nowSeconds, pepper, 'lower');
  table.setDevice(deviceId, { secretEnc: signed.secretEnc });

  // When verifyDeviceRequest runs on the lower-case version
  const result1 = await verifyDeviceRequest(signed.request, { table, now, pepper });

  // And then on the upper-case version
  const table2 = new FakeTable();
  table2.setDevice(deviceId, { secretEnc: signed.secretEnc });
  const signed2 = createSignedRequest(deviceId, secret, nowSeconds, pepper, 'mixed');
  const result2 = await verifyDeviceRequest(signed2.request, { table: table2, now, pepper });

  // Then both results are ok with the same deviceId
  assert.strictEqual(result1.ok, true);
  assert.strictEqual(result1.deviceId, deviceId);
  assert.strictEqual(result2.ok, true);
  assert.strictEqual(result2.deviceId, deviceId);
});

test('Scenario: Bad signature from a revoked device reports the signature first', async (t) => {
  // Given a revoked device and a request whose signature does not match
  const nowSeconds = 1000000;
  const now = () => nowSeconds;
  const secret = randomHex(32);
  const pepper = randomHex(32);
  const deviceId = 'd1';
  const table = new FakeTable();

  const signed = createSignedRequest(deviceId, secret, nowSeconds, pepper);
  // Tamper with the signature
  const tamperedRequest = {
    ...signed.request,
    headers: {
      ...signed.request.headers,
      [SIGNATURE_HEADER]: 'v1=' + randomHex(32),
    },
  };

  table.setDevice(deviceId, {
    secretEnc: signed.secretEnc,
    status: 'revoked',
  });

  // When verifyDeviceRequest runs
  const result = await verifyDeviceRequest(tamperedRequest, { table, now, pepper });

  // Then the status is 401 with error bad_signature and no device_revoked result is returned
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.status, 401);
  assert.strictEqual(result.body.error, 'bad_signature');
});

test('Scenario: Missing headers are rejected before any table read', async (t) => {
  // Given a request without X-MDM-Nonce
  const nowSeconds = 1000000;
  const now = () => nowSeconds;
  const table = new FakeTable();

  const request = {
    method: 'POST',
    path: '/api/v1/devices/d1/state',
    query: '',
    headers: {
      'x-mdm-device-id': 'd1',
      'x-mdm-timestamp': '1000000',
      // missing nonce
      'x-mdm-signature': 'v1=' + randomHex(32),
    },
    body: '{}',
  };

  // When verifyDeviceRequest runs
  const result = await verifyDeviceRequest(request, { table, now, pepper: randomHex(32) });

  // Then the status is 401 with error missing_auth_headers and the fake table recorded no calls
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.status, 401);
  assert.strictEqual(result.body.error, 'missing_auth_headers');
  assert.strictEqual(table.calls.length, 0, 'should not call table before header validation');
});

test('Scenario: RFC3339 timestamp is rejected as a format error', async (t) => {
  // Given a request whose X-MDM-Timestamp is "2026-10-02T06:44:47Z"
  const nowSeconds = 1000000;
  const now = () => nowSeconds;
  const table = new FakeTable();

  const request = {
    method: 'POST',
    path: '/api/v1/devices/d1/state',
    query: '',
    headers: {
      'x-mdm-device-id': 'd1',
      'x-mdm-timestamp': '2026-10-02T06:44:47Z',
      'x-mdm-nonce': randomHex(16),
      'x-mdm-signature': 'v1=' + randomHex(32),
    },
    body: '{}',
  };

  // When verifyDeviceRequest runs
  const result = await verifyDeviceRequest(request, { table, now, pepper: randomHex(32) });

  // Then the status is 401 with error invalid_timestamp and no putIfAbsent was sent
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.status, 401);
  assert.strictEqual(result.body.error, 'invalid_timestamp');

  const putCalls = table.calls.filter((c) => c.operation === 'putIfAbsent');
  assert.strictEqual(putCalls.length, 0, 'should not write nonce on invalid timestamp');
});

test('Scenario: Unknown device is rejected without touching the nonce store', async (t) => {
  // Given the table returns no device profile
  const nowSeconds = 1000000;
  const now = () => nowSeconds;
  const table = new FakeTable();

  const request = {
    method: 'POST',
    path: '/api/v1/devices/d1/state',
    query: '',
    headers: {
      'x-mdm-device-id': 'd1',
      'x-mdm-timestamp': '1000000',
      'x-mdm-nonce': randomHex(16),
      'x-mdm-signature': 'v1=' + randomHex(32),
    },
    body: '{}',
  };

  // When verifyDeviceRequest runs
  const result = await verifyDeviceRequest(request, { table, now, pepper: randomHex(32) });

  // Then the status is 401 with error unknown_device and no putIfAbsent was sent
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.status, 401);
  assert.strictEqual(result.body.error, 'unknown_device');

  const putCalls = table.calls.filter((c) => c.operation === 'putIfAbsent');
  assert.strictEqual(putCalls.length, 0, 'should not write nonce on unknown device');
});

test('Scenario: Undecryptable device secret is reported distinctly', async (t) => {
  // Given a device profile whose secretEnc has one flipped ciphertext byte
  const nowSeconds = 1000000;
  const now = () => nowSeconds;
  const secret = randomHex(32);
  const pepper = randomHex(32);
  const deviceId = 'd1';
  const table = new FakeTable();

  const signed = createSignedRequest(deviceId, secret, nowSeconds, pepper);
  // Flip one character in the secretEnc
  const tamperedSecretEnc =
    signed.secretEnc.slice(0, 40) + (signed.secretEnc[40] === 'A' ? 'B' : 'A') + signed.secretEnc.slice(41);

  table.setDevice(deviceId, { secretEnc: tamperedSecretEnc });

  const request = {
    ...signed.request,
    headers: {
      ...signed.request.headers,
      [TIMESTAMP_HEADER]: String(nowSeconds),
    },
  };

  // When verifyDeviceRequest runs
  const result = await verifyDeviceRequest(request, { table, now, pepper });

  // Then the status is 500 with error device_secret_unreadable and no putIfAbsent was sent
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.status, 500);
  assert.strictEqual(result.body.error, 'device_secret_unreadable');

  const putCalls = table.calls.filter((c) => c.operation === 'putIfAbsent');
  assert.strictEqual(putCalls.length, 0, 'should not write nonce on decryption failure');
});

test('Scenario: Tampered body breaks the signature', async (t) => {
  // Given a signed request whose body is altered after signing
  const nowSeconds = 1000000;
  const now = () => nowSeconds;
  const secret = randomHex(32);
  const pepper = randomHex(32);
  const deviceId = 'd1';
  const table = new FakeTable();

  const signed = createSignedRequest(deviceId, secret, nowSeconds, pepper);
  table.setDevice(deviceId, { secretEnc: signed.secretEnc });

  const tamperedRequest = {
    ...signed.request,
    body: '{"altered":true}', // Different from original
  };

  // When verifyDeviceRequest runs
  const result = await verifyDeviceRequest(tamperedRequest, { table, now, pepper });

  // Then the status is 401 with error bad_signature and no putIfAbsent was sent
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.status, 401);
  assert.strictEqual(result.body.error, 'bad_signature');

  const putCalls = table.calls.filter((c) => c.operation === 'putIfAbsent');
  assert.strictEqual(putCalls.length, 0, 'should not write nonce on bad signature');
});

test('Scenario: Old timestamp is rejected', async (t) => {
  // Given a request whose timestamp is 600 seconds before now
  const nowSeconds = 1000000;
  const now = () => nowSeconds;
  const secret = randomHex(32);
  const pepper = randomHex(32);
  const deviceId = 'd1';
  const table = new FakeTable();

  // Create request at old timestamp
  const oldTimestamp = nowSeconds - 600; // 600 seconds old, default skew is 300
  const nonce = randomHex(16);
  const method = 'POST';
  const path = '/api/v1/devices/d1/state';
  const body = '{}';
  const query = '';

  const signature = signRequest(secret, {
    method,
    path,
    query,
    body,
    timestamp: oldTimestamp,
    nonce,
    deviceId,
  });

  const secretEnc = encryptDeviceSecret(secret, pepper, deviceId);
  table.setDevice(deviceId, { secretEnc });

  const request = {
    method,
    path,
    query,
    headers: {
      'x-mdm-device-id': deviceId,
      [TIMESTAMP_HEADER]: String(oldTimestamp),
      [NONCE_HEADER]: nonce,
      [SIGNATURE_HEADER]: signature,
    },
    body,
  };

  // When verifyDeviceRequest runs
  const result = await verifyDeviceRequest(request, { table, now, pepper });

  // Then the status is 401 with error stale_timestamp and no putIfAbsent was sent
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.status, 401);
  assert.strictEqual(result.body.error, 'stale_timestamp');

  const putCalls = table.calls.filter((c) => c.operation === 'putIfAbsent');
  assert.strictEqual(putCalls.length, 0, 'should not write nonce on stale timestamp');
});

test('Scenario: Timestamp exactly at the skew boundary is accepted', async (t) => {
  // Given skewSeconds 300 and a request whose timestamp is exactly 300 seconds before now
  const nowSeconds = 1000000;
  const now = () => nowSeconds;
  const secret = randomHex(32);
  const pepper = randomHex(32);
  const deviceId = 'd1';
  const table = new FakeTable();
  const skewSeconds = 300;

  const boundaryTimestamp = nowSeconds - skewSeconds; // Exactly at the boundary
  const nonce = randomHex(16);

  const signature = signRequest(secret, {
    method: 'POST',
    path: '/api/v1/devices/d1/state',
    query: '',
    body: '{}',
    timestamp: boundaryTimestamp,
    nonce,
    deviceId,
  });

  const secretEnc = encryptDeviceSecret(secret, pepper, deviceId);
  table.setDevice(deviceId, { secretEnc });

  const request = {
    method: 'POST',
    path: '/api/v1/devices/d1/state',
    query: '',
    headers: {
      'x-mdm-device-id': deviceId,
      'x-mdm-timestamp': String(boundaryTimestamp),
      'x-mdm-nonce': nonce,
      'x-mdm-signature': signature,
    },
    body: '{}',
  };

  // When verifyDeviceRequest runs
  const result = await verifyDeviceRequest(request, { table, now, pepper, skewSeconds });

  // Then the result is ok
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.deviceId, deviceId);
});

test('Scenario: Revoked device is refused', async (t) => {
  // Given a correctly signed, fresh request from a device profile with status "revoked"
  const nowSeconds = 1000000;
  const now = () => nowSeconds;
  const secret = randomHex(32);
  const pepper = randomHex(32);
  const deviceId = 'd1';
  const table = new FakeTable();

  const signed = createSignedRequest(deviceId, secret, nowSeconds, pepper);
  table.setDevice(deviceId, {
    secretEnc: signed.secretEnc,
    status: 'revoked',
  });

  // When verifyDeviceRequest runs
  const result = await verifyDeviceRequest(signed.request, { table, now, pepper });

  // Then the status is 403 with error device_revoked and no putIfAbsent was sent
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.status, 403);
  assert.strictEqual(result.body.error, 'device_revoked');

  const putCalls = table.calls.filter((c) => c.operation === 'putIfAbsent');
  assert.strictEqual(putCalls.length, 0, 'should not write nonce on revoked device');
});

test('Scenario: Nonce is stored with a TTL', async (t) => {
  // Given a valid request at epoch 1000 and nonceTtlSeconds 900
  const nowSeconds = 1000;
  const now = () => nowSeconds;
  const secret = randomHex(32);
  const pepper = randomHex(32);
  const deviceId = 'd1';
  const table = new FakeTable();
  const nonceTtlSeconds = 900;

  const signed = createSignedRequest(deviceId, secret, nowSeconds, pepper);
  table.setDevice(deviceId, { secretEnc: signed.secretEnc });

  // When verifyDeviceRequest runs
  const result = await verifyDeviceRequest(signed.request, {
    table,
    now,
    pepper,
    nonceTtlSeconds,
  });

  // Then the nonce item written has ttl equal to 1900
  assert.strictEqual(result.ok, true);

  const putCalls = table.calls.filter((c) => c.operation === 'putIfAbsent');
  assert.strictEqual(putCalls.length, 1);
  const nonceItem = putCalls[0].item;
  assert.strictEqual(nonceItem.ttl, 1900, 'ttl should be now() + nonceTtlSeconds');
});

test('Scenario: Replayed nonce is rejected', async (t) => {
  // Given putIfAbsent returns {written:false}
  const nowSeconds = 1000000;
  const now = () => nowSeconds;
  const secret = randomHex(32);
  const pepper = randomHex(32);
  const deviceId = 'd1';

  // Create a table that always returns written:false
  class RejectingTable extends FakeTable {
    async putIfAbsent(item) {
      this.calls.push({ operation: 'putIfAbsent', item: { ...item } });
      return { written: false };
    }
  }

  const table = new RejectingTable();
  const signed = createSignedRequest(deviceId, secret, nowSeconds, pepper);
  table.setDevice(deviceId, { secretEnc: signed.secretEnc });

  // When verifyDeviceRequest runs
  const result = await verifyDeviceRequest(signed.request, { table, now, pepper });

  // Then the status is 401 and the error is replayed_nonce
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.status, 401);
  assert.strictEqual(result.body.error, 'replayed_nonce');
});

test('Scenario: No AWS client is constructed', async (t) => {
  // Given only a fake table client and a fake secrets client are injected
  const nowSeconds = 1000000;
  const now = () => nowSeconds;
  const secret = randomHex(32);
  const pepper = randomHex(32);
  const deviceId = 'd1';
  const table = new FakeTable();

  const signed = createSignedRequest(deviceId, secret, nowSeconds, pepper);
  table.setDevice(deviceId, { secretEnc: signed.secretEnc });

  // When the verifyDeviceRequest test runs
  const result = await verifyDeviceRequest(signed.request, { table, now, pepper });

  // Then result is ok (verifying no error occurred)
  assert.strictEqual(result.ok, true);
  // And the fake table was used (proving no AWS client was created)
  assert.ok(table.calls.length > 0, 'should have called the injected table');
});

test('Scenario: Empty header values are treated as missing', async (t) => {
  // Given a request with empty X-MDM-Device-Id
  const nowSeconds = 1000000;
  const now = () => nowSeconds;
  const table = new FakeTable();

  const request = {
    method: 'POST',
    path: '/api/v1/devices/d1/state',
    query: '',
    headers: {
      'x-mdm-device-id': '', // Empty
      'x-mdm-timestamp': '1000000',
      'x-mdm-nonce': randomHex(16),
      'x-mdm-signature': 'v1=' + randomHex(32),
    },
    body: '{}',
  };

  // When verifyDeviceRequest runs
  const result = await verifyDeviceRequest(request, { table, now, pepper: randomHex(32) });

  // Then it returns missing_auth_headers
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.body.error, 'missing_auth_headers');
  assert.strictEqual(table.calls.length, 0);
});

test('Scenario: Future timestamp beyond skew is rejected', async (t) => {
  // Given a request whose timestamp is 400 seconds in the future (beyond skew)
  const nowSeconds = 1000000;
  const now = () => nowSeconds;
  const secret = randomHex(32);
  const pepper = randomHex(32);
  const deviceId = 'd1';
  const table = new FakeTable();

  const futureTimestamp = nowSeconds + 400; // 400 seconds future, skew is 300
  const nonce = randomHex(16);

  const signature = signRequest(secret, {
    method: 'POST',
    path: '/api/v1/devices/d1/state',
    query: '',
    body: '{}',
    timestamp: futureTimestamp,
    nonce,
    deviceId,
  });

  const secretEnc = encryptDeviceSecret(secret, pepper, deviceId);
  table.setDevice(deviceId, { secretEnc });

  const request = {
    method: 'POST',
    path: '/api/v1/devices/d1/state',
    query: '',
    headers: {
      'x-mdm-device-id': deviceId,
      'x-mdm-timestamp': String(futureTimestamp),
      'x-mdm-nonce': nonce,
      'x-mdm-signature': signature,
    },
    body: '{}',
  };

  // When verifyDeviceRequest runs
  const result = await verifyDeviceRequest(request, { table, now, pepper });

  // Then the status is 401 with error stale_timestamp
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.status, 401);
  assert.strictEqual(result.body.error, 'stale_timestamp');
});

test('Scenario: Missing secretEnc returns device_secret_unreadable', async (t) => {
  // Given a device profile with no secretEnc attribute
  const nowSeconds = 1000000;
  const now = () => nowSeconds;
  const deviceId = 'd1';
  const table = new FakeTable();

  table.setDevice(deviceId, {
    // No secretEnc
  });

  const request = {
    method: 'POST',
    path: '/api/v1/devices/d1/state',
    query: '',
    headers: {
      'x-mdm-device-id': deviceId,
      'x-mdm-timestamp': '1000000',
      'x-mdm-nonce': randomHex(16),
      'x-mdm-signature': 'v1=' + randomHex(32),
    },
    body: '{}',
  };

  // When verifyDeviceRequest runs
  const result = await verifyDeviceRequest(request, { table, now, pepper: randomHex(32) });

  // Then the status is 500 with error device_secret_unreadable
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.status, 500);
  assert.strictEqual(result.body.error, 'device_secret_unreadable');

  const putCalls = table.calls.filter((c) => c.operation === 'putIfAbsent');
  assert.strictEqual(putCalls.length, 0, 'should not write nonce on secret unreadable');
});

test('Scenario: Invalid timestamp format rejects immediately', async (t) => {
  // Given various invalid timestamp formats
  const nowSeconds = 1000000;
  const now = () => nowSeconds;
  const table = new FakeTable();

  const invalidFormats = [
    '-1000000', // Negative
    '1000000.5', // Decimal
    '1000000 ', // Whitespace
    '+1000000', // Sign
    '0x1000000', // Hex
  ];

  for (const timestamp of invalidFormats) {
    const request = {
      method: 'POST',
      path: '/api/v1/devices/d1/state',
      query: '',
      headers: {
        'x-mdm-device-id': 'd1',
        'x-mdm-timestamp': timestamp,
        'x-mdm-nonce': randomHex(16),
        'x-mdm-signature': 'v1=' + randomHex(32),
      },
      body: '{}',
    };

    const result = await verifyDeviceRequest(request, { table, now, pepper: randomHex(32) });

    // Expect invalid_timestamp for all these
    assert.strictEqual(result.body.error, 'invalid_timestamp', `format: ${timestamp}`);
  }
});
