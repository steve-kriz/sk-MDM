/**
 * Unit tests for device secret encryption/decryption (TASK-005).
 * Tests the AES-256-GCM envelope encryption with deviceId as AAD.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { encryptDeviceSecret, decryptDeviceSecret, SECRET_ENC_LENGTH } = await import(
  `file://${join(__dirname, '../../dist/crypto/deviceSecret.js')}`
);

// Helper to generate a valid 64-char hex string
function randomHex(bytes = 32) {
  return randomBytes(bytes).toString('hex');
}

test('Device secret round-trips successfully', async (t) => {
  // Given a 64-hex secret, a 64-hex pepper and deviceId "d1"
  const secret = randomHex(32);
  const pepper = randomHex(32);
  const deviceId = 'd1';

  // When encryptDeviceSecret then decryptDeviceSecret run
  const encrypted = encryptDeviceSecret(secret, pepper, deviceId);
  const decrypted = decryptDeviceSecret(encrypted, pepper, deviceId);

  // Then the output equals the original secret
  assert.strictEqual(decrypted, secret, 'decrypted secret should match original');

  // And the ciphertext is 80 base64 characters
  assert.strictEqual(encrypted.length, SECRET_ENC_LENGTH, `encrypted should be ${SECRET_ENC_LENGTH} chars`);
  assert.match(encrypted, /^[A-Za-z0-9+/]{80}$/, 'encrypted should be valid base64');
});

test('Decrypting with different deviceId throws', async (t) => {
  // Given a 64-hex secret, a 64-hex pepper and deviceId "d1"
  const secret = randomHex(32);
  const pepper = randomHex(32);
  const deviceId = 'd1';

  // When encryptDeviceSecret runs
  const encrypted = encryptDeviceSecret(secret, pepper, deviceId);

  // And decryptDeviceSecret runs with deviceId "d2"
  // Then it throws
  assert.throws(
    () => decryptDeviceSecret(encrypted, pepper, 'd2'),
    Error,
    'should throw on AAD mismatch'
  );
});

test('Decrypting with different pepper throws', async (t) => {
  // Given a 64-hex secret, a 64-hex pepper and deviceId "d1"
  const secret = randomHex(32);
  const pepper = randomHex(32);
  const wrongPepper = randomHex(32);
  const deviceId = 'd1';

  // When encryptDeviceSecret runs with the correct pepper
  const encrypted = encryptDeviceSecret(secret, pepper, deviceId);

  // And decryptDeviceSecret runs with the wrong pepper
  // Then it throws
  assert.throws(
    () => decryptDeviceSecret(encrypted, wrongPepper, deviceId),
    Error,
    'should throw on key mismatch'
  );
});

test('Decrypting tampered ciphertext throws', async (t) => {
  // Given a 64-hex secret, a 64-hex pepper and deviceId "d1"
  const secret = randomHex(32);
  const pepper = randomHex(32);
  const deviceId = 'd1';

  // When encryptDeviceSecret runs
  const encrypted = encryptDeviceSecret(secret, pepper, deviceId);

  // Tamper with one character in the middle of the base64 string
  const tampered = encrypted.slice(0, 40) + (encrypted[40] === 'A' ? 'B' : 'A') + encrypted.slice(41);

  // Then decryptDeviceSecret throws
  assert.throws(
    () => decryptDeviceSecret(tampered, pepper, deviceId),
    Error,
    'should throw on tampered ciphertext'
  );
});

test('Invalid pepper throws with helpful message', async (t) => {
  // Given an invalid pepper (too short)
  const secret = randomHex(32);
  const invalidPepper = 'abc';
  const deviceId = 'd1';

  // When encryptDeviceSecret is called
  // Then it throws with a message naming pepper
  assert.throws(
    () => encryptDeviceSecret(secret, invalidPepper, deviceId),
    /pepper/i,
    'should name pepper in error'
  );
});

test('Invalid device secret throws with helpful message', async (t) => {
  // Given an invalid secret (not hex)
  const invalidSecret = 'not-hex';
  const pepper = randomHex(32);
  const deviceId = 'd1';

  // When encryptDeviceSecret is called
  // Then it throws with a message naming device secret
  assert.throws(
    () => encryptDeviceSecret(invalidSecret, pepper, deviceId),
    /device secret/i,
    'should name device secret in error'
  );
});

test('Invalid secretEnc format throws', async (t) => {
  // Given a pepper and deviceId
  const pepper = randomHex(32);
  const deviceId = 'd1';

  // When decryptDeviceSecret is called with invalid base64
  // Then it throws with a message about secretEnc
  assert.throws(
    () => decryptDeviceSecret('not-valid-base64-!!!', pepper, deviceId),
    /secretEnc/i,
    'should name secretEnc in error'
  );
});

test('Valid secretEnc with wrong length throws', async (t) => {
  // Given a valid base64 string but wrong length
  const pepper = randomHex(32);
  const deviceId = 'd1';
  const wrongLength = Buffer.from('test').toString('base64'); // 8 chars, not 80

  // When decryptDeviceSecret is called
  // Then it throws
  assert.throws(
    () => decryptDeviceSecret(wrongLength, pepper, deviceId),
    Error,
    'should throw on wrong length'
  );
});

test('Empty deviceId throws', async (t) => {
  // Given a valid secret and pepper but empty deviceId
  const secret = randomHex(32);
  const pepper = randomHex(32);

  // When encryptDeviceSecret is called with empty deviceId
  // Then it throws
  assert.throws(
    () => encryptDeviceSecret(secret, pepper, ''),
    /deviceId/i,
    'should throw on empty deviceId'
  );
});

test('Multiple encryptions produce different ciphertexts', async (t) => {
  // Given a 64-hex secret, pepper and deviceId
  const secret = randomHex(32);
  const pepper = randomHex(32);
  const deviceId = 'd1';

  // When encryptDeviceSecret runs twice
  const encrypted1 = encryptDeviceSecret(secret, pepper, deviceId);
  const encrypted2 = encryptDeviceSecret(secret, pepper, deviceId);

  // Then the ciphertexts are different (due to random IV)
  assert.notStrictEqual(encrypted1, encrypted2, 'random IV should produce different ciphertexts');

  // But both decrypt to the same secret
  const decrypted1 = decryptDeviceSecret(encrypted1, pepper, deviceId);
  const decrypted2 = decryptDeviceSecret(encrypted2, pepper, deviceId);
  assert.strictEqual(decrypted1, secret);
  assert.strictEqual(decrypted2, secret);
});
