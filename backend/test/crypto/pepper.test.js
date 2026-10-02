/**
 * Unit tests for pepper provider (TASK-005).
 * Tests the caching and SHA-256 hashing of the pepper secret.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { createPepperProvider, GET_SECRET_VALUE } = await import(
  `file://${join(__dirname, '../../dist/crypto/pepper.js')}`
);

test('Pepper is fetched once and cached', async (t) => {
  // Given a fake secrets client recording GetSecretValue calls
  const calls = [];
  const secretString = 'my-secret-pepper-value-12345678901234567890';
  const fakeClient = {
    getSecretValue: async ({ SecretId }) => {
      calls.push({ operation: 'getSecretValue', SecretId });
      return { SecretString: secretString };
    },
  };

  // When getPepper is awaited three times
  const provider = createPepperProvider({
    secretsClient: fakeClient,
    secretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:pepper',
  });

  const pepper1 = await provider.getPepper();
  const pepper2 = await provider.getPepper();
  const pepper3 = await provider();

  // Then one call was recorded
  assert.strictEqual(calls.length, 1, 'should fetch secret exactly once');

  // And each result is the same 64-hex string
  assert.strictEqual(pepper1, pepper2, 'getPepper() should return consistent value');
  assert.strictEqual(pepper2, pepper3, 'provider() should return same value');

  // And the result is the SHA-256 hex of the secret
  const expected = createHash('sha256').update(secretString, 'utf8').digest('hex');
  assert.strictEqual(pepper1, expected, 'pepper should be SHA-256 hex of secret');
  assert.strictEqual(pepper1.length, 64, 'pepper should be 64 hex characters');
  assert.match(pepper1, /^[0-9a-f]{64}$/, 'pepper should be lower-case hex');
});

test('Pepper provider is callable directly and has getPepper method', async (t) => {
  // Given a fake secrets client
  const secretString = 'test-secret';
  const fakeClient = {
    getSecretValue: async () => ({ SecretString: secretString }),
  };

  // When createPepperProvider runs
  const provider = createPepperProvider({
    secretsClient: fakeClient,
    secretArn: 'arn:test',
  });

  // Then the provider can be called as a function
  const result1 = await provider();
  assert.ok(typeof result1 === 'string' && result1.length === 64);

  // And it has a getPepper method
  assert.ok(typeof provider.getPepper === 'function');
  const result2 = await provider.getPepper();
  assert.strictEqual(result1, result2);
});

test('Pepper provider uses send() when getSecretValue is absent', async (t) => {
  // Given a fake client with only send() method
  const calls = [];
  const secretString = 'secret-via-send';
  const fakeClient = {
    send: async (command) => {
      calls.push(command);
      assert.strictEqual(command.operation, GET_SECRET_VALUE);
      return { SecretString: secretString };
    },
  };

  // When getPepper is awaited
  const provider = createPepperProvider({
    secretsClient: fakeClient,
    secretArn: 'arn:test',
  });
  const pepper = await provider();

  // Then the send method was called with operation GetSecretValue
  assert.strictEqual(calls.length, 1);
  assert.strictEqual(calls[0].operation, GET_SECRET_VALUE);

  // And the pepper is correct
  const expected = createHash('sha256').update(secretString, 'utf8').digest('hex');
  assert.strictEqual(pepper, expected);
});

test('Pepper works with SecretBinary as base64 string', async (t) => {
  // Given a fake client returning SecretBinary as base64
  const secretString = 'binary-secret';
  const secretBinary = Buffer.from(secretString, 'utf8').toString('base64');
  const fakeClient = {
    getSecretValue: async () => ({ SecretBinary: secretBinary }),
  };

  // When getPepper is awaited
  const provider = createPepperProvider({
    secretsClient: fakeClient,
    secretArn: 'arn:test',
  });
  const pepper = await provider();

  // Then the pepper is correct
  const expected = createHash('sha256').update(secretString, 'utf8').digest('hex');
  assert.strictEqual(pepper, expected);
});

test('Pepper works with SecretBinary as Uint8Array', async (t) => {
  // Given a fake client returning SecretBinary as Uint8Array
  const secretString = 'uint8-secret';
  const secretBinary = new TextEncoder().encode(secretString);
  const fakeClient = {
    getSecretValue: async () => ({ SecretBinary: secretBinary }),
  };

  // When getPepper is awaited
  const provider = createPepperProvider({
    secretsClient: fakeClient,
    secretArn: 'arn:test',
  });
  const pepper = await provider();

  // Then the pepper is correct
  const expected = createHash('sha256').update(secretString, 'utf8').digest('hex');
  assert.strictEqual(pepper, expected);
});

test('Pepper falls back to bare secret string', async (t) => {
  // Given a fake client returning the secret string directly
  const secretString = 'bare-secret-string';
  const fakeClient = {
    getSecretValue: async () => secretString,
  };

  // When getPepper is awaited
  const provider = createPepperProvider({
    secretsClient: fakeClient,
    secretArn: 'arn:test',
  });
  const pepper = await provider();

  // Then the pepper is correct
  const expected = createHash('sha256').update(secretString, 'utf8').digest('hex');
  assert.strictEqual(pepper, expected);
});

test('Failed fetch is not cached, allowing retry', async (t) => {
  // Given a fake client that fails once then succeeds
  let callCount = 0;
  const secretString = 'success-secret';
  const fakeClient = {
    getSecretValue: async () => {
      callCount++;
      if (callCount === 1) {
        throw new Error('temporary failure');
      }
      return { SecretString: secretString };
    },
  };

  // When getPepper is awaited the first time and it fails
  const provider = createPepperProvider({
    secretsClient: fakeClient,
    secretArn: 'arn:test',
  });

  let error1;
  try {
    await provider();
  } catch (e) {
    error1 = e;
  }
  assert.ok(error1, 'first call should throw');

  // Then when getPepper is awaited again
  const pepper = await provider();

  // It retries and succeeds
  assert.strictEqual(callCount, 2, 'should have called twice');
  const expected = createHash('sha256').update(secretString, 'utf8').digest('hex');
  assert.strictEqual(pepper, expected);
});

test('Invalid secretArn throws', async (t) => {
  // Given an empty secretArn
  const fakeClient = { getSecretValue: async () => ({ SecretString: 'secret' }) };

  // When createPepperProvider is called
  // Then it throws
  assert.throws(
    () =>
      createPepperProvider({
        secretsClient: fakeClient,
        secretArn: '',
      }),
    /secretArn/i
  );
});

test('Missing client method throws', async (t) => {
  // Given a fake client with neither getSecretValue nor send
  const fakeClient = {};

  // When getPepper is awaited
  const provider = createPepperProvider({
    secretsClient: fakeClient,
    secretArn: 'arn:test',
  });

  // Then it throws with a message about the client
  try {
    await provider();
    assert.fail('should have thrown');
  } catch (e) {
    assert.match(e.message, /secretsClient/i);
  }
});

test('Empty response throws', async (t) => {
  // Given a fake client returning empty response
  const fakeClient = {
    getSecretValue: async () => ({}),
  };

  // When getPepper is awaited
  const provider = createPepperProvider({
    secretsClient: fakeClient,
    secretArn: 'arn:test',
  });

  // Then it throws
  try {
    await provider();
    assert.fail('should have thrown');
  } catch (e) {
    assert.match(e.message, /unavailable/i);
  }
});
