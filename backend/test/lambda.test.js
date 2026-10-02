/**
 * Unit and e2e tests for the Lambda handler wrapper.
 *
 * These tests validate that the Lambda handler correctly memoizes bootstrap,
 * handles failures gracefully, and delegates to the index.ts handler on success.
 */

import test from 'node:test';
import assert from 'node:assert';
import { GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { createLambdaHandler, defaultLambdaOptions } from '../dist/lambda.js';
import { createSdkDocumentClient } from '../dist/aws/documentClient.js';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { handler as indexHandler } from '../dist/index.js';

// ============================================================================
// Bootstrap Memoization Tests
// ============================================================================

test('Lambda handler - Bootstrap is called once across sequential invocations', async (t) => {
  const documentClientCalls = [];
  const secretsClientCalls = [];

  const handler = createLambdaHandler({
    env: {
      TABLE_NAME: 'table',
      PEPPER_SECRET_ARN: 'arn:secret',
      ENTRA_TENANT_ID: 'tenant',
      ENTRA_CLIENT_ID: 'client',
    },
    createDocumentClient: () => {
      documentClientCalls.push(1);
      return { send: async () => ({}) };
    },
    createSecretsClient: () => {
      secretsClientCalls.push(1);
      return { send: async () => ({ SecretString: 'pepper' }) };
    },
    fetchImpl: async () => ({
      status: 200,
      json: async () => ({ keys: [] }),
    }),
  });

  const event = {
    requestContext: { http: { method: 'GET', path: '/' } },
    headers: {},
    body: '',
    isBase64Encoded: false,
  };

  // First invocation
  await handler(event);
  assert.strictEqual(documentClientCalls.length, 1);
  assert.strictEqual(secretsClientCalls.length, 1);

  // Second invocation - should not call factories again
  await handler(event);
  assert.strictEqual(documentClientCalls.length, 1);
  assert.strictEqual(secretsClientCalls.length, 1);
});

test('Lambda handler - Bootstrap is called once across concurrent invocations', async (t) => {
  const documentClientCalls = [];
  const secretsClientCalls = [];

  const handler = createLambdaHandler({
    env: {
      TABLE_NAME: 'table',
      PEPPER_SECRET_ARN: 'arn:secret',
      ENTRA_TENANT_ID: 'tenant',
      ENTRA_CLIENT_ID: 'client',
    },
    createDocumentClient: () => {
      documentClientCalls.push(1);
      return { send: async () => ({}) };
    },
    createSecretsClient: () => {
      secretsClientCalls.push(1);
      return { send: async () => ({ SecretString: 'pepper' }) };
    },
    fetchImpl: async () => ({
      status: 200,
      json: async () => ({ keys: [] }),
    }),
  });

  const event = {
    requestContext: { http: { method: 'GET', path: '/' } },
    headers: {},
    body: '',
    isBase64Encoded: false,
  };

  // Concurrent invocations
  await Promise.all([handler(event), handler(event)]);

  // Despite 2 concurrent calls, factories should be called only once
  assert.strictEqual(documentClientCalls.length, 1);
  assert.strictEqual(secretsClientCalls.length, 1);
});

// ============================================================================
// Bootstrap Failure and Retry Tests
// ============================================================================

test('Lambda handler - Bootstrap failure answers 503 and retries on next invocation', async (t) => {
  let secretsSendCount = 0;
  const handler = createLambdaHandler({
    env: {
      TABLE_NAME: 'table',
      PEPPER_SECRET_ARN: 'arn:secret',
      ENTRA_TENANT_ID: 'tenant',
      ENTRA_CLIENT_ID: 'client',
    },
    createDocumentClient: () => ({ send: async () => ({}) }),
    createSecretsClient: () => ({
      send: async () => {
        secretsSendCount++;
        if (secretsSendCount === 1) {
          throw new Error('Secrets Manager is down');
        }
        return { SecretString: 'pepper' };
      },
    }),
    fetchImpl: async () => ({
      status: 200,
      json: async () => ({ keys: [] }),
    }),
  });

  const event = {
    requestContext: { http: { method: 'GET', path: '/' } },
    headers: {},
    body: '',
    isBase64Encoded: false,
  };

  // First invocation: bootstrap fails
  const consoleErrors = [];
  const originalError = console.error;
  console.error = (...args) => consoleErrors.push(args.join(' '));

  const response1 = await handler(event);
  assert.strictEqual(response1.statusCode, 503);
  assert.deepStrictEqual(
    JSON.parse(response1.body),
    { error: 'service_unavailable' }
  );
  assert.strictEqual(response1.headers['content-type'], 'application/json');

  // Exactly one error line should have been logged
  const bootstrapErrors = consoleErrors.filter(line => line.includes('[bootstrap] failed:'));
  assert.strictEqual(bootstrapErrors.length, 1);
  assert.ok(bootstrapErrors[0].includes('Secrets Manager is down'));

  // Second invocation: bootstrap succeeds on retry
  consoleErrors.length = 0;
  const response2 = await handler(event);

  assert.strictEqual(secretsSendCount, 2);
  // Should succeed now (200 from UI handler)
  assert.ok(response2.statusCode === 200 || response2.statusCode === 404);

  console.error = originalError;
});

test('Lambda handler - Failed bootstrap does not cache the promise', async (t) => {
  let secretsSendCount = 0;
  const handler = createLambdaHandler({
    env: {
      TABLE_NAME: 'table',
      PEPPER_SECRET_ARN: 'arn:secret',
      ENTRA_TENANT_ID: 'tenant',
      ENTRA_CLIENT_ID: 'client',
    },
    createDocumentClient: () => ({ send: async () => ({}) }),
    createSecretsClient: () => ({
      send: async () => {
        secretsSendCount++;
        if (secretsSendCount === 1) {
          throw new Error('First call fails');
        }
        return { SecretString: 'pepper' };
      },
    }),
    fetchImpl: async () => ({
      status: 200,
      json: async () => ({ keys: [] }),
    }),
  });

  const event = {
    requestContext: { http: { method: 'GET', path: '/' } },
    headers: {},
    body: '',
    isBase64Encoded: false,
  };

  // Suppress error logging
  const originalError = console.error;
  console.error = () => {};

  // First invocation fails
  await handler(event);
  const count1 = secretsSendCount;

  // Second invocation retries
  await handler(event);
  const count2 = secretsSendCount;

  // Verify that secrets.send was called twice (once per invocation)
  assert.strictEqual(count1, 1);
  assert.strictEqual(count2, 2);

  console.error = originalError;
});

// ============================================================================
// Handler Delegation Tests
// ============================================================================

test('Lambda handler - Successful bootstrap delegates to index handler for GET /', async (t) => {
  const handler = createLambdaHandler({
    env: {
      TABLE_NAME: 'table',
      PEPPER_SECRET_ARN: 'arn:secret',
      ENTRA_TENANT_ID: 'tenant',
      ENTRA_CLIENT_ID: 'client',
    },
    createDocumentClient: () => ({ send: async () => ({}) }),
    createSecretsClient: () => ({ send: async () => ({ SecretString: 'pepper' }) }),
    fetchImpl: async () => ({
      status: 200,
      json: async () => ({ keys: [] }),
    }),
  });

  const event = {
    requestContext: { http: { method: 'GET', path: '/' } },
    headers: {},
    body: '',
    isBase64Encoded: false,
  };

  const response = await handler(event);

  // Should match index handler for same event
  const indexResponse = await indexHandler(event);

  assert.strictEqual(response.statusCode, indexResponse.statusCode);
  assert.strictEqual(response.headers['content-type'], indexResponse.headers['content-type']);
  // Both should return 200 for GET / (UI handler)
  assert.strictEqual(response.statusCode, 200);
});

test('Lambda handler - Successful bootstrap delegates to index handler for 404', async (t) => {
  const handler = createLambdaHandler({
    env: {
      TABLE_NAME: 'table',
      PEPPER_SECRET_ARN: 'arn:secret',
      ENTRA_TENANT_ID: 'tenant',
      ENTRA_CLIENT_ID: 'client',
    },
    createDocumentClient: () => ({ send: async () => ({}) }),
    createSecretsClient: () => ({ send: async () => ({ SecretString: 'pepper' }) }),
    fetchImpl: async () => ({
      status: 200,
      json: async () => ({ keys: [] }),
    }),
  });

  const event = {
    requestContext: { http: { method: 'GET', path: '/no-such-path' } },
    headers: {},
    body: '',
    isBase64Encoded: false,
  };

  const response = await handler(event);
  const indexResponse = await indexHandler(event);

  assert.strictEqual(response.statusCode, indexResponse.statusCode);
  assert.deepStrictEqual(JSON.parse(response.body), JSON.parse(indexResponse.body));
  assert.strictEqual(response.statusCode, 404);
});

// ============================================================================
// Default Lambda Options Tests
// ============================================================================

test('Lambda handler - defaultLambdaOptions.env is process.env', (t) => {
  assert.strictEqual(defaultLambdaOptions.env, process.env);
});

test('Lambda handler - defaultLambdaOptions.fetchImpl is globalThis.fetch', (t) => {
  assert.strictEqual(defaultLambdaOptions.fetchImpl, globalThis.fetch);
});

test('Lambda handler - defaultLambdaOptions.createDocumentClient is createSdkDocumentClient', (t) => {
  assert.strictEqual(defaultLambdaOptions.createDocumentClient, createSdkDocumentClient);
});

test('Lambda handler - defaultLambdaOptions.createSecretsClient returns SecretsManagerClient', (t) => {
  const client = defaultLambdaOptions.createSecretsClient();
  assert.ok(client instanceof SecretsManagerClient);
});

test('Lambda handler - Exported handler is built from defaultLambdaOptions', async (t) => {
  // The exported handler should use defaultLambdaOptions
  // We can't easily test this directly, but we can verify it's a function
  // and behaves like a Lambda handler
  const { handler } = await import('../dist/lambda.js');
  assert.strictEqual(typeof handler, 'function');
});

// ============================================================================
// Logging Tests
// ============================================================================

test('Lambda handler - Bootstrap failure logs exactly one error line', async (t) => {
  const errorLogs = [];
  const originalError = console.error;
  console.error = (msg) => errorLogs.push(msg);

  const handler = createLambdaHandler({
    env: {
      TABLE_NAME: 'table',
      PEPPER_SECRET_ARN: 'arn:secret',
      ENTRA_TENANT_ID: 'tenant',
      ENTRA_CLIENT_ID: 'client',
    },
    createDocumentClient: () => ({ send: async () => ({}) }),
    createSecretsClient: () => ({
      send: async () => {
        throw new Error('Test error');
      },
    }),
    fetchImpl: async () => ({
      status: 200,
      json: async () => ({ keys: [] }),
    }),
  });

  const event = {
    requestContext: { http: { method: 'GET', path: '/' } },
    headers: {},
    body: '',
    isBase64Encoded: false,
  };

  await handler(event);

  // Filter to only the [bootstrap] failed messages
  const bootstrapErrors = errorLogs.filter(msg => msg.includes('[bootstrap] failed:'));
  assert.strictEqual(bootstrapErrors.length, 1);
  assert.ok(bootstrapErrors[0].startsWith('[bootstrap] failed:'));
  assert.ok(bootstrapErrors[0].includes('Test error'));

  console.error = originalError;
});

test('Lambda handler - Bootstrap error messages do not contain newlines in log', async (t) => {
  const errorLogs = [];
  const originalError = console.error;
  console.error = (msg) => errorLogs.push(msg);

  const handler = createLambdaHandler({
    env: {
      TABLE_NAME: 'table',
      PEPPER_SECRET_ARN: 'arn:secret',
      ENTRA_TENANT_ID: 'tenant',
      ENTRA_CLIENT_ID: 'client',
    },
    createDocumentClient: () => ({ send: async () => ({}) }),
    createSecretsClient: () => ({
      send: async () => {
        throw new Error('Error\nwith\nnewlines');
      },
    }),
    fetchImpl: async () => ({
      status: 200,
      json: async () => ({ keys: [] }),
    }),
  });

  const event = {
    requestContext: { http: { method: 'GET', path: '/' } },
    headers: {},
    body: '',
    isBase64Encoded: false,
  };

  await handler(event);

  const bootstrapErrors = errorLogs.filter(msg => msg.includes('[bootstrap] failed:'));
  assert.strictEqual(bootstrapErrors.length, 1);
  // Newlines should be replaced with spaces
  assert.ok(!bootstrapErrors[0].includes('\n'));
  assert.ok(!bootstrapErrors[0].includes('\r'));

  console.error = originalError;
});

// ============================================================================
// Secret Material Logging Tests
// ============================================================================

test('Lambda handler - Secret material does not appear in logs', async (t) => {
  const logs = [];
  const originalLog = console.log;
  const originalInfo = console.info;
  const originalWarn = console.warn;
  const originalError = console.error;

  console.log = (msg) => logs.push(['log', msg]);
  console.info = (msg) => logs.push(['info', msg]);
  console.warn = (msg) => logs.push(['warn', msg]);
  console.error = (msg) => logs.push(['error', msg]);

  const secretValue = 'super-secret-password-12345';
  const handler = createLambdaHandler({
    env: {
      TABLE_NAME: 'table',
      PEPPER_SECRET_ARN: 'arn:secret',
      ENTRA_TENANT_ID: 'tenant',
      ENTRA_CLIENT_ID: 'client',
    },
    createDocumentClient: () => ({ send: async () => ({}) }),
    createSecretsClient: () => ({
      send: async () => ({ SecretString: secretValue }),
    }),
    fetchImpl: async () => ({
      status: 200,
      json: async () => ({ keys: [] }),
    }),
  });

  const event = {
    requestContext: { http: { method: 'GET', path: '/' } },
    headers: {},
    body: '',
    isBase64Encoded: false,
  };

  await handler(event);

  // Check that the secret value doesn't appear in any log
  const logText = logs.map(l => l[1]).join('\n');
  assert.ok(!logText.includes(secretValue));

  console.log = originalLog;
  console.info = originalInfo;
  console.warn = originalWarn;
  console.error = originalError;
});
