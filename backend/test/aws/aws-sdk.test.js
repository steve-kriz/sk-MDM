/**
 * Unit tests for AWS SDK adapters and factories.
 *
 * These tests validate that the adapters correctly map the simple injected
 * interfaces to the AWS SDK v3 client shapes, and that SDK errors propagate unchanged.
 */

import test from 'node:test';
import assert from 'node:assert';
import {
  GetCommand,
  PutCommand,
  UpdateCommand,
  QueryCommand,
  DeleteCommand,
} from '@aws-sdk/lib-dynamodb';
import { GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import {
  createSdkDocumentClient,
  createSdkDocumentClientAdapter,
} from '../../dist/aws/documentClient.js';
import {
  createSecretsClientAdapter,
} from '../../dist/aws/secrets.js';
import {
  createJwksFetcher,
  jwksUrl,
} from '../../dist/aws/jwks.js';
import { createTableClient } from '../../dist/db/table.js';
import { createTokenVerifier } from '../../dist/auth/entra.js';

// ============================================================================
// Document Client Adapter Tests
// ============================================================================

test('Document adapter - Get operation maps to GetCommand', async (t) => {
  const commands = [];
  const fakeSDKClient = {
    send(cmd) {
      commands.push(cmd);
      return Promise.resolve({ Item: {} });
    },
  };

  const adapter = createSdkDocumentClientAdapter(fakeSDKClient);
  const result = await adapter.send({
    operation: 'Get',
    input: { TableName: 't', Key: { pk: 'a', sk: 'b' } },
  });

  assert.strictEqual(commands.length, 1);
  assert.ok(commands[0] instanceof GetCommand);
  assert.deepStrictEqual(commands[0].input, { TableName: 't', Key: { pk: 'a', sk: 'b' } });
  assert.deepStrictEqual(result, { Item: {} });
});

test('Document adapter - Put operation maps to PutCommand', async (t) => {
  const commands = [];
  const fakeSDKClient = {
    send(cmd) {
      commands.push(cmd);
      return Promise.resolve({});
    },
  };

  const adapter = createSdkDocumentClientAdapter(fakeSDKClient);
  const input = { TableName: 't', Item: { pk: 'a', sk: 'b', data: 'x' } };
  await adapter.send({ operation: 'Put', input });

  assert.strictEqual(commands.length, 1);
  assert.ok(commands[0] instanceof PutCommand);
  assert.deepStrictEqual(commands[0].input, input);
});

test('Document adapter - Update operation maps to UpdateCommand', async (t) => {
  const commands = [];
  const fakeSDKClient = {
    send(cmd) {
      commands.push(cmd);
      return Promise.resolve({});
    },
  };

  const adapter = createSdkDocumentClientAdapter(fakeSDKClient);
  const input = { TableName: 't', Key: { pk: 'a' }, UpdateExpression: 'SET #n = :v' };
  await adapter.send({ operation: 'Update', input });

  assert.strictEqual(commands.length, 1);
  assert.ok(commands[0] instanceof UpdateCommand);
  assert.deepStrictEqual(commands[0].input, input);
});

test('Document adapter - Query operation maps to QueryCommand', async (t) => {
  const commands = [];
  const fakeSDKClient = {
    send(cmd) {
      commands.push(cmd);
      return Promise.resolve({ Items: [] });
    },
  };

  const adapter = createSdkDocumentClientAdapter(fakeSDKClient);
  const input = { TableName: 't', KeyConditionExpression: 'pk = :pk' };
  await adapter.send({ operation: 'Query', input });

  assert.strictEqual(commands.length, 1);
  assert.ok(commands[0] instanceof QueryCommand);
  assert.deepStrictEqual(commands[0].input, input);
});

test('Document adapter - Delete operation maps to DeleteCommand', async (t) => {
  const commands = [];
  const fakeSDKClient = {
    send(cmd) {
      commands.push(cmd);
      return Promise.resolve({});
    },
  };

  const adapter = createSdkDocumentClientAdapter(fakeSDKClient);
  const input = { TableName: 't', Key: { pk: 'a', sk: 'b' } };
  await adapter.send({ operation: 'Delete', input });

  assert.strictEqual(commands.length, 1);
  assert.ok(commands[0] instanceof DeleteCommand);
  assert.deepStrictEqual(commands[0].input, input);
});

test('Document adapter - Unknown operation is rejected', async (t) => {
  const fakeSDKClient = {
    send() {
      throw new Error('should not be called');
    },
  };

  const adapter = createSdkDocumentClientAdapter(fakeSDKClient);

  try {
    await adapter.send({
      operation: 'Scan',
      input: { TableName: 't' },
    });
    assert.fail('should have thrown');
  } catch (error) {
    assert.strictEqual(error.message, 'unsupported DynamoDB operation: Scan');
  }
});

test('Document adapter - SDK errors propagate unchanged', async (t) => {
  const testError = new Error('ConditionalCheckFailedException');
  testError.name = 'ConditionalCheckFailedException';

  const fakeSDKClient = {
    send() {
      return Promise.reject(testError);
    },
  };

  const adapter = createSdkDocumentClientAdapter(fakeSDKClient);

  try {
    await adapter.send({
      operation: 'Put',
      input: { TableName: 't', Item: { pk: 'a' } },
    });
    assert.fail('should have thrown');
  } catch (error) {
    assert.strictEqual(error, testError); // Same object
  }
});

test('Document adapter with ConditionalCheckFailedException resolves putIfAbsent with written: false', async (t) => {
  const testError = new Error('ConditionalCheckFailedException');
  testError.name = 'ConditionalCheckFailedException';

  const fakeSDKClient = {
    send() {
      return Promise.reject(testError);
    },
  };

  const adapter = createSdkDocumentClientAdapter(fakeSDKClient);
  const table = createTableClient({
    documentClient: adapter,
    tableName: 'test-table',
  });

  const result = await table.putIfAbsent({
    pk: 'test-pk',
    sk: 'test-sk',
  });

  assert.deepStrictEqual(result, { written: false });
});

test('Real document client has removeUndefinedValues: true', (t) => {
  const client = createSdkDocumentClient();
  const config = client.config;

  assert.ok(config.translateConfig);
  assert.ok(config.translateConfig.marshallOptions);
  assert.strictEqual(config.translateConfig.marshallOptions.removeUndefinedValues, true);
});

// ============================================================================
// Secrets Manager Adapter Tests
// ============================================================================

test('Secrets adapter - GetSecretValueCommand is sent with correct input', async (t) => {
  const commands = [];
  const fakeSDKClient = {
    send(cmd) {
      commands.push(cmd);
      return Promise.resolve({ SecretString: 's3cret' });
    },
  };

  const adapter = createSecretsClientAdapter(fakeSDKClient);
  const result = await adapter.getSecretValue({ SecretId: 'arn:x' });

  assert.strictEqual(commands.length, 1);
  assert.ok(commands[0] instanceof GetSecretValueCommand);
  assert.deepStrictEqual(commands[0].input, { SecretId: 'arn:x' });
  assert.deepStrictEqual(result, { SecretString: 's3cret' });
});

test('Secrets adapter - GetSecretValueCommand with full ARN', async (t) => {
  const commands = [];
  const fakeSDKClient = {
    send(cmd) {
      commands.push(cmd);
      return Promise.resolve({ SecretString: 'secret-value' });
    },
  };

  const adapter = createSecretsClientAdapter(fakeSDKClient);
  const arn = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:test';
  const result = await adapter.getSecretValue({ SecretId: arn });

  assert.deepStrictEqual(commands[0].input, { SecretId: arn });
  assert.deepStrictEqual(result, { SecretString: 'secret-value' });
});

// ============================================================================
// JWKS Fetcher Tests
// ============================================================================

test('JWKS fetcher - Builds correct URL for tenant', (t) => {
  const url = jwksUrl('t-1');
  assert.strictEqual(
    url,
    'https://login.microsoftonline.com/t-1/discovery/v2.0/keys'
  );
});

test('JWKS fetcher - Calls fetch with correct URL', async (t) => {
  let fetchedUrl = null;
  const fakeFetch = async (url) => {
    fetchedUrl = url;
    return {
      status: 200,
      json: async () => ({ keys: [] }),
    };
  };

  const fetcher = createJwksFetcher('t-1', fakeFetch);
  const result = await fetcher();

  assert.strictEqual(
    fetchedUrl,
    'https://login.microsoftonline.com/t-1/discovery/v2.0/keys'
  );
  assert.deepStrictEqual(result, { keys: [] });
});

test('JWKS fetcher - Rejects on non-2xx status', async (t) => {
  const fakeFetch = async () => ({
    status: 500,
    json: async () => ({}),
  });

  const fetcher = createJwksFetcher('t-1', fakeFetch);

  try {
    await fetcher();
    assert.fail('should have thrown');
  } catch (error) {
    assert.ok(error.message.includes('JWKS request failed'));
  }
});

test('JWKS fetcher - Rejects when fetch itself rejects', async (t) => {
  const testError = new Error('Network error');
  const fakeFetch = async () => {
    throw testError;
  };

  const fetcher = createJwksFetcher('t-1', fakeFetch);

  try {
    await fetcher();
    assert.fail('should have thrown');
  } catch (error) {
    assert.strictEqual(error, testError);
  }
});

test('JWKS fetcher - 500 status is handled', async (t) => {
  const fakeFetch = async () => ({
    status: 500,
  });

  const fetcher = createJwksFetcher('tenant-id', fakeFetch);

  try {
    await fetcher();
    assert.fail('should have thrown');
  } catch (error) {
    assert.ok(error.message.includes('JWKS request failed'));
  }
});

test('JWKS fetcher - Network error is handled', async (t) => {
  const testError = new Error('Network error');
  const fakeFetch = async () => {
    throw testError;
  };

  const fetcher = createJwksFetcher('tenant-id', fakeFetch);

  try {
    await fetcher();
    assert.fail('should have thrown');
  } catch (error) {
    assert.strictEqual(error, testError);
  }
});
