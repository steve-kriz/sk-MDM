/**
 * Unit and e2e tests for the production bootstrap wiring.
 *
 * These tests validate that bootstrap correctly initializes the DynamoDB and
 * Secrets Manager clients, derives the pepper, creates the verifier, and
 * configures every route family.
 */

import test from 'node:test';
import assert from 'node:assert';
import { GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { GetCommand } from '@aws-sdk/lib-dynamodb';
import {
  bootstrap,
  REQUIRED_ENV,
} from '../dist/bootstrap.js';
import { router } from '../dist/index.js';
import { resolveEnrollDependencies } from '../dist/routes/enroll.js';
import { resolveCheckInDependencies } from '../dist/routes/checkin.js';
import { resolvePolicyBundleDependencies } from '../dist/routes/policies.js';
import { resolveAdminDependencies } from '../dist/admin/router.js';

// ============================================================================
// Environment Validation Tests
// ============================================================================

test('Bootstrap - Missing TABLE_NAME is rejected before factories are called', async (t) => {
  let documentClientCalled = false;
  let secretsClientCalled = false;

  const result = await bootstrap({
    env: {
      // TABLE_NAME is absent
      PEPPER_SECRET_ARN: 'arn:secret',
      ENTRA_TENANT_ID: 'tenant',
      ENTRA_CLIENT_ID: 'client',
    },
    createDocumentClient: () => {
      documentClientCalled = true;
      throw new Error('should not be called');
    },
    createSecretsClient: () => {
      secretsClientCalled = true;
      throw new Error('should not be called');
    },
  }).catch(e => e);

  assert.ok(result instanceof Error);
  assert.strictEqual(result.message, 'missing environment variable TABLE_NAME');
  assert.strictEqual(documentClientCalled, false);
  assert.strictEqual(secretsClientCalled, false);
});

test('Bootstrap - Empty PEPPER_SECRET_ARN is rejected before factories are called', async (t) => {
  let documentClientCalled = false;
  let secretsClientCalled = false;

  const result = await bootstrap({
    env: {
      TABLE_NAME: 'table',
      PEPPER_SECRET_ARN: '', // empty string
      ENTRA_TENANT_ID: 'tenant',
      ENTRA_CLIENT_ID: 'client',
    },
    createDocumentClient: () => {
      documentClientCalled = true;
      throw new Error('should not be called');
    },
    createSecretsClient: () => {
      secretsClientCalled = true;
      throw new Error('should not be called');
    },
  }).catch(e => e);

  assert.ok(result instanceof Error);
  assert.strictEqual(result.message, 'missing environment variable PEPPER_SECRET_ARN');
  assert.strictEqual(documentClientCalled, false);
  assert.strictEqual(secretsClientCalled, false);
});

test('Bootstrap - Missing ENTRA_TENANT_ID is rejected', async (t) => {
  const result = await bootstrap({
    env: {
      TABLE_NAME: 'table',
      PEPPER_SECRET_ARN: 'arn:secret',
      // ENTRA_TENANT_ID is absent
      ENTRA_CLIENT_ID: 'client',
    },
    createDocumentClient: () => ({ send: async () => ({}) }),
    createSecretsClient: () => ({ send: async () => ({ SecretString: 'pepper' }) }),
  }).catch(e => e);

  assert.ok(result instanceof Error);
  assert.strictEqual(result.message, 'missing environment variable ENTRA_TENANT_ID');
});

test('Bootstrap - Empty ENTRA_CLIENT_ID is rejected', async (t) => {
  const result = await bootstrap({
    env: {
      TABLE_NAME: 'table',
      PEPPER_SECRET_ARN: 'arn:secret',
      ENTRA_TENANT_ID: 'tenant',
      ENTRA_CLIENT_ID: '', // empty
    },
    createDocumentClient: () => ({ send: async () => ({}) }),
    createSecretsClient: () => ({ send: async () => ({ SecretString: 'pepper' }) }),
  }).catch(e => e);

  assert.ok(result instanceof Error);
  assert.strictEqual(result.message, 'missing environment variable ENTRA_CLIENT_ID');
});

test('Bootstrap - Variables checked in documented order (TABLE_NAME first)', async (t) => {
  // Both TABLE_NAME and ENTRA_CLIENT_ID missing; TABLE_NAME error should be thrown first
  const result = await bootstrap({
    env: {
      PEPPER_SECRET_ARN: 'arn:secret',
      ENTRA_TENANT_ID: 'tenant',
    },
    createDocumentClient: () => ({ send: async () => ({}) }),
    createSecretsClient: () => ({ send: async () => ({ SecretString: 'pepper' }) }),
  }).catch(e => e);

  assert.ok(result instanceof Error);
  assert.strictEqual(result.message, 'missing environment variable TABLE_NAME');
});

// ============================================================================
// Bootstrap Success and Route Configuration Tests
// ============================================================================

test('Bootstrap - Successful bootstrap wraps clients and configures all route families', async (t) => {
  const commands = [];
  const fakeDocumentClient = {
    send(cmd) {
      commands.push({ client: 'document', cmd });
      return Promise.resolve({ Item: {} });
    },
  };

  const fakeSecretsClient = {
    send(cmd) {
      commands.push({ client: 'secrets', cmd });
      return Promise.resolve({ SecretString: 'pepper-value' });
    },
  };

  const result = await bootstrap({
    env: {
      TABLE_NAME: 'mdm-table',
      PEPPER_SECRET_ARN: 'arn:secret',
      ENTRA_TENANT_ID: 'tenant',
      ENTRA_CLIENT_ID: 'client',
      // ENTRA_ADMIN_GROUP_ID is not set
    },
    createDocumentClient: () => fakeDocumentClient,
    createSecretsClient: () => fakeSecretsClient,
    fetchImpl: async () => ({
      status: 200,
      json: async () => ({ keys: [] }),
    }),
  });

  // All resolve functions should work without throwing
  const enrollDeps = resolveEnrollDependencies();
  const checkinDeps = resolveCheckInDependencies();
  const policyDeps = resolvePolicyBundleDependencies();
  const adminDeps = resolveAdminDependencies();

  assert.ok(enrollDeps);
  assert.ok(checkinDeps);
  assert.ok(policyDeps);
  assert.ok(adminDeps);
  assert.ok(adminDeps.verifier);
  assert.ok(typeof adminDeps.verifier.verify === 'function');

  // Verify each route can access the table
  await enrollDeps.table.get({ pk: 'test', sk: 'test' });
  await checkinDeps.table.get({ pk: 'test', sk: 'test' });
  await policyDeps.table.get({ pk: 'test', sk: 'test' });
  await adminDeps.table.get({ pk: 'test', sk: 'test' });

  // All document operations should have created GetCommand instances
  const documentCmds = commands
    .filter(c => c.client === 'document')
    .map(c => c.cmd);

  assert.ok(documentCmds.length >= 4);
  documentCmds.forEach(cmd => {
    assert.ok(cmd instanceof GetCommand);
    assert.strictEqual(cmd.input.TableName, 'mdm-table');
  });

  // Secrets should have been called to get the pepper
  const secretsCmds = commands
    .filter(c => c.client === 'secrets')
    .map(c => c.cmd);

  assert.strictEqual(secretsCmds.length, 1);
  assert.ok(secretsCmds[0] instanceof GetSecretValueCommand);
  assert.deepStrictEqual(secretsCmds[0].input, { SecretId: 'arn:secret' });
});

test('Bootstrap - Pepper is derived correctly and cached', async (t) => {
  const getSecretCalls = [];
  const fakeSecretsClient = {
    send(cmd) {
      getSecretCalls.push(cmd);
      return Promise.resolve({ SecretString: 'pepper-src' });
    },
  };

  await bootstrap({
    env: {
      TABLE_NAME: 'table',
      PEPPER_SECRET_ARN: 'arn:secret',
      ENTRA_TENANT_ID: 'tenant',
      ENTRA_CLIENT_ID: 'client',
    },
    createDocumentClient: () => ({ send: async () => ({}) }),
    createSecretsClient: () => fakeSecretsClient,
    fetchImpl: async () => ({
      status: 200,
      json: async () => ({ keys: [] }),
    }),
  });

  // Pepper should be derived from 'pepper-src' via SHA-256
  // The derived pepper should be the hex of SHA-256('pepper-src')
  const enrollDeps = resolveEnrollDependencies();
  const expectedPepper = 'c444a12701c0933acca1e2f0aeaf216d1a26bff2799671156bbbd912caa2e548'; // SHA-256('pepper-src') hex

  assert.strictEqual(enrollDeps.pepper, expectedPepper);

  // getSecretValue should have been called exactly once
  assert.strictEqual(getSecretCalls.length, 1);
  assert.ok(getSecretCalls[0] instanceof GetSecretValueCommand);
});

test('Bootstrap - Routes are accessible after bootstrap', async (t) => {
  await bootstrap({
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

  // All resolvers should successfully return their dependencies
  const enrollDeps = resolveEnrollDependencies();
  const checkinDeps = resolveCheckInDependencies();
  const policyDeps = resolvePolicyBundleDependencies();
  const adminDeps = resolveAdminDependencies();

  assert.ok(enrollDeps);
  assert.ok(checkinDeps);
  assert.ok(policyDeps);
  assert.ok(adminDeps);
  assert.ok(adminDeps.verifier);
});

// ============================================================================
// Environment Variable Testing
// ============================================================================

test('Bootstrap environment requirement order matches REQUIRED_ENV', (t) => {
  assert.deepStrictEqual(
    Array.from(REQUIRED_ENV),
    ['TABLE_NAME', 'PEPPER_SECRET_ARN', 'ENTRA_TENANT_ID', 'ENTRA_CLIENT_ID']
  );
});

// ============================================================================
// TASK-027: bootstrap wires the Graph directory into the admin routes (AC26)
// ============================================================================

test('AC26: bootstrap wires graph into admin routes, reusing the pepper secrets client and sending no Graph request', async (t) => {
  const secretsSends = [];
  const fakeSecretsClient = {
    send(cmd) {
      secretsSends.push(cmd);
      return Promise.resolve({ SecretString: 'pepper-src' });
    },
  };
  const fetchCalls = [];
  const fakeFetch = async (url, init) => {
    fetchCalls.push(url);
    return { status: 200, json: async () => ({ keys: [] }) };
  };
  let secretsClientFactoryCalls = 0;

  await bootstrap({
    env: {
      TABLE_NAME: 'table',
      PEPPER_SECRET_ARN: 'arn:secret',
      ENTRA_TENANT_ID: 't-1',
      ENTRA_CLIENT_ID: 'c-1',
      GRAPH_SECRET_ID: 'prod/sk-mdm',
    },
    createDocumentClient: () => ({ send: async () => ({}) }),
    createSecretsClient: () => {
      secretsClientFactoryCalls += 1;
      return fakeSecretsClient;
    },
    fetchImpl: fakeFetch,
  });

  const adminDeps = resolveAdminDependencies();
  assert.ok(adminDeps.graph, 'resolveAdminDependencies().graph should be defined');

  assert.strictEqual(secretsClientFactoryCalls, 1, 'createSecretsClient should be called exactly once');
  assert.strictEqual(secretsSends.length, 1, 'the secrets client should have been sent exactly once (the pepper read)');

  const graphCalls = fetchCalls.filter(
    (url) => url.startsWith('https://graph.microsoft.com/') || url.endsWith('/oauth2/v2.0/token'),
  );
  assert.strictEqual(graphCalls.length, 0, 'building the directory should send no Graph or token request');

  // The new routes are registered on the router exported by backend/src/index.ts.
  const deviceRefresh = await router.handle({
    method: 'POST',
    path: '/admin/api/v1/devices/d1/user-link/refresh',
    query: {},
    headers: {},
    body: null,
  });
  assert.notStrictEqual(deviceRefresh.statusCode, 404, 'the per-device user-link route should be registered');

  const bulkRefresh = await router.handle({
    method: 'POST',
    path: '/admin/api/v1/user-links/refresh',
    query: {},
    headers: {},
    body: null,
  });
  assert.notStrictEqual(bulkRefresh.statusCode, 404, 'the bulk user-link route should be registered');
});

test('AC26 (edge): an absent GRAPH_SECRET_ID leaves graph undefined and sends no Graph or token request', async (t) => {
  const secretsSends = [];
  const fakeSecretsClient = {
    send(cmd) {
      secretsSends.push(cmd);
      return Promise.resolve({ SecretString: 'pepper-src' });
    },
  };
  const fetchCalls = [];
  const fakeFetch = async (url) => {
    fetchCalls.push(url);
    return { status: 200, json: async () => ({ keys: [] }) };
  };

  await bootstrap({
    env: {
      TABLE_NAME: 'table',
      PEPPER_SECRET_ARN: 'arn:secret',
      ENTRA_TENANT_ID: 't-1',
      ENTRA_CLIENT_ID: 'c-1',
      // GRAPH_SECRET_ID is absent.
    },
    createDocumentClient: () => ({ send: async () => ({}) }),
    createSecretsClient: () => fakeSecretsClient,
    fetchImpl: fakeFetch,
  });

  assert.strictEqual(resolveAdminDependencies().graph, undefined);
  assert.strictEqual(secretsSends.length, 1);
  const graphCalls = fetchCalls.filter(
    (url) => url.startsWith('https://graph.microsoft.com/') || url.endsWith('/oauth2/v2.0/token'),
  );
  assert.strictEqual(graphCalls.length, 0);
});

test('AC26 (edge): an empty GRAPH_SECRET_ID leaves graph undefined and sends no Graph or token request', async (t) => {
  const secretsSends = [];
  const fakeSecretsClient = {
    send(cmd) {
      secretsSends.push(cmd);
      return Promise.resolve({ SecretString: 'pepper-src' });
    },
  };
  const fetchCalls = [];
  const fakeFetch = async (url) => {
    fetchCalls.push(url);
    return { status: 200, json: async () => ({ keys: [] }) };
  };

  await bootstrap({
    env: {
      TABLE_NAME: 'table',
      PEPPER_SECRET_ARN: 'arn:secret',
      ENTRA_TENANT_ID: 't-1',
      ENTRA_CLIENT_ID: 'c-1',
      GRAPH_SECRET_ID: '',
    },
    createDocumentClient: () => ({ send: async () => ({}) }),
    createSecretsClient: () => fakeSecretsClient,
    fetchImpl: fakeFetch,
  });

  assert.strictEqual(resolveAdminDependencies().graph, undefined);
  assert.strictEqual(secretsSends.length, 1);
  const graphCalls = fetchCalls.filter(
    (url) => url.startsWith('https://graph.microsoft.com/') || url.endsWith('/oauth2/v2.0/token'),
  );
  assert.strictEqual(graphCalls.length, 0);
});
