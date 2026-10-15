/**
 * E2E cucumber-style and unit tests for bootstrap wiring the URL hasher
 * invoker (TASK-050, AC19): `backend/src/bootstrap.ts`.
 *
 * The Lambda client is always a fake `{send}` injected through
 * `createLambdaClient` -- no real AWS call is ever made, and no database
 * connection is opened either (the document/secrets clients are the usual
 * bootstrap-test fakes).
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { bootstrap } from '../dist/bootstrap.js';
import { resolveAdminDependencies } from '../dist/admin/router.js';
import { InvokeCommand } from '@aws-sdk/client-lambda';

function completeEnv(overrides = {}) {
  return {
    TABLE_NAME: 'mdm-table',
    PEPPER_SECRET_ARN: 'arn:secret',
    ENTRA_TENANT_ID: 'tenant',
    ENTRA_CLIENT_ID: 'client',
    ...overrides,
  };
}

function fakeFactories() {
  return {
    createDocumentClient: () => ({ send: async () => ({}) }),
    createSecretsClient: () => ({ send: async () => ({ SecretString: 'pepper' }) }),
    fetchImpl: async () => ({ status: 200, json: async () => ({ keys: [] }) }),
  };
}

function withEnvVar(name, run) {
  const had = Object.prototype.hasOwnProperty.call(process.env, name);
  const previous = process.env[name];
  delete process.env[name];
  return run().finally(() => {
    if (had) {
      process.env[name] = previous;
    } else {
      delete process.env[name];
    }
  });
}

// ============================================================================
// AC19
// ============================================================================

test('Scenario: Bootstrap wires the hasher invoker', () =>
  withEnvVar('HASHER_FUNCTION_NAME', async () => {
    // Given HASHER_FUNCTION_NAME "mdm-hasher" and a fake createLambdaClient
    const calls = [];
    const fakeLambdaClient = {
      async send(command) {
        calls.push(command);
        return { StatusCode: 202 };
      },
    };
    let createLambdaClientCalls = 0;

    // When bootstrap runs
    const result = await bootstrap({
      env: completeEnv({ HASHER_FUNCTION_NAME: 'mdm-hasher' }),
      ...fakeFactories(),
      createLambdaClient: () => {
        createLambdaClientCalls += 1;
        return fakeLambdaClient;
      },
    });
    assert.ok(result);

    // Then configureAdminRoutes receives a hasher whose invoke sends
    // InvokeCommand with FunctionName "mdm-hasher"
    const adminDeps = resolveAdminDependencies();
    assert.ok(adminDeps.hasher, 'admin dependencies should carry a hasher');
    assert.strictEqual(createLambdaClientCalls, 1);

    await adminDeps.hasher.invoke({ applicationId: 'app-1', url: 'https://x', hashRunId: 'r1' });
    assert.strictEqual(calls.length, 1);
    assert.ok(calls[0] instanceof InvokeCommand);
    assert.strictEqual(calls[0].input.FunctionName, 'mdm-hasher');
  }));

test('Scenario (edge): No hasher configured', () =>
  withEnvVar('HASHER_FUNCTION_NAME', async () => {
    // Given HASHER_FUNCTION_NAME is ""
    let createLambdaClientCalls = 0;

    // When bootstrap runs
    const result = await bootstrap({
      env: completeEnv({ HASHER_FUNCTION_NAME: '' }),
      ...fakeFactories(),
      createLambdaClient: () => {
        createLambdaClientCalls += 1;
        return { send: async () => ({ StatusCode: 202 }) };
      },
    });
    assert.ok(result);

    // Then the admin dependencies have hasher undefined and createLambdaClient was not called
    const adminDeps = resolveAdminDependencies();
    assert.strictEqual(adminDeps.hasher, undefined);
    assert.strictEqual(createLambdaClientCalls, 0);
  }));

test('Unit: HASHER_FUNCTION_NAME absent from env behaves like an empty string', () =>
  withEnvVar('HASHER_FUNCTION_NAME', async () => {
    const result = await bootstrap({
      env: completeEnv(),
      ...fakeFactories(),
    });
    assert.ok(result);

    const adminDeps = resolveAdminDependencies();
    assert.strictEqual(adminDeps.hasher, undefined);
  }));
