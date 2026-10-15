/**
 * E2E cucumber-style and unit tests for bootstrap wiring the AI script
 * generator (TASK-053, AC16, AC27): `backend/src/bootstrap.ts`.
 *
 * The Bedrock Runtime client is always a fake `{send}` injected through
 * `createBedrockRuntimeClient` -- no real AWS call is ever made, and no
 * database connection is opened either (the document/secrets clients are the
 * usual bootstrap-test fakes).
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { bootstrap } from '../dist/bootstrap.js';
import { resolveAdminDependencies } from '../dist/admin/router.js';
import { ConverseCommand } from '@aws-sdk/client-bedrock-runtime';

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
// AC16
// ============================================================================

test('Scenario: Bootstrap builds the generator only with a model id', () =>
  withEnvVar('BEDROCK_MODEL_ID', async () => {
    // Given a fake createBedrockRuntimeClient factory
    const calls = [];
    const fakeBedrockClient = {
      async send(command) {
        calls.push(command);
        return { output: { message: { content: [{ text: 'echo hi' }] } } };
      },
    };
    let createBedrockRuntimeClientCalls = 0;

    // When bootstrap runs with BEDROCK_MODEL_ID "anthropic.claude-haiku-4-5-20251001-v1:0"
    const result = await bootstrap({
      env: completeEnv({ BEDROCK_MODEL_ID: 'anthropic.claude-haiku-4-5-20251001-v1:0' }),
      ...fakeFactories(),
      createBedrockRuntimeClient: () => {
        createBedrockRuntimeClientCalls += 1;
        return fakeBedrockClient;
      },
    });
    assert.ok(result);

    // Then the factory was called once and the admin routes have a scriptGenerator
    const adminDeps = resolveAdminDependencies();
    assert.ok(adminDeps.scriptGenerator, 'admin dependencies should carry a scriptGenerator');
    assert.strictEqual(createBedrockRuntimeClientCalls, 1);

    // And the generator sends a ConverseCommand through the fake client
    const script = await adminDeps.scriptGenerator.generate(
      { prompt: 'say hi', interpreter: 'bash', platform: 'darwin', timeoutSeconds: 60, description: null },
      new AbortController().signal,
    );
    assert.strictEqual(calls.length, 1);
    assert.ok(calls[0] instanceof ConverseCommand);
    assert.strictEqual(calls[0].input.modelId, 'anthropic.claude-haiku-4-5-20251001-v1:0');
    assert.strictEqual(script, 'echo hi');

    // When bootstrap runs with BEDROCK_MODEL_ID ""
    createBedrockRuntimeClientCalls = 0;
    const result2 = await bootstrap({
      env: completeEnv({ BEDROCK_MODEL_ID: '' }),
      ...fakeFactories(),
      createBedrockRuntimeClient: () => {
        createBedrockRuntimeClientCalls += 1;
        return fakeBedrockClient;
      },
    });
    assert.ok(result2);

    // Then the factory was called 0 times and the admin routes have no scriptGenerator
    const adminDeps2 = resolveAdminDependencies();
    assert.strictEqual(adminDeps2.scriptGenerator, undefined);
    assert.strictEqual(createBedrockRuntimeClientCalls, 0);
  }));

test('Scenario: Bootstrap with BEDROCK_MODEL_ID absent', () =>
  withEnvVar('BEDROCK_MODEL_ID', async () => {
    // When bootstrap runs with an env that has no BEDROCK_MODEL_ID key
    let createBedrockRuntimeClientCalls = 0;
    const result = await bootstrap({
      env: completeEnv(),
      ...fakeFactories(),
      createBedrockRuntimeClient: () => {
        createBedrockRuntimeClientCalls += 1;
        return { send: async () => ({ output: { message: { content: [] } } }) };
      },
    });
    assert.ok(result);

    // Then the factory was called 0 times
    assert.strictEqual(createBedrockRuntimeClientCalls, 0);
    const adminDeps = resolveAdminDependencies();
    assert.strictEqual(adminDeps.scriptGenerator, undefined);
  }));

test('Unit: no createBedrockRuntimeClient override and no model id never builds a generator', () =>
  withEnvVar('BEDROCK_MODEL_ID', async () => {
    // No createBedrockRuntimeClient override at all: bootstrap must not touch the default
    // `new BedrockRuntimeClient({})` factory (and so never opens a real client) when the
    // model id is empty.
    const result = await bootstrap({
      env: completeEnv({ BEDROCK_MODEL_ID: '' }),
      ...fakeFactories(),
    });
    assert.ok(result);
    const adminDeps = resolveAdminDependencies();
    assert.strictEqual(adminDeps.scriptGenerator, undefined);
  }));

test('Unit: with a model id and no override, bootstrap falls back to new BedrockRuntimeClient({}) and still wires a generator', () =>
  withEnvVar('BEDROCK_MODEL_ID', async () => {
    // The default factory constructs a real (but never-sent-to) BedrockRuntimeClient;
    // this never calls .send(), so no network call or AWS credential is needed.
    const result = await bootstrap({
      env: completeEnv({ BEDROCK_MODEL_ID: 'anthropic.claude-haiku-4-5-20251001-v1:0' }),
      ...fakeFactories(),
    });
    assert.ok(result);
    const adminDeps = resolveAdminDependencies();
    assert.ok(adminDeps.scriptGenerator, 'the default client should still produce a usable generator');
  }));
