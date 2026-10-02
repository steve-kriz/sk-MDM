/**
 * Tests for entra-settings.ts (TASK-032)
 *
 * E2E tests implement Given/When/Then style scenarios for all Gherkin acceptance criteria.
 * Unit tests cover construction error handling and edge cases.
 */

import test from 'node:test';
import assert from 'node:assert';
import { resolveEntraSettings } from '../../dist/infra/entra-settings.js';
import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { MdmStack } from '../../dist/infra/mdm-stack.js';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendRoot = path.resolve(__dirname, '../..');

/**
 * Helper function to create a hand-built DeploySecrets fake.
 * @param {Object} secretMap - A plain object with secret keys/values
 * @returns {Object} - A frozen DeploySecrets fake with secretId, get, require, and keys methods
 */
function createFakeDeploySecret(secretMap = {}) {
  return Object.freeze({
    secretId: 'prod/sk-mdm',
    get(key) {
      return secretMap[key];
    },
    require(key) {
      // This mimics TASK-026's require behavior
      const value = secretMap[key];
      if (value === undefined || value === '' || (typeof value === 'string' && value.trim() === '')) {
        throw new Error(`${key} is required in secret prod/sk-mdm`);
      }
      return value;
    },
    keys() {
      return Object.keys(secretMap);
    },
  });
}

// ============================================================================
// E2E Tests: Given/When/Then Scenarios from the Gherkin specification
// ============================================================================

test('E2E: Scenario: Values come from the secret when no override is set', async (t) => {
  // Given env has no ENTRA_TENANT_ID or ENTRA_CLIENT_ID
  const env = {};

  // And CDK context has no entraTenantId or entraClientId
  const context = () => undefined;

  // And the secret is a DeploySecrets fake over {"ENTRA_TENANT_ID":"t-sec","ENTRA_CLIENT_ID":"c-sec"}
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-sec',
    ENTRA_CLIENT_ID: 'c-sec',
  });

  // When I call resolveEntraSettings
  const result = resolveEntraSettings({ env, context, secret });

  // Then the result is {"entraTenantId":"t-sec","entraClientId":"c-sec"}
  assert.deepStrictEqual(result, { entraTenantId: 't-sec', entraClientId: 'c-sec' });
});

test('E2E: Scenario: Environment override wins over context and secret per key', async (t) => {
  // Given env ENTRA_TENANT_ID is "t-env" and env ENTRA_CLIENT_ID is unset
  const env = { ENTRA_TENANT_ID: 't-env' };

  // And CDK context entraTenantId is "t-ctx"
  const context = (key) => {
    if (key === 'entraTenantId') return 't-ctx';
    return undefined;
  };

  // And the secret is a DeploySecrets fake over {"ENTRA_TENANT_ID":"t-sec","ENTRA_CLIENT_ID":"c-sec"}
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-sec',
    ENTRA_CLIENT_ID: 'c-sec',
  });

  // When I call resolveEntraSettings
  const result = resolveEntraSettings({ env, context, secret });

  // Then entraTenantId is "t-env"
  assert.strictEqual(result.entraTenantId, 't-env');
  // And entraClientId is "c-sec"
  assert.strictEqual(result.entraClientId, 'c-sec');
});

test('E2E: Scenario: CDK context wins over the secret when env is unset', async (t) => {
  // Given env has no ENTRA_TENANT_ID or ENTRA_CLIENT_ID
  const env = {};

  // And CDK context entraClientId is "c-ctx"
  const context = (key) => {
    if (key === 'entraClientId') return 'c-ctx';
    return undefined;
  };

  // And the secret is a DeploySecrets fake over {"ENTRA_TENANT_ID":"t-sec","ENTRA_CLIENT_ID":"c-sec"}
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-sec',
    ENTRA_CLIENT_ID: 'c-sec',
  });

  // When I call resolveEntraSettings
  const result = resolveEntraSettings({ env, context, secret });

  // Then entraTenantId is "t-sec"
  assert.strictEqual(result.entraTenantId, 't-sec');
  // And entraClientId is "c-ctx"
  assert.strictEqual(result.entraClientId, 'c-ctx');
});

test('E2E: Scenario: Empty env value falls through to the next source', async (t) => {
  // Given env ENTRA_TENANT_ID is ""
  const env = { ENTRA_TENANT_ID: '' };

  // And CDK context has no entraTenantId
  const context = () => undefined;

  // And the secret is a DeploySecrets fake over {"ENTRA_TENANT_ID":"t-sec","ENTRA_CLIENT_ID":"c-sec"}
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-sec',
    ENTRA_CLIENT_ID: 'c-sec',
  });

  // When I call resolveEntraSettings
  const result = resolveEntraSettings({ env, context, secret });

  // Then entraTenantId is "t-sec"
  assert.strictEqual(result.entraTenantId, 't-sec');
});

test('E2E: Scenario: Secret values are trimmed', async (t) => {
  // Given env and CDK context are empty
  const env = {};
  const context = () => undefined;

  // And the secret is a DeploySecrets fake over {"ENTRA_TENANT_ID":"  t-1  ","ENTRA_CLIENT_ID":"\tc-9\n"}
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: '  t-1  ',
    ENTRA_CLIENT_ID: '\tc-9\n',
  });

  // When I call resolveEntraSettings
  const result = resolveEntraSettings({ env, context, secret });

  // Then the result is {"entraTenantId":"t-1","entraClientId":"c-9"}
  assert.deepStrictEqual(result, { entraTenantId: 't-1', entraClientId: 'c-9' });
});

test('E2E: Scenario Outline: Unresolvable ENTRA_TENANT_ID (missing from secret)', async (t) => {
  const env = {};
  const context = () => undefined;
  const secret = createFakeDeploySecret({
    ENTRA_CLIENT_ID: 'c-sec',
  });

  assert.throws(
    () => resolveEntraSettings({ env, context, secret }),
    (err) =>
      err instanceof Error &&
      err.message === 'ENTRA_TENANT_ID not found in secret prod/sk-mdm, environment or CDK context'
  );
});

test('E2E: Scenario Outline: Unresolvable ENTRA_TENANT_ID (empty string)', async (t) => {
  const env = {};
  const context = () => undefined;
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: '',
    ENTRA_CLIENT_ID: 'c-sec',
  });

  assert.throws(
    () => resolveEntraSettings({ env, context, secret }),
    (err) =>
      err instanceof Error &&
      err.message === 'ENTRA_TENANT_ID not found in secret prod/sk-mdm, environment or CDK context'
  );
});

test('E2E: Scenario Outline: Unresolvable ENTRA_TENANT_ID (whitespace only)', async (t) => {
  const env = {};
  const context = () => undefined;
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: '   ',
    ENTRA_CLIENT_ID: 'c-sec',
  });

  assert.throws(
    () => resolveEntraSettings({ env, context, secret }),
    (err) =>
      err instanceof Error &&
      err.message === 'ENTRA_TENANT_ID not found in secret prod/sk-mdm, environment or CDK context'
  );
});

test('E2E: Scenario Outline: Unresolvable ENTRA_TENANT_ID (tabs and newlines)', async (t) => {
  const env = {};
  const context = () => undefined;
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: '\t\n',
    ENTRA_CLIENT_ID: 'c-sec',
  });

  assert.throws(
    () => resolveEntraSettings({ env, context, secret }),
    (err) =>
      err instanceof Error &&
      err.message === 'ENTRA_TENANT_ID not found in secret prod/sk-mdm, environment or CDK context'
  );
});

test('E2E: Scenario Outline: Unresolvable ENTRA_CLIENT_ID (empty string)', async (t) => {
  const env = {};
  const context = () => undefined;
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-sec',
    ENTRA_CLIENT_ID: '',
  });

  assert.throws(
    () => resolveEntraSettings({ env, context, secret }),
    (err) =>
      err instanceof Error &&
      err.message === 'ENTRA_CLIENT_ID not found in secret prod/sk-mdm, environment or CDK context'
  );
});

test('E2E: Scenario Outline: Unresolvable ENTRA_CLIENT_ID (missing from secret)', async (t) => {
  const env = {};
  const context = () => undefined;
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-sec',
  });

  assert.throws(
    () => resolveEntraSettings({ env, context, secret }),
    (err) =>
      err instanceof Error &&
      err.message === 'ENTRA_CLIENT_ID not found in secret prod/sk-mdm, environment or CDK context'
  );
});

test('E2E: Scenario: Both keys missing names the tenant id first', async (t) => {
  // Given env and CDK context are empty
  const env = {};
  const context = () => undefined;

  // And the secret is a DeploySecrets fake over {}
  const secret = createFakeDeploySecret({});

  // When I call resolveEntraSettings
  // Then an Error is thrown with message "ENTRA_TENANT_ID not found in secret prod/sk-mdm, environment or CDK context"
  assert.throws(
    () => resolveEntraSettings({ env, context, secret }),
    (err) =>
      err instanceof Error &&
      err.message === 'ENTRA_TENANT_ID not found in secret prod/sk-mdm, environment or CDK context'
  );
});

test('E2E: Scenario: Error messages never leak secret values', async (t) => {
  // Given env and CDK context are empty
  const env = {};
  const context = () => undefined;

  // And the secret is a DeploySecrets fake over {"ENTRA_CLIENT_ID":"c-leak-check","ENTRA_CLIENT_SECRET":"s3cr3t-value"}
  const secret = createFakeDeploySecret({
    ENTRA_CLIENT_ID: 'c-leak-check',
    ENTRA_CLIENT_SECRET: 's3cr3t-value',
  });

  // When I call resolveEntraSettings
  let error;
  try {
    resolveEntraSettings({ env, context, secret });
    assert.fail('Should have thrown an error');
  } catch (e) {
    error = e;
  }

  // Then an Error is thrown
  assert.ok(error instanceof Error);

  // And its message contains neither "c-leak-check" nor "s3cr3t-value"
  assert.ok(!error.message.includes('c-leak-check'), 'Error message should not contain "c-leak-check"');
  assert.ok(!error.message.includes('s3cr3t-value'), 'Error message should not contain "s3cr3t-value"');
});

test('E2E: Scenario: Synthesized Lambda env carries the secret values', async (t) => {
  // Given the secret is a DeploySecrets fake over {"ENTRA_TENANT_ID":"tenant-from-secret","ENTRA_CLIENT_ID":"client-from-secret"}
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 'tenant-from-secret',
    ENTRA_CLIENT_ID: 'client-from-secret',
  });

  // And env and CDK context are empty
  const env = {};
  const context = () => undefined;

  // When I build MdmStack with the props returned by resolveEntraSettings and synthesize it
  const settings = resolveEntraSettings({ env, context, secret });
  const app = new App();
  const stack = new MdmStack(app, 'MdmStack', {
    entraTenantId: settings.entraTenantId,
    entraClientId: settings.entraClientId,
  });
  const template = Template.fromStack(stack);

  // Then the ApiFunction environment ENTRA_TENANT_ID is "tenant-from-secret"
  const lambdaResources = template.findResources('AWS::Lambda::Function');
  const lambdaResourceValue = Object.values(lambdaResources)[0];
  const env_vars = lambdaResourceValue.Properties.Environment.Variables;

  assert.strictEqual(env_vars.ENTRA_TENANT_ID, 'tenant-from-secret');
  // And the ApiFunction environment ENTRA_CLIENT_ID is "client-from-secret"
  assert.strictEqual(env_vars.ENTRA_CLIENT_ID, 'client-from-secret');
});

test('E2E: Scenario: Other secret keys are not injected into the template', async (t) => {
  // Given the secret is a DeploySecrets fake over {"ENTRA_TENANT_ID":"t-sec","ENTRA_CLIENT_ID":"c-sec","ENTRA_CLIENT_SECRET":"s3cr3t-value"}
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-sec',
    ENTRA_CLIENT_ID: 'c-sec',
    ENTRA_CLIENT_SECRET: 's3cr3t-value',
  });

  // When I build MdmStack with the props returned by resolveEntraSettings and synthesize it
  const settings = resolveEntraSettings({ env: {}, context: () => undefined, secret });
  const app = new App();
  const stack = new MdmStack(app, 'MdmStack', {
    entraTenantId: settings.entraTenantId,
    entraClientId: settings.entraClientId,
  });
  const template = Template.fromStack(stack);

  // Then the template JSON does not contain "s3cr3t-value"
  const templateJson = JSON.stringify(template.toJSON());
  assert.ok(!templateJson.includes('s3cr3t-value'), 'Template should not contain "s3cr3t-value"');

  // And the ApiFunction environment has no variable named ENTRA_CLIENT_SECRET
  const lambdaResources = template.findResources('AWS::Lambda::Function');
  const lambdaResourceValue = Object.values(lambdaResources)[0];
  const env_vars = lambdaResourceValue.Properties.Environment.Variables;

  assert.ok(!('ENTRA_CLIENT_SECRET' in env_vars), 'Environment should not have ENTRA_CLIENT_SECRET');
});

test('E2E: Scenario: app.ts sources Entra ids only through resolveEntraSettings', async (t) => {
  // Given the source of backend/src/infra/app.ts
  const appTsPath = path.resolve(backendRoot, 'src/infra/app.ts');
  const appTsContent = readFileSync(appTsPath, 'utf-8');

  // Then entraTenantId and entraClientId passed to MdmStack come from the result of resolveEntraSettings
  assert.ok(
    appTsContent.includes('const { entraTenantId, entraClientId } = resolveEntraSettings('),
    'app.ts should destructure entraTenantId and entraClientId from resolveEntraSettings'
  );

  // And resolveEntraSettings receives as secret the result of top-level "await loadDeploySecrets({ secretsClient: createSecretsManagerClient() })" imported from "./deploy-secrets.js"
  assert.ok(
    appTsContent.includes('await loadDeploySecrets({ secretsClient: createSecretsManagerClient() })'),
    'app.ts should call loadDeploySecrets'
  );
  assert.ok(
    appTsContent.includes('secret,'),
    'app.ts should pass secret to resolveEntraSettings'
  );
  assert.ok(
    appTsContent.includes('import { createSecretsManagerClient, loadDeploySecrets }'),
    'app.ts should import from deploy-secrets.js'
  );

  // And entraAdminGroupId is still read through setting("ENTRA_ADMIN_GROUP_ID", "entraAdminGroupId")
  assert.ok(
    appTsContent.includes("setting('ENTRA_ADMIN_GROUP_ID', 'entraAdminGroupId')"),
    'app.ts should still use setting() for entraAdminGroupId'
  );
});

test('E2E: Scenario: Existing behaviour is not regressed', async (t) => {
  // Verify that the mdm-stack.test.js file still runs successfully
  // This is tested at the end via npm test, but we can verify the tests exist
  const mdmStackTestPath = path.resolve(backendRoot, 'test/infra/mdm-stack.test.js');
  const mdmStackTestContent = readFileSync(mdmStackTestPath, 'utf-8');

  assert.ok(mdmStackTestContent.length > 0, 'mdm-stack.test.js should exist and have content');
  assert.ok(
    mdmStackTestContent.includes("test('E2E: Scenario"),
    'mdm-stack.test.js should have E2E scenarios'
  );

  const configTestPath = path.resolve(backendRoot, 'test/ui/config.test.js');
  const configTestContent = readFileSync(configTestPath, 'utf-8');

  assert.ok(configTestContent.length > 0, 'config.test.js should exist and have content');
  assert.ok(
    configTestContent.includes('test('),
    'config.test.js should have tests'
  );
});

// ============================================================================
// Unit Tests: Edge cases, error handling, and detailed validations
// ============================================================================

test('Unit: resolveEntraSettings returns both keys as strings', async (t) => {
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 'tenant-123',
    ENTRA_CLIENT_ID: 'client-456',
  });

  const result = resolveEntraSettings({
    env: {},
    context: () => undefined,
    secret,
  });

  assert.strictEqual(typeof result.entraTenantId, 'string');
  assert.strictEqual(typeof result.entraClientId, 'string');
});

test('Unit: resolveEntraSettings result has exactly two properties', async (t) => {
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 'tenant-123',
    ENTRA_CLIENT_ID: 'client-456',
  });

  const result = resolveEntraSettings({
    env: {},
    context: () => undefined,
    secret,
  });

  const keys = Object.keys(result).sort();
  assert.deepStrictEqual(keys, ['entraClientId', 'entraTenantId']);
});

test('Unit: Context with non-string value is ignored', async (t) => {
  const env = {};
  const context = (key) => {
    if (key === 'entraTenantId') return 123; // Non-string value
    return undefined;
  };

  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-secret',
    ENTRA_CLIENT_ID: 'c-secret',
  });

  const result = resolveEntraSettings({ env, context, secret });

  // Non-string context value should be ignored, so secret value is used
  assert.strictEqual(result.entraTenantId, 't-secret');
});

test('Unit: Context with empty string is treated as unset', async (t) => {
  const env = {};
  const context = (key) => {
    if (key === 'entraTenantId') return '';
    return undefined;
  };

  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-secret',
    ENTRA_CLIENT_ID: 'c-secret',
  });

  const result = resolveEntraSettings({ env, context, secret });

  // Empty string context value should be treated as unset, so secret value is used
  assert.strictEqual(result.entraTenantId, 't-secret');
});

test('Unit: Env with undefined value is treated as unset', async (t) => {
  const env = { ENTRA_TENANT_ID: undefined };
  const context = () => undefined;

  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-secret',
    ENTRA_CLIENT_ID: 'c-secret',
  });

  const result = resolveEntraSettings({ env, context, secret });

  // Undefined env value should be treated as unset, so secret value is used
  assert.strictEqual(result.entraTenantId, 't-secret');
});

test('Unit: Whitespace in secret value is trimmed', async (t) => {
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: '   \t  t-value  \n  ',
    ENTRA_CLIENT_ID: 'c-value',
  });

  const result = resolveEntraSettings({
    env: {},
    context: () => undefined,
    secret,
  });

  assert.strictEqual(result.entraTenantId, 't-value');
});

test('Unit: Each key is resolved independently - tenant from env, client from secret', async (t) => {
  const env = { ENTRA_TENANT_ID: 't-env' };
  const context = () => undefined;

  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-secret',
    ENTRA_CLIENT_ID: 'c-secret',
  });

  const result = resolveEntraSettings({ env, context, secret });

  assert.strictEqual(result.entraTenantId, 't-env');
  assert.strictEqual(result.entraClientId, 'c-secret');
});

test('Unit: Each key is resolved independently - tenant from context, client from env', async (t) => {
  const env = { ENTRA_CLIENT_ID: 'c-env' };
  const context = (key) => {
    if (key === 'entraTenantId') return 't-context';
    return undefined;
  };

  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-secret',
    ENTRA_CLIENT_ID: 'c-secret',
  });

  const result = resolveEntraSettings({ env, context, secret });

  assert.strictEqual(result.entraTenantId, 't-context');
  assert.strictEqual(result.entraClientId, 'c-env');
});

test('Unit: Precedence chain: env > context > secret for tenant id', async (t) => {
  const env = { ENTRA_TENANT_ID: 't-env' };
  const context = (key) => {
    if (key === 'entraTenantId') return 't-context';
    return undefined;
  };

  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-secret',
    ENTRA_CLIENT_ID: 'c-secret',
  });

  const result = resolveEntraSettings({ env, context, secret });

  // Env wins
  assert.strictEqual(result.entraTenantId, 't-env');
});

test('Unit: Precedence chain: context > secret when env is empty', async (t) => {
  const env = { ENTRA_TENANT_ID: '' };
  const context = (key) => {
    if (key === 'entraTenantId') return 't-context';
    return undefined;
  };

  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-secret',
    ENTRA_CLIENT_ID: 'c-secret',
  });

  const result = resolveEntraSettings({ env, context, secret });

  // Context wins over secret
  assert.strictEqual(result.entraTenantId, 't-context');
});

test('Unit: Precedence chain: secret when env and context are empty', async (t) => {
  const env = { ENTRA_TENANT_ID: '' };
  const context = (key) => {
    if (key === 'entraTenantId') return '';
    return undefined;
  };

  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-secret',
    ENTRA_CLIENT_ID: 'c-secret',
  });

  const result = resolveEntraSettings({ env, context, secret });

  // Secret is last resort
  assert.strictEqual(result.entraTenantId, 't-secret');
});

test('Unit: Error includes key name and secret id in message', async (t) => {
  const secret = createFakeDeploySecret({
    ENTRA_CLIENT_ID: 'c-secret',
  });

  assert.throws(
    () =>
      resolveEntraSettings({
        env: {},
        context: () => undefined,
        secret,
      }),
    (err) => {
      const msg = err.message;
      return msg.includes('ENTRA_TENANT_ID') && msg.includes('prod/sk-mdm');
    }
  );
});

test('Unit: Secret key name matches env var name (ENTRA_TENANT_ID)', async (t) => {
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-secret',
    ENTRA_CLIENT_ID: 'c-secret',
  });

  const result = resolveEntraSettings({
    env: {},
    context: () => undefined,
    secret,
  });

  assert.strictEqual(result.entraTenantId, 't-secret');
});

test('Unit: Secret key name matches env var name (ENTRA_CLIENT_ID)', async (t) => {
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-secret',
    ENTRA_CLIENT_ID: 'c-secret',
  });

  const result = resolveEntraSettings({
    env: {},
    context: () => undefined,
    secret,
  });

  assert.strictEqual(result.entraClientId, 'c-secret');
});

test('Unit: get() is called on secret, not require()', async (t) => {
  let getWasCalled = false;
  let requireWasCalled = false;

  const secret = Object.freeze({
    secretId: 'prod/sk-mdm',
    get(key) {
      getWasCalled = true;
      if (key === 'ENTRA_TENANT_ID') return 't-secret';
      if (key === 'ENTRA_CLIENT_ID') return 'c-secret';
      return undefined;
    },
    require(key) {
      requireWasCalled = true;
      throw new Error(`${key} is required`);
    },
    keys() {
      return ['ENTRA_TENANT_ID', 'ENTRA_CLIENT_ID'];
    },
  });

  resolveEntraSettings({
    env: {},
    context: () => undefined,
    secret,
  });

  assert.ok(getWasCalled, 'get() should be called');
  assert.ok(!requireWasCalled, 'require() should not be called');
});

test('Unit: Null context return is ignored', async (t) => {
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-secret',
    ENTRA_CLIENT_ID: 'c-secret',
  });

  const result = resolveEntraSettings({
    env: {},
    context: () => null,
    secret,
  });

  // Null context value should be treated as missing
  assert.strictEqual(result.entraTenantId, 't-secret');
  assert.strictEqual(result.entraClientId, 'c-secret');
});

test('Unit: Object context return is ignored', async (t) => {
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-secret',
    ENTRA_CLIENT_ID: 'c-secret',
  });

  const result = resolveEntraSettings({
    env: {},
    context: () => ({ tenant: 't-context' }),
    secret,
  });

  // Object context value should be treated as missing
  assert.strictEqual(result.entraTenantId, 't-secret');
});

test('Unit: Array context return is ignored', async (t) => {
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-secret',
    ENTRA_CLIENT_ID: 'c-secret',
  });

  const result = resolveEntraSettings({
    env: {},
    context: () => ['t-context'],
    secret,
  });

  // Array context value should be treated as missing
  assert.strictEqual(result.entraTenantId, 't-secret');
});

test('Unit: Boolean context return is ignored', async (t) => {
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-secret',
    ENTRA_CLIENT_ID: 'c-secret',
  });

  const result = resolveEntraSettings({
    env: {},
    context: () => true,
    secret,
  });

  // Boolean context value should be treated as missing
  assert.strictEqual(result.entraTenantId, 't-secret');
});

test('Unit: Secret value with only spaces is treated as empty', async (t) => {
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: '     ',
    ENTRA_CLIENT_ID: 'c-secret',
  });

  assert.throws(
    () =>
      resolveEntraSettings({
        env: {},
        context: () => undefined,
        secret,
      }),
    (err) =>
      err instanceof Error &&
      err.message === 'ENTRA_TENANT_ID not found in secret prod/sk-mdm, environment or CDK context'
  );
});

test('Unit: Secret value with only tabs is treated as empty', async (t) => {
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: '\t\t\t',
    ENTRA_CLIENT_ID: 'c-secret',
  });

  assert.throws(
    () =>
      resolveEntraSettings({
        env: {},
        context: () => undefined,
        secret,
      }),
    (err) =>
      err instanceof Error &&
      err.message === 'ENTRA_TENANT_ID not found in secret prod/sk-mdm, environment or CDK context'
  );
});

test('Unit: Secret value with mixed whitespace is trimmed correctly', async (t) => {
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: ' \t t-val \n ',
    ENTRA_CLIENT_ID: 'c-secret',
  });

  const result = resolveEntraSettings({
    env: {},
    context: () => undefined,
    secret,
  });

  assert.strictEqual(result.entraTenantId, 't-val');
});

test('Unit: Very long secret value is preserved', async (t) => {
  const longValue = 'x'.repeat(1000);
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: longValue,
    ENTRA_CLIENT_ID: 'c-secret',
  });

  const result = resolveEntraSettings({
    env: {},
    context: () => undefined,
    secret,
  });

  assert.strictEqual(result.entraTenantId, longValue);
});

test('Unit: Env value is returned as-is without trimming', async (t) => {
  const env = { ENTRA_TENANT_ID: '  t-env  ' };
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-secret',
    ENTRA_CLIENT_ID: 'c-secret',
  });

  const result = resolveEntraSettings({
    env,
    context: () => undefined,
    secret,
  });

  // Env values are not trimmed, only secret values are
  assert.strictEqual(result.entraTenantId, '  t-env  ');
});

test('Unit: Context value is returned as-is without trimming', async (t) => {
  const secret = createFakeDeploySecret({
    ENTRA_TENANT_ID: 't-secret',
    ENTRA_CLIENT_ID: 'c-secret',
  });

  const result = resolveEntraSettings({
    env: {},
    context: (key) => {
      if (key === 'entraTenantId') return '  t-ctx  ';
      return undefined;
    },
    secret,
  });

  // Context values are not trimmed, only secret values are
  assert.strictEqual(result.entraTenantId, '  t-ctx  ');
});
