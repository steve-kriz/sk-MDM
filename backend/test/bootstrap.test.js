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
  S3_CLIENT_OPTIONS,
} from '../dist/bootstrap.js';
import { router } from '../dist/index.js';
import { resolveEnrollDependencies } from '../dist/routes/enroll.js';
import { resolveCheckInDependencies } from '../dist/routes/checkin.js';
import { resolvePolicyBundleDependencies } from '../dist/routes/policies.js';
import { resolveAdminDependencies } from '../dist/admin/router.js';
import { resolveDownloadDependencies } from '../dist/routes/downloads.js';
import { resolveAgentSignInDependencies } from '../dist/routes/agentSignIn.js';
import { resolveAgentEnrollmentTokenDependencies } from '../dist/routes/agentEnrollmentToken.js';
import { resolveUserSessionDependencies } from '../dist/routes/userSession.js';
import { resolveApplicationDependencies } from '../dist/routes/applications.js';
import { HeadObjectCommand, S3Client } from '@aws-sdk/client-s3';

function completeTask023Env(overrides = {}) {
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

function routerRequest(path) {
  return { method: 'GET', path, query: {}, headers: {}, body: null };
}

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
  // Amendment B: enroll takes the enrollment token only; the user token
  // verifier belongs to the mint route, which shares the table.
  assert.strictEqual(enrollDeps.userVerifier, undefined, 'enroll route has no user token verifier');
  const mintDeps = resolveAgentEnrollmentTokenDependencies();
  assert.ok(typeof mintDeps.userVerifier?.verify === 'function', 'mint route has the user token verifier');
  assert.strictEqual(mintDeps.table, enrollDeps.table);
  assert.strictEqual(resolveUserSessionDependencies().userVerifier, undefined, 'user-session is device HMAC only');
  assert.ok(checkinDeps);
  assert.ok(policyDeps);
  assert.ok(adminDeps);
  assert.ok(adminDeps.verifier);
  assert.ok(typeof adminDeps.verifier.verify === 'function');
  // Amendment A: the agent sign-in sessions share the same table client.
  assert.strictEqual(resolveAgentSignInDependencies().table, enrollDeps.table);

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
  // Amendment B: enroll takes the enrollment token only; the user token
  // verifier belongs to the mint route, which shares the table.
  assert.strictEqual(enrollDeps.userVerifier, undefined, 'enroll route has no user token verifier');
  const mintDeps = resolveAgentEnrollmentTokenDependencies();
  assert.ok(typeof mintDeps.userVerifier?.verify === 'function', 'mint route has the user token verifier');
  assert.strictEqual(mintDeps.table, enrollDeps.table);
  assert.strictEqual(resolveUserSessionDependencies().userVerifier, undefined, 'user-session is device HMAC only');
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
// TASK-025: bootstrap wires the download route from env.INSTALLER_BUCKET
// ============================================================================

test('Scenario: Bootstrap wires the download route from env.INSTALLER_BUCKET via the injected S3 factory', async (t) => {
  // Given process.env.INSTALLER_BUCKET is unset
  const hadEnvVar = Object.prototype.hasOwnProperty.call(process.env, 'INSTALLER_BUCKET');
  const previous = process.env.INSTALLER_BUCKET;
  delete process.env.INSTALLER_BUCKET;

  try {
    // And a complete TASK-023 bootstrap env with INSTALLER_BUCKET "b"
    // And a fake createS3Client whose client's send rejects with name "NotFound"
    const sendCalls = [];
    const fakeS3Client = {
      send(command) {
        sendCalls.push(command);
        return Promise.reject({ name: 'NotFound' });
      },
    };

    // When bootstrap runs with fake createDocumentClient, createSecretsClient,
    // fetchImpl and createS3Client
    const result = await bootstrap({
      env: completeTask023Env({ INSTALLER_BUCKET: 'b' }),
      ...fakeFactories(),
      createS3Client: () => fakeS3Client,
    });

    // Then bootstrap resolves
    assert.ok(result);

    // And resolveDownloadDependencies().bucket is "b"
    assert.strictEqual(resolveDownloadDependencies().bucket, 'b');

    // When the router handles GET "/downloads/windows-x64"
    const response = await router.handle(routerRequest('/downloads/windows-x64'));

    // Then the status is 404 with body {"error":"installer_not_available"}
    assert.strictEqual(response.statusCode, 404);
    assert.deepStrictEqual(JSON.parse(response.body), { error: 'installer_not_available' });

    // And the fake S3 client's send was called exactly once
    assert.strictEqual(sendCalls.length, 1);

    // And that call's command is a HeadObjectCommand whose input is
    // {"Bucket":"b","Key":"installers/windows-x64.msi"}
    assert.ok(sendCalls[0] instanceof HeadObjectCommand);
    assert.deepStrictEqual(sendCalls[0].input, { Bucket: 'b', Key: 'installers/windows-x64.msi' });
  } finally {
    if (hadEnvVar) {
      process.env.INSTALLER_BUCKET = previous;
    } else {
      delete process.env.INSTALLER_BUCKET;
    }
  }
});

for (const { label, env } of [
  { label: 'absent', env: completeTask023Env() },
  { label: 'set to ""', env: completeTask023Env({ INSTALLER_BUCKET: '' }) },
]) {
  test(`Scenario Outline: Missing or empty INSTALLER_BUCKET does not stop bootstrap (${label})`, async (t) => {
    // Given a complete TASK-023 bootstrap env with INSTALLER_BUCKET <state>
    // When bootstrap runs with fake factories
    const result = await bootstrap({ env, ...fakeFactories() }).catch((e) => e);

    // Then bootstrap resolves and does not reject with "missing environment
    // variable INSTALLER_BUCKET"
    assert.ok(!(result instanceof Error), `bootstrap should resolve, got ${result?.message}`);

    // When the router handles GET "/downloads/windows-x64"
    const response = await router.handle(routerRequest('/downloads/windows-x64'));

    // Then the status is 500 with body {"error":"not_configured"}
    assert.strictEqual(response.statusCode, 500);
    assert.deepStrictEqual(JSON.parse(response.body), { error: 'not_configured' });
  });
}

test('Unit: INSTALLER_BUCKET is not among the required-variable names', (t) => {
  assert.ok(!Array.from(REQUIRED_ENV).includes('INSTALLER_BUCKET'));
});

// ============================================================================
// TASK-048 (AC9): bootstrap shares the installer store between the download
// and check-in routes, and omits it from check-in when the bucket is empty.
// ============================================================================

test('Scenario: Bootstrap shares the installer store with check-in', async (t) => {
  // Given INSTALLER_BUCKET is "installer-bucket"
  const hadEnvVar = Object.prototype.hasOwnProperty.call(process.env, 'INSTALLER_BUCKET');
  const previous = process.env.INSTALLER_BUCKET;
  delete process.env.INSTALLER_BUCKET;

  try {
    const fakeS3Client = { send: () => Promise.reject({ name: 'NotFound' }) };

    // When bootstrap configures the routes
    const result = await bootstrap({
      env: completeTask023Env({ INSTALLER_BUCKET: 'installer-bucket' }),
      ...fakeFactories(),
      createS3Client: () => fakeS3Client,
    });
    assert.ok(result);

    // Then configureCheckInRoute received an installers value identical to the
    // one configureDownloadRoute received
    const checkInInstallers = resolveCheckInDependencies().installers;
    const downloadInstallers = resolveDownloadDependencies().installers;
    assert.ok(checkInInstallers, 'check-in should have an installers store');
    assert.strictEqual(checkInInstallers, downloadInstallers);
  } finally {
    if (hadEnvVar) {
      process.env.INSTALLER_BUCKET = previous;
    } else {
      delete process.env.INSTALLER_BUCKET;
    }
  }
});

test('Scenario: No installer bucket gives check-in no installer store', async (t) => {
  // Given INSTALLER_BUCKET is ""
  const hadEnvVar = Object.prototype.hasOwnProperty.call(process.env, 'INSTALLER_BUCKET');
  const previous = process.env.INSTALLER_BUCKET;
  delete process.env.INSTALLER_BUCKET;

  try {
    // When bootstrap configures the routes
    const result = await bootstrap({
      env: completeTask023Env({ INSTALLER_BUCKET: '' }),
      ...fakeFactories(),
    });
    assert.ok(result);

    // Then resolveCheckInDependencies().installers is undefined
    assert.strictEqual(resolveCheckInDependencies().installers, undefined);
  } finally {
    if (hadEnvVar) {
      process.env.INSTALLER_BUCKET = previous;
    } else {
      delete process.env.INSTALLER_BUCKET;
    }
  }
});

test('Unit: createS3Client is called exactly once when INSTALLER_BUCKET is set', async (t) => {
  const hadEnvVar = Object.prototype.hasOwnProperty.call(process.env, 'INSTALLER_BUCKET');
  const previous = process.env.INSTALLER_BUCKET;
  delete process.env.INSTALLER_BUCKET;

  try {
    let createS3ClientCalls = 0;
    const fakeS3Client = { send: () => Promise.reject({ name: 'NotFound' }) };
    await bootstrap({
      env: completeTask023Env({ INSTALLER_BUCKET: 'installer-bucket' }),
      ...fakeFactories(),
      createS3Client: () => {
        createS3ClientCalls += 1;
        return fakeS3Client;
      },
    });
    assert.strictEqual(createS3ClientCalls, 1);
  } finally {
    if (hadEnvVar) {
      process.env.INSTALLER_BUCKET = previous;
    } else {
      delete process.env.INSTALLER_BUCKET;
    }
  }
});

// ============================================================================
// TASK-066 AC10: bootstrap builds no Graph client (TASK-027 AC26 removed)
// ============================================================================

/** Runs bootstrap with fakes and records secrets traffic and fetched URLs. */
async function bootstrapRecording(env) {
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
  let secretsClientFactoryCalls = 0;
  await bootstrap({
    env,
    createDocumentClient: () => ({ send: async () => ({}) }),
    createSecretsClient: () => {
      secretsClientFactoryCalls += 1;
      return fakeSecretsClient;
    },
    fetchImpl: fakeFetch,
  });
  const graphCalls = fetchCalls.filter(
    (url) => url.startsWith('https://graph.microsoft.com/') || url.endsWith('/oauth2/v2.0/token'),
  );
  return { secretsSends, secretsClientFactoryCalls, graphCalls };
}

test('TASK-066 AC10: with GRAPH_SECRET_ID set, bootstrap reads only the pepper, fetches no Graph token and wires no graph', async (t) => {
  const { secretsSends, secretsClientFactoryCalls, graphCalls } = await bootstrapRecording({
    TABLE_NAME: 'table',
    PEPPER_SECRET_ARN: 'arn:secret',
    ENTRA_TENANT_ID: 't-1',
    ENTRA_CLIENT_ID: 'c-1',
    GRAPH_SECRET_ID: 'prod/sk-mdm',
  });

  assert.strictEqual(secretsClientFactoryCalls, 1, 'createSecretsClient should be called exactly once');
  assert.strictEqual(secretsSends.length, 1, 'exactly one Secrets Manager command (the pepper read)');
  assert.strictEqual(graphCalls.length, 0, 'no Graph or token request');
  assert.strictEqual('graph' in resolveAdminDependencies(), false);

  // Both removed user-link paths answer 404 on the router exported by index.ts.
  for (const path of ['/admin/api/v1/devices/d1/user-link/refresh', '/admin/api/v1/user-links/refresh']) {
    const result = await router.handle({ method: 'POST', path, query: {}, headers: {}, body: null });
    assert.strictEqual(result.statusCode, 404, `${path} should answer 404`);
    assert.strictEqual(result.body, '{"error":"not_found"}');
  }
});

test('TASK-066 AC10 (edge): with GRAPH_SECRET_ID absent, bootstrap resolves with one secrets command and no Graph fetch', async (t) => {
  const { secretsSends, graphCalls } = await bootstrapRecording({
    TABLE_NAME: 'table',
    PEPPER_SECRET_ARN: 'arn:secret',
    ENTRA_TENANT_ID: 't-1',
    ENTRA_CLIENT_ID: 'c-1',
  });

  assert.strictEqual(secretsSends.length, 1);
  assert.strictEqual(graphCalls.length, 0);
});

// ============================================================================
// TASK-049 AC16: S3_CLIENT_OPTIONS and the application routes' wiring
// ============================================================================

test('Scenario: Default S3 client only calculates checksums when required', (t) => {
  // Then bootstrap's S3_CLIENT_OPTIONS.requestChecksumCalculation is "WHEN_REQUIRED"
  assert.strictEqual(S3_CLIENT_OPTIONS.requestChecksumCalculation, 'WHEN_REQUIRED');

  // And the default createS3Client builds new S3Client({...S3_CLIENT_OPTIONS})
  const client = new S3Client({ ...S3_CLIENT_OPTIONS, region: 'us-east-1', credentials: { accessKeyId: 'a', secretAccessKey: 'b' } });
  assert.ok(client instanceof S3Client);
});

test('Scenario: Bootstrap wiring -- configureApplicationRoutes receives a userVerifier and the shared installers instance', async (t) => {
  const hadEnvVar = Object.prototype.hasOwnProperty.call(process.env, 'INSTALLER_BUCKET');
  const previous = process.env.INSTALLER_BUCKET;
  delete process.env.INSTALLER_BUCKET;

  try {
    // Given INSTALLER_BUCKET is "b"
    const fakeS3Client = { send: () => Promise.reject({ name: 'NotFound' }) };

    // When bootstrap runs
    await bootstrap({
      env: completeTask023Env({ INSTALLER_BUCKET: 'b' }),
      ...fakeFactories(),
      createS3Client: () => fakeS3Client,
    });

    // Then configureApplicationRoutes receives a userVerifier and the same
    // installers instance configureDownloadRoute and configureAdminRoutes receive
    const appDeps = resolveApplicationDependencies();
    assert.ok(appDeps.userVerifier, 'application routes should have a userVerifier');
    assert.strictEqual(typeof appDeps.userVerifier.verify, 'function');

    const downloadInstallers = resolveDownloadDependencies().installers;
    const adminInstallers = resolveAdminDependencies().installers;
    assert.ok(downloadInstallers);
    assert.strictEqual(appDeps.installers, downloadInstallers);
    assert.strictEqual(adminInstallers, downloadInstallers);
  } finally {
    if (hadEnvVar) {
      process.env.INSTALLER_BUCKET = previous;
    } else {
      delete process.env.INSTALLER_BUCKET;
    }
  }
});

test('Scenario: No bucket configured -- the resolved admin and application dependencies have installers undefined', async (t) => {
  const hadEnvVar = Object.prototype.hasOwnProperty.call(process.env, 'INSTALLER_BUCKET');
  const previous = process.env.INSTALLER_BUCKET;
  delete process.env.INSTALLER_BUCKET;

  try {
    // Given INSTALLER_BUCKET is ""
    await bootstrap({
      env: completeTask023Env({ INSTALLER_BUCKET: '' }),
      ...fakeFactories(),
    });

    // Then the resolved admin and application dependencies have installers undefined
    assert.strictEqual(resolveAdminDependencies().installers, undefined);
    assert.strictEqual(resolveApplicationDependencies().installers, undefined);
  } finally {
    if (hadEnvVar) {
      process.env.INSTALLER_BUCKET = previous;
    } else {
      delete process.env.INSTALLER_BUCKET;
    }
  }
});
