/**
 * E2E cucumber-style and unit tests for the `application_not_ready` refusal
 * TASK-050 adds to the device application queue (AC12):
 * `backend/src/admin/commandDispatch.ts`.
 *
 * Uses the real `createTableClient` over an in-memory `FakeDocumentClient`
 * (test/helpers/fakeDynamo.js), so the conditional writes and the `CMDSEQ`
 * counter run through production code -- no real database connection is made.
 */

import test from 'node:test';
import assert from 'node:assert';
import { createRouter } from '../../dist/index.js';
import { registerCommandDispatchRoutes } from '../../dist/admin/commandDispatch.js';
import { deviceProfile, application as applicationKey } from '../../dist/db/keys.js';
import { createFakeTable } from '../helpers/fakeDynamo.js';

class StubVerifier {
  async verify(token) {
    if (token === 'invalid') {
      throw { status: 401, error: 'invalid_token' };
    }
    return { sub: 'user123', preferred_username: 'admin@example.com' };
  }
}

async function makeRequest(router, method, path, options = {}) {
  const { headers = {}, query = {}, body = null } = options;
  return router.handle({ method, path, query, headers, body });
}

async function seedDevice(table, deviceId, platform) {
  await table.put({ ...deviceProfile(deviceId), deviceId, hostname: `host-${deviceId}`, platform });
}

async function seedApplication(table, applicationId, fields) {
  await table.put({
    ...applicationKey(applicationId),
    applicationId,
    name: 'App',
    source: 'url',
    url: 'https://example.test/a',
    sha256: null,
    createdAt: '2026-10-01T00:00:00Z',
    createdBy: 'seed@officehq.com.au',
    ...fields,
  });
}

function commandItemCount(documentClient) {
  let count = 0;
  for (const item of documentClient.items.values()) {
    if (typeof item.sk === 'string' && item.sk.startsWith('CMD#')) {
      count += 1;
    }
  }
  return count;
}

function auditCount(documentClient) {
  return [...documentClient.items.values()].filter((item) => item.action !== undefined).length;
}

// ============================================================================
// AC12
// ============================================================================

test('Scenario (failure): Queue refused while not ready', async () => {
  // Given windows device "dev-1" and a failed windows URL application "app-2"
  const { table, documentClient } = createFakeTable();
  const router = createRouter();
  registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => new Date('2026-10-11T00:00:00Z') });
  await seedDevice(table, 'dev-1', 'windows');
  await seedApplication(table, 'app-2', { platform: 'windows', installerType: 'msi', hashStatus: 'failed', hashError: 'http_404' });

  // When an admin posts {applicationId:"app-2"} to /admin/api/v1/devices/dev-1/applications
  const response = await makeRequest(router, 'POST', '/admin/api/v1/devices/dev-1/applications', {
    headers: { authorization: 'Bearer t' },
    body: JSON.stringify({ applicationId: 'app-2' }),
  });

  // Then the status is 409 with error "application_not_ready", no item is
  // written, CMDSEQ is unchanged and no audit is appended
  assert.strictEqual(response.statusCode, 409);
  assert.strictEqual(JSON.parse(response.body).error, 'application_not_ready');
  assert.strictEqual(commandItemCount(documentClient), 0);
  assert.strictEqual(documentClient.peek('DEVICE#dev-1', 'CMDSEQ'), undefined);
  assert.strictEqual(auditCount(documentClient), 0);
});

test('Unit: a pending application is refused the same way', async () => {
  const { table } = createFakeTable();
  const router = createRouter();
  registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => new Date('2026-10-11T00:00:00Z') });
  await seedDevice(table, 'dev-1', 'windows');
  await seedApplication(table, 'app-3', { platform: 'windows', installerType: 'msi', hashStatus: 'pending' });

  const response = await makeRequest(router, 'POST', '/admin/api/v1/devices/dev-1/applications', {
    headers: { authorization: 'Bearer t' },
    body: JSON.stringify({ applicationId: 'app-3' }),
  });

  assert.strictEqual(response.statusCode, 409);
  assert.strictEqual(JSON.parse(response.body).error, 'application_not_ready');
});

test('Scenario (edge): Platform mismatch is still reported first', async () => {
  // Given windows device "dev-1" and a pending darwin application
  const { table, documentClient } = createFakeTable();
  const router = createRouter();
  registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => new Date('2026-10-11T00:00:00Z') });
  await seedDevice(table, 'dev-1', 'windows');
  await seedApplication(table, 'app-4', { platform: 'darwin', installerType: 'pkg', hashStatus: 'pending' });

  // When an admin queues it
  const response = await makeRequest(router, 'POST', '/admin/api/v1/devices/dev-1/applications', {
    headers: { authorization: 'Bearer t' },
    body: JSON.stringify({ applicationId: 'app-4' }),
  });

  // Then the status is 409 with error "platform_mismatch"
  assert.strictEqual(response.statusCode, 409);
  assert.strictEqual(JSON.parse(response.body).error, 'platform_mismatch');
  assert.strictEqual(commandItemCount(documentClient), 0);
});

test('Unit: a ready application is still queued successfully', async () => {
  const { table, documentClient } = createFakeTable();
  const router = createRouter();
  registerCommandDispatchRoutes(router, { verifier: new StubVerifier(), table, now: () => new Date('2026-10-11T00:00:00Z') });
  await seedDevice(table, 'dev-1', 'windows');
  await seedApplication(table, 'app-5', { platform: 'windows', installerType: 'msi', sha256: 'a'.repeat(64) });

  const response = await makeRequest(router, 'POST', '/admin/api/v1/devices/dev-1/applications', {
    headers: { authorization: 'Bearer t' },
    body: JSON.stringify({ applicationId: 'app-5' }),
  });

  assert.strictEqual(response.statusCode, 202);
  assert.strictEqual(commandItemCount(documentClient), 1);
});
