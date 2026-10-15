/**
 * E2E cucumber-style and unit tests for the "not ready" refusals TASK-050
 * adds to the user and device application routes (AC11, AC13):
 * `backend/src/routes/applications.ts`.
 *
 * All database calls are mocked with a tiny in-memory fake table and an
 * injected `verifyDevice` -- no real DB connection and no signed-request
 * machinery is exercised here.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

const {
  createUserApplicationListHandler,
  createUserApplicationDownloadHandler,
  createDeviceApplicationDownloadHandler,
} = await import('../../dist/routes/applications.js');
const { application: applicationKey } = await import('../../dist/db/keys.js');

const VALID_SHA256 = 'c'.repeat(64);

class FakeTable {
  constructor() {
    this.items = new Map();
  }

  keyStr(key) {
    return `${key.pk}#${key.sk}`;
  }

  async put(item) {
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  async get(key) {
    return this.items.get(this.keyStr(key));
  }

  async query(request) {
    const gsi1pk = request.ExpressionAttributeValues?.[':gsi1pk'];
    const items = [...this.items.values()].filter((item) => item.gsi1pk === gsi1pk);
    return { items, cursor: null };
  }

  async putIfAbsent() {
    throw new Error('not used by these tests');
  }
}

function seedApp(table, applicationId, fields) {
  table.put({
    ...applicationKey(applicationId),
    applicationId,
    gsi1pk: 'APPLICATION',
    gsi1sk: fields.name,
    description: null,
    installArgs: null,
    createdAt: '2026-10-01T00:00:00Z',
    createdBy: 'seed@officehq.com.au',
    ...fields,
  });
}

function makeVerifier() {
  return {
    async verify(token) {
      if (token === 'T') {
        return { sub: 'u-1' };
      }
      throw { status: 401, error: 'invalid_token' };
    },
  };
}

function req({ headers = {}, params = {} } = {}) {
  return { headers, params, query: {} };
}

function deviceReq(deviceId, applicationId) {
  return { headers: {}, params: { deviceId, applicationId }, query: {} };
}

function failingPresignGet() {
  return async () => {
    throw new Error('presignGet must not be called while not ready');
  };
}

// ============================================================================
// AC11
// ============================================================================

test('Scenario: User list hides applications that are not ready', async () => {
  // Given applications "A" ready, "B" pending and "C" failed
  const table = new FakeTable();
  seedApp(table, 'app-a', { name: 'A', platform: 'windows', installerType: 'msi', source: 'url', url: 'https://x/a', sha256: VALID_SHA256, hashStatus: 'ready' });
  seedApp(table, 'app-b', { name: 'B', platform: 'windows', installerType: 'msi', source: 'url', url: 'https://x/b', sha256: null, hashStatus: 'pending' });
  seedApp(table, 'app-c', { name: 'C', platform: 'windows', installerType: 'msi', source: 'url', url: 'https://x/c', sha256: null, hashStatus: 'failed', hashError: 'http_404' });
  const handler = createUserApplicationListHandler({ table, userVerifier: makeVerifier() });

  // When a signed-in user gets /api/v1/applications
  const result = await handler(req({ headers: { authorization: 'Bearer T' } }));

  // Then the items are only "A" with the five TASK-049 keys
  assert.equal(result.statusCode, 200);
  assert.deepEqual(result.body.items.map((item) => item.name), ['A']);
  assert.deepEqual(Object.keys(result.body.items[0]).sort(), ['applicationId', 'description', 'installerType', 'name', 'platform']);
});

test('Scenario (failure): User download of a pending application', async () => {
  // Given a pending URL application "app-2" and a valid MDM.User token
  const table = new FakeTable();
  seedApp(table, 'app-2', { name: 'Zoom', platform: 'windows', installerType: 'msi', source: 'url', url: 'https://x/a', sha256: null, hashStatus: 'pending' });
  const handler = createUserApplicationDownloadHandler({ table, userVerifier: makeVerifier(), installers: { presignGet: failingPresignGet() } });

  // When the user gets /api/v1/applications/app-2/download
  const result = await handler(req({ headers: { authorization: 'Bearer T' }, params: { applicationId: 'app-2' } }));

  // Then the status is 409 with error "application_not_ready", cache-control
  // "no-store" and presignGet was not called (the stubbed presignGet throws
  // if ever invoked, so reaching this assertion already proves it)
  assert.equal(result.statusCode, 409);
  assert.equal(result.body.error, 'application_not_ready');
  assert.equal(result.headers['cache-control'], 'no-store');
});

test('Unit: a failed URL application is refused the same way', async () => {
  const table = new FakeTable();
  seedApp(table, 'app-3', { name: 'Zoom', platform: 'windows', installerType: 'msi', source: 'url', url: 'https://x/a', sha256: null, hashStatus: 'failed', hashError: 'timeout' });
  const handler = createUserApplicationDownloadHandler({ table, userVerifier: makeVerifier(), installers: { presignGet: failingPresignGet() } });

  const result = await handler(req({ headers: { authorization: 'Bearer T' }, params: { applicationId: 'app-3' } }));

  assert.equal(result.statusCode, 409);
  assert.equal(result.body.error, 'application_not_ready');
});

test('Unit: an unknown application still answers 404 not_found, not 409', async () => {
  const table = new FakeTable();
  const handler = createUserApplicationDownloadHandler({ table, userVerifier: makeVerifier(), installers: { presignGet: failingPresignGet() } });

  const result = await handler(req({ headers: { authorization: 'Bearer T' }, params: { applicationId: 'app-missing' } }));

  assert.equal(result.statusCode, 404);
  assert.equal(result.body.error, 'not_found');
});

// ============================================================================
// AC13
// ============================================================================

test('Scenario (failure): Agent details refused while not ready', async () => {
  // Given dev-1 is authenticated and "app-2" is a pending URL application
  const table = new FakeTable();
  seedApp(table, 'app-2', { name: 'Zoom', platform: 'windows', installerType: 'msi', source: 'url', url: 'https://x/a', sha256: null, hashStatus: 'pending' });
  const verifyDevice = async () => ({ ok: true, deviceId: 'dev-1' });
  const handler = createDeviceApplicationDownloadHandler({ table, installers: { presignGet: failingPresignGet() }, verifyDevice });

  // When dev-1 gets /api/v1/devices/dev-1/applications/app-2/download
  const result = await handler(deviceReq('dev-1', 'app-2'));

  // Then the status is 409 with error "application_not_ready" and presignGet was not called
  assert.equal(result.statusCode, 409);
  assert.equal(result.body.error, 'application_not_ready');

  // And authenticated dev-1 asking on /api/v1/devices/dev-2/applications/app-2/download
  // still gets 403 "device_mismatch"
  const mismatch = await handler(deviceReq('dev-2', 'app-2'));
  assert.equal(mismatch.statusCode, 403);
  assert.equal(mismatch.body.error, 'device_mismatch');
});

test('Unit: the not_ready check runs after application_not_found, not before', async () => {
  const table = new FakeTable();
  const verifyDevice = async () => ({ ok: true, deviceId: 'dev-1' });
  const handler = createDeviceApplicationDownloadHandler({ table, installers: { presignGet: failingPresignGet() }, verifyDevice });

  const result = await handler(deviceReq('dev-1', 'app-missing'));

  assert.equal(result.statusCode, 404);
  assert.equal(result.body.error, 'application_not_found');
});

test('Unit: a ready application still gets its presigned download details', async () => {
  const table = new FakeTable();
  seedApp(table, 'app-4', { name: 'Ready App', platform: 'windows', installerType: 'msi', source: 'url', url: 'https://registered.example/x.msi', sha256: VALID_SHA256, hashStatus: 'ready' });
  const verifyDevice = async () => ({ ok: true, deviceId: 'dev-1' });
  const handler = createDeviceApplicationDownloadHandler({ table, verifyDevice });

  const result = await handler(deviceReq('dev-1', 'app-4'));

  assert.equal(result.statusCode, 200);
  assert.equal(result.body.url, 'https://registered.example/x.msi');
});
