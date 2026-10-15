/**
 * E2E cucumber-style and unit tests for the signed-in user and device-signed
 * application routes (TASK-049, AC10, AC11, AC14):
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
  userApplicationItem,
} = await import('../../dist/routes/applications.js');
const { application: applicationKey } = await import('../../dist/db/keys.js');

const VALID_SHA256 = 'b'.repeat(64);

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

/** A verifier that resolves when token === "T", otherwise rejects as scripted. */
function makeVerifier(rejection = { status: 401, error: 'invalid_token' }) {
  return {
    calls: 0,
    async verify(token) {
      this.calls += 1;
      if (token === 'T') {
        return { sub: 'u-1' };
      }
      throw rejection;
    },
  };
}

function req({ headers = {}, params = {} } = {}) {
  return { headers, params, query: {} };
}

// ============================================================================
// AC10: GET /api/v1/applications
// ============================================================================

test('Scenario: Signed-in user lists applications', async () => {
  const table = new FakeTable();
  seedApp(table, 'app-1', { name: '7-Zip', platform: 'windows', installerType: 'msi', source: 'upload', objectKey: 'k', sha256: VALID_SHA256, fileName: '7z.msi', sizeBytes: 10 });
  const verifier = makeVerifier();
  const handler = createUserApplicationListHandler({ table, userVerifier: verifier });

  const result = await handler(req({ headers: { authorization: 'Bearer T' } }));

  assert.equal(result.statusCode, 200);
  assert.equal(result.headers['cache-control'], 'no-store');
  assert.equal(result.body.items.length, 1);
  const keys = Object.keys(result.body.items[0]).sort();
  assert.deepEqual(keys, ['applicationId', 'description', 'installerType', 'name', 'platform']);
});

test('Scenario (failure): Unauthenticated and wrong-scope list requests', async () => {
  const table = new FakeTable();
  let tableCalled = false;
  const trackedTable = {
    async get(key) {
      tableCalled = true;
      return table.get(key);
    },
    async query(request) {
      tableCalled = true;
      return table.query(request);
    },
  };
  const verifier = makeVerifier();
  const handler = createUserApplicationListHandler({ table: trackedTable, userVerifier: verifier });

  // When a client gets /api/v1/applications with no Authorization header
  const noAuth = await handler(req());
  assert.equal(noAuth.statusCode, 401);
  assert.equal(noAuth.body.error, 'unauthorized');
  assert.equal(verifier.calls, 0, 'the verifier must not be called');
  assert.equal(tableCalled, false, 'the table must not be called');

  // And with a token the verifier rejects as {403, missing_scope}
  const forbiddenVerifier = makeVerifier({ status: 403, error: 'missing_scope' });
  const forbiddenHandler = createUserApplicationListHandler({ table, userVerifier: forbiddenVerifier });
  const forbidden = await forbiddenHandler(req({ headers: { authorization: 'Bearer bad' } }));
  assert.equal(forbidden.statusCode, 403);
  assert.equal(forbidden.body.error, 'missing_scope');
});

test('Unit: userApplicationItem carries exactly five keys, never url/objectKey/sha256/fileName', () => {
  const item = userApplicationItem({
    applicationId: 'app-1',
    name: 'X',
    description: null,
    platform: 'windows',
    installerType: 'msi',
    url: 'https://example.test/a',
    objectKey: 'k',
    sha256: VALID_SHA256,
    fileName: 'a.msi',
  });
  assert.deepEqual(Object.keys(item).sort(), ['applicationId', 'description', 'installerType', 'name', 'platform']);
});

// ============================================================================
// AC11: GET /api/v1/applications/{applicationId}/download
// ============================================================================

test('Scenario: Signed-in user gets a download URL', async () => {
  const table = new FakeTable();
  seedApp(table, 'app-1', { name: 'Upload App', platform: 'windows', installerType: 'msi', source: 'upload', objectKey: 'applications/a/b.msi', sha256: VALID_SHA256, fileName: 'b.msi', sizeBytes: 10 });
  seedApp(table, 'app-2', { name: 'URL App', platform: 'windows', installerType: 'msi', source: 'url', url: 'https://registered.example/x.msi', sha256: VALID_SHA256 });

  const presignCalls = [];
  const installers = {
    async presignGet(objectKey, ttlSeconds) {
      presignCalls.push({ objectKey, ttlSeconds });
      return 'https://bucket/presigned';
    },
  };
  const verifier = makeVerifier();
  const handler = createUserApplicationDownloadHandler({ table, userVerifier: verifier, installers });

  // Upload source
  const uploadResult = await handler(req({ headers: { authorization: 'Bearer T' }, params: { applicationId: 'app-1' } }));
  assert.equal(uploadResult.statusCode, 200);
  assert.equal(uploadResult.headers['cache-control'], 'no-store');
  assert.deepEqual(uploadResult.body, { url: 'https://bucket/presigned' });
  assert.equal(presignCalls[0].objectKey, 'applications/a/b.msi');
  assert.equal(presignCalls[0].ttlSeconds, 300);

  // URL source: the body is {url: <stored url>}
  const urlResult = await handler(req({ headers: { authorization: 'Bearer T' }, params: { applicationId: 'app-2' } }));
  assert.equal(urlResult.statusCode, 200);
  assert.deepEqual(urlResult.body, { url: 'https://registered.example/x.msi' });
});

test('Scenario (failure): Download URL failures', async () => {
  const table = new FakeTable();
  seedApp(table, 'app-1', { name: 'Upload App', platform: 'windows', installerType: 'msi', source: 'upload', objectKey: 'k', sha256: VALID_SHA256, fileName: 'f.msi', sizeBytes: 1 });
  const verifier = makeVerifier();

  // Unknown id -> 404 not_found
  const noInstallers = createUserApplicationDownloadHandler({ table, userVerifier: verifier });
  const unknown = await noInstallers(req({ headers: { authorization: 'Bearer T' }, params: { applicationId: 'app-missing' } }));
  assert.equal(unknown.statusCode, 404);
  assert.equal(unknown.body.error, 'not_found');

  // No Authorization header -> 401 unauthorized
  const noAuth = await noInstallers(req({ params: { applicationId: 'app-1' } }));
  assert.equal(noAuth.statusCode, 401);
  assert.equal(noAuth.body.error, 'unauthorized');

  // No installer store -> an upload application answers 500 not_configured
  const withoutStore = await noInstallers(req({ headers: { authorization: 'Bearer T' }, params: { applicationId: 'app-1' } }));
  assert.equal(withoutStore.statusCode, 500);
  assert.equal(withoutStore.body.error, 'not_configured');
});

// ============================================================================
// AC14: GET /api/v1/devices/{deviceId}/applications/{applicationId}/download
// ============================================================================

function deviceReq(deviceId, applicationId) {
  return { headers: {}, params: { deviceId, applicationId }, query: {} };
}

test('Scenario: Agent fetches fresh download details', async () => {
  const table = new FakeTable();
  seedApp(table, 'app-1', { name: 'Upload App', platform: 'windows', installerType: 'msi', source: 'upload', objectKey: 'k', sha256: VALID_SHA256, fileName: '7z.msi', sizeBytes: 1 });
  const presignCalls = [];
  const installers = {
    async presignGet(objectKey, ttlSeconds) {
      presignCalls.push({ objectKey, ttlSeconds });
      return 'https://bucket/device-presigned';
    },
  };
  const verifyDevice = async () => ({ ok: true, deviceId: 'dev-1' });
  const handler = createDeviceApplicationDownloadHandler({ table, installers, verifyDevice });

  const result = await handler(deviceReq('dev-1', 'app-1'));

  assert.equal(result.statusCode, 200);
  assert.equal(result.body.url, 'https://bucket/device-presigned');
  assert.equal(result.body.sha256, VALID_SHA256);
  assert.equal(result.body.installerType, 'msi');
  assert.equal(result.body.installArgs, null);
  assert.equal(result.body.fileName, '7z.msi');
  assert.equal(presignCalls[0].objectKey, 'k');
  assert.equal(presignCalls[0].ttlSeconds, 900);
});

test('Scenario (failure): Device asks for another device or a deleted application', async () => {
  const table = new FakeTable();
  seedApp(table, 'app-1', { name: 'X', platform: 'windows', installerType: 'msi', source: 'upload', objectKey: 'k', sha256: VALID_SHA256, fileName: 'f.msi', sizeBytes: 1 });
  let tableGetCalled = false;
  const trackedTable = {
    async get(key) {
      tableGetCalled = true;
      return table.get(key);
    },
    async query(request) {
      return table.query(request);
    },
  };
  const verifyDevice = async () => ({ ok: true, deviceId: 'dev-1' });
  const handler = createDeviceApplicationDownloadHandler({ table: trackedTable, verifyDevice });

  // A path device id different from the authenticated one -> 403 device_mismatch
  const mismatch = await handler(deviceReq('dev-2', 'app-1'));
  assert.equal(mismatch.statusCode, 403);
  assert.equal(mismatch.body.error, 'device_mismatch');
  assert.equal(tableGetCalled, false, 'no application should be read before the device check');

  // A deleted application on its own path -> 404 application_not_found
  const deleted = await handler(deviceReq('dev-1', 'app-missing'));
  assert.equal(deleted.statusCode, 404);
  assert.equal(deleted.body.error, 'application_not_found');
});

test('Unit: an authentication failure is returned unchanged', async () => {
  const table = new FakeTable();
  const verifyDevice = async () => ({ ok: false, status: 401, body: { error: 'invalid_signature' } });
  const handler = createDeviceApplicationDownloadHandler({ table, verifyDevice });

  const result = await handler(deviceReq('dev-1', 'app-1'));
  assert.equal(result.statusCode, 401);
  assert.deepEqual(result.body, { error: 'invalid_signature' });
});
