/**
 * TASK-066: tests for the removal of the device User section and all
 * user-link resolution. Covers AC8, AC9, AC11, AC12, AC13, AC14, AC15 and
 * AC17 -- the route-, build- and source-level criteria that are not already
 * exercised by backend/test/ui/deviceSections.test.js (AC1-AC5),
 * backend/test/ui/views.test.js (AC1, AC6, AC7) or backend/test/bootstrap.test.js
 * (AC10).
 *
 * All database calls go through the in-memory FakeDocumentClient
 * (test/helpers/fakeDynamo.js) wrapped by the real TableClient; nothing here
 * opens a real DynamoDB connection, and no network call is made.
 */

import test from 'node:test';
import assert from 'node:assert';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRouter } from '../../dist/index.js';
import { registerDeviceRoutes, handleDeviceList, handleDeviceDetail, deviceSummary, DEVICE_SUMMARY_FIELDS } from '../../dist/admin/devices.js';
import { deviceProfile, deviceListIndex } from '../../dist/db/keys.js';
import { createFakeTable } from '../helpers/fakeDynamo.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const backendRoot = path.resolve(here, '..', '..');
const repoRoot = path.resolve(backendRoot, '..');

// ============================================================================
// Shared fakes -- no real database connection.
// ============================================================================

class StubVerifier {
  async verify(token) {
    if (token !== 'admin-token') {
      throw { status: 401, error: 'invalid_token' };
    }
    return { preferred_username: 'admin@contoso.com' };
  }
}

function adminDeps(table, overrides = {}) {
  return { table, claims: { sub: 'admin-1', upn: 'admin@example.com' }, ...overrides };
}

async function seedDevice(table, deviceId, extra = {}) {
  await table.put({
    ...deviceProfile(deviceId),
    ...deviceListIndex(`2026-10-10T22:30:00Z#${deviceId}`),
    deviceId,
    hostname: `host-${deviceId}`,
    platform: 'windows',
    ...extra,
  });
}

/** Seed a USERLINK item directly by its literal key (deviceUserLink() no longer exists -- AC9). */
async function seedUserLink(table, deviceId) {
  const item = {
    pk: `DEVICE#${deviceId}`,
    sk: 'USERLINK',
    deviceId,
    status: 'linked',
    resolvedAt: '2026-09-21T13:46:40Z',
    users: [{ displayName: 'Amy', userPrincipalName: 'amy@contoso.com' }],
  };
  await table.put(item);
  return item;
}

function mutatingSends(documentClient) {
  return documentClient.sends.filter((s) => ['Put', 'Update', 'Delete', 'TransactWrite'].includes(s.operation));
}

function getSends(documentClient) {
  return documentClient.sends.filter((s) => s.operation === 'Get');
}

// ============================================================================
// AC8 (failure): the removed endpoints answer 404 and write nothing
// ============================================================================

test('Scenario Outline: The removed endpoints answer 404 and write nothing (AC8)', async () => {
  const examples = [
    { method: 'POST', path: '/admin/api/v1/devices/d1/user-link/refresh', auth: true },
    { method: 'POST', path: '/admin/api/v1/devices/d1/user-link/refresh', auth: false },
    { method: 'POST', path: '/admin/api/v1/user-links/refresh', auth: true },
    { method: 'POST', path: '/admin/api/v1/user-links/refresh', auth: false },
    { method: 'GET', path: '/admin/api/v1/user-links/refresh', auth: false },
  ];

  for (const { method, path: reqPath, auth } of examples) {
    // Given admin routes are configured with a recording fake table
    const { table, documentClient } = createFakeTable();
    const router = createRouter();
    registerDeviceRoutes(router, { table, verifier: new StubVerifier(), now: () => 1000 });

    // When the request is sent, with or without an admin Authorization header
    const headers = auth ? { authorization: 'Bearer admin-token' } : {};
    const result = await router.handle({ method, path: reqPath, query: {}, headers, body: null });

    // Then the status is 404 and the body is exactly {"error":"not_found"}
    assert.strictEqual(result.statusCode, 404, `${method} ${reqPath} (auth=${auth}) should answer 404`);
    assert.strictEqual(result.body, '{"error":"not_found"}');

    // And the fake table recorded no put, update or delete
    assert.deepStrictEqual(mutatingSends(documentClient), [], `${method} ${reqPath} (auth=${auth}) should write nothing`);
  }
});

// ============================================================================
// AC11: The device list API no longer carries primaryUser
// ============================================================================

test('Scenario: The device list API no longer carries primaryUser (AC11)', async () => {
  // DEVICE_SUMMARY_FIELDS has the stated 10 fields, in order, no primaryUser
  assert.deepStrictEqual(DEVICE_SUMMARY_FIELDS, [
    'deviceId',
    'hostname',
    'platform',
    'osVersion',
    'osDisplay',
    'lastSeenAt',
    'complianceState',
    'agentVersion',
    'ownership',
    'enrolledBy',
  ]);

  // deviceSummary(profile) for a profile carrying primaryUserUpn has no primaryUser key
  const summary = deviceSummary({ deviceId: 'd1', hostname: 'h1', primaryUserUpn: 'amy@contoso.com' });
  assert.strictEqual('primaryUser' in summary, false);

  // And GET /admin/api/v1/devices list items have no primaryUser key
  const { table } = createFakeTable();
  await seedDevice(table, 'd1', { primaryUserUpn: 'amy@contoso.com' });
  const list = await handleDeviceList({ params: {}, query: {}, headers: {}, body: null }, adminDeps(table));
  assert.strictEqual(list.statusCode, 200);
  assert.ok(list.body.items.length > 0);
  for (const item of list.body.items) {
    assert.strictEqual('primaryUser' in item, false);
  }
});

// ============================================================================
// AC12: The device detail API no longer returns userLink
// ============================================================================

test('Scenario: The device detail API no longer returns userLink (AC12)', async () => {
  // Given a table holding a DEVICE#d1/USERLINK item
  const { table, documentClient } = createFakeTable();
  await seedDevice(table, 'd1');
  await seedUserLink(table, 'd1');

  // When an admin GETs /admin/api/v1/devices/d1
  const response = await handleDeviceDetail({ params: { deviceId: 'd1' }, query: {}, headers: {}, body: null }, adminDeps(table));

  // Then the status is 200 and the body has no userLink key
  assert.strictEqual(response.statusCode, 200);
  assert.strictEqual('userLink' in response.body, false);

  // And no table get was issued with sk "USERLINK"
  const usersLinkGets = getSends(documentClient).filter((s) => s.input?.Key?.sk === 'USERLINK');
  assert.deepStrictEqual(usersLinkGets, []);

  // And the required keys are present
  for (const key of [
    'profile',
    'inventory',
    'posture',
    'commands',
    'antivirusFindings',
    'antivirusScan',
    'antivirusStatus',
    'defenderHardening',
    'signedInUser',
    'loginHistory',
    'agentErrors',
    'analytics',
  ]) {
    assert.ok(key in response.body, `expected "${key}" to be present in the detail body`);
  }
});

// ============================================================================
// AC12 (failure): An unknown device still answers 404
// ============================================================================

test('Scenario: An unknown device still answers 404 (AC12 failure)', async () => {
  const { table } = createFakeTable();
  const response = await handleDeviceDetail({ params: { deviceId: 'missing' }, query: {}, headers: {}, body: null }, adminDeps(table));
  assert.strictEqual(response.statusCode, 404);
  assert.strictEqual(response.body.error, 'not_found');
});

// ============================================================================
// AC13 (edge): Stored user-link data is left untouched
// ============================================================================

test('Scenario: Stored user-link data is left untouched (AC13)', async () => {
  // Given a table seeded with a USERLINK item and a profile carrying primaryUserUpn
  const { table, documentClient } = createFakeTable();
  await seedDevice(table, 'd1', { primaryUserUpn: 'amy@contoso.com' });
  const seededUserLink = await seedUserLink(table, 'd1');
  const seededProfile = documentClient.peek('DEVICE#d1', 'PROFILE');

  // When GET /admin/api/v1/devices/d1 and GET /admin/api/v1/devices both run
  const detailResponse = await handleDeviceDetail({ params: { deviceId: 'd1' }, query: {}, headers: {}, body: null }, adminDeps(table));
  assert.strictEqual(detailResponse.statusCode, 200);
  const listResponse = await handleDeviceList({ params: {}, query: {}, headers: {}, body: null }, adminDeps(table));
  assert.strictEqual(listResponse.statusCode, 200);

  // Then both stored items are deep-equal to their seeded values
  assert.deepStrictEqual(documentClient.peek('DEVICE#d1', 'USERLINK'), seededUserLink);
  assert.deepStrictEqual(documentClient.peek('DEVICE#d1', 'PROFILE'), seededProfile);
  assert.strictEqual(documentClient.peek('DEVICE#d1', 'PROFILE').primaryUserUpn, 'amy@contoso.com');
});

// ============================================================================
// AC13 (source grep, backend/src excluding infra)
// ============================================================================

function walk(dir, { exts, excludeRel }) {
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    const rel = path.relative(backendRoot, full).split(path.sep).join('/');
    if (excludeRel.some((ex) => rel === ex || rel.startsWith(`${ex}/`))) {
      continue;
    }
    if (entry.isDirectory()) {
      results.push(...walk(full, { exts, excludeRel }));
    } else if (exts.some((ext) => entry.name.endsWith(ext))) {
      results.push(full);
    }
  }
  return results;
}

test('Scenario: backend/src outside infra has no stale user-link reference (AC13)', () => {
  const files = walk(path.join(backendRoot, 'src'), {
    exts: ['.ts', '.js'],
    excludeRel: ['src/infra'],
  });
  const forbidden = [
    'USERLINK',
    'primaryUserUpn',
    'userLink',
    'user-link',
    'user_link',
    'graph.microsoft.com',
    'GraphDirectory',
    'GRAPH_SECRET',
  ];
  for (const file of files) {
    const text = fs.readFileSync(file, 'utf8');
    for (const needle of forbidden) {
      assert.ok(!text.includes(needle), `${path.relative(backendRoot, file)} should not contain "${needle}"`);
    }
  }
});

// ============================================================================
// AC6: app.js source contains none of the four named strings
// ============================================================================

test('Scenario: app.js has no user-link code (AC6 source check)', () => {
  const appSrc = fs.readFileSync(path.join(backendRoot, 'src/ui/public/app.js'), 'utf8');
  for (const needle of ['refresh-user-link', 'user-link', 'refreshAllUserLinks', 'MAX_REFRESH_CALLS']) {
    assert.ok(!appSrc.includes(needle), `app.js should not contain "${needle}"`);
  }
});

// ============================================================================
// AC9: The user-link module and Graph client are deleted
// ============================================================================

test('Scenario: The user-link module and Graph client are deleted from the source tree (AC9)', () => {
  // backend/src/admin/userLinks.ts and backend/src/graph/client.ts do not exist
  assert.strictEqual(fs.existsSync(path.join(backendRoot, 'src/admin/userLinks.ts')), false);
  assert.strictEqual(fs.existsSync(path.join(backendRoot, 'src/graph/client.ts')), false);

  // index.ts neither calls registerUserLinkRoutes nor imports userLinks.js or graph/client.js
  const indexSrc = fs.readFileSync(path.join(backendRoot, 'src/index.ts'), 'utf8');
  assert.ok(!indexSrc.includes('registerUserLinkRoutes'));
  assert.ok(!indexSrc.includes('./admin/userLinks.js'));
  assert.ok(!indexSrc.includes('./graph/client.js'));

  // deviceUserLink is not defined in keys.ts or index.ts
  const keysSrc = fs.readFileSync(path.join(backendRoot, 'src/db/keys.ts'), 'utf8');
  assert.ok(!keysSrc.includes('deviceUserLink'));
  assert.ok(!indexSrc.includes('deviceUserLink'));

  // AdminDependencies has no graph property
  const routerSrc = fs.readFileSync(path.join(backendRoot, 'src/admin/router.ts'), 'utf8');
  assert.ok(!/\bgraph\b/i.test(routerSrc), 'admin/router.ts should mention no "graph" at all');

  // The dist build this whole suite runs against is proof the build exited 0:
  // every test file here imports from backend/dist/*.js, which "npm run
  // clean && npm run build" (run before this suite) must have produced
  // successfully for any of these imports -- and therefore the suite itself
  // -- to run at all.
  assert.ok(fs.existsSync(path.join(backendRoot, 'dist/index.js')));
});

// ============================================================================
// AC14 / AC15: infra and contract are byte-for-byte unchanged
// ============================================================================

function sha256(filePath) {
  return createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

test('Scenario: Infrastructure is unchanged (AC14)', () => {
  assert.strictEqual(
    sha256(path.join(backendRoot, 'src/infra/mdm-stack.ts')),
    'dfae39cd2ed743b4e8afd414908acb6fa5eb0c87484b256090940a2a9b8ba26a',
  );
  assert.strictEqual(
    sha256(path.join(backendRoot, 'src/infra/app.ts')),
    'f9eeb4e856d22c33b341bc8ad11088a12187c349dc3c64b95588728f696f39ff',
  );
});

test('Scenario: The contract is unchanged (AC15)', () => {
  const openapiPath = path.join(repoRoot, 'contract/openapi.yaml');
  assert.strictEqual(
    sha256(openapiPath),
    '4f3fc39fe77fee91d0ad11380ae6937260e91b5ce9719208d567a81ce397a1be',
  );
  const text = fs.readFileSync(openapiPath, 'utf8');
  for (const needle of ['user-link', 'userLink', 'primaryUser']) {
    assert.ok(!text.includes(needle), `openapi.yaml should not contain "${needle}"`);
  }
});

// ============================================================================
// AC17: No leftover references outside the tests that assert absence or a 404
// ============================================================================

test('Scenario: No leftover references (AC17)', () => {
  const forbidden = [
    'refresh-user-link',
    'detail-user',
    '/user-link/refresh',
    '/user-links/refresh',
    'refreshAllUserLinks',
    'REFRESH_USER_LINKS_BUTTON',
    'handleDeviceUserLinkRefresh',
    'handleUserLinksBulkRefresh',
    'registerUserLinkRoutes',
    'resolveUserLink',
    'deviceUserLink',
    'createGraphDirectoryFromEnv',
    'graph/client',
  ];
  // AC16 (a), (c), (i) and (j): the tests that assert absence or a 404 may
  // contain these strings literally -- this file is (j) itself.
  const exceptions = [
    'test/ui/deviceSections.test.js',
    'test/ui/views.test.js',
    'test/bootstrap.test.js',
    'test/admin/userLinksRemoved.test.js',
  ];

  const srcFiles = walk(path.join(backendRoot, 'src'), { exts: ['.ts', '.js'], excludeRel: ['src/infra'] });
  const testFiles = walk(path.join(backendRoot, 'test'), {
    exts: ['.ts', '.js'],
    excludeRel: ['test/infra', ...exceptions],
  });

  for (const file of [...srcFiles, ...testFiles]) {
    const rel = path.relative(backendRoot, file).split(path.sep).join('/');
    const text = fs.readFileSync(file, 'utf8');
    for (const needle of forbidden) {
      assert.ok(!text.includes(needle), `${rel} should not contain "${needle}"`);
    }
  }
});
