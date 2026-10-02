/**
 * Unit + e2e (Given/When/Then) tests for TASK-027's user-link resolution and
 * routes (`backend/src/admin/userLinks.ts`), plus the `userLink` field added
 * to the device detail route (AC21) and the single-statement Graph secret
 * grant (exercised indirectly through bootstrap -- see bootstrap.test.js).
 *
 * All database calls are mocked with an in-memory fake table; nothing here
 * opens a real connection, and Microsoft Graph is always a fake `fetch`
 * wired into the real `createGraphClient`, never a real network call.
 *
 * Covers AC9 (route-level), AC10-AC19, AC21.
 */

import test from 'node:test';
import assert from 'node:assert';
import { createRouter } from '../../dist/index.js';
import {
  registerUserLinkRoutes,
  resolveUserLink,
  lookupName,
  DEVICE_USER_LINK_REFRESH_PATH,
  USER_LINKS_REFRESH_PATH,
} from '../../dist/admin/userLinks.js';
import { registerDeviceRoutes } from '../../dist/admin/devices.js';
import { createGraphClient, createGraphSecretProvider } from '../../dist/graph/client.js';
import { deviceProfile, deviceUserLink, deviceListIndex, assertValidId } from '../../dist/db/keys.js';

// ============================================================================
// Fake table: get/put/update/query, no real database connection.
// ============================================================================

class FakeTable {
  constructor() {
    this.items = new Map();
    this.putCalls = [];
    this.updateCalls = [];
    this.queryCalls = 0;
  }

  keyStr(key) {
    return `${key.pk}#${key.sk}`;
  }

  async get(key) {
    return this.items.get(this.keyStr(key));
  }

  async put(item) {
    this.putCalls.push({ ...item });
    this.items.set(this.keyStr(item), { ...item });
  }

  async update(key, fields = {}) {
    this.updateCalls.push({ key: { ...key }, fields: { ...fields } });
    const existing = this.items.get(this.keyStr(key)) ?? { ...key };
    const expr = fields.UpdateExpression ?? '';
    if (expr.startsWith('SET ')) {
      const match = expr.match(/^SET\s+(\w+)\s*=\s*(:\w+)$/);
      if (match) {
        const [, attr, placeholder] = match;
        existing[attr] = fields.ExpressionAttributeValues[placeholder];
      }
    } else if (expr.startsWith('REMOVE ')) {
      delete existing[expr.slice('REMOVE '.length).trim()];
    }
    this.items.set(this.keyStr(key), existing);
    return existing;
  }

  async query(request) {
    this.queryCalls += 1;
    const { KeyConditionExpression, ExpressionAttributeValues, ScanIndexForward = true, limit = 50, cursor } = request;
    const items = [];
    for (const item of this.items.values()) {
      if (KeyConditionExpression.includes('gsi1pk')) {
        if (item.gsi1pk !== ExpressionAttributeValues[':gsi1pk']) continue;
        if (KeyConditionExpression.includes('gsi1sk < :staleBefore')) {
          if (item.gsi1sk >= ExpressionAttributeValues[':staleBefore']) continue;
        }
      } else if (KeyConditionExpression.includes(':pk')) {
        if (item.pk !== ExpressionAttributeValues[':pk']) continue;
      } else {
        continue;
      }
      items.push(item);
    }
    const sorted = items.sort((a, b) => {
      const av = a.gsi1sk ?? a.sk;
      const bv = b.gsi1sk ?? b.sk;
      if (ScanIndexForward === false) {
        return bv < av ? -1 : bv > av ? 1 : 0;
      }
      return av < bv ? -1 : av > bv ? 1 : 0;
    });
    let startIdx = 0;
    if (cursor) {
      startIdx = JSON.parse(Buffer.from(cursor, 'base64').toString()).offset ?? 0;
    }
    const pageSize = Math.min(limit, sorted.length - startIdx);
    const page = sorted.slice(startIdx, startIdx + pageSize);
    const nextCursor =
      startIdx + pageSize < sorted.length
        ? Buffer.from(JSON.stringify({ offset: startIdx + pageSize })).toString('base64')
        : null;
    return { items: page, cursor: nextCursor };
  }

  seedProfile({ deviceId, hostname, lastSeenAt = '2026-01-01T00:00:00.000Z', ...extra }) {
    const key = deviceProfile(deviceId);
    const index = deviceListIndex(lastSeenAt);
    const item = { ...key, ...index, deviceId, lastSeenAt, ...extra };
    if (hostname !== undefined) {
      item.hostname = hostname;
    }
    this.items.set(this.keyStr(key), item);
    return item;
  }

  auditItems() {
    return [...this.items.values()].filter((item) => typeof item.pk === 'string' && item.pk.startsWith('AUDIT#'));
  }
}

// ============================================================================
// Stub verifier: accepts an admin bearer token for admin@contoso.com.
// ============================================================================

class StubVerifier {
  async verify(token) {
    if (token !== 'admin-token') {
      throw { status: 401, error: 'invalid_token' };
    }
    return { preferred_username: 'admin@contoso.com' };
  }
}

// ============================================================================
// Graph fakes
// ============================================================================

function jsonResponse(status, body) {
  return { status, text: async () => JSON.stringify(body) };
}

function tokenOk(token = 'TOKEN-SENTINEL') {
  return jsonResponse(200, { access_token: token, expires_in: 3600 });
}

/**
 * A Graph client wired to a fake fetch.
 *
 *   devicesFor(name)      -> array of {id, displayName, accountEnabled}
 *   usersFor(objectId)    -> array of {id, displayName, userPrincipalName, mail}
 *   devicesStatus         -> override: the /devices call answers this status
 *   usersStatus           -> override: the /registeredUsers call answers this status
 *   networkErrorOnDevices -> the /devices call's fetch rejects
 *   tokenStatus           -> override: the token endpoint answers this status
 */
function makeGraph({
  devicesFor = () => [],
  usersFor = () => [],
  devicesStatus,
  usersStatus,
  networkErrorOnDevices,
  tokenStatus,
  tenantId = 't-1',
  clientSecret = 'S3CRET-SENTINEL',
  token = 'TOKEN-SENTINEL',
} = {}) {
  const calls = [];
  const fetchFn = async (url, init) => {
    calls.push({ url, init });
    if (url === `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`) {
      return tokenStatus ? jsonResponse(tokenStatus, {}) : tokenOk(token);
    }
    const u = new URL(url);
    if (u.pathname === '/v1.0/devices') {
      if (devicesStatus) {
        return jsonResponse(devicesStatus, {});
      }
      if (networkErrorOnDevices) {
        throw new Error('network down');
      }
      const filter = u.searchParams.get('$filter') ?? '';
      const match = filter.match(/^displayName eq '(.*)'$/s);
      const name = match ? match[1].replace(/''/g, "'") : '';
      return jsonResponse(200, { value: devicesFor(name) });
    }
    if (u.pathname.includes('/registeredUsers')) {
      if (usersStatus) {
        return jsonResponse(usersStatus, {});
      }
      const objectId = u.pathname.split('/')[3];
      return jsonResponse(200, { value: usersFor(objectId) });
    }
    return jsonResponse(404, {});
  };
  const graph = createGraphClient({ tenantId, clientId: 'c-1', clientSecret, fetch: fetchFn, now: () => 1000 });
  graph.calls = calls;
  return graph;
}

// ============================================================================
// Router helpers
// ============================================================================

function buildRouter(deps) {
  const router = createRouter();
  registerUserLinkRoutes(router, deps);
  registerDeviceRoutes(router, deps);
  return router;
}

function call(router, method, path, { body = null, admin = true } = {}) {
  return router.handle({
    method,
    path,
    query: {},
    headers: admin ? { authorization: 'Bearer admin-token' } : {},
    body,
  });
}

function deviceRefreshPath(deviceId) {
  return `/admin/api/v1${DEVICE_USER_LINK_REFRESH_PATH.replace('{deviceId}', deviceId)}`;
}

const BULK_PATH = `/admin/api/v1${USER_LINKS_REFRESH_PATH}`;

// ============================================================================
// AC10: Status from Graph matches
// ============================================================================

test('AC10: no devices match -> not_found', async () => {
  const table = new FakeTable();
  table.seedProfile({ deviceId: 'd1', hostname: 'LAT-7440.contoso.local' });
  const graph = makeGraph({ devicesFor: () => [] });
  const deps = { table, now: () => 1000, verifier: new StubVerifier(), graph };

  const item = await resolveUserLink(deps, graph, 'd1', 'LAT-7440.contoso.local');
  assert.strictEqual(item.status, 'not_found');
  assert.strictEqual(item.entraDeviceId, null);
});

test('AC10: one case-insensitive enabled match with users -> linked', async () => {
  const table = new FakeTable();
  const graph = makeGraph({
    devicesFor: (name) => (name === 'LAT-7440' ? [{ id: 'obj-1', displayName: 'lat-7440', accountEnabled: true }] : []),
    usersFor: () => [
      { id: 'u1', displayName: 'A', userPrincipalName: 'a@x.com', mail: 'a@x.com' },
      { id: 'u2', displayName: 'B', userPrincipalName: 'b@x.com', mail: 'b@x.com' },
    ],
  });
  const deps = { table, now: () => 1000 };
  const item = await resolveUserLink(deps, graph, 'd1', 'LAT-7440.contoso.local');
  assert.strictEqual(item.status, 'linked');
  assert.strictEqual(item.users.length, 2);
});

test('AC10: one enabled match with no registered users -> no_registered_user', async () => {
  const table = new FakeTable();
  const graph = makeGraph({
    devicesFor: () => [{ id: 'obj-1', displayName: 'LAT-7440', accountEnabled: true }],
    usersFor: () => [],
  });
  const deps = { table, now: () => 1000 };
  const item = await resolveUserLink(deps, graph, 'd1', 'LAT-7440.contoso.local');
  assert.strictEqual(item.status, 'no_registered_user');
});

test('AC10: two enabled matches -> ambiguous', async () => {
  const table = new FakeTable();
  const graph = makeGraph({
    devicesFor: () => [
      { id: 'obj-1', displayName: 'LAT-7440', accountEnabled: true },
      { id: 'obj-2', displayName: 'LAT-7440', accountEnabled: true },
    ],
  });
  const deps = { table, now: () => 1000 };
  const item = await resolveUserLink(deps, graph, 'd1', 'LAT-7440.contoso.local');
  assert.strictEqual(item.status, 'ambiguous');
  assert.strictEqual(item.entraDeviceId, null);
});

test('AC10: a disabled duplicate is dropped, leaving exactly one kept -> linked', async () => {
  const table = new FakeTable();
  const graph = makeGraph({
    devicesFor: () => [
      { id: 'obj-1', displayName: 'LAT-7440', accountEnabled: true },
      { id: 'obj-stale', displayName: 'LAT-7440', accountEnabled: false },
    ],
    usersFor: () => [{ id: 'u1', displayName: 'A', userPrincipalName: 'a@x.com', mail: null }],
  });
  const deps = { table, now: () => 1000 };
  const item = await resolveUserLink(deps, graph, 'd1', 'LAT-7440.contoso.local');
  assert.strictEqual(item.status, 'linked');
  assert.strictEqual(item.entraDeviceId, 'obj-1');
});

test('AC10: a name that does not match exactly -> not_found', async () => {
  const table = new FakeTable();
  const graph = makeGraph({
    devicesFor: () => [{ id: 'obj-1', displayName: 'LAT-7440X', accountEnabled: true }],
  });
  const deps = { table, now: () => 1000 };
  const item = await resolveUserLink(deps, graph, 'd1', 'LAT-7440.contoso.local');
  assert.strictEqual(item.status, 'not_found');
});

test('AC10 (edge): registered users are not read when the match is ambiguous', async () => {
  const table = new FakeTable();
  let usersRequested = false;
  const graph = makeGraph({
    devicesFor: () => [
      { id: 'obj-1', displayName: 'LAT-7440', accountEnabled: true },
      { id: 'obj-2', displayName: 'LAT-7440', accountEnabled: true },
    ],
    usersFor: () => {
      usersRequested = true;
      return [];
    },
  });
  const deps = { table, now: () => 1000 };
  await resolveUserLink(deps, graph, 'd1', 'LAT-7440.contoso.local');
  assert.strictEqual(usersRequested, false);
});

test('Unit: lookupName cuts the hostname at its first dot', () => {
  assert.strictEqual(lookupName('LAT-7440.contoso.local'), 'LAT-7440');
  assert.strictEqual(lookupName('LAT-7440'), 'LAT-7440');
  assert.strictEqual(lookupName('a.b.c'), 'a');
});

// ============================================================================
// AC11: Stored link item shape
// ============================================================================

test('AC11: stored link item shape, ordering and resolvedAt', async () => {
  const table = new FakeTable();
  const graph = makeGraph({
    devicesFor: () => [{ id: 'obj-1', displayName: 'LAT-7440', accountEnabled: true }],
    usersFor: () => [
      { id: 'u-zoe', displayName: 'Zoe', userPrincipalName: 'zoe@contoso.com' },
      { id: 'u-amy', displayName: 'Amy', userPrincipalName: 'amy@contoso.com', mail: 'amy@contoso.com' },
    ],
  });
  const deps = { table, now: () => 1790000000 };

  await resolveUserLink(deps, graph, 'd1', 'LAT-7440.contoso.local');
  const stored = await table.get(deviceUserLink('d1'));

  assert.strictEqual(stored.pk, 'DEVICE#d1');
  assert.strictEqual(stored.sk, 'USERLINK');
  assert.strictEqual(stored.status, 'linked');
  assert.strictEqual(stored.entraDeviceId, 'obj-1');
  assert.strictEqual(stored.resolvedAt, '2026-09-21T14:13:20.000Z');
  assert.deepStrictEqual(
    stored.users.map((u) => u.userPrincipalName),
    ['amy@contoso.com', 'zoe@contoso.com'],
  );
  for (const user of stored.users) {
    assert.deepStrictEqual(Object.keys(user).sort(), ['displayName', 'id', 'mail', 'userPrincipalName']);
  }
  assert.strictEqual(stored.users[1].mail, null);
});

test('AC11 (failure): deviceUserLink rejects an id containing a separator', () => {
  assert.throws(() => deviceUserLink('bad#id'), /invalid id: bad#id/);
});

// ============================================================================
// AC12: Profile primaryUserUpn set and then removed
// ============================================================================

test('AC12: primaryUserUpn is set with update, not put, and unrelated attributes survive', async () => {
  const table = new FakeTable();
  table.seedProfile({
    deviceId: 'd1',
    hostname: 'LAT-7440.contoso.local',
    platform: 'windows',
    complianceState: 'compliant',
    secretEnc: 'should-not-change',
  });
  const graph = makeGraph({
    devicesFor: () => [{ id: 'obj-1', displayName: 'LAT-7440', accountEnabled: true }],
    usersFor: () => [{ id: 'u1', displayName: 'Amy', userPrincipalName: 'amy@contoso.com', mail: null }],
  });
  const deps = { table, now: () => 1000 };

  await resolveUserLink(deps, graph, 'd1', 'LAT-7440.contoso.local');

  const profile = await table.get(deviceProfile('d1'));
  assert.strictEqual(profile.primaryUserUpn, 'amy@contoso.com');
  assert.strictEqual(profile.platform, 'windows');
  assert.strictEqual(profile.complianceState, 'compliant');
  assert.strictEqual(profile.secretEnc, 'should-not-change');
  assert.strictEqual(profile.hostname, 'LAT-7440.contoso.local');

  // The profile write used update(), never put().
  const profilePuts = table.putCalls.filter((item) => item.sk === 'PROFILE');
  assert.strictEqual(profilePuts.length, 0);
  assert.ok(table.updateCalls.some((c) => c.key.sk === 'PROFILE'));
});

test('AC12: a later not_found resolution removes primaryUserUpn', async () => {
  const table = new FakeTable();
  table.seedProfile({ deviceId: 'd1', hostname: 'LAT-7440.contoso.local' });
  const linkedGraph = makeGraph({
    devicesFor: () => [{ id: 'obj-1', displayName: 'LAT-7440', accountEnabled: true }],
    usersFor: () => [{ id: 'u1', displayName: 'Amy', userPrincipalName: 'amy@contoso.com', mail: null }],
  });
  const deps = { table, now: () => 1000 };
  await resolveUserLink(deps, linkedGraph, 'd1', 'LAT-7440.contoso.local');
  assert.strictEqual((await table.get(deviceProfile('d1'))).primaryUserUpn, 'amy@contoso.com');

  const notFoundGraph = makeGraph({ devicesFor: () => [] });
  await resolveUserLink(deps, notFoundGraph, 'd1', 'LAT-7440.contoso.local');
  const profile = await table.get(deviceProfile('d1'));
  assert.strictEqual(Object.prototype.hasOwnProperty.call(profile, 'primaryUserUpn'), false);
});

// ============================================================================
// AC13: Per-device refresh response and audit
// ============================================================================

test('AC13: per-device refresh answers 200 {userLink} with no pk/sk and writes one audit entry', async () => {
  const table = new FakeTable();
  table.seedProfile({ deviceId: 'd1', hostname: 'LAT-7440.contoso.local' });
  const graph = makeGraph({
    devicesFor: () => [{ id: 'obj-1', displayName: 'LAT-7440', accountEnabled: true }],
    usersFor: () => [
      { id: 'u1', displayName: 'Amy', userPrincipalName: 'amy@contoso.com', mail: null },
      { id: 'u2', displayName: 'Zoe', userPrincipalName: 'zoe@contoso.com', mail: null },
    ],
  });
  const deps = { table, now: () => 1790000000, verifier: new StubVerifier(), graph };
  const router = buildRouter(deps);

  const response = await call(router, 'POST', deviceRefreshPath('d1'));
  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.ok(!('pk' in body.userLink) && !('sk' in body.userLink));
  assert.strictEqual(body.userLink.status, 'linked');

  const audits = table.auditItems();
  assert.strictEqual(audits.length, 1);
  assert.strictEqual(audits[0].action, 'device.user_link.refreshed');
  assert.strictEqual(audits[0].actor, 'admin@contoso.com');
  assert.strictEqual(audits[0].target, 'd1');
  assert.deepStrictEqual(audits[0].detail, { status: 'linked', userCount: 2 });
});

test('AC13 (failure): per-device refresh requires an admin', async () => {
  const table = new FakeTable();
  table.seedProfile({ deviceId: 'd1', hostname: 'host' });
  const graph = makeGraph();
  const deps = { table, now: () => 1000, verifier: new StubVerifier(), graph };
  const router = buildRouter(deps);

  const response = await call(router, 'POST', deviceRefreshPath('d1'), { admin: false });
  assert.strictEqual(response.statusCode, 401);
  assert.strictEqual(graph.calls.length, 0, 'no Graph request should have been sent');
});

// ============================================================================
// AC14: Unknown device or missing hostname
// ============================================================================

test('AC14: an unknown device answers 404, with no Graph request, write or audit', async () => {
  const table = new FakeTable();
  const graph = makeGraph();
  const deps = { table, now: () => 1000, verifier: new StubVerifier(), graph };
  const router = buildRouter(deps);

  const response = await call(router, 'POST', deviceRefreshPath('ghost'));
  assert.strictEqual(response.statusCode, 404);
  assert.deepStrictEqual(JSON.parse(response.body), { error: 'not_found' });
  assert.strictEqual(graph.calls.length, 0);
  assert.strictEqual(table.putCalls.length, 0);
  assert.strictEqual(table.updateCalls.length, 0);
  assert.strictEqual(table.auditItems().length, 0);
});

test('AC14: a deviceId no key can be built from answers 404', async () => {
  const table = new FakeTable();
  const graph = makeGraph();
  const deps = { table, now: () => 1000, verifier: new StubVerifier(), graph };
  const router = buildRouter(deps);

  const response = await call(router, 'POST', deviceRefreshPath('a%23b'));
  assert.strictEqual(response.statusCode, 404);
  assert.deepStrictEqual(JSON.parse(response.body), { error: 'not_found' });
  assert.strictEqual(graph.calls.length, 0);
  assert.strictEqual(table.putCalls.length, 0);
  assert.strictEqual(table.updateCalls.length, 0);
});

test('AC14: a profile with no hostname answers 409 hostname_unknown', async () => {
  const table = new FakeTable();
  table.seedProfile({ deviceId: 'd2' });
  const graph = makeGraph();
  const deps = { table, now: () => 1000, verifier: new StubVerifier(), graph };
  const router = buildRouter(deps);

  const response = await call(router, 'POST', deviceRefreshPath('d2'));
  assert.strictEqual(response.statusCode, 409);
  assert.deepStrictEqual(JSON.parse(response.body), { error: 'hostname_unknown' });
  assert.strictEqual(graph.calls.length, 0);
  assert.strictEqual(table.putCalls.length, 0);
  assert.strictEqual(table.updateCalls.length, 0);
  assert.strictEqual(table.auditItems().length, 0);
});

// ============================================================================
// AC15: Graph not configured
// ============================================================================

test('AC15: with no graph, both refresh routes answer 503 and the read routes still answer 200', async () => {
  const table = new FakeTable();
  table.seedProfile({ deviceId: 'd1', hostname: 'host' });
  const deps = { table, now: () => 1000, verifier: new StubVerifier() }; // graph is undefined
  const router = buildRouter(deps);

  const perDevice = await call(router, 'POST', deviceRefreshPath('d1'));
  assert.strictEqual(perDevice.statusCode, 503);
  assert.deepStrictEqual(JSON.parse(perDevice.body), { error: 'graph_not_configured' });

  const bulk = await call(router, 'POST', BULK_PATH, { body: '{}' });
  assert.strictEqual(bulk.statusCode, 503);
  assert.deepStrictEqual(JSON.parse(bulk.body), { error: 'graph_not_configured' });

  assert.strictEqual(table.putCalls.length, 0);
  assert.strictEqual(table.updateCalls.length, 0);

  const list = await call(router, 'GET', '/admin/api/v1/devices');
  assert.strictEqual(list.statusCode, 200);
  const detail = await call(router, 'GET', '/admin/api/v1/devices/d1');
  assert.strictEqual(detail.statusCode, 200);
});

// ============================================================================
// AC16: Graph failure leaves the stored link untouched
// ============================================================================

test('AC16: a Graph failure leaves the stored USERLINK and primaryUserUpn untouched, with no audit entry', async () => {
  const table = new FakeTable();
  table.seedProfile({ deviceId: 'd1', hostname: 'LAT-7440.contoso.local', primaryUserUpn: 'amy@contoso.com' });
  await table.put({ ...deviceUserLink('d1'), deviceId: 'd1', status: 'linked', entraDeviceId: 'obj-1', users: [], resolvedAt: 'x' });
  table.putCalls = []; // Reset so the assertion below is about this call only.

  const graph = makeGraph({ devicesStatus: 503 });
  const deps = { table, now: () => 1000, verifier: new StubVerifier(), graph };
  const router = buildRouter(deps);

  const response = await call(router, 'POST', deviceRefreshPath('d1'));
  assert.strictEqual(response.statusCode, 502);
  assert.deepStrictEqual(JSON.parse(response.body), { error: 'graph_unavailable' });

  const stored = await table.get(deviceUserLink('d1'));
  assert.strictEqual(stored.status, 'linked');
  assert.strictEqual(stored.entraDeviceId, 'obj-1');
  const profile = await table.get(deviceProfile('d1'));
  assert.strictEqual(profile.primaryUserUpn, 'amy@contoso.com');
  assert.strictEqual(table.auditItems().length, 0);
});

// ============================================================================
// AC17: Bulk refresh of one fleet page
// ============================================================================

function seedFleet(table, count) {
  for (let i = 1; i <= count; i += 1) {
    const seq = String(i).padStart(2, '0');
    table.seedProfile({ deviceId: `d${i}`, hostname: `D${i}`, lastSeenAt: `2026-01-01T00:00:${seq}.000Z` });
  }
}

function fleetGraph() {
  return makeGraph({
    devicesFor: (name) => [{ id: `obj-${name}`, displayName: name, accountEnabled: true }],
    usersFor: (objectId) => [{ id: 'u1', displayName: 'User', userPrincipalName: `${objectId}@contoso.com`, mail: null }],
  });
}

test('AC17: bulk refresh pages the fleet, newest check-in first, with primaryUser', async () => {
  const table = new FakeTable();
  seedFleet(table, 30);
  const graph = fleetGraph();
  const deps = { table, now: () => 1000, verifier: new StubVerifier(), graph };
  const router = buildRouter(deps);

  const page1 = await call(router, 'POST', BULK_PATH, { body: '{}' });
  assert.strictEqual(page1.statusCode, 200);
  const body1 = JSON.parse(page1.body);
  assert.strictEqual(body1.items.length, 25);
  assert.ok(body1.items.every((item) => item.status === 'linked' && typeof item.primaryUser === 'string'));
  // Newest check-in first: d30 (..:30) down to d6 (..:06).
  assert.strictEqual(body1.items[0].deviceId, 'd30');
  assert.strictEqual(body1.items[24].deviceId, 'd6');
  assert.ok(typeof body1.cursor === 'string' && body1.cursor.length > 0);

  const page2 = await call(router, 'POST', BULK_PATH, { body: JSON.stringify({ cursor: body1.cursor }) });
  assert.strictEqual(page2.statusCode, 200);
  const body2 = JSON.parse(page2.body);
  assert.strictEqual(body2.items.length, 5);
  assert.strictEqual(body2.cursor, null);
});

test('AC17 (edge): no body at all uses the defaults', async () => {
  const table = new FakeTable();
  seedFleet(table, 30);
  const graph = fleetGraph();
  const deps = { table, now: () => 1000, verifier: new StubVerifier(), graph };
  const router = buildRouter(deps);

  const response = await call(router, 'POST', BULK_PATH, { body: null });
  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.items.length, 25);
  assert.ok(body.cursor);
});

test('AC17 (edge): an empty-string body uses the defaults', async () => {
  const table = new FakeTable();
  seedFleet(table, 30);
  const graph = fleetGraph();
  const deps = { table, now: () => 1000, verifier: new StubVerifier(), graph };
  const router = buildRouter(deps);

  const response = await call(router, 'POST', BULK_PATH, { body: '' });
  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.items.length, 25);
  assert.ok(body.cursor);
});

// ============================================================================
// AC17 (failure): bad paging input is rejected before any table or Graph call
// ============================================================================

const BAD_BODIES = [
  '{"limit":0}',
  '{"limit":26}',
  '{"limit":"10"}',
  '{"limit":2.5}',
  '{"cursor":"%%junk%%"}',
  '{"cursor":42}',
  'not json',
  '[]',
  '"text"',
  'null',
];

for (const badBody of BAD_BODIES) {
  test(`AC17 (failure): bulk refresh rejects body ${JSON.stringify(badBody)}`, async () => {
    const table = new FakeTable();
    const graph = makeGraph();
    const deps = { table, now: () => 1000, verifier: new StubVerifier(), graph };
    const router = buildRouter(deps);

    const response = await call(router, 'POST', BULK_PATH, { body: badBody });
    assert.strictEqual(response.statusCode, 400);
    assert.deepStrictEqual(JSON.parse(response.body), { error: 'invalid_request' });
    assert.strictEqual(table.queryCalls, 0, 'no table read should have occurred');
    assert.strictEqual(graph.calls.length, 0, 'no Graph request should have occurred');
  });
}

// ============================================================================
// AC18 (edge): partial failures inside a bulk refresh
// ============================================================================

test('AC18 (edge): a missing hostname, a per-device Graph failure and a success coexist on one page', async () => {
  const table = new FakeTable();
  table.seedProfile({ deviceId: 'a', lastSeenAt: '2026-01-01T00:00:01.000Z' }); // no hostname
  table.seedProfile({ deviceId: 'b', hostname: 'B', lastSeenAt: '2026-01-01T00:00:02.000Z' });
  table.seedProfile({ deviceId: 'c', hostname: 'C', lastSeenAt: '2026-01-01T00:00:03.000Z' });

  const fetchCalls = [];
  const fetchFn = async (url) => {
    fetchCalls.push(url);
    if (url === 'https://login.microsoftonline.com/t-1/oauth2/v2.0/token') {
      return jsonResponse(200, { access_token: 'TOKEN-SENTINEL', expires_in: 3600 });
    }
    const u = new URL(url);
    if (u.pathname === '/v1.0/devices') {
      const filter = u.searchParams.get('$filter') ?? '';
      const match = filter.match(/^displayName eq '(.*)'$/s);
      const name = match ? match[1] : '';
      if (name === 'B') {
        return jsonResponse(403, {});
      }
      if (name === 'C') {
        return jsonResponse(200, { value: [{ id: 'obj-c', displayName: 'C', accountEnabled: true }] });
      }
      return jsonResponse(200, { value: [] });
    }
    return jsonResponse(200, { value: [{ id: 'u1', displayName: 'Amy', userPrincipalName: 'amy@contoso.com', mail: null }] });
  };
  const realGraph = createGraphClient({ tenantId: 't-1', clientId: 'c-1', clientSecret: 's', fetch: fetchFn, now: () => 1000 });

  const deps = { table, now: () => 1000, verifier: new StubVerifier(), graph: realGraph };
  const router = buildRouter(deps);

  const response = await call(router, 'POST', BULK_PATH, { body: '{}' });
  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  const byId = Object.fromEntries(body.items.map((item) => [item.deviceId, item]));
  assert.strictEqual(byId.a.status, 'hostname_unknown');
  assert.strictEqual(byId.b.status, 'error');
  assert.strictEqual(byId.b.error, 'graph_forbidden');
  assert.strictEqual(byId.c.status, 'linked');

  assert.strictEqual(await table.get(deviceUserLink('a')), undefined);
  assert.strictEqual(await table.get(deviceUserLink('b')), undefined);
  assert.ok(await table.get(deviceUserLink('c')));
});

// ============================================================================
// AC18 (failure): a token failure ends the bulk call, keeping earlier writes
// ============================================================================

test('AC18 (failure): a token failure ends the bulk call; the earlier write for "a" survives', async () => {
  const table = new FakeTable();
  // Newest check-in first, so "a" is resolved before "b".
  table.seedProfile({ deviceId: 'a', hostname: 'A', lastSeenAt: '2026-01-01T00:00:02.000Z' });
  table.seedProfile({ deviceId: 'b', hostname: 'B', lastSeenAt: '2026-01-01T00:00:01.000Z' });

  let tokenCalls = 0;
  const fetchFn = async (url) => {
    if (url === 'https://login.microsoftonline.com/t-1/oauth2/v2.0/token') {
      tokenCalls += 1;
      // The first token is immediately expired (expires_in: 0), forcing a
      // renewal before the second device is resolved; that renewal fails.
      return tokenCalls === 1
        ? jsonResponse(200, { access_token: 'TOK1', expires_in: 0 })
        : jsonResponse(401, {});
    }
    return jsonResponse(200, { value: [] });
  };
  const graph = createGraphClient({ tenantId: 't-1', clientId: 'c-1', clientSecret: 's', fetch: fetchFn, now: () => 1000 });
  const deps = { table, now: () => 1000, verifier: new StubVerifier(), graph };
  const router = buildRouter(deps);

  const response = await call(router, 'POST', BULK_PATH, { body: '{}' });
  assert.strictEqual(response.statusCode, 502);
  assert.deepStrictEqual(JSON.parse(response.body), { error: 'graph_auth_failed' });

  const storedA = await table.get(deviceUserLink('a'));
  assert.ok(storedA, 'the USERLINK written for "a" should still be stored');
  assert.strictEqual(storedA.status, 'not_found');
});

// ============================================================================
// AC19: Audit on a successful or failed bulk refresh
// ============================================================================

test('AC19: one audit entry per successful bulk call, with count and linked', async () => {
  const table = new FakeTable();
  table.seedProfile({ deviceId: 'd1', hostname: 'D1', lastSeenAt: '2026-01-01T00:00:01.000Z' });
  table.seedProfile({ deviceId: 'd2', hostname: 'D2', lastSeenAt: '2026-01-01T00:00:02.000Z' });
  table.seedProfile({ deviceId: 'd3', hostname: 'NOMATCH', lastSeenAt: '2026-01-01T00:00:03.000Z' });

  const graph = makeGraph({
    devicesFor: (name) => (name === 'NOMATCH' ? [] : [{ id: `obj-${name}`, displayName: name, accountEnabled: true }]),
    usersFor: (objectId) => [{ id: 'u1', displayName: 'U', userPrincipalName: `${objectId}@x.com`, mail: null }],
  });
  const deps = { table, now: () => 1000, verifier: new StubVerifier(), graph };
  const router = buildRouter(deps);

  const response = await call(router, 'POST', BULK_PATH, { body: '{}' });
  assert.strictEqual(response.statusCode, 200);

  const audits = table.auditItems();
  assert.strictEqual(audits.length, 1);
  assert.strictEqual(audits[0].action, 'user_links.refreshed');
  assert.strictEqual(audits[0].target, 'fleet');
  assert.deepStrictEqual(audits[0].detail, { count: 3, linked: 2 });
});

test('AC19 (failure): no audit entry when the bulk call fails', async () => {
  const table = new FakeTable();
  table.seedProfile({ deviceId: 'd1', hostname: 'D1' });
  const secretsClient = { send: async () => { throw new Error('AccessDenied'); } };
  const clientSecret = createGraphSecretProvider({ secretsClient, secretId: 's', key: 'K' });
  const graph = createGraphClient({ tenantId: 't-1', clientId: 'c-1', clientSecret, fetch: async () => jsonResponse(200, {}), now: () => 1000 });
  const deps = { table, now: () => 1000, verifier: new StubVerifier(), graph };
  const router = buildRouter(deps);

  const response = await call(router, 'POST', BULK_PATH, { body: '{}' });
  assert.strictEqual(response.statusCode, 503);
  assert.deepStrictEqual(JSON.parse(response.body), { error: 'graph_secret_unavailable' });
  assert.strictEqual(table.auditItems().length, 0);
});

// ============================================================================
// AC21: Device detail includes userLink or null
// ============================================================================

test('AC21: device detail carries userLink (redacted) or null, alongside the other sections', async () => {
  const table = new FakeTable();
  table.seedProfile({ deviceId: 'd1', hostname: 'D1' });
  table.seedProfile({ deviceId: 'd2', hostname: 'D2' });
  await table.put({
    ...deviceUserLink('d1'),
    deviceId: 'd1',
    status: 'linked',
    entraDeviceId: 'obj-1',
    users: [{ id: 'u1', displayName: 'Amy', userPrincipalName: 'amy@contoso.com', mail: null }],
    resolvedAt: '2026-09-21T14:13:20.000Z',
  });

  const deps = { table, now: () => 1000, verifier: new StubVerifier() };
  const router = buildRouter(deps);

  const d1 = JSON.parse((await call(router, 'GET', '/admin/api/v1/devices/d1')).body);
  assert.ok(d1.userLink);
  assert.strictEqual(d1.userLink.status, 'linked');
  assert.ok(Array.isArray(d1.userLink.users));
  assert.ok(!('pk' in d1.userLink) && !('sk' in d1.userLink));
  assert.ok('profile' in d1 && 'inventory' in d1 && 'posture' in d1 && 'commands' in d1);

  const d2 = JSON.parse((await call(router, 'GET', '/admin/api/v1/devices/d2')).body);
  assert.strictEqual(d2.userLink, null);
  assert.ok('profile' in d2 && 'inventory' in d2 && 'posture' in d2 && 'commands' in d2);
});

// ============================================================================
// AC9 (route-level): the secret and token never leak through a response,
// an audit item, a rejection object or console output.
// ============================================================================

test('AC9: the secret and token never leak across a success, a Graph failure and a token failure', async () => {
  const table = new FakeTable();
  table.seedProfile({ deviceId: 'e1', hostname: 'E1' });
  table.seedProfile({ deviceId: 'e2', hostname: 'E2' });
  table.seedProfile({ deviceId: 'e3', hostname: 'E3' });

  const consoleLines = [];
  const original = { log: console.log, error: console.error, warn: console.warn, info: console.info };
  for (const method of Object.keys(original)) {
    console[method] = (...args) => {
      consoleLines.push(args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' '));
    };
  }

  try {
    const successGraph = makeGraph({
      devicesFor: () => [{ id: 'obj-e1', displayName: 'E1', accountEnabled: true }],
      usersFor: () => [{ id: 'u1', displayName: 'Amy', userPrincipalName: 'amy@contoso.com', mail: null }],
    });
    const graphFailure = makeGraph({ devicesStatus: 503 });
    const tokenFailure = makeGraph({ tokenStatus: 401 });

    const deps = { table, now: () => 1000, verifier: new StubVerifier(), graph: successGraph };
    const router = buildRouter(deps);

    const r1 = await call(router, 'POST', deviceRefreshPath('e1'));
    assert.strictEqual(r1.statusCode, 200);

    deps.graph = graphFailure;
    const r2 = await call(router, 'POST', deviceRefreshPath('e2'));
    assert.strictEqual(r2.statusCode, 502);

    deps.graph = tokenFailure;
    const r3 = await call(router, 'POST', deviceRefreshPath('e3'));
    assert.strictEqual(r3.statusCode, 502);

    const haystacks = [r1.body, r2.body, r3.body, JSON.stringify(table.auditItems()), consoleLines.join('\n')];
    for (const haystack of haystacks) {
      assert.ok(!haystack.includes('S3CRET-SENTINEL'), `leaked the secret: ${haystack}`);
      assert.ok(!haystack.includes('TOKEN-SENTINEL'), `leaked the token: ${haystack}`);
    }
  } finally {
    Object.assign(console, original);
  }
});
