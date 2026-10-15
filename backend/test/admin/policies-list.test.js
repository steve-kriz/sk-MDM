/**
 * E2E and unit tests for listing policies and re-indexing the ones written
 * before the list index existed ("create policy doesn't save anything").
 *
 *   GET  /admin/api/v1/policies           -- the policy list, from gsi1 POLICY
 *   POST /admin/api/v1/policies/reindex   -- backfill gsi1 onto old policies
 *
 * Every database call is mocked by an in-memory FakeTable; no real DB
 * connection is opened. Routes are driven through the real router so the
 * admin-only wrapping is exercised too.
 */

import test from 'node:test';
import assert from 'node:assert';
import { createRouter } from '../../dist/index.js';
import {
  registerPolicyRoutes,
  handlePolicyCreate,
  handlePolicyUpdate,
  handlePolicyList,
  handlePolicyReindex,
  POLICY_REINDEXED_ACTION,
} from '../../dist/admin/policies.js';
import { policy as policyKey, policyListIndex } from '../../dist/db/keys.js';

// ============================================================================
// Mock Table Client
// ============================================================================

class FakeTable {
  constructor() {
    this.items = new Map();
    this.queries = [];
    this.scans = [];
    this.puts = [];
  }

  keyStr(key) {
    return `${key.pk}|${key.sk}`;
  }

  async get(key) {
    const item = this.items.get(this.keyStr(key));
    return item === undefined ? undefined : { ...item };
  }

  async put(item) {
    this.puts.push({ ...item });
    this.items.set(this.keyStr(item), { ...item });
  }

  /** gsi1 queries only: every item whose gsi1pk matches, one page. */
  async query(request = {}) {
    this.queries.push(request);
    const gsi1pk = request.ExpressionAttributeValues?.[':gsi1pk'];
    const items = [...this.items.values()]
      .filter((item) => request.IndexName === 'gsi1' && item.gsi1pk === gsi1pk)
      .sort((a, b) => (a.gsi1sk < b.gsi1sk ? -1 : 1));
    return { items, cursor: null };
  }

  /**
   * A scan that pages one item at a time so the handler must follow the
   * cursor, and that applies the `pk` prefix / `sk` filter it was handed.
   */
  async scan(request = {}) {
    this.scans.push(request);
    const values = request.ExpressionAttributeValues ?? {};
    const all = [...this.items.values()].sort((a, b) => (this.keyStr(a) < this.keyStr(b) ? -1 : 1));
    const start = request.cursor ? Number(Buffer.from(request.cursor, 'base64').toString('utf8')) : 0;
    const slice = all.slice(start, start + 1);
    const items = slice.filter(
      (item) => item.sk === values[':sk'] && typeof item.pk === 'string' && item.pk.startsWith(values[':pkPrefix']),
    );
    const next = start + 1 < all.length ? Buffer.from(String(start + 1), 'utf8').toString('base64') : null;
    return { items, cursor: next };
  }

  seed(item) {
    this.items.set(this.keyStr(item), { ...item });
  }

  stored(key) {
    return this.items.get(this.keyStr(key));
  }

  audits() {
    return [...this.items.values()].filter((item) => typeof item.pk === 'string' && item.pk.startsWith('AUDIT#'));
  }
}

class StubVerifier {
  async verify(token) {
    if (token === 'invalid') {
      throw { status: 401, error: 'invalid_token' };
    }
    return { sub: 'user123', preferred_username: 'admin@example.com' };
  }
}

const NOW = new Date('2026-10-09T10:00:00Z');

function deps(table) {
  let counter = 0;
  return {
    table,
    verifier: new StubVerifier(),
    now: () => NOW,
    randomBytes: (n) => {
      counter += 1;
      return Buffer.alloc(n, counter);
    },
  };
}

function routerFor(table) {
  const router = createRouter();
  registerPolicyRoutes(router, deps(table));
  return router;
}

function call(router, method, path, { body = null, query = {}, token = 'valid-token' } = {}) {
  const headers = token === null ? {} : { authorization: `Bearer ${token}` };
  return router.handle({ method, path, query, headers, body: body === null ? null : JSON.stringify(body) });
}

function adminReq(body, params = {}) {
  return {
    method: 'POST',
    path: '/admin/api/v1/policies',
    query: {},
    headers: { authorization: 'Bearer valid-token' },
    params,
    body: body === null ? null : JSON.stringify(body),
    claims: { sub: 'user123', preferred_username: 'admin@example.com' },
  };
}

// ============================================================================
// Index attributes on write
// ============================================================================

test('Scenario: A created policy carries the policy list index', async () => {
  const table = new FakeTable();
  const result = await handlePolicyCreate(adminReq({ name: 'Baseline', settings: { firewallEnabled: true } }), deps(table));
  assert.strictEqual(result.statusCode, 201);

  const stored = table.stored(policyKey(result.body.policyId));
  assert.strictEqual(stored.gsi1pk, 'POLICY');
  assert.strictEqual(stored.gsi1sk, 'Baseline');
});

test('Scenario: An updated policy keeps the list index, following a rename', async () => {
  const table = new FakeTable();
  const created = await handlePolicyCreate(adminReq({ name: 'Old name', settings: {} }), deps(table));
  const policyId = created.body.policyId;

  const renamed = await handlePolicyUpdate(
    { ...adminReq({ name: 'New name', settings: { firewallEnabled: false } }, { policyId }), method: 'PUT' },
    deps(table),
  );
  assert.strictEqual(renamed.statusCode, 200);
  let stored = table.stored(policyKey(policyId));
  assert.deepStrictEqual({ gsi1pk: stored.gsi1pk, gsi1sk: stored.gsi1sk }, policyListIndex('New name'));

  // A settings-only update keeps the existing name as the sort key.
  await handlePolicyUpdate({ ...adminReq({ settings: {} }, { policyId }), method: 'PUT' }, deps(table));
  stored = table.stored(policyKey(policyId));
  assert.deepStrictEqual({ gsi1pk: stored.gsi1pk, gsi1sk: stored.gsi1sk }, policyListIndex('New name'));
});

test('Scenario: Updating a policy written before the index existed adds the index', async () => {
  const table = new FakeTable();
  table.seed({ ...policyKey('pol-legacy'), policyId: 'pol-legacy', name: 'Legacy', settings: {}, version: 1 });

  await handlePolicyUpdate({ ...adminReq({ settings: {} }, { policyId: 'pol-legacy' }), method: 'PUT' }, deps(table));

  const stored = table.stored(policyKey('pol-legacy'));
  assert.strictEqual(stored.gsi1pk, 'POLICY');
  assert.strictEqual(stored.gsi1sk, 'Legacy');
});

// ============================================================================
// GET /admin/api/v1/policies
// ============================================================================

test('Scenario: A created policy is listed', async () => {
  const table = new FakeTable();
  const router = routerFor(table);

  // Given an admin creates a policy
  const created = await call(router, 'POST', '/admin/api/v1/policies', {
    body: { name: 'Baseline', settings: { screenLockTimeoutSeconds: 300 } },
  });
  assert.strictEqual(created.statusCode, 201);
  const { policyId } = JSON.parse(created.body);

  // When the policy list is read
  const listed = await call(router, 'GET', '/admin/api/v1/policies');

  // Then it holds that policy with its summary fields
  assert.strictEqual(listed.statusCode, 200);
  const body = JSON.parse(listed.body);
  assert.strictEqual(body.cursor, null);
  assert.strictEqual(body.items.length, 1);
  assert.deepStrictEqual(body.items[0], {
    policyId,
    name: 'Baseline',
    version: 1,
    settings: { screenLockTimeoutSeconds: 300 },
    createdAt: '2026-10-09T10:00:00Z',
    updatedAt: '2026-10-09T10:00:00Z',
  });
});

test('Unit: the list queries gsi1 for the POLICY partition with limit and cursor', async () => {
  const table = new FakeTable();
  const cursor = Buffer.from(JSON.stringify({ pk: 'POLICY#p', sk: 'PROFILE' }), 'utf8').toString('base64');

  const result = await handlePolicyList(
    { method: 'GET', path: '/admin/api/v1/policies', query: { limit: '10', cursor }, headers: {}, claims: {} },
    deps(table),
  );

  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(table.queries.length, 1);
  const request = table.queries[0];
  assert.strictEqual(request.IndexName, 'gsi1');
  assert.strictEqual(request.ExpressionAttributeValues[':gsi1pk'], 'POLICY');
  assert.strictEqual(request.limit, 10);
  assert.strictEqual(request.cursor, cursor);
});

test('Unit: the list passes the next-page cursor through', async () => {
  const table = new FakeTable();
  table.query = async () => ({
    items: [{ ...policyKey('pol-1'), name: 'A', version: 2, settings: {}, createdAt: 'c', updatedAt: 'u' }],
    cursor: 'next-page',
  });

  const result = await handlePolicyList({ method: 'GET', query: {}, headers: {}, claims: {} }, deps(table));

  assert.deepStrictEqual(result.body, {
    items: [{ policyId: 'pol-1', name: 'A', version: 2, settings: {}, createdAt: 'c', updatedAt: 'u' }],
    cursor: 'next-page',
  });
});

test('Unit: the list refuses a bad limit or cursor', async () => {
  const table = new FakeTable();
  for (const query of [{ limit: '0' }, { limit: 'abc' }, { cursor: '!!!not-a-cursor' }]) {
    const result = await handlePolicyList({ method: 'GET', query, headers: {}, claims: {} }, deps(table));
    assert.strictEqual(result.statusCode, 400, JSON.stringify(query));
  }
  assert.strictEqual(table.queries.length, 0);
});

test('Scenario: The policy list is admin-only', async () => {
  const table = new FakeTable();
  const router = routerFor(table);

  const anonymous = await call(router, 'GET', '/admin/api/v1/policies', { token: null });
  assert.strictEqual(anonymous.statusCode, 401);
  const rejected = await call(router, 'GET', '/admin/api/v1/policies', { token: 'invalid' });
  assert.strictEqual(rejected.statusCode, 401);
  assert.strictEqual(table.queries.length, 0);
});

// ============================================================================
// POST /admin/api/v1/policies/reindex
// ============================================================================

test('Scenario: Policies written before the index are re-indexed and then listed', async () => {
  const table = new FakeTable();
  const router = routerFor(table);

  // Given two policies with no index attributes, one that already has them,
  // and unrelated items that must be left alone
  table.seed({ ...policyKey('pol-a'), policyId: 'pol-a', name: 'Alpha', settings: {}, version: 1 });
  table.seed({ ...policyKey('pol-b'), policyId: 'pol-b', name: 'Bravo', settings: { firewallEnabled: true }, version: 3 });
  table.seed({ ...policyKey('pol-c'), ...policyListIndex('Charlie'), policyId: 'pol-c', name: 'Charlie', settings: {}, version: 1 });
  table.seed({ pk: 'POLICY#pol-a', sk: 'ASSIGN#grp-1', policyId: 'pol-a', groupId: 'grp-1' });
  table.seed({ pk: 'GROUP#grp-1', sk: 'PROFILE', groupId: 'grp-1', name: 'G' });

  // When an admin re-indexes
  const response = await call(router, 'POST', '/admin/api/v1/policies/reindex');

  // Then exactly the two unindexed policies are written
  assert.strictEqual(response.statusCode, 200);
  assert.deepStrictEqual(JSON.parse(response.body), { reindexed: 2 });
  const a = table.stored(policyKey('pol-a'));
  assert.deepStrictEqual({ gsi1pk: a.gsi1pk, gsi1sk: a.gsi1sk }, policyListIndex('Alpha'));
  const b = table.stored(policyKey('pol-b'));
  assert.deepStrictEqual({ gsi1pk: b.gsi1pk, gsi1sk: b.gsi1sk }, policyListIndex('Bravo'));
  // ...without losing any of their attributes
  assert.strictEqual(b.version, 3);
  assert.deepStrictEqual(b.settings, { firewallEnabled: true });
  // ...and nothing else is touched
  assert.strictEqual(table.stored({ pk: 'POLICY#pol-a', sk: 'ASSIGN#grp-1' }).gsi1pk, undefined);
  assert.strictEqual(table.stored({ pk: 'GROUP#grp-1', sk: 'PROFILE' }).gsi1pk, undefined);

  // And the scan followed the cursor to the end with the policy filter
  assert.ok(table.scans.length > 1, 'the scan should be paged to the end');
  for (const scan of table.scans) {
    assert.strictEqual(scan.ExpressionAttributeValues[':sk'], 'PROFILE');
    assert.strictEqual(scan.ExpressionAttributeValues[':pkPrefix'], 'POLICY#');
  }

  // And all three policies are now listed
  const listed = JSON.parse((await call(router, 'GET', '/admin/api/v1/policies')).body);
  assert.deepStrictEqual(
    listed.items.map((item) => item.name),
    ['Alpha', 'Bravo', 'Charlie'],
  );
});

test('Scenario: Re-indexing is idempotent and audited', async () => {
  const table = new FakeTable();
  table.seed({ ...policyKey('pol-a'), policyId: 'pol-a', name: 'Alpha', settings: {}, version: 1 });
  const req = { ...adminReq(null), path: '/admin/api/v1/policies/reindex' };

  const first = await handlePolicyReindex(req, deps(table));
  assert.deepStrictEqual(first.body, { reindexed: 1 });
  const putsAfterFirst = table.puts.filter((item) => item.pk.startsWith('POLICY#')).length;

  const second = await handlePolicyReindex(req, deps(table));
  assert.deepStrictEqual(second.body, { reindexed: 0 });
  assert.strictEqual(
    table.puts.filter((item) => item.pk.startsWith('POLICY#')).length,
    putsAfterFirst,
    'a second run writes no policy',
  );

  const audits = table.audits().filter((item) => item.action === POLICY_REINDEXED_ACTION);
  assert.strictEqual(POLICY_REINDEXED_ACTION, 'policy.reindexed');
  assert.ok(audits.length >= 1, 'the re-index is audited');
  assert.ok(audits.some((item) => item.detail?.reindexed === 1));
  assert.strictEqual(audits[0].actor, 'admin@example.com');
});

test('Scenario: A policy record with no name is indexed under its id', async () => {
  const table = new FakeTable();
  table.seed({ ...policyKey('pol-x'), settings: {}, version: 1 });

  const result = await handlePolicyReindex({ ...adminReq(null) }, deps(table));

  assert.deepStrictEqual(result.body, { reindexed: 1 });
  const stored = table.stored(policyKey('pol-x'));
  assert.deepStrictEqual({ gsi1pk: stored.gsi1pk, gsi1sk: stored.gsi1sk }, policyListIndex('pol-x'));
});

test('Scenario: Re-indexing is admin-only', async () => {
  const table = new FakeTable();
  table.seed({ ...policyKey('pol-a'), policyId: 'pol-a', name: 'Alpha', settings: {}, version: 1 });
  const router = routerFor(table);

  const anonymous = await call(router, 'POST', '/admin/api/v1/policies/reindex', { token: null });
  assert.strictEqual(anonymous.statusCode, 401);
  assert.strictEqual(table.scans.length, 0);
  assert.strictEqual(table.stored(policyKey('pol-a')).gsi1pk, undefined);
});

test('Unit: Re-indexing with a table client that cannot scan is a wiring fault', async () => {
  const table = new FakeTable();
  table.scan = undefined;
  await assert.rejects(() => handlePolicyReindex(adminReq(null), deps(table)), /scan/);
});
