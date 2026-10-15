/**
 * Tests for editing an application: `PATCH /admin/api/v1/applications/{applicationId}`
 * (`handleApplicationUpdate` in `backend/src/admin/applications.ts`).
 *
 * All database access is a fake, in-memory table -- no real DynamoDB
 * connection is ever opened. The hasher invoker is a fake `{invoke}`.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

const {
  handleApplicationUpdate,
  readApplicationEdit,
  registerApplicationAdminRoutes,
  APPLICATION_UPDATED_ACTION,
  APPLICATION_DETAIL_PATH,
} = await import('../../dist/admin/applications.js');
const { application: applicationKey } = await import('../../dist/db/keys.js');
const { CONDITIONAL_CHECK_FAILED } = await import('../../dist/db/table.js');

const SHA = 'b'.repeat(64);

class FakeTable {
  constructor() {
    this.items = new Map();
    this.auditItems = [];
    this.updates = [];
  }

  keyStr(key) {
    return `${key.pk}#${key.sk}`;
  }

  async get(key) {
    const item = this.items.get(this.keyStr(key));
    return item === undefined ? undefined : { ...item };
  }

  async put(item) {
    if (item.action) {
      this.auditItems.push(item);
      return;
    }
    this.items.set(this.keyStr(item), { ...item });
  }

  async delete(key) {
    this.items.delete(this.keyStr(key));
  }

  async query() {
    return { items: [...this.items.values()], cursor: null };
  }

  /** SET-only updates, resolving `#name` / `:value` placeholders. */
  async update(key, fields = {}) {
    this.updates.push(fields);
    const k = this.keyStr(key);
    const existing = this.items.get(k);
    const values = fields.ExpressionAttributeValues ?? {};
    const names = fields.ExpressionAttributeNames ?? {};
    const condition = fields.ConditionExpression ?? '';
    if (existing === undefined || (condition.includes('hashRunId = :runId') && existing.hashRunId !== values[':runId'])) {
      const error = new Error('conditional check failed');
      error.name = CONDITIONAL_CHECK_FAILED;
      throw error;
    }
    const updated = { ...existing };
    for (const assignment of String(fields.UpdateExpression ?? '').replace(/^SET\s+/, '').split(',')) {
      const [name, placeholder] = assignment.split('=').map((part) => part.trim());
      updated[names[name] ?? name] = values[placeholder];
    }
    this.items.set(k, updated);
    return updated;
  }

  stored(applicationId) {
    return this.items.get(this.keyStr(applicationKey(applicationId)));
  }
}

function seedUrlApp(table, overrides = {}) {
  table.items.set(table.keyStr(applicationKey('app-url')), {
    ...applicationKey('app-url'),
    gsi1pk: 'APPLICATION',
    gsi1sk: 'TeamViewer',
    applicationId: 'app-url',
    name: 'TeamViewer',
    description: null,
    source: 'url',
    url: 'https://download.teamviewer.com/TeamViewer_Setup_x64.exe',
    installerType: 'exe',
    platform: 'windows',
    installArgs: null,
    sha256: SHA,
    hashStatus: 'ready',
    hashError: null,
    hashRunId: 'oldrun',
    createdAt: '2026-10-01T00:00:00Z',
    createdBy: 'admin@officehq.com.au',
    ...overrides,
  });
}

function seedUploadApp(table) {
  table.items.set(table.keyStr(applicationKey('app-up')), {
    ...applicationKey('app-up'),
    gsi1pk: 'APPLICATION',
    gsi1sk: '7-Zip',
    applicationId: 'app-up',
    name: '7-Zip',
    description: 'Archiver',
    source: 'upload',
    objectKey: 'applications/aaaaaaaaaaaaaaaa/7z.msi',
    fileName: '7z.msi',
    sizeBytes: 1000,
    installerType: 'msi',
    platform: 'windows',
    installArgs: null,
    sha256: SHA,
    hashStatus: 'ready',
    hashError: null,
  });
}

function deps(table, overrides = {}) {
  const invoked = [];
  return {
    invoked,
    table,
    now: () => new Date('2026-10-14T10:00:00Z'),
    randomBytes: (bytes) => Buffer.alloc(bytes, 0xab),
    hasher: { invoke: async (event) => invoked.push(event) },
    ...overrides,
  };
}

function req(body, applicationId = 'app-url') {
  return {
    body: body === undefined ? null : JSON.stringify(body),
    params: { applicationId },
    query: {},
    claims: { preferred_username: 'steve.k@officehq.com.au' },
  };
}

test('Scenario: Setting installArgs on an exe saves it without re-hashing', async () => {
  const table = new FakeTable();
  seedUrlApp(table);
  const d = deps(table);

  const result = await handleApplicationUpdate(req({ installArgs: '/S' }), d);

  assert.equal(result.statusCode, 200);
  assert.equal(result.body.installArgs, '/S');
  assert.equal(result.body.hashStatus, 'ready');
  assert.equal(result.body.sha256, SHA);
  const stored = table.stored('app-url');
  assert.equal(stored.installArgs, '/S');
  assert.equal(stored.updatedAt, '2026-10-14T10:00:00Z');
  assert.equal(stored.updatedBy, 'steve.k@officehq.com.au');
  assert.equal(d.invoked.length, 0, 'no hash run for an unchanged url');

  assert.equal(table.auditItems.length, 1);
  assert.equal(table.auditItems[0].action, APPLICATION_UPDATED_ACTION);
  assert.equal(table.auditItems[0].target, 'app-url');
  assert.deepEqual(table.auditItems[0].detail, { name: 'TeamViewer', changed: ['installArgs'] });
});

test('Scenario: Renaming rewrites the list index so the list stays sorted', async () => {
  const table = new FakeTable();
  seedUrlApp(table);

  const result = await handleApplicationUpdate(req({ name: 'TeamViewer Host' }), deps(table));

  assert.equal(result.statusCode, 200);
  const stored = table.stored('app-url');
  assert.equal(stored.name, 'TeamViewer Host');
  assert.equal(stored.gsi1pk, 'APPLICATION');
  assert.equal(stored.gsi1sk, 'TeamViewer Host');
  // `name` is a DynamoDB reserved word: every attribute goes through a placeholder.
  assert.match(table.updates[0].UpdateExpression, /#name = :name/);
  assert.equal(table.updates[0].ExpressionAttributeNames['#name'], 'name');
});

test('Scenario: Changing the url hashes it again', async () => {
  const table = new FakeTable();
  seedUrlApp(table);
  const d = deps(table);
  const url = 'https://download.teamviewer.com/full/TeamViewer_Setup_x64.exe';

  const result = await handleApplicationUpdate(req({ url }), d);

  assert.equal(result.statusCode, 200);
  assert.equal(result.body.hashStatus, 'pending');
  assert.equal(result.body.sha256, null);
  const stored = table.stored('app-url');
  assert.equal(stored.url, url);
  assert.equal(stored.hashStatus, 'pending');
  assert.equal(stored.sha256, null);
  assert.equal(stored.hashRunId, 'ab'.repeat(8));
  assert.equal(stored.hashRequestedAt, '2026-10-14T10:00:00Z');
  assert.deepEqual(d.invoked, [{ applicationId: 'app-url', url, hashRunId: 'ab'.repeat(8) }]);
});

test('Scenario: A url change with no hasher configured writes nothing', async () => {
  const table = new FakeTable();
  seedUrlApp(table);

  const result = await handleApplicationUpdate(req({ url: 'https://example.com/x.exe' }), deps(table, { hasher: null }));

  assert.equal(result.statusCode, 500);
  assert.equal(result.body.error, 'not_configured');
  assert.equal(table.updates.length, 0);
  assert.equal(table.auditItems.length, 0);
});

test('Scenario: A hasher that cannot start marks the edited record failed', async () => {
  const table = new FakeTable();
  seedUrlApp(table);
  const hasher = {
    invoke: async () => {
      throw new Error('boom');
    },
  };

  const result = await handleApplicationUpdate(req({ url: 'https://example.com/x.exe' }), deps(table, { hasher }));

  assert.equal(result.statusCode, 200);
  assert.equal(result.body.hashStatus, 'failed');
  assert.equal(result.body.hashError, 'invoke_failed');
  assert.equal(table.stored('app-url').hashStatus, 'failed');
});

test('Scenario: Changing a URL app from exe to msi moves its platform and needs installArgs cleared', async () => {
  const table = new FakeTable();
  seedUrlApp(table, { installArgs: '/S' });

  const refused = await handleApplicationUpdate(req({ installerType: 'msi' }), deps(table));
  assert.equal(refused.statusCode, 400);
  assert.deepEqual(refused.body.fields, ['installArgs']);

  const result = await handleApplicationUpdate(req({ installerType: 'pkg', installArgs: '' }), deps(table));
  assert.equal(result.statusCode, 200);
  assert.equal(result.body.installerType, 'pkg');
  assert.equal(result.body.platform, 'darwin');
  assert.equal(result.body.installArgs, null);
});

test('Scenario: An upload app may not change its url or installer type', async () => {
  const table = new FakeTable();
  seedUploadApp(table);

  const result = await handleApplicationUpdate(
    req({ url: 'https://example.com/x.msi', installerType: 'exe' }, 'app-up'),
    deps(table),
  );

  assert.equal(result.statusCode, 400);
  assert.equal(result.body.error, 'invalid_request');
  assert.deepEqual(result.body.fields, ['url', 'installerType']);
  assert.equal(table.updates.length, 0);
});

test('Scenario: An upload app keeps its file when its details are edited', async () => {
  const table = new FakeTable();
  seedUploadApp(table);

  const result = await handleApplicationUpdate(req({ name: '7-Zip x64', description: '' }, 'app-up'), deps(table));

  assert.equal(result.statusCode, 200);
  assert.equal(result.body.name, '7-Zip x64');
  assert.equal(result.body.description, null);
  assert.equal(result.body.fileName, '7z.msi');
  assert.equal(result.body.url, null);
  const stored = table.stored('app-up');
  assert.equal(stored.objectKey, 'applications/aaaaaaaaaaaaaaaa/7z.msi');
  assert.ok(!('url' in stored), 'an upload app gets no url attribute');
});

test('Scenario Outline: Invalid edits are refused, listing every offending field', async () => {
  const cases = [
    { body: { name: '' }, fields: ['name'] },
    { body: { name: '   ' }, fields: ['name'] },
    { body: { name: 'x'.repeat(101) }, fields: ['name'] },
    { body: { description: 'x'.repeat(501) }, fields: ['description'] },
    { body: { url: 'http://insecure.example/x.exe' }, fields: ['url'] },
    { body: { installerType: 'zip' }, fields: ['installerType'] },
    { body: { installArgs: 'x'.repeat(501) }, fields: ['installArgs'] },
    { body: { source: 'upload', sha256: SHA }, fields: ['source', 'sha256'] },
    { body: { name: '', url: 'nope' }, fields: ['name', 'url'] },
  ];
  for (const { body, fields } of cases) {
    const table = new FakeTable();
    seedUrlApp(table);
    const result = await handleApplicationUpdate(req(body), deps(table));
    assert.equal(result.statusCode, 400, JSON.stringify(body));
    assert.deepEqual(result.body.fields, fields, JSON.stringify(body));
    assert.equal(table.updates.length, 0);
  }
});

test('Scenario: A body that is not a JSON object is refused', async () => {
  const table = new FakeTable();
  seedUrlApp(table);
  for (const raw of ['not json', '[1]', null]) {
    const result = await handleApplicationUpdate({ ...req(undefined), body: raw }, deps(table));
    assert.equal(result.statusCode, 400);
  }
});

test('Scenario: An unknown application is 404', async () => {
  const table = new FakeTable();
  const result = await handleApplicationUpdate(req({ name: 'x' }, 'app-missing'), deps(table));
  assert.equal(result.statusCode, 404);
  assert.equal(result.body.error, 'not_found');
});

test('Scenario: An edit that changes nothing writes nothing', async () => {
  const table = new FakeTable();
  seedUrlApp(table);

  const result = await handleApplicationUpdate(
    req({ name: 'TeamViewer', description: '', installArgs: null, url: 'https://download.teamviewer.com/TeamViewer_Setup_x64.exe' }),
    deps(table),
  );

  assert.equal(result.statusCode, 200);
  assert.equal(result.body.name, 'TeamViewer');
  assert.equal(table.updates.length, 0);
  assert.equal(table.auditItems.length, 0);
});

test('Unit: readApplicationEdit reports exactly the changed fields', () => {
  const existing = { source: 'url', name: 'A', description: null, url: 'https://a.example/a.exe', installerType: 'exe', installArgs: null };
  const read = readApplicationEdit({ name: 'B', installArgs: '/S', description: null }, existing);
  assert.deepEqual(read.changed, ['name', 'installArgs']);
  assert.deepEqual(read.edited, { name: 'B', description: null, url: 'https://a.example/a.exe', installerType: 'exe', installArgs: '/S' });
});

test('Unit: the PATCH route is registered on the application detail path', () => {
  const added = [];
  const router = { add: (method, pattern) => (added.push(`${method} ${pattern}`), router) };
  registerApplicationAdminRoutes(router, {});
  assert.ok(added.some((route) => route.startsWith('PATCH ') && route.endsWith(APPLICATION_DETAIL_PATH)), added.join(', '));
});
