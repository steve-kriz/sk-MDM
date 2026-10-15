/**
 * E2E cucumber-style and unit tests for the admin application safe-list routes
 * (TASK-049, AC2-AC6): `backend/src/admin/applications.ts`.
 *
 * Tests implement the ticket's Gherkin scenarios in Given/When/Then style using
 * node:test. All database calls are mocked with an in-memory fake table -- no
 * real DB connection is ever opened.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

const {
  handleApplicationList,
  handleApplicationUploadUrl,
  handleApplicationCreate,
  handleApplicationDelete,
  readApplication,
  applicationRecord,
  byApplicationName,
  APPLICATION_UPLOAD_MAX_BYTES,
  APPLICATION_UPLOAD_URL_TTL_SECONDS,
  APPLICATION_CREATED_ACTION,
  APPLICATION_DELETED_ACTION,
} = await import('../../dist/admin/applications.js');
const { application: applicationKey } = await import('../../dist/db/keys.js');

const VALID_SHA256 = 'a'.repeat(64);

// ============================================================================
// Fake table
// ============================================================================

class FakeTable {
  constructor() {
    this.items = new Map();
    this.auditItems = [];
  }

  keyStr(key) {
    return `${key.pk}#${key.sk}`;
  }

  async get(key) {
    return this.items.get(this.keyStr(key));
  }

  async put(item) {
    if (item.action) {
      this.auditItems.push(item);
    }
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  async delete(key) {
    this.items.delete(this.keyStr(key));
  }

  async query(request) {
    const gsi1pk = request.ExpressionAttributeValues?.[':gsi1pk'];
    const items = [];
    for (const item of this.items.values()) {
      if (item.gsi1pk === gsi1pk) {
        items.push(item);
      }
    }
    return { items, cursor: null };
  }

  countApplications() {
    return [...this.items.values()].filter((item) => item.pk?.startsWith('APPLICATION#')).length;
  }
}

/** A fake installer store; each method's outcome is scripted per test. */
class FakeInstallers {
  constructor() {
    this.presignPutCalls = [];
    this.objectSizeCalls = [];
    this.presignGetCalls = [];
    this.sizeAnswer = 1600000;
    this.presignPutUrl = 'https://bucket.s3.ap-southeast-2.amazonaws.com/put';
  }

  async presignPut(key, ttlSeconds) {
    this.presignPutCalls.push({ key, ttlSeconds });
    return this.presignPutUrl;
  }

  async objectSize(key) {
    this.objectSizeCalls.push(key);
    return this.sizeAnswer;
  }

  async presignGet(key, ttlSeconds) {
    this.presignGetCalls.push({ key, ttlSeconds });
    return 'https://bucket/presigned';
  }
}

function deps(table, overrides = {}) {
  let randomCounter = 0;
  return {
    table,
    now: () => new Date('2026-10-11T10:00:00Z'),
    randomBytes: (bytes) => {
      const buf = Buffer.alloc(bytes);
      for (let i = 0; i < bytes; i += 1) {
        buf[i] = ((randomCounter + i) * 17) % 256;
      }
      randomCounter += bytes;
      return buf;
    },
    // TASK-050: a URL create needs a hasher; this one accepts every run.
    hasher: { invoke: async () => {} },
    ...overrides,
  };
}

function req(body, { params = {}, query = {}, actor = 'admin@officehq.com.au' } = {}) {
  return {
    body: body === undefined ? null : JSON.stringify(body),
    params,
    query,
    claims: { preferred_username: actor },
  };
}

// ============================================================================
// AC2: POST /admin/api/v1/applications/upload-url
// ============================================================================

test('Scenario: Admin gets a presigned upload URL', async () => {
  // Given an installer store whose presignPut returns a URL
  const table = new FakeTable();
  const installers = new FakeInstallers();
  const d = deps(table, { installers });

  // When an admin posts {fileName, sizeBytes} to the upload-url route
  const result = await handleApplicationUploadUrl(req({ fileName: '7z2408-x64.msi', sizeBytes: 1600000 }), d);

  // Then the status is 200, uploadKey matches the pattern, presignPut was
  // called with (uploadKey, 900) and expiresInSeconds is 900
  assert.equal(result.statusCode, 200);
  assert.match(result.body.uploadKey, /^applications\/[0-9a-f]{16}\/7z2408-x64\.msi$/);
  assert.equal(result.body.url, installers.presignPutUrl);
  assert.equal(result.body.expiresInSeconds, APPLICATION_UPLOAD_URL_TTL_SECONDS);
  assert.equal(installers.presignPutCalls.length, 1);
  assert.equal(installers.presignPutCalls[0].key, result.body.uploadKey);
  assert.equal(installers.presignPutCalls[0].ttlSeconds, 900);
  // And no table item was written
  assert.equal(table.countApplications(), 0);
});

const uploadUrlRefusals = [
  { body: { fileName: 'setup.dmg', sizeBytes: 10 }, fields: ['fileName'] },
  { body: { fileName: 'setup.msi', sizeBytes: 524288001 }, fields: ['sizeBytes'] },
  { body: { fileName: '../x.exe', sizeBytes: 0 }, fields: ['fileName', 'sizeBytes'] },
];

for (const { body, fields } of uploadUrlRefusals) {
  test(`Scenario Outline: Upload URL request is refused -- ${JSON.stringify(body)}`, async () => {
    const table = new FakeTable();
    const d = deps(table, { installers: new FakeInstallers() });

    const result = await handleApplicationUploadUrl(req(body), d);

    assert.equal(result.statusCode, 400);
    assert.equal(result.body.error, 'invalid_request');
    assert.deepEqual(result.body.fields, fields);
  });
}

test('Scenario: No installer store -- upload URL answers 500 not_configured', async () => {
  // Given the admin dependencies have no installers
  const table = new FakeTable();
  const d = deps(table);

  // When an admin requests an upload URL for "a.msi" of 10 bytes
  const result = await handleApplicationUploadUrl(req({ fileName: 'a.msi', sizeBytes: 10 }), d);

  // Then the status is 500 with error "not_configured"
  assert.equal(result.statusCode, 500);
  assert.equal(result.body.error, 'not_configured');
});

test('Unit: sizeBytes above 500 MiB is refused and APPLICATION_UPLOAD_MAX_BYTES is the boundary', () => {
  assert.equal(APPLICATION_UPLOAD_MAX_BYTES, 524288000);
});

// ============================================================================
// AC3: POST /admin/api/v1/applications, source upload
// ============================================================================

test('Scenario: Register an uploaded application', async () => {
  // Given objectSize for the uploaded key returns 1600000
  const table = new FakeTable();
  const installers = new FakeInstallers();
  installers.sizeAnswer = 1600000;
  const d = deps(table, { installers });

  // When an admin posts the create body for an uploaded 7-Zip installer
  const result = await handleApplicationCreate(
    req({
      source: 'upload',
      name: '7-Zip',
      uploadKey: 'applications/0123456789abcdef/7z.msi',
      sha256: VALID_SHA256,
    }),
    d,
  );

  // Then the status is 201 with installerType "msi", platform "windows",
  // fileName "7z.msi", sizeBytes 1600000
  assert.equal(result.statusCode, 201);
  assert.equal(result.body.installerType, 'msi');
  assert.equal(result.body.platform, 'windows');
  assert.equal(result.body.fileName, '7z.msi');
  assert.equal(result.body.sizeBytes, 1600000);
  assert.equal(installers.objectSizeCalls[0], 'applications/0123456789abcdef/7z.msi');

  // And the item carries gsi1pk "APPLICATION" and gsi1sk "7-Zip"
  const stored = table.items.get(table.keyStr(applicationKey(result.body.applicationId)));
  assert.equal(stored.gsi1pk, 'APPLICATION');
  assert.equal(stored.gsi1sk, '7-Zip');

  // And audit "application.created" has detail {name, source, installerType}
  const audit = table.auditItems.find((item) => item.action === APPLICATION_CREATED_ACTION);
  assert.ok(audit);
  assert.deepEqual(audit.detail, { name: '7-Zip', source: 'upload', installerType: 'msi' });
});

const uploadedObjectProblems = [
  { size: null, error: 'upload_not_found' },
  { size: 524288001, error: 'upload_too_large' },
];

for (const { size, error } of uploadedObjectProblems) {
  test(`Scenario Outline: Uploaded object problems -- objectSize ${size} -> ${error}`, async () => {
    const table = new FakeTable();
    const installers = new FakeInstallers();
    installers.sizeAnswer = size;
    const d = deps(table, { installers });

    const result = await handleApplicationCreate(
      req({
        source: 'upload',
        name: '7-Zip',
        uploadKey: 'applications/0123456789abcdef/7z.msi',
        sha256: VALID_SHA256,
      }),
      d,
    );

    assert.equal(result.statusCode, 400);
    assert.equal(result.body.error, error);
    assert.equal(table.countApplications(), 0);
  });
}

test('Scenario: Bad sha256 and installArgs on an msi are both reported', async () => {
  const table = new FakeTable();
  const installers = new FakeInstallers();
  const d = deps(table, { installers });

  const result = await handleApplicationCreate(
    req({
      source: 'upload',
      name: '7-Zip',
      uploadKey: 'applications/0123456789abcdef/a.msi',
      sha256: 'XYZ',
      installArgs: '/S',
    }),
    d,
  );

  assert.equal(result.statusCode, 400);
  assert.deepEqual(result.body.fields, ['sha256', 'installArgs']);
  assert.equal(table.countApplications(), 0);
  assert.equal(installers.objectSizeCalls.length, 0, 'objectSize should not be called until validation passes');
});

// ============================================================================
// AC4: POST /admin/api/v1/applications, source url
// ============================================================================

test('Scenario: Register a URL application', async () => {
  const table = new FakeTable();
  const installers = new FakeInstallers();
  const d = deps(table, { installers });

  const result = await handleApplicationCreate(
    req({ source: 'url', name: 'Zoom', url: 'https://zoom.us/x.msi', installerType: 'msi', sha256: VALID_SHA256 }),
    d,
  );

  assert.equal(result.statusCode, 201);
  assert.equal(result.body.platform, 'windows');
  assert.equal(installers.objectSizeCalls.length, 0, 'no S3 call should be made for a url source');
});

const urlRefusals = [
  {
    body: { source: 'url', name: 'X', url: 'http://x.test/a.msi', installerType: 'msi', sha256: VALID_SHA256 },
    field: 'url',
  },
  {
    body: { source: 'url', name: 'X', url: 'https://x.test/a', installerType: 'dmg', sha256: VALID_SHA256 },
    field: 'installerType',
  },
  { body: { source: 'ftp', name: 'X' }, field: 'source' },
];

for (const { body, field } of urlRefusals) {
  test(`Scenario Outline: URL application refused -- field "${field}"`, async () => {
    const table = new FakeTable();
    const d = deps(table, { installers: new FakeInstallers() });

    const result = await handleApplicationCreate(req(body), d);

    assert.equal(result.statusCode, 400);
    assert.equal(result.body.error, 'invalid_request');
    assert.ok(result.body.fields.includes(field), `expected fields ${JSON.stringify(result.body.fields)} to include "${field}"`);
    assert.equal(table.countApplications(), 0);
  });
}

// ============================================================================
// AC5: GET /admin/api/v1/applications
// ============================================================================

test('Scenario: Admin list sorted and filtered', async () => {
  const table = new FakeTable();
  const installers = new FakeInstallers();
  const d = deps(table, { installers });

  await handleApplicationCreate(
    req({ source: 'url', name: 'zoom', url: 'https://x.test/a.msi', installerType: 'msi', sha256: VALID_SHA256 }),
    d,
  );
  await handleApplicationCreate(
    req({
      source: 'upload',
      name: '7-Zip',
      uploadKey: 'applications/0123456789abcdef/7z.msi',
      sha256: VALID_SHA256,
    }),
    d,
  );
  await handleApplicationCreate(
    req({ source: 'url', name: 'Slack', url: 'https://x.test/a.pkg', installerType: 'pkg', sha256: VALID_SHA256 }),
    d,
  );

  const result = await handleApplicationList(req(undefined, { query: { platform: 'windows' } }), d);

  assert.equal(result.statusCode, 200);
  assert.deepEqual(
    result.body.items.map((item) => item.name),
    ['7-Zip', 'zoom'],
  );
});

test('Scenario: Admin list item carries exactly the AC5 keys', async () => {
  const table = new FakeTable();
  const d = deps(table, { installers: new FakeInstallers() });
  const created = await handleApplicationCreate(
    req({ source: 'url', name: 'Zoom', url: 'https://x.test/a.msi', installerType: 'msi', sha256: VALID_SHA256 }),
    d,
  );
  assert.equal(created.statusCode, 201);

  const result = await handleApplicationList(req(undefined), d);
  const keys = Object.keys(result.body.items[0]).sort();
  assert.deepEqual(keys, [
    'applicationId',
    'createdAt',
    'createdBy',
    'description',
    'fileName',
    'hashError',
    'hashStatus',
    'installArgs',
    'installerType',
    'name',
    'platform',
    'sha256',
    'sizeBytes',
    'source',
    'url',
  ]);
});

test('Scenario: Unknown platform filter is refused', async () => {
  const table = new FakeTable();
  const d = deps(table);

  const result = await handleApplicationList(req(undefined, { query: { platform: 'linux' } }), d);

  assert.equal(result.statusCode, 400);
  assert.equal(result.body.error, 'invalid_request');
});

// ============================================================================
// AC6: DELETE /admin/api/v1/applications/{applicationId}
// ============================================================================

test('Scenario: Delete an application', async () => {
  const table = new FakeTable();
  const installers = new FakeInstallers();
  const d = deps(table, { installers });
  const created = await handleApplicationCreate(
    req({ source: 'url', name: 'Zoom', url: 'https://x.test/a.msi', installerType: 'msi', sha256: VALID_SHA256 }),
    d,
  );
  const applicationId = created.body.applicationId;

  const result = await handleApplicationDelete(req(undefined, { params: { applicationId } }), d);

  assert.equal(result.statusCode, 204);
  assert.equal(await readApplication(table, applicationId), null);
  assert.equal(installers.presignGetCalls.length, 0, 'no S3 call should be made on delete');

  const audit = table.auditItems.find((item) => item.action === APPLICATION_DELETED_ACTION);
  assert.ok(audit);
  assert.deepEqual(audit.detail, { name: 'Zoom' });
});

test('Scenario: Delete an unknown application', async () => {
  const table = new FakeTable();
  const d = deps(table);

  const result = await handleApplicationDelete(req(undefined, { params: { applicationId: 'app-ffffffffffffffff' } }), d);

  assert.equal(result.statusCode, 404);
  assert.equal(result.body.error, 'not_found');
});

test('Unit: byApplicationName sorts ignoring case, ties by name then id', () => {
  const items = [
    { name: 'beta', applicationId: 'app-2' },
    { name: 'alpha', applicationId: 'app-0' },
    { name: 'Alpha', applicationId: 'app-1' },
  ];
  const sorted = [...items].sort(byApplicationName);
  // Ignoring case, "alpha" ties with "Alpha" and both sort before "beta"; the
  // tie is broken by the name string itself ("Alpha" < "alpha" in code-unit
  // order), then, were that equal too, by applicationId.
  assert.deepEqual(
    sorted.map((item) => item.applicationId),
    ['app-1', 'app-0', 'app-2'],
  );
});

test('Unit: applicationRecord fills absent fields with null', () => {
  const record = applicationRecord({ applicationId: 'app-1', name: 'X' });
  assert.deepEqual(record, {
    applicationId: 'app-1',
    name: 'X',
    description: null,
    source: null,
    installerType: null,
    platform: null,
    fileName: null,
    sizeBytes: null,
    url: null,
    sha256: null,
    installArgs: null,
    createdAt: null,
    createdBy: null,
    hashStatus: 'failed',
    hashError: null,
  });
});
