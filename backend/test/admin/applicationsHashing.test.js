/**
 * E2E cucumber-style and unit tests for the server-computed URL-application
 * hash (TASK-050, AC1-AC4, AC10): `backend/src/admin/applications.ts`.
 *
 * All database access is a fake, in-memory table (`FakeTable` below) -- no
 * real DynamoDB connection is ever opened. The hasher invoker is always a
 * fake `{invoke}` scripted per test.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

const {
  applicationHashStatus,
  applicationRecord,
  handleApplicationCreate,
  handleApplicationRetryHash,
  APPLICATION_HASH_STALE_SECONDS,
  APPLICATION_HASH_RETRIED_ACTION,
  APPLICATION_CREATED_ACTION,
} = await import('../../dist/admin/applications.js');
const { HASH_OUTCOME_CONDITION } = await import('../../dist/hashing/urlHasher.js');
const { CONDITIONAL_CHECK_FAILED } = await import('../../dist/db/table.js');

const VALID_SHA256 = 'a'.repeat(64);

// ============================================================================
// Fake table: get/put/update, with just enough conditional-update semantics
// to exercise the hashing conditions this module writes.
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

  async query() {
    return { items: [...this.items.values()], cursor: null };
  }

  async update(key, fields = {}) {
    const k = this.keyStr(key);
    const existing = this.items.get(k);
    const fail = () => {
      const error = new Error('conditional check failed');
      error.name = CONDITIONAL_CHECK_FAILED;
      throw error;
    };
    if (existing === undefined) {
      fail();
    }
    const condition = fields.ConditionExpression ?? '';
    const values = fields.ExpressionAttributeValues ?? {};
    if (condition.includes('hashRunId = :runId') && existing.hashRunId !== values[':runId']) {
      fail();
    }
    if (condition.includes('attribute_not_exists(hashRunId)') && existing.hashRunId !== undefined) {
      fail();
    }
    const setClause = String(fields.UpdateExpression ?? '').replace(/^SET\s+/, '');
    const updated = { ...existing };
    for (const assignment of setClause.split(',')) {
      const [name, placeholder] = assignment.split('=').map((part) => part.trim());
      if (name && placeholder) {
        updated[name] = values[placeholder];
      }
    }
    this.items.set(k, updated);
    return updated;
  }

  countApplications() {
    return [...this.items.values()].filter((item) => item.pk?.startsWith('APPLICATION#')).length;
  }
}

function deps(table, overrides = {}) {
  let counter = 0;
  return {
    table,
    now: () => new Date('2026-10-11T10:00:00Z'),
    randomBytes: (bytes) => {
      const buf = Buffer.alloc(bytes);
      for (let i = 0; i < bytes; i += 1) {
        buf[i] = ((counter + i) * 17) % 256;
      }
      counter += bytes;
      return buf;
    },
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
// AC1
// ============================================================================

test('Scenario: Legacy TASK-049 record reads as ready', () => {
  // Given a stored application with sha256 of 64 hex and no hashStatus attribute
  const item = { applicationId: 'app-1', name: 'Zoom', sha256: VALID_SHA256 };

  // When applicationRecord is applied to it
  const record = applicationRecord(item);

  // Then hashStatus is "ready", hashError is null and the keys are the
  // TASK-049 keys plus hashStatus and hashError
  assert.equal(record.hashStatus, 'ready');
  assert.equal(record.hashError, null);
  assert.deepEqual(
    Object.keys(record).sort(),
    [
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
    ].sort(),
  );
  // And hashRunId, hashRequestedAt and hashedAt are not keys of the record
  for (const key of ['hashRunId', 'hashRequestedAt', 'hashedAt']) {
    assert.equal(key in record, false, `${key} must not be a key of applicationRecord`);
  }
});

const hashStatusCases = [
  { stored: 'pending', sha: null, status: 'pending' },
  { stored: 'failed', sha: null, status: 'failed' },
  { stored: undefined, sha: 'XYZ', status: 'failed' },
  { stored: 'ready', sha: VALID_SHA256, status: 'ready' },
];

for (const { stored, sha, status } of hashStatusCases) {
  test(`Scenario Outline: Hash status derivation -- stored ${JSON.stringify(stored)}, sha ${JSON.stringify(sha)}`, () => {
    // Given a stored item with hashStatus <stored> and sha256 <sha>
    const item = { sha256: sha };
    if (stored !== undefined) {
      item.hashStatus = stored;
    }
    // Then applicationHashStatus returns "<status>"
    assert.equal(applicationHashStatus(item), status);
  });
}

// ============================================================================
// AC2
// ============================================================================

test('Scenario: Register a URL application without a hash', async () => {
  // Given a fake hasher and randomBytes producing hashRunId "0123456789abcdef"
  const table = new FakeTable();
  const invokeCalls = [];
  const invoke = async (event) => {
    invokeCalls.push({ event, putAt: table.items.size });
  };
  const d = deps(table, {
    hasher: { invoke },
    randomBytes: () => Buffer.from('0123456789abcdef', 'hex'),
  });

  // When an admin posts {source:"url", name:"Zoom", url:..., installerType:"msi", sha256:"abc"}
  const result = await handleApplicationCreate(
    req({ source: 'url', name: 'Zoom', url: 'https://zoom.us/x.msi', installerType: 'msi', sha256: 'abc' }),
    d,
  );

  // Then the status is 201 with hashStatus "pending", hashError null and sha256 null
  assert.equal(result.statusCode, 201);
  assert.equal(result.body.hashStatus, 'pending');
  assert.equal(result.body.hashError, null);
  assert.equal(result.body.sha256, null);

  // And the stored item has hashRunId "0123456789abcdef" and hashRequestedAt set
  const applicationId = result.body.applicationId;
  const stored = await table.get({ pk: `APPLICATION#${applicationId}`, sk: 'PROFILE' });
  assert.equal(stored.hashRunId, '0123456789abcdef');
  assert.ok(typeof stored.hashRequestedAt === 'string' && stored.hashRequestedAt.length > 0);

  // And hasher.invoke was called once with {applicationId, url, hashRunId} after the put
  assert.equal(invokeCalls.length, 1);
  assert.deepEqual(invokeCalls[0].event, {
    applicationId,
    url: 'https://zoom.us/x.msi',
    hashRunId: '0123456789abcdef',
  });
  assert.equal(invokeCalls[0].putAt, 1, 'the put must happen before invoke is called');

  // And audit "application.created" has detail {name:"Zoom", source:"url", installerType:"msi"}
  const audit = table.auditItems.find((item) => item.action === APPLICATION_CREATED_ACTION);
  assert.ok(audit);
  assert.deepEqual(audit.detail, { name: 'Zoom', source: 'url', installerType: 'msi' });
});

test('Scenario (failure): URL create without a hasher configured', async () => {
  // Given the admin dependencies have no hasher
  const table = new FakeTable();
  const d = deps(table, { hasher: undefined });

  // When an admin posts a valid URL application
  const result = await handleApplicationCreate(
    req({ source: 'url', name: 'Zoom', url: 'https://zoom.us/x.msi', installerType: 'msi' }),
    d,
  );

  // Then the status is 500 with error "not_configured" and nothing is written
  assert.equal(result.statusCode, 500);
  assert.equal(result.body.error, 'not_configured');
  assert.equal(table.countApplications(), 0);
});

test('Scenario (failure): URL validation still applies', async () => {
  const table = new FakeTable();
  let invoked = false;
  const d = deps(table, { hasher: { invoke: async () => { invoked = true; } } });

  // When an admin posts {source:"url", name:"X", url:"http://x.test/a.msi", installerType:"msi"}
  const result = await handleApplicationCreate(
    req({ source: 'url', name: 'X', url: 'http://x.test/a.msi', installerType: 'msi' }),
    d,
  );

  // Then the status is 400 with fields ["url"] and the hasher was not invoked
  assert.equal(result.statusCode, 400);
  assert.deepEqual(result.body.fields, ['url']);
  assert.equal(invoked, false);
});

// ============================================================================
// AC3
// ============================================================================

test('Scenario (failure): Invoking the hasher fails', async () => {
  // Given hasher.invoke rejects
  const table = new FakeTable();
  const d = deps(table, { hasher: { invoke: async () => { throw new Error('boom'); } } });

  // When an admin posts a valid URL application
  const result = await handleApplicationCreate(
    req({ source: 'url', name: 'Zoom', url: 'https://zoom.us/x.msi', installerType: 'msi' }),
    d,
  );

  // Then the status is 201 with hashStatus "failed" and hashError "invoke_failed"
  assert.equal(result.statusCode, 201);
  assert.equal(result.body.hashStatus, 'failed');
  assert.equal(result.body.hashError, 'invoke_failed');

  // And the update was conditional on the run's hashRunId
  const stored = await table.get({ pk: `APPLICATION#${result.body.applicationId}`, sk: 'PROFILE' });
  assert.equal(stored.hashStatus, 'failed');
  assert.equal(stored.hashError, 'invoke_failed');

  // And audit "application.created" was appended
  const audit = table.auditItems.find((item) => item.action === APPLICATION_CREATED_ACTION);
  assert.ok(audit);
});

// ============================================================================
// AC4
// ============================================================================

test('Scenario: Upload create is ready immediately', async () => {
  const table = new FakeTable();
  let invoked = false;
  const d = deps(table, {
    hasher: { invoke: async () => { invoked = true; } },
    installers: { objectSize: async () => 1600000 },
  });

  // When an admin registers an upload application with a valid sha256
  const result = await handleApplicationCreate(
    req({ source: 'upload', name: '7-Zip', uploadKey: 'applications/0123456789abcdef/7z.msi', sha256: VALID_SHA256 }),
    d,
  );

  // Then the status is 201 with hashStatus "ready", the item has no hashRunId
  // and hasher.invoke was not called
  assert.equal(result.statusCode, 201);
  assert.equal(result.body.hashStatus, 'ready');
  const stored = await table.get({ pk: `APPLICATION#${result.body.applicationId}`, sk: 'PROFILE' });
  assert.equal('hashRunId' in stored, false);
  assert.equal(invoked, false);
});

test('Scenario (failure): Upload create still requires sha256', async () => {
  const table = new FakeTable();
  const d = deps(table, { installers: { objectSize: async () => 1600000 } });

  // When an admin registers an upload application with no sha256
  const result = await handleApplicationCreate(
    req({ source: 'upload', name: '7-Zip', uploadKey: 'applications/0123456789abcdef/7z.msi' }),
    d,
  );

  // Then the status is 400 with fields containing "sha256"
  assert.equal(result.statusCode, 400);
  assert.ok(result.body.fields.includes('sha256'));
});

// ============================================================================
// AC10
// ============================================================================

async function seedUrlApplication(table, applicationId, overrides = {}) {
  const item = {
    pk: `APPLICATION#${applicationId}`,
    sk: 'PROFILE',
    applicationId,
    name: 'Zoom',
    source: 'url',
    url: 'https://zoom.us/x.msi',
    installerType: 'msi',
    sha256: null,
    hashStatus: 'failed',
    hashError: 'http_500',
    hashRunId: 'r1',
    hashRequestedAt: '2026-10-11T09:00:00Z',
    createdAt: '2026-10-01T00:00:00Z',
    createdBy: 'seed@officehq.com.au',
    ...overrides,
  };
  await table.put(item);
  return item;
}

test('Scenario: Retry a failed hash', async () => {
  // Given URL application "app-1" with hashStatus "failed", hashRunId "r1" and a fake hasher
  const table = new FakeTable();
  await seedUrlApplication(table, 'app-1');
  const invokeCalls = [];
  const d = deps(table, {
    hasher: { invoke: async (event) => invokeCalls.push(event) },
    randomBytes: () => Buffer.from('fedcba9876543210', 'hex'),
  });

  // When an admin posts to /admin/api/v1/applications/app-1/retry-hash
  const result = await handleApplicationRetryHash(req(undefined, { params: { applicationId: 'app-1' } }), d);

  // Then the status is 202 with hashStatus "pending"
  assert.equal(result.statusCode, 202);
  assert.equal(result.body.hashStatus, 'pending');

  // And the update was conditional on hashRunId "r1" and set a new hashRunId,
  // sha256 null and hashError null
  const stored = await table.get({ pk: 'APPLICATION#app-1', sk: 'PROFILE' });
  assert.equal(stored.hashRunId, 'fedcba9876543210');
  assert.equal(stored.sha256, null);
  assert.equal(stored.hashError, null);

  // And hasher.invoke was called with the new hashRunId
  assert.equal(invokeCalls.length, 1);
  assert.equal(invokeCalls[0].hashRunId, 'fedcba9876543210');

  // And audit "application.hash_retried" has detail {name}
  const audit = table.auditItems.find((item) => item.action === APPLICATION_HASH_RETRIED_ACTION);
  assert.ok(audit);
  assert.deepEqual(audit.detail, { name: 'Zoom' });
});

const retryRefusals = [
  {
    name: 'an unknown id "app-ffffffffffffffff"',
    setup: async () => {},
    applicationId: 'app-ffffffffffffffff',
    status: 404,
    error: 'not_found',
  },
  {
    name: 'an upload application',
    setup: async (table) =>
      table.put({
        pk: 'APPLICATION#app-2',
        sk: 'PROFILE',
        applicationId: 'app-2',
        name: 'Upload App',
        source: 'upload',
        sha256: VALID_SHA256,
        hashStatus: 'ready',
      }),
    applicationId: 'app-2',
    status: 409,
    error: 'not_url_source',
  },
  {
    name: 'a ready URL application',
    setup: async (table) => seedUrlApplication(table, 'app-3', { hashStatus: 'ready', sha256: VALID_SHA256, hashError: null }),
    applicationId: 'app-3',
    status: 409,
    error: 'already_hashed',
  },
  {
    name: 'a URL application pending since 100 seconds ago',
    setup: async (table) =>
      seedUrlApplication(table, 'app-4', { hashStatus: 'pending', hashError: null, hashRequestedAt: '2026-10-11T09:58:20Z' }),
    applicationId: 'app-4',
    status: 409,
    error: 'hash_in_progress',
  },
  {
    name: 'a failed URL application with no hasher configured',
    setup: async (table) => seedUrlApplication(table, 'app-5'),
    applicationId: 'app-5',
    status: 500,
    error: 'not_configured',
    noHasher: true,
  },
];

for (const testCase of retryRefusals) {
  test(`Scenario Outline: Retry refused -- ${testCase.name}`, async () => {
    const table = new FakeTable();
    await testCase.setup(table);
    const d = deps(table, testCase.noHasher ? { hasher: undefined } : {});

    const result = await handleApplicationRetryHash(req(undefined, { params: { applicationId: testCase.applicationId } }), d);

    assert.equal(result.statusCode, testCase.status, testCase.name);
    assert.equal(result.body.error, testCase.error, testCase.name);
    // Nothing is written: the audit log stays empty and (for a seeded item)
    // its hashStatus is unchanged.
    assert.equal(table.auditItems.length, 0, testCase.name);
  });
}

test('Scenario (edge): Stale pending run may be retried; a racing retry loses', async () => {
  // Given a URL application pending since 961 seconds ago
  const table = new FakeTable();
  await seedUrlApplication(table, 'app-6', { hashStatus: 'pending', hashError: null, hashRequestedAt: '2026-10-11T09:43:59Z' });
  assert.ok(961 > APPLICATION_HASH_STALE_SECONDS, 'test fixture must exceed the stale threshold');

  let invokeOutcome = { kind: 'resolve' };
  const d = deps(table, {
    hasher: {
      invoke: async () => {
        if (invokeOutcome.kind === 'reject') {
          throw new Error('invoke failed');
        }
      },
    },
    randomBytes: () => Buffer.from('1111111111111111', 'hex'),
  });

  // When an admin retries it
  const result = await handleApplicationRetryHash(req(undefined, { params: { applicationId: 'app-6' } }), d);
  // Then the status is 202
  assert.equal(result.statusCode, 202);

  // And when the conditional update rejects with ConditionalCheckFailedException
  // the status is 409 "hash_in_progress" -- simulated with a second retry
  // racing against the now-current hashRunId.
  const raceTable = new FakeTable();
  await seedUrlApplication(raceTable, 'app-7', { hashStatus: 'pending', hashError: null, hashRequestedAt: '2026-10-11T09:43:59Z' });
  const original = raceTable.update.bind(raceTable);
  let firstCall = true;
  raceTable.update = async (key, fields) => {
    if (firstCall) {
      firstCall = false;
      // Simulate another request changing hashRunId between read and write.
      const existing = raceTable.items.get(raceTable.keyStr(key));
      raceTable.items.set(raceTable.keyStr(key), { ...existing, hashRunId: 'someone-elses-run' });
    }
    return original(key, fields);
  };
  const raceDeps = deps(raceTable, { hasher: { invoke: async () => {} } });
  const raceResult = await handleApplicationRetryHash(req(undefined, { params: { applicationId: 'app-7' } }), raceDeps);
  assert.equal(raceResult.statusCode, 409);
  assert.equal(raceResult.body.error, 'hash_in_progress');

  // And when hasher.invoke rejects the record is set to "failed" with "invoke_failed"
  const failTable = new FakeTable();
  await seedUrlApplication(failTable, 'app-8', { hashStatus: 'pending', hashError: null, hashRequestedAt: '2026-10-11T09:43:59Z' });
  const failDeps = deps(failTable, {
    hasher: { invoke: async () => { throw new Error('boom'); } },
    randomBytes: () => Buffer.from('2222222222222222', 'hex'),
  });
  const failResult = await handleApplicationRetryHash(req(undefined, { params: { applicationId: 'app-8' } }), failDeps);
  assert.equal(failResult.statusCode, 202);
  assert.equal(failResult.body.hashStatus, 'failed');
  assert.equal(failResult.body.hashError, 'invoke_failed');
});

test('Unit: HASH_OUTCOME_CONDITION is used for the create-time invoke_failed fallback', () => {
  // Documentation check: the constant the retry/create paths share with the hasher.
  assert.equal(HASH_OUTCOME_CONDITION, 'attribute_exists(pk) AND hashRunId = :runId');
});
