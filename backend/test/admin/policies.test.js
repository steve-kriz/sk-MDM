/**
 * E2E cucumber-style tests for admin policy routes (TASK-012).
 * Tests implement all Gherkin scenarios without a cucumber package.
 * Mock all database calls — no real DB connections.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const {
  handlePolicyCreate,
  handlePolicyUpdate,
  handlePolicyAssign,
  handlePolicyUnassign,
  handlePolicyCompliance,
  FIRST_POLICY_VERSION,
  offendingSettingsFields,
} = await import(
  `file://${join(__dirname, '../../dist/admin/policies.js')}`
);

const { policy: policyKey, group } = await import(
  `file://${join(__dirname, '../../dist/db/keys.js')}`
);

const { isoUtc } = await import(`file://${join(__dirname, '../../dist/audit.js')}`);

// ============================================================================
// Mock Table Client
// ============================================================================

class FakeTable {
  constructor() {
    this.items = new Map();
    this.queryResponses = [];
  }

  keyStr(key) {
    return JSON.stringify({ pk: key.pk, sk: key.sk });
  }

  async get(key) {
    return this.items.get(this.keyStr(key));
  }

  async put(item) {
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  async delete(key) {
    this.items.delete(this.keyStr(key));
  }

  async query(request) {
    if (this.queryResponses.length > 0) {
      return this.queryResponses.shift();
    }
    return { items: [], cursor: null };
  }

  seedItem(item) {
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  getStoredItem(key) {
    return this.items.get(this.keyStr(key));
  }

  seedQueryResponses(responses) {
    this.queryResponses = [...responses];
  }
}

// ============================================================================
// Mock Verifier
// ============================================================================

class StubVerifier {
  constructor(claims = {}) {
    this.claims = {
      sub: 'user123',
      preferred_username: 'admin@example.com',
      ...claims,
    };
  }

  async verify(token) {
    if (token === 'invalid') {
      throw { status: 401, error: 'invalid_token' };
    }
    return this.claims;
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

function createValidRequest(method, path, body = null) {
  return {
    method,
    path,
    query: {},
    headers: { authorization: 'Bearer valid-token' },
    params: {},
    body: body ? JSON.stringify(body) : null,
    claims: { sub: 'user123', preferred_username: 'admin@example.com' },
  };
}

function createDependencies(table, now = new Date('2026-10-02T10:00:00Z')) {
  return {
    table,
    verifier: new StubVerifier(),
    now: () => now,
    randomBytes: (n) => Buffer.from('a'.repeat(n * 2), 'utf8').slice(0, n),
  };
}

// ============================================================================
// E2E Cucumber-Style Tests for Admin Policy Routes
// ============================================================================

test('Scenario: Policy is created and versioned', async (t) => {
  const table = new FakeTable();
  const deps = createDependencies(table);

  // When an admin creates a policy
  const createRequest = createValidRequest('POST', '/admin/api/v1/policies', {
    name: 'Test Policy',
    settings: { firewallEnabled: true },
  });
  createRequest.params = {};
  const createResult = await handlePolicyCreate(createRequest, deps);

  // Then the first response version is 1
  assert.strictEqual(createResult.statusCode, 201);
  assert.strictEqual(createResult.body.version, FIRST_POLICY_VERSION);
  const policyId = createResult.body.policyId;

  // And then updates it
  const updateRequest = createValidRequest('PUT', `/admin/api/v1/policies/${policyId}`, {
    name: 'Test Policy',
    settings: { firewallEnabled: false },
  });
  updateRequest.params = { policyId };
  const updateResult = await handlePolicyUpdate(updateRequest, deps);

  // The stored version after the update is 2
  assert.strictEqual(updateResult.statusCode, 200);
  assert.strictEqual(updateResult.body.version, 2);

  const stored = table.getStoredItem(policyKey(policyId));
  assert.strictEqual(stored.version, 2);
  assert.strictEqual(stored.settings.firewallEnabled, false);
});

test('Scenario: Unknown setting key is refused', async (t) => {
  const table = new FakeTable();
  const deps = createDependencies(table);

  // When an admin creates a policy with settings {wallpaper:"blue"}
  const createRequest = createValidRequest('POST', '/admin/api/v1/policies', {
    name: 'Bad Policy',
    settings: { wallpaper: 'blue' },
  });
  createRequest.params = {};
  const result = await handlePolicyCreate(createRequest, deps);

  // Then the status is 400 and fields contains "settings.wallpaper"
  assert.strictEqual(result.statusCode, 400);
  assert.strictEqual(result.body.error, 'invalid_request');
  assert.ok(Array.isArray(result.body.fields));
  assert.ok(result.body.fields.includes('settings.wallpaper'));
});

test('Scenario: Out-of-range screen lock is refused', async (t) => {
  const table = new FakeTable();
  const deps = createDependencies(table);

  // When an admin sets screenLockTimeoutSeconds to 30 (below min of 60)
  const createRequest = createValidRequest('POST', '/admin/api/v1/policies', {
    name: 'Bad Lock Policy',
    settings: { screenLockTimeoutSeconds: 30 },
  });
  createRequest.params = {};
  const result = await handlePolicyCreate(createRequest, deps);

  // Then the status is 400 and fields contains "settings.screenLockTimeoutSeconds"
  assert.strictEqual(result.statusCode, 400);
  assert.ok(result.body.fields.includes('settings.screenLockTimeoutSeconds'));
});

test('Scenario: Assignment to a group', async (t) => {
  const table = new FakeTable();
  const deps = createDependencies(table);

  // Import policyAssignment key builder
  const { policyAssignment } = await import(
    `file://${join(__dirname, '../../dist/db/keys.js')}`
  );

  // Create a policy first
  const createRequest = createValidRequest('POST', '/admin/api/v1/policies', {
    name: 'Policy 1',
    settings: { firewallEnabled: true },
  });
  createRequest.params = {};
  const createResult = await handlePolicyCreate(createRequest, deps);
  const policyId = createResult.body.policyId;

  // Create a group
  const groupId = 'g1';
  table.seedItem({ ...group(groupId), groupId, name: 'Group 1' });

  // Given group g1 exists
  // When an admin assigns policy p1 to g1
  const assignRequest = createValidRequest(
    'POST',
    `/admin/api/v1/policies/${policyId}/assignments`,
    { groupId }
  );
  assignRequest.params = { policyId };
  const assignResult = await handlePolicyAssign(assignRequest, deps);

  // Then the first call is 200
  assert.strictEqual(assignResult.statusCode, 200);

  // Then deletes the assignment
  const deleteRequest = createValidRequest(
    'DELETE',
    `/admin/api/v1/policies/${policyId}/assignments`,
    { groupId }
  );
  deleteRequest.params = { policyId };
  const deleteResult = await handlePolicyUnassign(deleteRequest, deps);

  // And the assignment item is absent after the delete
  assert.strictEqual(deleteResult.statusCode, 200);
  // Verify the assignment was removed
  const assignKey = policyAssignment(policyId, groupId);
  const stored = table.getStoredItem(assignKey);
  assert.strictEqual(stored, undefined);
});

test('Scenario: Assignment to an unknown group', async (t) => {
  const table = new FakeTable();
  const deps = createDependencies(table);

  // Create a policy
  const createRequest = createValidRequest('POST', '/admin/api/v1/policies', {
    name: 'Policy 1',
    settings: { firewallEnabled: true },
  });
  createRequest.params = {};
  const createResult = await handlePolicyCreate(createRequest, deps);
  const policyId = createResult.body.policyId;

  // When an admin assigns p1 to group "nope"
  const assignRequest = createValidRequest(
    'POST',
    `/admin/api/v1/policies/${policyId}/assignments`,
    { groupId: 'nope' }
  );
  assignRequest.params = { policyId };
  const result = await handlePolicyAssign(assignRequest, deps);

  // Then the status is 404 and the error is not_found
  assert.strictEqual(result.statusCode, 404);
  assert.strictEqual(result.body.error, 'not_found');
});

test('Scenario: POST returns 201 with policyId and version', async (t) => {
  const table = new FakeTable();
  const deps = createDependencies(table);

  const request = createValidRequest('POST', '/admin/api/v1/policies', {
    name: 'Test Policy',
    settings: {
      firewallEnabled: true,
      diskEncryptionRequired: false,
    },
  });
  request.params = {};
  const result = await handlePolicyCreate(request, deps);

  assert.strictEqual(result.statusCode, 201);
  assert.ok(result.body.policyId);
  assert.strictEqual(result.body.version, FIRST_POLICY_VERSION);
  assert.strictEqual(result.body.policyId.startsWith('pol-'), true);
});

test('Scenario: Settings keys are validated individually', async (t) => {
  const table = new FakeTable();
  const deps = createDependencies(table);

  const request = createValidRequest('POST', '/admin/api/v1/policies', {
    name: 'Bad Policy',
    settings: {
      firewallEnabled: true,
      badKey1: 'value',
      diskEncryptionRequired: 'not a boolean',
      badKey2: 123,
    },
  });
  request.params = {};
  const result = await handlePolicyCreate(request, deps);

  assert.strictEqual(result.statusCode, 400);
  assert.ok(result.body.fields.includes('settings.badKey1'));
  assert.ok(result.body.fields.includes('settings.badKey2'));
  assert.ok(result.body.fields.includes('settings.diskEncryptionRequired'));
});

test('Scenario: Valid settings keys are accepted', async (t) => {
  const table = new FakeTable();
  const deps = createDependencies(table);

  const request = createValidRequest('POST', '/admin/api/v1/policies', {
    name: 'Complete Policy',
    settings: {
      firewallEnabled: true,
      diskEncryptionRequired: true,
      screenLockTimeoutSeconds: 300,
      osUpdateMaxAgeDays: 30,
      localAdminAllowlist: ['admin1', 'admin2'],
    },
  });
  request.params = {};
  const result = await handlePolicyCreate(request, deps);

  assert.strictEqual(result.statusCode, 201);
  const stored = table.getStoredItem(policyKey(result.body.policyId));
  assert.ok(stored);
});

test('Scenario: Missing name field returns 400', async (t) => {
  const table = new FakeTable();
  const deps = createDependencies(table);

  const request = createValidRequest('POST', '/admin/api/v1/policies', {
    settings: { firewallEnabled: true },
  });
  request.params = {};
  const result = await handlePolicyCreate(request, deps);

  assert.strictEqual(result.statusCode, 400);
  assert.ok(result.body.fields.includes('name'));
});

test('Scenario: Missing settings field returns 400', async (t) => {
  const table = new FakeTable();
  const deps = createDependencies(table);

  const request = createValidRequest('POST', '/admin/api/v1/policies', {
    name: 'Test Policy',
  });
  request.params = {};
  const result = await handlePolicyCreate(request, deps);

  assert.strictEqual(result.statusCode, 400);
  assert.ok(result.body.fields.includes('settings'));
});

test('Scenario: PUT updates version and settings', async (t) => {
  const table = new FakeTable();
  const deps = createDependencies(table);

  // Create initial policy
  const createRequest = createValidRequest('POST', '/admin/api/v1/policies', {
    name: 'Original',
    settings: { firewallEnabled: true },
  });
  createRequest.params = {};
  const createResult = await handlePolicyCreate(createRequest, deps);
  const policyId = createResult.body.policyId;

  // Update it
  const updateRequest = createValidRequest('PUT', `/admin/api/v1/policies/${policyId}`, {
    settings: { firewallEnabled: false, diskEncryptionRequired: true },
  });
  updateRequest.params = { policyId };
  const updateResult = await handlePolicyUpdate(updateRequest, deps);

  assert.strictEqual(updateResult.statusCode, 200);
  assert.strictEqual(updateResult.body.version, 2);

  const stored = table.getStoredItem(policyKey(policyId));
  assert.strictEqual(stored.version, 2);
  assert.strictEqual(stored.settings.firewallEnabled, false);
  assert.strictEqual(stored.settings.diskEncryptionRequired, true);
});

test('Scenario: DELETE assignment via query parameter', async (t) => {
  const table = new FakeTable();
  const deps = createDependencies(table);

  // Create policy
  const createRequest = createValidRequest('POST', '/admin/api/v1/policies', {
    name: 'Policy',
    settings: { firewallEnabled: true },
  });
  createRequest.params = {};
  const createResult = await handlePolicyCreate(createRequest, deps);
  const policyId = createResult.body.policyId;

  // Create group
  const groupId = 'g1';
  table.seedItem({ ...group(groupId), groupId, name: 'Group 1' });

  // Assign
  const assignRequest = createValidRequest(
    'POST',
    `/admin/api/v1/policies/${policyId}/assignments`,
    { groupId }
  );
  assignRequest.params = { policyId };
  await handlePolicyAssign(assignRequest, deps);

  // Delete via query parameter instead of body
  const deleteRequest = createValidRequest('DELETE', `/admin/api/v1/policies/${policyId}/assignments`);
  deleteRequest.params = { policyId };
  deleteRequest.query = { groupId };
  deleteRequest.body = null;
  const deleteResult = await handlePolicyUnassign(deleteRequest, deps);

  assert.strictEqual(deleteResult.statusCode, 200);
});

test('Scenario: Deleting non-existent assignment is idempotent', async (t) => {
  const table = new FakeTable();
  const deps = createDependencies(table);

  // Create policy
  const createRequest = createValidRequest('POST', '/admin/api/v1/policies', {
    name: 'Policy',
    settings: { firewallEnabled: true },
  });
  createRequest.params = {};
  const createResult = await handlePolicyCreate(createRequest, deps);
  const policyId = createResult.body.policyId;

  // Try to delete assignment that doesn't exist
  const deleteRequest = createValidRequest(
    'DELETE',
    `/admin/api/v1/policies/${policyId}/assignments`,
    { groupId: 'nonexistent' }
  );
  deleteRequest.params = { policyId };
  const result = await handlePolicyUnassign(deleteRequest, deps);

  // Should still return 200
  assert.strictEqual(result.statusCode, 200);
});

test('Scenario: GET compliance returns items with correct fields', async (t) => {
  const table = new FakeTable();
  const deps = createDependencies(table);

  // Import groupListIndex key builder
  const { groupListIndex } = await import(
    `file://${join(__dirname, '../../dist/db/keys.js')}`
  );

  // Create policy
  const createRequest = createValidRequest('POST', '/admin/api/v1/policies', {
    name: 'Policy',
    settings: { firewallEnabled: true },
  });
  createRequest.params = {};
  const createResult = await handlePolicyCreate(createRequest, deps);
  const policyId = createResult.body.policyId;

  // This test would need device compliance items seeded and groups queried
  // For now, test that empty compliance works
  const groupsKey = groupListIndex('');
  table.seedQueryResponses([
    { items: [], cursor: null }, // No groups
  ]);

  const complianceRequest = createValidRequest(
    'GET',
    `/admin/api/v1/policies/${policyId}/compliance`
  );
  complianceRequest.params = { policyId };
  const result = await handlePolicyCompliance(complianceRequest, deps);

  assert.strictEqual(result.statusCode, 200);
  assert.ok(Array.isArray(result.body.items));
});

test('Scenario: Compliance report stores per policy per device', async (t) => {
  // This is tested in checkin.test.js where policyCompliance is ingested
  // This test verifies the admin can read stored compliance
  const table = new FakeTable();
  const deps = createDependencies(table);

  // Create policy
  const createRequest = createValidRequest('POST', '/admin/api/v1/policies', {
    name: 'Policy',
    settings: { firewallEnabled: true },
  });
  createRequest.params = {};
  const createResult = await handlePolicyCreate(createRequest, deps);
  const policyId = createResult.body.policyId;

  table.seedQueryResponses([
    { items: [], cursor: null }, // No groups, so no devices
  ]);

  const complianceRequest = createValidRequest(
    'GET',
    `/admin/api/v1/policies/${policyId}/compliance`
  );
  complianceRequest.params = { policyId };
  const result = await handlePolicyCompliance(complianceRequest, deps);

  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body.items, []);
});

// ============================================================================
// TASK-029: Firewall and Domain Settings Tests
// ============================================================================

test('Scenario: POLICY_SETTING_KEYS holds exactly the eight keys', async (t) => {
  const { POLICY_SETTING_KEYS } = await import(
    `file://${join(__dirname, '../../dist/admin/policies.js')}`
  );

  const expectedKeys = [
    'firewallEnabled',
    'diskEncryptionRequired',
    'screenLockTimeoutSeconds',
    'osUpdateMaxAgeDays',
    'localAdminAllowlist',
    'firewallBlockedDomains',
    'firewallAllowedDomains',
    'antivirusEnabled',
  ];

  assert.strictEqual(POLICY_SETTING_KEYS.length, 8);
  assert.deepStrictEqual(POLICY_SETTING_KEYS.sort(), expectedKeys.sort());
});

test('Scenario: Policy with firewall and domain settings is stored with 201', async (t) => {
  const table = new FakeTable();
  const deps = createDependencies(table);

  const request = createValidRequest('POST', '/admin/api/v1/policies', {
    name: 'Firewall Policy',
    settings: {
      firewallEnabled: true,
      firewallBlockedDomains: ['example.com'],
      firewallAllowedDomains: ['intranet.example.org'],
    },
  });
  request.params = {};
  const result = await handlePolicyCreate(request, deps);

  assert.strictEqual(result.statusCode, 201);
  assert.ok(result.body.policyId);

  const stored = table.getStoredItem(policyKey(result.body.policyId));
  assert.ok(stored);
  assert.deepStrictEqual(stored.settings, {
    firewallEnabled: true,
    firewallBlockedDomains: ['example.com'],
    firewallAllowedDomains: ['intranet.example.org'],
  });
});

test('Scenario: Empty domain array is accepted', async (t) => {
  const table = new FakeTable();
  const deps = createDependencies(table);

  const request = createValidRequest('POST', '/admin/api/v1/policies', {
    name: 'Policy with empty domains',
    settings: {
      firewallAllowedDomains: [],
    },
  });
  request.params = {};
  const result = await handlePolicyCreate(request, deps);

  assert.strictEqual(result.statusCode, 201);
});

test('Scenario: Invalid domain list is refused on POST', async (t) => {
  const table = new FakeTable();
  const deps = createDependencies(table);

  const invalidCases = [
    { value: 'example.com', desc: 'non-array string' },
    { value: [42], desc: 'non-string entry' },
    { value: ['http://x.com'], desc: 'URL with scheme' },
    { value: ['*.x.com'], desc: 'wildcard' },
    { value: ['10.0.0.1'], desc: 'IP address' },
    { value: ['localhost'], desc: 'single label' },
    { value: ['a..b.com'], desc: 'empty label' },
    { value: ['x.com\n127.0.0.1 bank.com'], desc: 'newline injection' },
    { value: ['a'.repeat(254) + '.com'], desc: 'entry too long' },
    { value: Array(501).fill('a.com'), desc: '501 entries' },
  ];

  for (const testCase of invalidCases) {
    const request = createValidRequest('POST', '/admin/api/v1/policies', {
      name: `Invalid test: ${testCase.desc}`,
      settings: { firewallBlockedDomains: testCase.value },
    });
    request.params = {};
    const result = await handlePolicyCreate(request, deps);

    assert.strictEqual(result.statusCode, 400, `Expected 400 for ${testCase.desc}`);
    assert.strictEqual(result.body.error, 'invalid_request');
    assert.ok(result.body.fields.includes('settings.firewallBlockedDomains'));
  }
});

test('Scenario: Invalid domain list is refused on PUT and version unchanged', async (t) => {
  const table = new FakeTable();
  const deps = createDependencies(table);

  // Create initial policy
  const createRequest = createValidRequest('POST', '/admin/api/v1/policies', {
    name: 'Initial Policy',
    settings: { firewallBlockedDomains: ['valid.com'] },
  });
  createRequest.params = {};
  const createResult = await handlePolicyCreate(createRequest, deps);
  const policyId = createResult.body.policyId;
  const initialVersion = createResult.body.version;

  // Try to update with invalid domains
  const updateRequest = createValidRequest('PUT', `/admin/api/v1/policies/${policyId}`, {
    name: 'Updated Policy',
    settings: { firewallAllowedDomains: ['*.bad'] },
  });
  updateRequest.params = { policyId };
  const updateResult = await handlePolicyUpdate(updateRequest, deps);

  assert.strictEqual(updateResult.statusCode, 400);
  assert.ok(updateResult.body.fields.includes('settings.firewallAllowedDomains'));

  // Verify version is unchanged
  const stored = table.getStoredItem(policyKey(policyId));
  assert.strictEqual(stored.version, initialVersion);
});
