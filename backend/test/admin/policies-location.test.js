/**
 * E2E cucumber-style tests for TASK-056: the `locationTracking` policy
 * setting (`src/admin/policies.ts`). Mocks the table with a simple in-memory
 * fake; no real database connection is ever opened.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { handlePolicyCreate, handlePolicyUpdate, POLICY_SETTING_KEYS, offendingSettingsFields } = await import(
  `file://${join(__dirname, '../../dist/admin/policies.js')}`
);
const { policy: policyKey } = await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);

class FakeTable {
  constructor() {
    this.items = new Map();
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
  async query() {
    return { items: [], cursor: null };
  }
  getStoredItem(key) {
    return this.items.get(this.keyStr(key));
  }
}

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

function createDependencies(table, now = new Date('2026-10-11T10:00:00Z')) {
  return {
    table,
    verifier: { verify: async () => ({ sub: 'user123', preferred_username: 'admin@example.com' }) },
    now: () => now,
    randomBytes: (n) => Buffer.from('a'.repeat(n * 2), 'utf8').slice(0, n),
  };
}

// ============================================================================
// Scenario: Policy accepts a boolean locationTracking
// ============================================================================

test('Scenario: Policy accepts a boolean locationTracking', async () => {
  const table = new FakeTable();
  const deps = createDependencies(table);

  const request = createValidRequest('POST', '/admin/api/v1/policies', {
    name: 'Tracking policy',
    settings: { locationTracking: true },
  });
  request.params = {};
  const result = await handlePolicyCreate(request, deps);

  assert.strictEqual(result.statusCode, 201);
  const stored = table.getStoredItem(policyKey(result.body.policyId));
  assert.deepStrictEqual(stored.settings, { locationTracking: true });
});

test('Scenario: Policy accepts locationTracking false', async () => {
  const table = new FakeTable();
  const deps = createDependencies(table);

  const request = createValidRequest('POST', '/admin/api/v1/policies', {
    name: 'Tracking policy',
    settings: { locationTracking: false },
  });
  request.params = {};
  const result = await handlePolicyCreate(request, deps);

  assert.strictEqual(result.statusCode, 201);
  const stored = table.getStoredItem(policyKey(result.body.policyId));
  assert.deepStrictEqual(stored.settings, { locationTracking: false });
});

// ============================================================================
// Scenario Outline: Policy rejects a non-boolean locationTracking
// ============================================================================

const nonBooleanCases = [
  { label: '"true" (string)', value: 'true' },
  { label: '1 (number)', value: 1 },
];

for (const { label, value } of nonBooleanCases) {
  test(`Scenario Outline: Policy rejects a non-boolean locationTracking - ${label}`, async () => {
    const table = new FakeTable();
    const deps = createDependencies(table);

    const request = createValidRequest('POST', '/admin/api/v1/policies', {
      name: 'Bad policy',
      settings: { locationTracking: value },
    });
    request.params = {};
    const result = await handlePolicyCreate(request, deps);

    assert.strictEqual(result.statusCode, 400);
    assert.strictEqual(result.body.error, 'invalid_request');
    assert.ok(result.body.fields.includes('settings.locationTracking'));
    assert.strictEqual(table.items.size, 0, 'no policy should be stored');
  });

  test(`Scenario Outline: Policy update rejects a non-boolean locationTracking - ${label}`, async () => {
    const table = new FakeTable();
    const deps = createDependencies(table);

    const createRequest = createValidRequest('POST', '/admin/api/v1/policies', {
      name: 'Good policy',
      settings: { locationTracking: true },
    });
    createRequest.params = {};
    const created = await handlePolicyCreate(createRequest, deps);
    assert.strictEqual(created.statusCode, 201);
    const policyId = created.body.policyId;
    const beforeUpdate = table.getStoredItem(policyKey(policyId));

    const updateRequest = createValidRequest('PUT', `/admin/api/v1/policies/${policyId}`, {
      settings: { locationTracking: value },
    });
    updateRequest.params = { policyId };
    const result = await handlePolicyUpdate(updateRequest, deps);

    assert.strictEqual(result.statusCode, 400);
    assert.strictEqual(result.body.error, 'invalid_request');
    assert.ok(result.body.fields.includes('settings.locationTracking'));
    // The stored policy is untouched by the rejected update.
    assert.deepStrictEqual(table.getStoredItem(policyKey(policyId)), beforeUpdate);
  });
}

// ============================================================================
// Unit: POLICY_SETTING_KEYS / offendingSettingsFields
// ============================================================================

test('Unit: POLICY_SETTING_KEYS contains locationTracking', () => {
  assert.ok(POLICY_SETTING_KEYS.includes('locationTracking'));
});

test('Unit: offendingSettingsFields accepts true and false for locationTracking', () => {
  assert.deepStrictEqual(offendingSettingsFields({ locationTracking: true }), []);
  assert.deepStrictEqual(offendingSettingsFields({ locationTracking: false }), []);
});

test('Unit: offendingSettingsFields names settings.locationTracking for a non-boolean', () => {
  assert.deepStrictEqual(offendingSettingsFields({ locationTracking: 'true' }), ['settings.locationTracking']);
  assert.deepStrictEqual(offendingSettingsFields({ locationTracking: 1 }), ['settings.locationTracking']);
});
