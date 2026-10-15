/**
 * E2E cucumber-style tests for TASK-060, the six Defender protection policy
 * keys in backend/src/admin/policies.ts (AC1, AC2). Tests implement the
 * ticket's Gherkin scenarios without a cucumber package. Mock all database
 * calls -- no real DB connections.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { handlePolicyCreate, handlePolicyUpdate, POLICY_SETTING_KEYS } = await import(
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

test('Scenario: Backend accepts the six Defender keys', async (t) => {
  const table = new FakeTable();
  const deps = createDependencies(table);

  // When the admin creates a policy with the five boolean keys true and
  // defenderRansomwareProtection "block"
  const createRequest = createValidRequest('POST', '/admin/api/v1/policies', {
    name: 'Defender Policy',
    settings: {
      defenderRealTimeProtection: true,
      defenderCloudProtection: true,
      defenderNetworkProtection: true,
      defenderReputationProtection: true,
      defenderDailySignatureUpdate: true,
      defenderRansomwareProtection: 'block',
    },
  });
  createRequest.params = {};
  const createResult = await handlePolicyCreate(createRequest, deps);

  // Then the response status is 201
  assert.strictEqual(createResult.statusCode, 201);
  // And POLICY_SETTING_KEYS has 16 entries
  assert.strictEqual(POLICY_SETTING_KEYS.length, 16);
  const policyId = createResult.body.policyId;

  // When the admin updates it with defenderRansomwareProtection "audit"
  const updateRequest = createValidRequest('PUT', `/admin/api/v1/policies/${policyId}`, {
    name: 'Defender Policy',
    settings: {
      defenderRealTimeProtection: true,
      defenderCloudProtection: true,
      defenderNetworkProtection: true,
      defenderReputationProtection: true,
      defenderDailySignatureUpdate: true,
      defenderRansomwareProtection: 'audit',
    },
  });
  updateRequest.params = { policyId };
  const updateResult = await handlePolicyUpdate(updateRequest, deps);

  // Then the response status is 200
  assert.strictEqual(updateResult.statusCode, 200);
  const stored = table.getStoredItem(policyKey(policyId));
  assert.strictEqual(stored.settings.defenderRansomwareProtection, 'audit');
});

test('Scenario Outline: Backend refuses an invalid Defender value', async (t) => {
  const cases = [
    { key: 'defenderRealTimeProtection', value: 'true' },
    { key: 'defenderCloudProtection', value: 1 },
    { key: 'defenderRansomwareProtection', value: 'off' },
    { key: 'defenderRansomwareProtection', value: 'Block' },
    { key: 'defenderRansomwareProtection', value: true },
  ];

  for (const { key, value } of cases) {
    await t.test(`${key} = ${JSON.stringify(value)}`, async () => {
      const table = new FakeTable();
      const deps = createDependencies(table);

      const request = createValidRequest('POST', '/admin/api/v1/policies', {
        name: 'Bad Policy',
        settings: { [key]: value },
      });
      request.params = {};
      const result = await handlePolicyCreate(request, deps);

      // Then the response status is 400 with error "invalid_request"
      assert.strictEqual(result.statusCode, 400, `${key}=${JSON.stringify(value)} should be refused`);
      assert.strictEqual(result.body.error, 'invalid_request');
      // And fields contains "settings.<key>"
      assert.ok(
        result.body.fields.includes(`settings.${key}`),
        `fields should contain settings.${key}, got ${JSON.stringify(result.body.fields)}`,
      );
    });
  }
});

test('Scenario (edge): A valid audit value alongside an invalid boolean is refused together', async (t) => {
  // Given a body mixing one valid Defender key with one invalid one
  const table = new FakeTable();
  const deps = createDependencies(table);

  const request = createValidRequest('POST', '/admin/api/v1/policies', {
    name: 'Mixed Policy',
    settings: { defenderRansomwareProtection: 'audit', defenderCloudProtection: 'yes' },
  });
  request.params = {};
  const result = await handlePolicyCreate(request, deps);

  // Then only the invalid key is named, and the request is refused as a whole
  assert.strictEqual(result.statusCode, 400);
  assert.deepStrictEqual(result.body.fields, ['settings.defenderCloudProtection']);
});
