/**
 * E2E tests for command settings routes (TASK-045, OF1-OF2).
 * Tests implement Gherkin scenarios without a cucumber package.
 * Mock all database calls — no real DB connections.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

const {
  handleCommandSettingsGet,
  handleCommandSettingsPut,
  readCommandSettings,
  DEFAULT_ON_FAILURE,
  COMMAND_SETTINGS_UPDATED_ACTION,
} = await import('../../dist/admin/commandSettings.js');

const { commandSettings } = await import('../../dist/db/keys.js');

// ============================================================================
// Mock Table Client
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
    const key = { pk: item.pk, sk: item.sk };
    if (item.action) {
      this.auditItems.push(item);
    }
    this.items.set(this.keyStr(key), { ...item });
  }

  getStoredItem(key) {
    return this.items.get(this.keyStr(key));
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

function createFakeDeps(table, actor = 'admin@officehq.com.au', now = new Date('2026-10-11T10:00:00Z')) {
  return {
    table,
    now: () => now,
  };
}

function createRequest(body = {}, actor = 'admin@officehq.com.au') {
  return {
    body: body ? JSON.stringify(body) : null,
    params: {},
    claims: {
      sub: 'user123',
      preferred_username: actor,
    },
    query: {},
  };
}

// ============================================================================
// OF1: Setting defaults to continue
// ============================================================================

test('OF1: GET /settings/commands returns continue when no item exists', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  const req = createRequest({});

  const result = await handleCommandSettingsGet(req, deps);

  assert.equal(result.statusCode, 200);
  assert.equal(result.body.onFailure, 'continue');
});

test('OF1: GET returns stored setting after PUT', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);

  // First, PUT the setting
  let req = createRequest({ onFailure: 'stop' });
  let result = await handleCommandSettingsPut(req, deps);
  assert.equal(result.statusCode, 200);
  assert.equal(result.body.onFailure, 'stop');

  // Then, GET should return the stored setting
  req = createRequest({});
  result = await handleCommandSettingsGet(req, deps);
  assert.equal(result.statusCode, 200);
  assert.equal(result.body.onFailure, 'stop');
});

// ============================================================================
// OF2: Saving the setting
// ============================================================================

test('OF2: PUT with onFailure stop returns 200 and stores it', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  const req = createRequest({ onFailure: 'stop' });

  const result = await handleCommandSettingsPut(req, deps);

  assert.equal(result.statusCode, 200);
  assert.equal(result.body.onFailure, 'stop');

  const key = commandSettings();
  const stored = table.getStoredItem(key);
  assert(stored);
  assert.equal(stored.onFailure, 'stop');
});

test('OF2: PUT with onFailure continue returns 200 and stores it', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  const req = createRequest({ onFailure: 'continue' });

  const result = await handleCommandSettingsPut(req, deps);

  assert.equal(result.statusCode, 200);
  assert.equal(result.body.onFailure, 'continue');

  const key = commandSettings();
  const stored = table.getStoredItem(key);
  assert(stored);
  assert.equal(stored.onFailure, 'continue');
});

test('OF2: PUT creates audit entry when saving setting', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  const req = createRequest({ onFailure: 'stop' });

  const result = await handleCommandSettingsPut(req, deps);

  assert.equal(result.statusCode, 200);
  const audit = table.auditItems.find((item) => item.action === COMMAND_SETTINGS_UPDATED_ACTION);
  assert(audit);
  assert.equal(audit.detail.onFailure, 'stop');
});

test('OF2: PUT with invalid value returns 400 and stores nothing', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  const req = createRequest({ onFailure: 'halt' });

  const result = await handleCommandSettingsPut(req, deps);

  assert.equal(result.statusCode, 400);
  assert.equal(result.body.error, 'invalid_request');

  const key = commandSettings();
  const stored = table.getStoredItem(key);
  assert(!stored);
});

test('OF2: PUT with missing onFailure returns 400', async () => {
  const table = new FakeTable();
  const deps = createFakeDeps(table);
  const req = createRequest({});

  const result = await handleCommandSettingsPut(req, deps);

  assert.equal(result.statusCode, 400);
  assert.equal(result.body.error, 'invalid_request');

  const key = commandSettings();
  const stored = table.getStoredItem(key);
  assert(!stored);
});

// ============================================================================
// readCommandSettings helper
// ============================================================================

test('readCommandSettings: Returns default when item absent', async () => {
  const table = new FakeTable();

  const result = await readCommandSettings(table);

  assert.equal(result.onFailure, 'continue');
});

test('readCommandSettings: Returns stored value when present', async () => {
  const table = new FakeTable();
  const key = commandSettings();
  await table.put({ ...key, onFailure: 'stop' });

  const result = await readCommandSettings(table);

  assert.equal(result.onFailure, 'stop');
});
