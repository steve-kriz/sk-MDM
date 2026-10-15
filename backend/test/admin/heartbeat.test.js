/**
 * E2E cucumber-style tests for TASK-044: the per-device heartbeat admin API
 * (`backend/src/admin/heartbeat.ts`).
 *
 *   POST /admin/api/v1/devices/{deviceId}/heartbeat
 *   GET  /admin/api/v1/devices/{deviceId}/heartbeats
 *
 * All database calls are mocked; the CloudWatch heartbeat log is an
 * in-process fake. No real DB or network connection is ever opened.
 */

import test from 'node:test';
import assert from 'node:assert';
import { createRouter } from '../../dist/index.js';
import {
  HEARTBEAT_SETTING_PATH,
  HEARTBEAT_HISTORY_PATH,
  HEARTBEAT_CHANGED_ACTION,
  HEARTBEAT_HISTORY_LIMIT,
  handleHeartbeatSet,
  handleHeartbeatHistory,
  registerHeartbeatAdminRoutes,
} from '../../dist/admin/heartbeat.js';
import { deviceProfile, deviceHeartbeatSettings, deviceSettings } from '../../dist/db/keys.js';

// ============================================================================
// Fakes
// ============================================================================

class FakeTable {
  constructor() {
    this.items = new Map();
    this.getCalls = [];
    this.putCalls = [];
  }

  keyStr(key) {
    return JSON.stringify({ pk: key.pk, sk: key.sk });
  }

  async get(key) {
    this.getCalls.push(key);
    return this.items.get(this.keyStr(key));
  }

  async put(item) {
    this.putCalls.push(item);
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  async query() {
    return { items: [], cursor: null };
  }

  seedItem(item) {
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  getStoredItem(key) {
    return this.items.get(this.keyStr(key));
  }

  getAllItems() {
    return Array.from(this.items.values());
  }
}

class StubVerifier {
  constructor(acceptToken) {
    this.acceptToken = acceptToken;
  }

  async verify(token) {
    if (token === this.acceptToken) {
      return { sub: 'admin@officehq.com.au', preferred_username: 'admin@officehq.com.au', roles: ['MDM.Administrator'] };
    }
    if (token === 'not-admin') {
      throw { status: 403, error: 'not_admin' };
    }
    throw { status: 401, error: 'unauthorized' };
  }
}

/** A heartbeat log fake recording every call; answers are scripted per test. */
function fakeHeartbeatLog({ readResult = [], readError = null } = {}) {
  const writeCalls = [];
  const readCalls = [];
  return {
    writeCalls,
    readCalls,
    async write(deviceId, event) {
      writeCalls.push({ deviceId, event });
    },
    async read(deviceId, limit) {
      readCalls.push({ deviceId, limit });
      if (readError !== null) {
        throw readError;
      }
      return readResult;
    },
  };
}

async function makeRequest(router, method, path, options = {}) {
  const { headers = {}, body = null } = options;
  return router.handle({ method, path, headers, body });
}

const NOW = () => new Date('2026-10-11T12:00:00Z');

function seedDevice(table, deviceId = 'd1') {
  table.seedItem({ ...deviceProfile(deviceId), deviceId, hostname: 'host-d1' });
}

// ============================================================================
// Module shape
// ============================================================================

test('Scenario: Module exports the expected constants and handlers', () => {
  assert.strictEqual(HEARTBEAT_SETTING_PATH, '/devices/{deviceId}/heartbeat');
  assert.strictEqual(HEARTBEAT_HISTORY_PATH, '/devices/{deviceId}/heartbeats');
  assert.strictEqual(HEARTBEAT_CHANGED_ACTION, 'device.heartbeat.changed');
  assert.strictEqual(HEARTBEAT_HISTORY_LIMIT, 100);
  assert.strictEqual(typeof handleHeartbeatSet, 'function');
  assert.strictEqual(typeof handleHeartbeatHistory, 'function');
});

// ============================================================================
// Scenario Outline: Unauthenticated or non-admin callers are refused on both
// admin routes (AC12)
// ============================================================================

test('Scenario Outline: Unauthenticated or non-admin callers are refused on both admin routes', async () => {
  const cases = [
    { method: 'POST', path: '/admin/api/v1/devices/d1/heartbeat', headers: {}, status: 401, error: 'unauthorized' },
    {
      method: 'POST',
      path: '/admin/api/v1/devices/d1/heartbeat',
      headers: { authorization: 'Bearer not-admin' },
      status: 403,
      error: 'not_admin',
    },
    { method: 'GET', path: '/admin/api/v1/devices/d1/heartbeats', headers: {}, status: 401, error: 'unauthorized' },
    {
      method: 'GET',
      path: '/admin/api/v1/devices/d1/heartbeats',
      headers: { authorization: 'Bearer not-admin' },
      status: 403,
      error: 'not_admin',
    },
  ];

  for (const tc of cases) {
    const router = createRouter();
    const table = new FakeTable();
    const heartbeatLog = fakeHeartbeatLog();
    seedDevice(table);
    registerHeartbeatAdminRoutes(router, { verifier: new StubVerifier('good'), table, now: NOW, heartbeatLog });

    const response = await makeRequest(router, tc.method, tc.path, {
      headers: tc.headers,
      body: tc.method === 'POST' ? JSON.stringify({ enabled: true, intervalSeconds: 300 }) : null,
    });

    assert.strictEqual(response.statusCode, tc.status, `${tc.method} ${tc.path} with ${JSON.stringify(tc.headers)}`);
    const body = JSON.parse(response.body);
    assert.strictEqual(body.error, tc.error);
    assert.strictEqual(table.getCalls.length, 0, 'no table get issued');
    assert.strictEqual(table.putCalls.length, 0, 'no table put issued');
    assert.strictEqual(heartbeatLog.readCalls.length, 0, 'heartbeat log not called');
    assert.strictEqual(heartbeatLog.writeCalls.length, 0, 'heartbeat log not called');
  }
});

test('Scenario: The application router serves the admin heartbeat routes with 401, not 404', async () => {
  const { router } = await import('../../dist/index.js');
  const postResponse = await router.handle({
    method: 'POST',
    path: '/admin/api/v1/devices/d1/heartbeat',
    headers: {},
    body: JSON.stringify({ enabled: true, intervalSeconds: 300 }),
  });
  const getResponse = await router.handle({
    method: 'GET',
    path: '/admin/api/v1/devices/d1/heartbeats',
    headers: {},
    body: null,
  });
  assert.strictEqual(postResponse.statusCode, 401);
  assert.strictEqual(getResponse.statusCode, 401);
});

// ============================================================================
// Scenario Outline: Invalid heartbeat setting bodies are refused (AC13)
// ============================================================================

test('Scenario Outline: Invalid heartbeat setting bodies are refused', async () => {
  const cases = [
    { body: undefined, fields: ['enabled', 'intervalSeconds'] },
    { body: 'not json', fields: ['enabled', 'intervalSeconds'] },
    { body: JSON.stringify([]), fields: ['enabled', 'intervalSeconds'] },
    { body: JSON.stringify({ enabled: 'true', intervalSeconds: 300 }), fields: ['enabled'] },
    { body: JSON.stringify({ enabled: 1, intervalSeconds: 300 }), fields: ['enabled'] },
    { body: JSON.stringify({ intervalSeconds: 300 }), fields: ['enabled'] },
    { body: JSON.stringify({ enabled: true, intervalSeconds: 120 }), fields: ['intervalSeconds'] },
    { body: JSON.stringify({ enabled: true, intervalSeconds: 0 }), fields: ['intervalSeconds'] },
    { body: JSON.stringify({ enabled: true, intervalSeconds: '300' }), fields: ['intervalSeconds'] },
    { body: JSON.stringify({ enabled: true, intervalSeconds: 300.5 }), fields: ['intervalSeconds'] },
    { body: JSON.stringify({ enabled: true }), fields: ['intervalSeconds'] },
    { body: JSON.stringify({ enabled: null, intervalSeconds: null }), fields: ['enabled', 'intervalSeconds'] },
  ];

  for (const tc of cases) {
    const router = createRouter();
    const table = new FakeTable();
    seedDevice(table);
    registerHeartbeatAdminRoutes(router, { verifier: new StubVerifier('good'), table, now: NOW });

    const response = await makeRequest(router, 'POST', '/admin/api/v1/devices/d1/heartbeat', {
      headers: { authorization: 'Bearer good' },
      body: tc.body,
    });

    assert.strictEqual(response.statusCode, 400, `body ${tc.body}`);
    const body = JSON.parse(response.body);
    assert.strictEqual(body.error, 'invalid_request');
    assert.deepStrictEqual(body.fields, tc.fields, `body ${tc.body}`);
    assert.strictEqual(table.putCalls.length, 0, `no put for body ${tc.body}`);
  }
});

// ============================================================================
// Scenario Outline: Unknown or malformed devices are not found (AC14)
// ============================================================================

test('Scenario Outline: Unknown or malformed devices are not found on both admin routes', async () => {
  const cases = [
    { method: 'POST', id: 'missing', sub: 'heartbeat' },
    { method: 'POST', id: 'bad#id', sub: 'heartbeat' },
    { method: 'GET', id: 'missing', sub: 'heartbeats' },
    { method: 'GET', id: 'bad#id', sub: 'heartbeats' },
  ];

  for (const tc of cases) {
    const router = createRouter();
    const table = new FakeTable();
    const heartbeatLog = fakeHeartbeatLog();
    seedDevice(table, 'd1');
    registerHeartbeatAdminRoutes(router, { verifier: new StubVerifier('good'), table, now: NOW, heartbeatLog });

    const response = await makeRequest(router, tc.method, `/admin/api/v1/devices/${tc.id}/${tc.sub}`, {
      headers: { authorization: 'Bearer good' },
      body: tc.method === 'POST' ? JSON.stringify({ enabled: true, intervalSeconds: 300 }) : null,
    });

    assert.strictEqual(response.statusCode, 404, `${tc.method} ${tc.id}/${tc.sub}`);
    assert.strictEqual(JSON.parse(response.body).error, 'not_found');
    assert.strictEqual(table.putCalls.length, 0);
    assert.strictEqual(heartbeatLog.readCalls.length, 0, 'heartbeat log read not called');
  }
});

// ============================================================================
// Scenario Outline: Admin sets the heartbeat (AC15)
// ============================================================================

test('Scenario Outline: Admin sets the heartbeat', async () => {
  const cases = [
    { enabled: true, interval: 900 },
    { enabled: false, interval: 300 },
  ];

  for (const tc of cases) {
    const router = createRouter();
    const table = new FakeTable();
    seedDevice(table);
    registerHeartbeatAdminRoutes(router, { verifier: new StubVerifier('good'), table, now: NOW });

    const response = await makeRequest(router, 'POST', '/admin/api/v1/devices/d1/heartbeat', {
      headers: { authorization: 'Bearer good' },
      body: JSON.stringify({ enabled: tc.enabled, intervalSeconds: tc.interval }),
    });

    assert.strictEqual(response.statusCode, 200);
    const body = JSON.parse(response.body);
    assert.deepStrictEqual(Object.keys(body).sort(), ['deviceId', 'heartbeatEnabled', 'intervalSeconds', 'updatedAt', 'updatedBy'].sort());

    const stored = table.getStoredItem(deviceHeartbeatSettings('d1'));
    assert.deepStrictEqual(stored, {
      pk: 'DEVICE#d1',
      sk: 'HEARTBEAT',
      deviceId: 'd1',
      heartbeatEnabled: tc.enabled,
      intervalSeconds: tc.interval,
      updatedAt: '2026-10-11T12:00:00Z',
      updatedBy: 'admin@officehq.com.au',
    });

    const settingsPuts = table.putCalls.filter((item) => item.sk === 'SETTINGS');
    assert.strictEqual(settingsPuts.length, 0, 'no put targets sk SETTINGS');
  }
});

// ============================================================================
// Scenario: Every heartbeat change is audited, repeats included (AC16)
// ============================================================================

test('Scenario: Every heartbeat change is audited, repeats included', async () => {
  const router = createRouter();
  const table = new FakeTable();
  seedDevice(table);
  registerHeartbeatAdminRoutes(router, { verifier: new StubVerifier('good'), table, now: NOW });

  for (let i = 0; i < 2; i += 1) {
    const response = await makeRequest(router, 'POST', '/admin/api/v1/devices/d1/heartbeat', {
      headers: { authorization: 'Bearer good' },
      body: JSON.stringify({ enabled: true, intervalSeconds: 60 }),
    });
    assert.strictEqual(response.statusCode, 200);
  }

  const auditItems = table.getAllItems().filter((item) => item.action === HEARTBEAT_CHANGED_ACTION);
  assert.strictEqual(auditItems.length, 2);
  for (const item of auditItems) {
    assert.strictEqual(item.actor, 'admin@officehq.com.au');
    assert.strictEqual(item.target, 'd1');
    assert.deepStrictEqual(item.detail, { enabled: true, intervalSeconds: 60 });
  }
});

// ============================================================================
// Scenario: History returns what CloudWatch holds, newest first (AC17)
// ============================================================================

test('Scenario: History returns what CloudWatch holds, newest first', async () => {
  const router = createRouter();
  const table = new FakeTable();
  seedDevice(table);
  const items = [
    { deviceId: 'd1', receivedAt: '2026-10-11T12:00:00Z' },
    { deviceId: 'd1', receivedAt: '2026-10-11T11:55:00Z' },
  ];
  const heartbeatLog = fakeHeartbeatLog({ readResult: items });
  registerHeartbeatAdminRoutes(router, { verifier: new StubVerifier('good'), table, now: NOW, heartbeatLog });

  const response = await makeRequest(router, 'GET', '/admin/api/v1/devices/d1/heartbeats', {
    headers: { authorization: 'Bearer good' },
  });

  assert.strictEqual(response.statusCode, 200);
  assert.strictEqual(heartbeatLog.readCalls.length, 1);
  assert.deepStrictEqual(heartbeatLog.readCalls[0], { deviceId: 'd1', limit: 100 });

  const body = JSON.parse(response.body);
  assert.deepStrictEqual(Object.keys(body).sort(), ['deviceId', 'items']);
  assert.deepStrictEqual(body.items, items);
});

// ============================================================================
// Scenario Outline: History when CloudWatch is unusable (AC18)
// ============================================================================

test('Scenario Outline: History when CloudWatch is unusable', async () => {
  const noLog = {
    router: createRouter(),
    table: new FakeTable(),
    heartbeatLog: undefined,
    error: 'heartbeat_not_configured',
  };
  seedDevice(noLog.table);
  registerHeartbeatAdminRoutes(noLog.router, { verifier: new StubVerifier('good'), table: noLog.table, now: NOW });

  const rejects = {
    router: createRouter(),
    table: new FakeTable(),
    heartbeatLog: fakeHeartbeatLog({ readError: new Error('boom') }),
    error: 'heartbeat_store_unavailable',
  };
  seedDevice(rejects.table);
  registerHeartbeatAdminRoutes(rejects.router, {
    verifier: new StubVerifier('good'),
    table: rejects.table,
    now: NOW,
    heartbeatLog: rejects.heartbeatLog,
  });

  for (const tc of [noLog, rejects]) {
    const response = await makeRequest(tc.router, 'GET', '/admin/api/v1/devices/d1/heartbeats', {
      headers: { authorization: 'Bearer good' },
    });
    assert.strictEqual(response.statusCode, 503);
    assert.strictEqual(JSON.parse(response.body).error, tc.error);
  }
});

// ============================================================================
// Scenario Outline: Detail exposes the heartbeat state (AC19)
// ============================================================================

test('Scenario Outline: Device detail exposes the heartbeat state', async () => {
  const { handleDeviceDetail } = await import('../../dist/admin/devices.js');

  const cases = [
    {
      description: 'HEARTBEAT absent',
      stored: null,
      expected: { enabled: false, intervalSeconds: 300, updatedAt: null, updatedBy: null },
    },
    {
      description: 'on at 900',
      stored: { heartbeatEnabled: true, intervalSeconds: 900, updatedAt: '2026-10-11T11:00:00Z', updatedBy: 'a@x' },
      expected: { enabled: true, intervalSeconds: 900, updatedAt: '2026-10-11T11:00:00Z', updatedBy: 'a@x' },
    },
    {
      description: 'heartbeatEnabled is the string "true"',
      stored: { heartbeatEnabled: 'true', intervalSeconds: 900 },
      expected: { enabled: false, intervalSeconds: 900, updatedAt: null, updatedBy: null },
    },
    {
      description: 'interval not an option',
      stored: { heartbeatEnabled: true, intervalSeconds: 120 },
      expected: { enabled: false, intervalSeconds: 300, updatedAt: null, updatedBy: null },
    },
  ];

  for (const tc of cases) {
    const table = new FakeTable();
    seedDevice(table);
    if (tc.stored !== null) {
      table.seedItem({ ...deviceHeartbeatSettings('d1'), deviceId: 'd1', ...tc.stored });
    }

    const response = await handleDeviceDetail({ params: { deviceId: 'd1' }, query: {}, headers: {} }, { table });

    assert.strictEqual(response.statusCode, 200, tc.description);
    assert.deepStrictEqual(response.body.heartbeat, tc.expected, tc.description);
    // Every previously returned key is unchanged, analyticsCollection included.
    assert.ok('analytics' in response.body, tc.description);
    assert.ok('analyticsCollection' in response.body, tc.description);
    assert.ok('profile' in response.body, tc.description);
    assert.ok('credential' in response.body, tc.description);
  }
});

test('Scenario: Unknown device reads no heartbeat setting', async () => {
  const { handleDeviceDetail } = await import('../../dist/admin/devices.js');
  const table = new FakeTable();

  const response = await handleDeviceDetail({ params: { deviceId: 'missing' }, query: {}, headers: {} }, { table });

  assert.strictEqual(response.statusCode, 404);
  assert.strictEqual(response.body.error, 'not_found');
  const heartbeatGets = table.getCalls.filter((key) => key.sk === 'HEARTBEAT');
  assert.strictEqual(heartbeatGets.length, 0);
});
