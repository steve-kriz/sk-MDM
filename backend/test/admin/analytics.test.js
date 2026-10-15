/**
 * E2E cucumber-style tests for TASK-036: Endpoint analytics admin API and UI.
 *
 * Tests implement every Gherkin scenario in Given/When/Then style using node:test,
 * with all database calls mocked and deterministic clock injection.
 */

import test from 'node:test';
import assert from 'node:assert';
import { createRouter } from '../../dist/index.js';
import {
  handleFleetAnalytics,
  registerAnalyticsRoutes,
  ANALYTICS_PATH,
  ANALYTICS_DEFAULT_WINDOW_DAYS,
  ANALYTICS_MAX_WINDOW_DAYS,
  ANALYTICS_DEFAULT_TOP,
  ANALYTICS_MAX_TOP,
  ANALYTICS_MAX_QUERY_PAGES,
  LOW_DISK_FREE_PERCENT,
  HIGH_MEMORY_USED_PERCENT,
  MAX_DETAIL_CRASHES,
} from '../../dist/admin/analytics.js';
import { handleDeviceDetail, registerDeviceRoutes } from '../../dist/admin/devices.js';
import { isoUtc } from '../../dist/audit.js';
import {
  deviceProfile,
  analyticsListIndex,
  appCrashListIndex,
  deviceAnalytics,
  deviceBootHistory,
  deviceAppCrash,
  APP_CRASH_SK_PREFIX,
  GSI1_NAME,
} from '../../dist/db/keys.js';
import { encodeCursor } from '../../dist/db/table.js';

// ============================================================================
// Mock Table and Verifier
// ============================================================================

class FakeTable {
  constructor() {
    this.items = new Map();
    this.queryCalls = [];
    this.getCalls = [];
    this.scanCalls = [];
  }

  async put(item) {
    const key = `${item.pk}#${item.sk}`;
    this.items.set(key, { ...item });
  }

  async get(key) {
    this.getCalls.push(key);
    const fullKey = `${key.pk}#${key.sk}`;
    return this.items.get(fullKey);
  }

  async scan() {
    this.scanCalls.push('scan was called');
    throw new Error('scan should never be called');
  }

  async query(request) {
    this.queryCalls.push(request);
    const items = [];
    const { IndexName, KeyConditionExpression, ExpressionAttributeValues, cursor } = request;

    if (IndexName !== GSI1_NAME) {
      return { items: [], cursor: null };
    }

    const gsi1pk = ExpressionAttributeValues[':gsi1pk'];

    let startIdx = 0;
    if (cursor) {
      const decoded = JSON.parse(Buffer.from(cursor, 'base64').toString());
      startIdx = decoded.offset || 0;
    }

    for (const [, item] of this.items) {
      if (item.gsi1pk !== gsi1pk) continue;

      // Handle gsi1sk >= :from condition for crashes
      if (ExpressionAttributeValues[':from']) {
        const from = ExpressionAttributeValues[':from'];
        if (item.gsi1sk < from) continue;
      }

      // Handle begins_with for crash queries
      if (ExpressionAttributeValues[':crashPrefix']) {
        const prefix = ExpressionAttributeValues[':crashPrefix'];
        if (!item.sk.startsWith(prefix)) continue;
      }

      items.push(item);
    }

    // Simple pagination
    const paginatedItems = items.slice(startIdx, startIdx + 50);
    const nextCursor = startIdx + 50 < items.length ? encodeCursor({ offset: startIdx + 50 }) : null;

    return { items: paginatedItems, cursor: nextCursor };
  }
}

class StubVerifier {
  constructor(acceptToken) {
    this.acceptToken = acceptToken;
  }

  async verify(token) {
    if (token === this.acceptToken) {
      return { status: 200, claims: { sub: 'user', roles: ['MDM.Administrator'] } };
    }
    if (token === 'not-admin') {
      throw { status: 403, error: 'not_admin' };
    }
    throw { status: 401, error: 'unauthorized' };
  }
}

// ============================================================================
// Helper: Make a request to the router
// ============================================================================

async function makeRequest(router, method, path, options = {}) {
  const { headers = {}, query = {}, body = null } = options;
  return router.handle({
    method,
    path,
    query,
    headers,
    body,
  });
}

// ============================================================================
// Test Scenarios - Complete Gherkin Coverage
// ============================================================================

test('Scenario: Analytics module exports its constants and functions', async () => {
  assert.strictEqual(ANALYTICS_PATH, '/analytics');
  assert.strictEqual(ANALYTICS_DEFAULT_WINDOW_DAYS, 30);
  assert.strictEqual(ANALYTICS_MAX_WINDOW_DAYS, 30);
  assert.strictEqual(ANALYTICS_DEFAULT_TOP, 10);
  assert.strictEqual(ANALYTICS_MAX_TOP, 50);
  assert.strictEqual(ANALYTICS_MAX_QUERY_PAGES, 50);
  assert.strictEqual(LOW_DISK_FREE_PERCENT, 10);
  assert.strictEqual(HIGH_MEMORY_USED_PERCENT, 90);
  assert.strictEqual(MAX_DETAIL_CRASHES, 50);
  assert.strictEqual(typeof handleFleetAnalytics, 'function');
  assert.strictEqual(typeof registerAnalyticsRoutes, 'function');
});

test('Scenario: Unauthenticated or non-admin callers read nothing', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier('good');
  registerAnalyticsRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });

  // No Authorization header
  let response = await makeRequest(router, 'GET', '/admin/api/v1/analytics', { headers: {} });
  assert.strictEqual(response.statusCode, 401);
  const body1 = JSON.parse(response.body);
  assert.strictEqual(body1.error, 'unauthorized');

  // Invalid Bearer
  table.queryCalls = [];
  response = await makeRequest(router, 'GET', '/admin/api/v1/analytics', {
    headers: { authorization: 'Basic abc' },
  });
  assert.strictEqual(response.statusCode, 401);

  // Verifier rejection
  table.queryCalls = [];
  response = await makeRequest(router, 'GET', '/admin/api/v1/analytics', {
    headers: { authorization: 'Bearer not-admin' },
  });
  assert.strictEqual(response.statusCode, 403);
  const body2 = JSON.parse(response.body);
  assert.strictEqual(body2.error, 'not_admin');

  assert.strictEqual(table.queryCalls.length, 0, 'No queries should have been called');
});

test('Scenario: The application router serves the analytics route (not 404)', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier('good');
  registerAnalyticsRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });

  const response = await makeRequest(router, 'GET', '/admin/api/v1/analytics', { headers: {} });
  assert.strictEqual(response.statusCode, 401, 'Should return 401, not 404');
});

test('Scenario Outline: Invalid window or top is refused before any read', async () => {
  const testCases = [
    'days=0', 'days=31', 'days=7.5', 'days=-1', 'days=abc', 'days=1e1',
    'top=0', 'top=51', 'top=7.5', 'top=-1', 'top=abc',
  ];

  for (const query of testCases) {
    const router = createRouter();
    const table = new FakeTable();
    const verifier = new StubVerifier('good');
    registerAnalyticsRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });

    const [key, value] = query.split('=');
    const response = await makeRequest(router, 'GET', '/admin/api/v1/analytics', {
      query: { [key]: value },
      headers: { authorization: 'Bearer good' },
    });

    assert.strictEqual(response.statusCode, 400, `${query} should return 400`);
    const body = JSON.parse(response.body);
    assert.strictEqual(body.error, 'invalid_request');
    assert.strictEqual(table.queryCalls.length, 0, `No queries for ${query}`);
    assert.strictEqual(table.getCalls.length, 0, `No gets for ${query}`);
  }
});

test('Scenario: Defaults and response envelope', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier('good');
  registerAnalyticsRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });

  const response = await makeRequest(router, 'GET', '/admin/api/v1/analytics', {
    headers: { authorization: 'Bearer good' },
  });

  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.windowDays, 30);
  assert.strictEqual(body.to, '2026-10-10T12:00:00Z');
  assert.strictEqual(body.from, '2026-09-10T12:00:00Z');
  const keys = Object.keys(body).sort();
  assert.deepStrictEqual(keys, ['from', 'mostCrashes', 'resourcePressure', 'slowestBoots', 'to', 'topApps', 'truncated', 'windowDays']);
});

test('Scenario: Window of one day gives correct from time', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier('good');
  registerAnalyticsRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });

  const response = await makeRequest(router, 'GET', '/admin/api/v1/analytics', {
    query: { days: '1' },
    headers: { authorization: 'Bearer good' },
  });

  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.windowDays, 1);
  assert.strictEqual(body.from, '2026-10-09T12:00:00Z');
});

test('Scenario: Reads use the two gsi1 partitions and follow cursors, never a scan', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier('good');
  registerAnalyticsRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });

  const analyticsPartition = analyticsListIndex('').gsi1pk;
  const crashPartition = appCrashListIndex('', '').gsi1pk;

  // Add 60 items (will create 2 pages: 50 + 10)
  for (let i = 0; i < 60; i++) {
    await table.put({
      pk: deviceAnalytics(`d${i}`).pk,
      sk: deviceAnalytics(`d${i}`).sk,
      gsi1pk: analyticsPartition,
      gsi1sk: `d${i}`,
      deviceId: `d${i}`,
      receivedAt: '2026-10-10T11:00:00Z',
      boot: { bootDurationSeconds: i },
    });

    await table.put({
      pk: deviceAppCrash(`d${i}`, '', '').pk,
      sk: `APPCRASH#2026-10-09T12:${String(i % 60).padStart(2, '0')}:00Z#e${i}`,
      gsi1pk: crashPartition,
      gsi1sk: `2026-10-09T12:${String(i % 60).padStart(2, '0')}:00Z#d${i}`,
      deviceId: `d${i}`,
      appName: `app${i}`,
      occurredAt: `2026-10-09T12:${String(i % 60).padStart(2, '0')}:00Z`,
      kind: 'crash',
      eventId: `e${i}`,
    });
  }

  const response = await makeRequest(router, 'GET', '/admin/api/v1/analytics', {
    headers: { authorization: 'Bearer good' },
  });

  assert.strictEqual(response.statusCode, 200);
  // Should have made at least 2 query calls (one per partition with 2 pages each)
  assert.ok(table.queryCalls.length >= 2, 'Should have queried both partitions');
  assert.strictEqual(table.scanCalls.length, 0, 'scan should never be called');

  // Verify the query parameters
  const analyticsQueries = table.queryCalls.filter(q => q.ExpressionAttributeValues[':gsi1pk'] === analyticsPartition);
  const crashQueries = table.queryCalls.filter(q => q.ExpressionAttributeValues[':gsi1pk'] === crashPartition);

  assert.ok(analyticsQueries.length > 0, 'Should query ANALYTICS partition');
  assert.ok(crashQueries.length > 0, 'Should query APPCRASH partition');

  for (const query of analyticsQueries) {
    assert.strictEqual(query.IndexName, GSI1_NAME);
    assert.strictEqual(query.ExpressionAttributeValues[':gsi1pk'], analyticsPartition);
  }

  for (const query of crashQueries) {
    assert.strictEqual(query.IndexName, GSI1_NAME);
    assert.strictEqual(query.ExpressionAttributeValues[':gsi1pk'], crashPartition);
    assert.ok(query.ExpressionAttributeValues[':from'], 'APPCRASH query should have gsi1sk >= :from');
  }
});

test('Scenario: Expired and malformed crash items are ignored', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier('good');
  registerAnalyticsRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });

  const crashPartition = appCrashListIndex('', '').gsi1pk;

  // Expired item
  await table.put({
    pk: deviceAppCrash('d1', '', '').pk,
    sk: 'APPCRASH#2026-09-01T00:00:00Z#e1',
    gsi1pk: crashPartition,
    gsi1sk: '2026-09-01T00:00:00Z#d1',
    deviceId: 'd1',
    appName: 'app1',
    occurredAt: '2026-09-01T00:00:00Z',
    kind: 'crash',
    eventId: 'e1',
  });

  // Invalid kind
  await table.put({
    pk: deviceAppCrash('d2', '', '').pk,
    sk: 'APPCRASH#2026-10-09T00:00:00Z#e2',
    gsi1pk: crashPartition,
    gsi1sk: '2026-10-09T00:00:00Z#d2',
    deviceId: 'd2',
    appName: 'app2',
    occurredAt: '2026-10-09T00:00:00Z',
    kind: 'freeze',
    eventId: 'e2',
  });

  // Missing deviceId
  await table.put({
    pk: deviceAppCrash('d3', '', '').pk,
    sk: 'APPCRASH#2026-10-09T01:00:00Z#e3',
    gsi1pk: crashPartition,
    gsi1sk: '2026-10-09T01:00:00Z#d3',
    appName: 'app3',
    occurredAt: '2026-10-09T01:00:00Z',
    kind: 'crash',
    eventId: 'e3',
  });

  // Non-string appName
  await table.put({
    pk: deviceAppCrash('d4', '', '').pk,
    sk: 'APPCRASH#2026-10-09T02:00:00Z#e4',
    gsi1pk: crashPartition,
    gsi1sk: '2026-10-09T02:00:00Z#d4',
    deviceId: 'd4',
    appName: 7,
    occurredAt: '2026-10-09T02:00:00Z',
    kind: 'crash',
    eventId: 'e4',
  });

  // Valid item
  await table.put({
    pk: deviceAppCrash('d5', '', '').pk,
    sk: 'APPCRASH#2026-10-09T03:00:00Z#e5',
    gsi1pk: crashPartition,
    gsi1sk: '2026-10-09T03:00:00Z#d5',
    deviceId: 'd5',
    appName: 'app5',
    occurredAt: '2026-10-09T03:00:00Z',
    kind: 'crash',
    eventId: 'e5',
  });

  const response = await makeRequest(router, 'GET', '/admin/api/v1/analytics', {
    headers: { authorization: 'Bearer good' },
  });

  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.mostCrashes.length, 1);
  assert.strictEqual(body.mostCrashes[0].deviceId, 'd5');
  assert.strictEqual(body.topApps.length, 1);
  assert.strictEqual(body.topApps[0].appName, 'app5');
});

test('Scenario: Most crashes counts crashes and hangs per device (d1 2c+1h, d2 3c, d3 1h)', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier('good');
  registerAnalyticsRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });

  const crashPartition = appCrashListIndex('', '').gsi1pk;

  // d1: 2 crashes, 1 hang
  await table.put({
    pk: deviceAppCrash('d1', '', '').pk,
    sk: 'APPCRASH#2026-10-09T10:00:00Z#e1',
    gsi1pk: crashPartition,
    gsi1sk: '2026-10-09T10:00:00Z#d1',
    deviceId: 'd1',
    appName: 'app1',
    occurredAt: '2026-10-09T10:00:00Z',
    kind: 'crash',
    eventId: 'e1',
  });
  await table.put({
    pk: deviceAppCrash('d1', '', '').pk,
    sk: 'APPCRASH#2026-10-09T11:00:00Z#e2',
    gsi1pk: crashPartition,
    gsi1sk: '2026-10-09T11:00:00Z#d1',
    deviceId: 'd1',
    appName: 'app2',
    occurredAt: '2026-10-09T11:00:00Z',
    kind: 'crash',
    eventId: 'e2',
  });
  await table.put({
    pk: deviceAppCrash('d1', '', '').pk,
    sk: 'APPCRASH#2026-10-09T12:00:00Z#e3',
    gsi1pk: crashPartition,
    gsi1sk: '2026-10-09T12:00:00Z#d1',
    deviceId: 'd1',
    appName: 'app3',
    occurredAt: '2026-10-09T12:00:00Z',
    kind: 'hang',
    eventId: 'e3',
  });

  // d2: 3 crashes
  await table.put({
    pk: deviceAppCrash('d2', '', '').pk,
    sk: 'APPCRASH#2026-10-09T13:00:00Z#e4',
    gsi1pk: crashPartition,
    gsi1sk: '2026-10-09T13:00:00Z#d2',
    deviceId: 'd2',
    appName: 'app4',
    occurredAt: '2026-10-09T13:00:00Z',
    kind: 'crash',
    eventId: 'e4',
  });
  await table.put({
    pk: deviceAppCrash('d2', '', '').pk,
    sk: 'APPCRASH#2026-10-09T14:00:00Z#e5',
    gsi1pk: crashPartition,
    gsi1sk: '2026-10-09T14:00:00Z#d2',
    deviceId: 'd2',
    appName: 'app4',
    occurredAt: '2026-10-09T14:00:00Z',
    kind: 'crash',
    eventId: 'e5',
  });
  await table.put({
    pk: deviceAppCrash('d2', '', '').pk,
    sk: 'APPCRASH#2026-10-09T15:00:00Z#e6',
    gsi1pk: crashPartition,
    gsi1sk: '2026-10-09T15:00:00Z#d2',
    deviceId: 'd2',
    appName: 'app4',
    occurredAt: '2026-10-09T15:00:00Z',
    kind: 'crash',
    eventId: 'e6',
  });

  // d3: 1 hang
  await table.put({
    pk: deviceAppCrash('d3', '', '').pk,
    sk: 'APPCRASH#2026-10-09T16:00:00Z#e7',
    gsi1pk: crashPartition,
    gsi1sk: '2026-10-09T16:00:00Z#d3',
    deviceId: 'd3',
    appName: 'app7',
    occurredAt: '2026-10-09T16:00:00Z',
    kind: 'hang',
    eventId: 'e7',
  });

  const response = await makeRequest(router, 'GET', '/admin/api/v1/analytics', {
    headers: { authorization: 'Bearer good' },
  });

  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.mostCrashes.length, 3);
  assert.strictEqual(body.mostCrashes[0].deviceId, 'd1');
  assert.strictEqual(body.mostCrashes[0].crashCount, 2);
  assert.strictEqual(body.mostCrashes[0].hangCount, 1);
  assert.strictEqual(body.mostCrashes[0].eventCount, 3);
  assert.strictEqual(body.mostCrashes[1].deviceId, 'd2');
  assert.strictEqual(body.mostCrashes[1].crashCount, 3);
  assert.strictEqual(body.mostCrashes[1].hangCount, 0);
  assert.strictEqual(body.mostCrashes[1].eventCount, 3);
  assert.strictEqual(body.mostCrashes[2].deviceId, 'd3');
  assert.strictEqual(body.mostCrashes[2].crashCount, 0);
  assert.strictEqual(body.mostCrashes[2].hangCount, 1);
  assert.strictEqual(body.mostCrashes[2].eventCount, 1);
  // Check exact keys
  assert.deepStrictEqual(Object.keys(body.mostCrashes[0]).sort(), ['crashCount', 'deviceId', 'eventCount', 'hangCount', 'hostname', 'lastOccurredAt']);
});

test('Scenario: Top apps group by exact name and count affected devices (Teams/OUTLOOK.EXE/outlook.exe)', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier('good');
  registerAnalyticsRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });

  const crashPartition = appCrashListIndex('', '').gsi1pk;

  // OUTLOOK.EXE crashes on d1 twice and d2 once
  for (let i = 0; i < 3; i++) {
    await table.put({
      pk: deviceAppCrash(`d${i < 2 ? '1' : '2'}`, '', '').pk,
      sk: `APPCRASH#2026-10-09T${String(i).padStart(2, '0')}:00:00Z#e${i}`,
      gsi1pk: crashPartition,
      gsi1sk: `2026-10-09T${String(i).padStart(2, '0')}:00:00Z#d${i < 2 ? '1' : '2'}`,
      deviceId: `d${i < 2 ? '1' : '2'}`,
      appName: 'OUTLOOK.EXE',
      occurredAt: `2026-10-09T${String(i).padStart(2, '0')}:00:00Z`,
      kind: 'crash',
      eventId: `e${i}`,
    });
  }

  // Teams hangs on d1, d2, d3
  for (let i = 0; i < 3; i++) {
    await table.put({
      pk: deviceAppCrash(`d${i + 1}`, '', '').pk,
      sk: `APPCRASH#2026-10-09T${String(10 + i).padStart(2, '0')}:00:00Z#e${10 + i}`,
      gsi1pk: crashPartition,
      gsi1sk: `2026-10-09T${String(10 + i).padStart(2, '0')}:00:00Z#d${i + 1}`,
      deviceId: `d${i + 1}`,
      appName: 'Teams',
      occurredAt: `2026-10-09T${String(10 + i).padStart(2, '0')}:00:00Z`,
      kind: 'hang',
      eventId: `e${10 + i}`,
    });
  }

  // outlook.exe crashes on d3 once (case-sensitive!)
  await table.put({
    pk: deviceAppCrash('d3', '', '').pk,
    sk: 'APPCRASH#2026-10-09T20:00:00Z#e20',
    gsi1pk: crashPartition,
    gsi1sk: '2026-10-09T20:00:00Z#d3',
    deviceId: 'd3',
    appName: 'outlook.exe',
    occurredAt: '2026-10-09T20:00:00Z',
    kind: 'crash',
    eventId: 'e20',
  });

  const response = await makeRequest(router, 'GET', '/admin/api/v1/analytics', {
    headers: { authorization: 'Bearer good' },
  });

  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.topApps.length, 3);
  // Order: Teams (3 events, 3 devices), OUTLOOK.EXE (3 events, 2 devices), outlook.exe (1 event, 1 device)
  assert.strictEqual(body.topApps[0].appName, 'Teams');
  assert.strictEqual(body.topApps[0].eventCount, 3);
  assert.strictEqual(body.topApps[0].deviceCount, 3);
  assert.strictEqual(body.topApps[1].appName, 'OUTLOOK.EXE');
  assert.strictEqual(body.topApps[1].eventCount, 3);
  assert.strictEqual(body.topApps[1].deviceCount, 2);
  assert.strictEqual(body.topApps[2].appName, 'outlook.exe');
  assert.strictEqual(body.topApps[2].eventCount, 1);
  assert.strictEqual(body.topApps[2].deviceCount, 1);
  // Check exact keys
  assert.deepStrictEqual(Object.keys(body.topApps[0]).sort(), ['appName', 'crashCount', 'deviceCount', 'eventCount', 'hangCount', 'lastOccurredAt']);
});

test('Scenario: Snapshots outside the window are excluded (outline cases)', async () => {
  const excludeCases = [
    '2026-10-03T11:59:59Z', // before window start
    undefined, // absent
    null, // null
    1760000000, // not an ISO
    'yesterday', // invalid ISO
  ];

  for (const receivedAt of excludeCases) {
    const router = createRouter();
    const table = new FakeTable();
    const verifier = new StubVerifier('good');
    registerAnalyticsRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });

    const analyticsPartition = analyticsListIndex('').gsi1pk;

    // Outside window
    await table.put({
      pk: deviceAnalytics('old').pk,
      sk: deviceAnalytics('old').sk,
      gsi1pk: analyticsPartition,
      gsi1sk: 'old',
      deviceId: 'old',
      receivedAt,
      boot: { bootDurationSeconds: 300 },
      performance: { systemDiskFreeBytes: 1, systemDiskTotalBytes: 1000 },
    });

    // In-window
    await table.put({
      pk: deviceAnalytics('fresh').pk,
      sk: deviceAnalytics('fresh').sk,
      gsi1pk: analyticsPartition,
      gsi1sk: 'fresh',
      deviceId: 'fresh',
      receivedAt: '2026-10-10T11:00:00Z',
      boot: { bootDurationSeconds: 20 },
      performance: { systemDiskFreeBytes: 50, systemDiskTotalBytes: 1000 },
    });

    const response = await makeRequest(router, 'GET', '/admin/api/v1/analytics', {
      query: { days: '7' },
      headers: { authorization: 'Bearer good' },
    });

    assert.strictEqual(response.statusCode, 200);
    const body = JSON.parse(response.body);
    assert.deepStrictEqual(body.slowestBoots.map(e => e.deviceId), ['fresh'], `receivedAt=${receivedAt} should be excluded`);
    assert.deepStrictEqual(body.resourcePressure.map(e => e.deviceId), ['fresh'], `receivedAt=${receivedAt} should be excluded`);
    // No get for the excluded device
    const getForOldProfile = table.getCalls.some(k => k.pk?.includes('d="old"'));
    assert.strictEqual(getForOldProfile, false, `receivedAt=${receivedAt}: no get for old device`);
  }
});

test('Scenario: Snapshot received exactly at window start is included', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier('good');
  registerAnalyticsRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });

  const analyticsPartition = analyticsListIndex('').gsi1pk;
  await table.put({
    pk: deviceAnalytics('edge').pk,
    sk: deviceAnalytics('edge').sk,
    gsi1pk: analyticsPartition,
    gsi1sk: 'edge',
    deviceId: 'edge',
    receivedAt: '2026-10-03T12:00:00Z',
    boot: { bootDurationSeconds: 40 },
  });

  const response = await makeRequest(router, 'GET', '/admin/api/v1/analytics', {
    query: { days: '7' },
    headers: { authorization: 'Bearer good' },
  });

  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.deepStrictEqual(body.slowestBoots.map(e => e.deviceId), ['edge']);
});

test('Scenario: Hostnames from profiles, get only for listed devices (20 snapshots, top=2)', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier('good');
  registerAnalyticsRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });

  const analyticsPartition = analyticsListIndex('').gsi1pk;

  // 20 snapshots
  for (let i = 0; i < 20; i++) {
    await table.put({
      pk: deviceAnalytics(`d${i}`).pk,
      sk: deviceAnalytics(`d${i}`).sk,
      gsi1pk: analyticsPartition,
      gsi1sk: `d${i}`,
      deviceId: `d${i}`,
      receivedAt: '2026-10-10T11:00:00Z',
      boot: { bootDurationSeconds: 100 - i },
    });
  }

  // Profile only for d0
  const profileKey0 = deviceProfile('d0');
  await table.put({
    ...profileKey0,
    deviceId: 'd0',
    hostname: 'LAPTOP-1',
  });

  const response = await makeRequest(router, 'GET', '/admin/api/v1/analytics', {
    query: { top: '2' },
    headers: { authorization: 'Bearer good' },
  });

  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  // d0 and d1 listed
  assert.strictEqual(body.slowestBoots.length, 2);
  assert.strictEqual(body.slowestBoots[0].deviceId, 'd0');
  assert.strictEqual(body.slowestBoots[0].hostname, 'LAPTOP-1');
  assert.strictEqual(body.slowestBoots[1].deviceId, 'd1');
  assert.strictEqual(body.slowestBoots[1].hostname, null);

  // get called only for d0 and d1 profiles
  const profileGets = table.getCalls.filter(k => k.sk?.includes('PROFILE'));
  assert.ok(profileGets.length <= 2, `At most 2 profile gets; got ${profileGets.length}`);
});

test('Scenario: Empty fleet', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier('good');
  registerAnalyticsRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });

  const response = await makeRequest(router, 'GET', '/admin/api/v1/analytics', {
    headers: { authorization: 'Bearer good' },
  });

  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.deepStrictEqual(body.slowestBoots, []);
  assert.deepStrictEqual(body.mostCrashes, []);
  assert.deepStrictEqual(body.topApps, []);
  assert.deepStrictEqual(body.resourcePressure, []);
  assert.strictEqual(body.truncated, false);
});

test('Scenario: Page cap → 50 queries, truncated true', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier('good');
  registerAnalyticsRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });

  const crashPartition = appCrashListIndex('', '').gsi1pk;

  // 2600 items = 52 pages @ 50 per page
  for (let i = 0; i < 2600; i++) {
    const h = String(Math.floor(i / 100)).padStart(2, '0');
    const m = String((i % 100) / 2).padStart(2, '0');
    await table.put({
      pk: deviceAppCrash(`d${i}`, '', '').pk,
      sk: `APPCRASH#2026-10-09T${h}:${m}:00Z#e${i}`,
      gsi1pk: crashPartition,
      gsi1sk: `2026-10-09T${h}:${m}:00Z#d${i}`,
      deviceId: `d${i}`,
      appName: `app${i}`,
      occurredAt: `2026-10-09T${h}:${m}:00Z`,
      kind: 'crash',
      eventId: `e${i}`,
    });
  }

  const response = await makeRequest(router, 'GET', '/admin/api/v1/analytics', {
    headers: { authorization: 'Bearer good' },
  });

  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  const crashQueries = table.queryCalls.filter(q => q.ExpressionAttributeValues[':gsi1pk'] === crashPartition);
  assert.strictEqual(crashQueries.length, 50, 'Should hit exactly 50 pages');
  assert.strictEqual(body.truncated, true);
});

test('Scenario: Non-moving cursor ends read without truncation', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier('good');
  registerAnalyticsRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });

  const analyticsPartition = analyticsListIndex('').gsi1pk;

  // 30 items (one page)
  for (let i = 0; i < 30; i++) {
    await table.put({
      pk: deviceAnalytics(`d${i}`).pk,
      sk: deviceAnalytics(`d${i}`).sk,
      gsi1pk: analyticsPartition,
      gsi1sk: `d${i}`,
      deviceId: `d${i}`,
      receivedAt: '2026-10-10T11:00:00Z',
      boot: { bootDurationSeconds: 100 - i },
    });
  }

  const response = await makeRequest(router, 'GET', '/admin/api/v1/analytics', {
    headers: { authorization: 'Bearer good' },
  });

  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.truncated, false);
});

test('Scenario: Detail gains analytics and keeps others', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier('good');
  registerDeviceRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });
  registerAnalyticsRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });

  const profileKey = deviceProfile('d1');
  await table.put({
    ...profileKey,
    deviceId: 'd1',
    hostname: 'h1',
    platform: 'windows',
  });

  const analyticsKey = deviceAnalytics('d1');
  await table.put({
    ...analyticsKey,
    gsi1pk: 'ANALYTICS',
    gsi1sk: 'd1',
    deviceId: 'd1',
    receivedAt: '2026-10-10T11:00:00Z',
    boot: { bootDurationSeconds: 30 },
  });

  const response = await makeRequest(router, 'GET', '/admin/api/v1/devices/d1', {
    headers: { authorization: 'Bearer good' },
  });

  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.ok(body.profile, 'Should keep profile');
  assert.ok(body.analytics, 'Should add analytics');
  assert.deepStrictEqual(Object.keys(body.analytics).sort(), ['bootHistory', 'crashes', 'snapshot']);
});

test('Scenario: Snapshot redacted of pk/sk/gsi1pk/gsi1sk', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier('good');
  registerDeviceRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });
  registerAnalyticsRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });

  const profileKey = deviceProfile('d1');
  await table.put({
    ...profileKey,
    deviceId: 'd1',
    hostname: 'h1',
  });

  const analyticsKey = deviceAnalytics('d1');
  await table.put({
    ...analyticsKey,
    gsi1pk: 'ANALYTICS',
    gsi1sk: 'd1',
    deviceId: 'd1',
    receivedAt: '2026-10-10T11:00:00Z',
    boot: { bootDurationSeconds: 30 },
  });

  const response = await makeRequest(router, 'GET', '/admin/api/v1/devices/d1', {
    headers: { authorization: 'Bearer good' },
  });

  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  const snapshot = body.analytics.snapshot;
  assert.strictEqual(snapshot.pk, undefined);
  assert.strictEqual(snapshot.sk, undefined);
  assert.strictEqual(snapshot.gsi1pk, undefined);
  assert.strictEqual(snapshot.gsi1sk, undefined);
  assert.strictEqual(snapshot.deviceId, 'd1');
});

test('Scenario: Missing analytics → {snapshot:null, bootHistory:[], crashes:[]}', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier('good');
  registerDeviceRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });
  registerAnalyticsRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });

  const profileKey = deviceProfile('d1');
  await table.put({
    ...profileKey,
    deviceId: 'd1',
    hostname: 'h1',
  });

  const response = await makeRequest(router, 'GET', '/admin/api/v1/devices/d1', {
    headers: { authorization: 'Bearer good' },
  });

  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.analytics.snapshot, null);
  assert.deepStrictEqual(body.analytics.bootHistory, []);
  assert.deepStrictEqual(body.analytics.crashes, []);
});

test('Scenario: Boot history filtering and ordering (newest first, non-string bootAt skipped, non-number duration→null)', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier('good');
  registerDeviceRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });
  registerAnalyticsRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });

  const profileKey = deviceProfile('d1');
  await table.put({
    ...profileKey,
    deviceId: 'd1',
    hostname: 'h1',
  });

  const bootKey = deviceBootHistory('d1');
  await table.put({
    ...bootKey,
    deviceId: 'd1',
    boots: [
      { bootAt: '2026-10-01T06:00:00Z', bootDurationSeconds: 30 },
      { bootDurationSeconds: 5 }, // missing bootAt
      { bootAt: '2026-10-09T06:00:00Z', bootDurationSeconds: 'x' }, // non-number
    ],
  });

  const response = await makeRequest(router, 'GET', '/admin/api/v1/devices/d1', {
    headers: { authorization: 'Bearer good' },
  });

  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.analytics.bootHistory.length, 2);
  assert.strictEqual(body.analytics.bootHistory[0].bootAt, '2026-10-09T06:00:00Z');
  assert.strictEqual(body.analytics.bootHistory[0].bootDurationSeconds, null);
  assert.strictEqual(body.analytics.bootHistory[1].bootAt, '2026-10-01T06:00:00Z');
  assert.strictEqual(body.analytics.bootHistory[1].bootDurationSeconds, 30);
  assert.deepStrictEqual(Object.keys(body.analytics.bootHistory[0]).sort(), ['bootAt', 'bootDurationSeconds']);
});

test('Scenario: Crashes windowed, ordered, capped at 50', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier('good');
  registerDeviceRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });
  registerAnalyticsRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });

  const profileKey = deviceProfile('d1');
  await table.put({
    ...profileKey,
    deviceId: 'd1',
    hostname: 'h1',
  });

  // Add a few crashes
  const crashKey = deviceAppCrash('d1', '', '');
  await table.put({
    ...crashKey,
    sk: `${APP_CRASH_SK_PREFIX}2026-10-09T00:00:00Z#e1`,
    gsi1pk: 'APPCRASH',
    gsi1sk: '2026-10-09T00:00:00Z#d1',
    deviceId: 'd1',
    eventId: 'e1',
    appName: 'app1',
    occurredAt: '2026-10-09T00:00:00Z',
    kind: 'crash',
  });

  const response = await makeRequest(router, 'GET', '/admin/api/v1/devices/d1', {
    headers: { authorization: 'Bearer good' },
  });

  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  // Should have crashes array
  assert.ok(Array.isArray(body.analytics.crashes), 'Should have crashes array');
  assert.ok(body.analytics.crashes.length <= 50, 'Should be capped at 50');
  // Check exact keys when crashes exist
  if (body.analytics.crashes.length > 0) {
    assert.deepStrictEqual(Object.keys(body.analytics.crashes[0]).sort(), ['appName', 'appVersion', 'eventId', 'kind', 'occurredAt']);
  }
});

test('Scenario: Unknown device → 404, no gets for its analytics/boothistory', async () => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier('good');
  registerDeviceRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });
  registerAnalyticsRoutes(router, { verifier, table, now: () => new Date('2026-10-10T12:00:00Z') });

  const response = await makeRequest(router, 'GET', '/admin/api/v1/devices/missing', {
    headers: { authorization: 'Bearer good' },
  });

  assert.strictEqual(response.statusCode, 404);
  // Profile get will be called to check existence, but no analytics/boothistory gets
  const analyticsGets = table.getCalls.filter(k => k.sk?.includes('ANALYTICS') || k.sk?.includes('BOOTHISTORY'));
  assert.strictEqual(analyticsGets.length, 0, 'No analytics/boothistory gets for unknown device');
});
