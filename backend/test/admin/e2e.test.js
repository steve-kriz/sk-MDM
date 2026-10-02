/**
 * E2E cucumber-style tests for TASK-010: Admin API device and audit read endpoints.
 *
 * Tests implement the Gherkin scenarios in Given/When/Then style using node:test,
 * with all database calls mocked and deterministic clock injection.
 */

import test from 'node:test';
import assert from 'node:assert';
import { createRouter } from '../../dist/index.js';
import {
  registerAdminRoute,
  registerAuditRoutes,
  requireAdmin,
  bearerToken,
  parseLimit,
  isUsableCursor,
  readCursor,
  isIsoUtc,
  ADMIN_PREFIX,
  AUDIT_PATH,
} from '../../dist/admin/router.js';
import {
  registerDeviceRoutes,
  handleDeviceList,
  handleDeviceDetail,
  DEVICE_LIST_PATH,
  DEVICE_DETAIL_PATH,
  DEVICE_SUMMARY_FIELDS,
  UNKNOWN_COMPLIANCE,
} from '../../dist/admin/devices.js';
import { queryAudit, isoUtc, utcDay, auditSeq, appendAudit } from '../../dist/audit.js';
import {
  deviceProfile,
  deviceInventory,
  devicePosture,
  deviceCommand,
  deviceAntivirusFinding,
  deviceListIndex,
  groupMember,
  audit as auditKey,
  GSI1_NAME,
} from '../../dist/db/keys.js';
import { encodeCursor } from '../../dist/db/table.js';

// ============================================================================
// Mock Table Client
// ============================================================================

class FakeTable {
  constructor() {
    this.items = new Map();
  }

  async put(item) {
    const key = `${item.pk}#${item.sk}`;
    this.items.set(key, { ...item });
  }

  async get(key) {
    const fullKey = `${key.pk}#${key.sk}`;
    return this.items.get(fullKey);
  }

  async query(request) {
    const items = [];
    const { KeyConditionExpression, ExpressionAttributeValues, ScanIndexForward = true, limit = 50, cursor } = request;

    let startIdx = 0;
    if (cursor) {
      const decoded = JSON.parse(Buffer.from(cursor, 'base64').toString());
      startIdx = decoded.offset || 0;
    }

    for (const [, item] of this.items) {
      if (KeyConditionExpression.includes('gsi1pk')) {
        const pk = ExpressionAttributeValues[':gsi1pk'];
        if (item.gsi1pk !== pk) continue;

        if (KeyConditionExpression.includes('gsi1sk < :staleBefore')) {
          const staleBefore = ExpressionAttributeValues[':staleBefore'];
          if (item.gsi1sk >= staleBefore) continue;
        }
      } else if (KeyConditionExpression.includes(':pk')) {
        const pk = ExpressionAttributeValues[':pk'];
        if (item.pk !== pk) continue;

        if (KeyConditionExpression.includes('begins_with(#sk')) {
          const prefix =
            ExpressionAttributeValues[':memberPrefix'] ||
            ExpressionAttributeValues[':commandPrefix'] ||
            ExpressionAttributeValues[':findingPrefix'];
          if (!item.sk.startsWith(prefix)) continue;
        }
      }

      items.push(item);
    }

    const sorted = items.sort((a, b) => {
      if (ScanIndexForward === false) {
        return (b.gsi1sk || b.sk) < (a.gsi1sk || a.sk) ? 1 : -1;
      }
      return (a.gsi1sk || a.sk) < (b.gsi1sk || b.sk) ? 1 : -1;
    });

    const pageSize = Math.min(limit, sorted.length - startIdx);
    const page = sorted.slice(startIdx, startIdx + pageSize);
    const nextCursor = startIdx + pageSize < sorted.length
      ? encodeCursor({ offset: startIdx + pageSize })
      : null;

    return { items: page, cursor: nextCursor };
  }
}

// ============================================================================
// Mock Token Verifier
// ============================================================================

class StubVerifier {
  constructor(claims = {}) {
    this.claims = { sub: 'user123', roles: ['MDM.Admin'], ...claims };
  }

  async verify(token) {
    if (token === 'invalid') {
      throw { status: 401, error: 'invalid_token' };
    }
    if (token === 'not_admin') {
      throw { status: 403, error: 'not_admin' };
    }
    return this.claims;
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
// Scenario: Missing bearer token is refused
// ============================================================================

test('Scenario: Missing bearer token is refused', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  // When I GET /admin/api/v1/devices with no Authorization header
  const response = await makeRequest(router, 'GET', '/admin/api/v1/devices', {
    headers: {},
  });

  // Then the status is 401, the error is unauthorized and no handler ran
  assert.strictEqual(response.statusCode, 401);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'unauthorized');
});

// ============================================================================
// Scenario: Device list is paged newest first
// ============================================================================

test('Scenario: Device list is paged newest first', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  // Given 60 devices with limit 50
  const now = new Date('2026-10-02T10:00:00Z').toISOString().replace(/\.\d{3}Z$/, 'Z');
  for (let i = 0; i < 60; i++) {
    const deviceId = `device-${String(i).padStart(2, '0')}`;
    const item = {
      pk: `DEVICE#${deviceId}`,
      sk: 'PROFILE',
      deviceId,
      hostname: `host-${i}`,
      platform: 'linux',
      osVersion: '22.04',
      lastSeenAt: new Date(new Date(now).getTime() - i * 60000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
      agentVersion: '1.0',
      gsi1pk: 'DEVICE',
      gsi1sk: new Date(new Date(now).getTime() - i * 60000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    };
    await table.put(item);
  }

  // When an admin lists devices
  const response = await makeRequest(router, 'GET', '/admin/api/v1/devices', {
    headers: { authorization: 'Bearer valid-token' },
    query: { limit: '50' },
  });

  // Then 50 items are returned ordered by lastSeenAt descending with a non-null cursor
  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.items.length, 50);
  assert.notStrictEqual(body.cursor, null);

  // And each item has exactly deviceId, hostname, platform, osVersion, lastSeenAt, complianceState and agentVersion
  for (const item of body.items) {
    const keys = Object.keys(item).sort();
    const expected = DEVICE_SUMMARY_FIELDS.slice().sort();
    assert.deepStrictEqual(keys, expected);
  }

  // Items are ordered by lastSeenAt descending
  for (let i = 1; i < body.items.length; i++) {
    assert(
      body.items[i - 1].lastSeenAt >= body.items[i].lastSeenAt,
      'Items should be ordered by lastSeenAt descending',
    );
  }
});

// ============================================================================
// Scenario: Missing compliance state reads as unknown
// ============================================================================

test('Scenario: Missing compliance state reads as unknown', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  const now = new Date('2026-10-02T10:00:00Z').toISOString().replace(/\.\d{3}Z$/, 'Z');

  // Given device d1 has complianceState "noncompliant" and d2 has no complianceState attribute
  await table.put({
    pk: 'DEVICE#d1',
    sk: 'PROFILE',
    deviceId: 'd1',
    hostname: 'host-d1',
    platform: 'windows',
    osVersion: '10',
    lastSeenAt: now,
    agentVersion: '1.0',
    complianceState: 'noncompliant',
    gsi1pk: 'DEVICE',
    gsi1sk: now,
  });

  await table.put({
    pk: 'DEVICE#d2',
    sk: 'PROFILE',
    deviceId: 'd2',
    hostname: 'host-d2',
    platform: 'macos',
    osVersion: '12',
    lastSeenAt: now,
    agentVersion: '1.0',
    gsi1pk: 'DEVICE',
    gsi1sk: now,
  });

  // When an admin lists devices
  const response = await makeRequest(router, 'GET', '/admin/api/v1/devices', {
    headers: { authorization: 'Bearer valid-token' },
  });

  // Then d1 shows "noncompliant" and d2 shows "unknown"
  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  const d1 = body.items.find((item) => item.deviceId === 'd1');
  const d2 = body.items.find((item) => item.deviceId === 'd2');
  assert.strictEqual(d1.complianceState, 'noncompliant');
  assert.strictEqual(d2.complianceState, 'unknown');
});

// ============================================================================
// Scenario: Group filter is hydrated, ordered and paginated like the list
// ============================================================================

test('Scenario: Group filter is hydrated, ordered and paginated like the list', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  const now = new Date('2026-10-02T10:00:00Z').toISOString().replace(/\.\d{3}Z$/, 'Z');

  // Create devices and memberships
  for (const id of ['d1', 'd2', 'd3']) {
    await table.put({
      pk: `DEVICE#${id}`,
      sk: 'PROFILE',
      deviceId: id,
      hostname: `host-${id}`,
      platform: 'linux',
      osVersion: '22.04',
      lastSeenAt: new Date(new Date(now).getTime() - (id === 'd1' ? 0 : id === 'd3' ? 1000 : 2000)).toISOString().replace(/\.\d{3}Z$/, 'Z'),
      agentVersion: '1.0',
      gsi1pk: 'DEVICE',
      gsi1sk: new Date(new Date(now).getTime() - (id === 'd1' ? 0 : id === 'd3' ? 1000 : 2000)).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    });
  }

  // Devices d1 and d3 are members of group g1
  await table.put({
    pk: 'GROUP#g1',
    sk: 'MEMBER#d1',
    deviceId: 'd1',
  });

  await table.put({
    pk: 'GROUP#g1',
    sk: 'MEMBER#d3',
    deviceId: 'd3',
  });

  // d2 is a member of group g2 instead
  await table.put({
    pk: 'GROUP#g2',
    sk: 'MEMBER#d2',
    deviceId: 'd2',
  });

  // When an admin lists devices with group=g1
  const response = await makeRequest(router, 'GET', '/admin/api/v1/devices', {
    headers: { authorization: 'Bearer valid-token' },
    query: { group: 'g1' },
  });

  // Then the response is an {items, cursor} envelope
  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert(Array.isArray(body.items));
  assert(body.cursor !== undefined);

  // And only d1 and d3 are returned with the same seven fields in lastSeenAt-descending order
  assert.strictEqual(body.items.length, 2);
  const ids = body.items.map((item) => item.deviceId);
  assert.deepStrictEqual(ids, ['d1', 'd3']);

  for (const item of body.items) {
    const keys = Object.keys(item).sort();
    const expected = DEVICE_SUMMARY_FIELDS.slice().sort();
    assert.deepStrictEqual(keys, expected);
  }
});

// ============================================================================
// Scenario: Empty group returns an empty page
// ============================================================================

test('Scenario: Empty group returns an empty page', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  // When an admin lists devices with group=g9 (which has no members)
  const response = await makeRequest(router, 'GET', '/admin/api/v1/devices', {
    headers: { authorization: 'Bearer valid-token' },
    query: { group: 'g9' },
  });

  // Then the status is 200, items is empty and cursor is null
  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.deepStrictEqual(body.items, []);
  assert.strictEqual(body.cursor, null);
});

// ============================================================================
// Scenario: Stale filter uses a strict 24 hour threshold
// ============================================================================

test('Scenario: Stale filter uses a strict 24 hour threshold', async (t) => {
  const router = createRouter();
  const table = new FakeTable();

  // With deterministic now = 2026-10-02T10:00:00Z
  const now = new Date('2026-10-02T10:00:00Z');
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table, now: () => now });

  // Given d1 was last seen 30 hours ago
  const d1Time = new Date(now.getTime() - 30 * 3600000);
  await table.put({
    pk: 'DEVICE#d1',
    sk: 'PROFILE',
    deviceId: 'd1',
    hostname: 'host-d1',
    platform: 'linux',
    osVersion: '22.04',
    lastSeenAt: d1Time.toISOString().replace(/\.\d{3}Z$/, 'Z'),
    agentVersion: '1.0',
    gsi1pk: 'DEVICE',
    gsi1sk: d1Time.toISOString().replace(/\.\d{3}Z$/, 'Z'),
  });

  // d2 ten minutes ago
  const d2Time = new Date(now.getTime() - 10 * 60000);
  await table.put({
    pk: 'DEVICE#d2',
    sk: 'PROFILE',
    deviceId: 'd2',
    hostname: 'host-d2',
    platform: 'linux',
    osVersion: '22.04',
    lastSeenAt: d2Time.toISOString().replace(/\.\d{3}Z$/, 'Z'),
    agentVersion: '1.0',
    gsi1pk: 'DEVICE',
    gsi1sk: d2Time.toISOString().replace(/\.\d{3}Z$/, 'Z'),
  });

  // d3 exactly 24 hours ago
  const d3Time = new Date(now.getTime() - 24 * 3600000);
  await table.put({
    pk: 'DEVICE#d3',
    sk: 'PROFILE',
    deviceId: 'd3',
    hostname: 'host-d3',
    platform: 'linux',
    osVersion: '22.04',
    lastSeenAt: d3Time.toISOString().replace(/\.\d{3}Z$/, 'Z'),
    agentVersion: '1.0',
    gsi1pk: 'DEVICE',
    gsi1sk: d3Time.toISOString().replace(/\.\d{3}Z$/, 'Z'),
  });

  // When an admin lists devices with stale=true
  const response = await makeRequest(router, 'GET', '/admin/api/v1/devices', {
    headers: { authorization: 'Bearer valid-token' },
    query: { stale: 'true' },
  });

  // Then only d1 is returned
  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.items.length, 1);
  assert.strictEqual(body.items[0].deviceId, 'd1');

  // With the same seven fields and an {items, cursor} envelope
  const keys = Object.keys(body.items[0]).sort();
  const expected = DEVICE_SUMMARY_FIELDS.slice().sort();
  assert.deepStrictEqual(keys, expected);
});

// ============================================================================
// Scenario: Device detail returns the most recently issued commands
// ============================================================================

test('Scenario: Device detail returns the most recently issued commands', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  // Given device d1 with inventory, posture and 25 commands
  await table.put({
    pk: 'DEVICE#d1',
    sk: 'PROFILE',
    deviceId: 'd1',
    hostname: 'host-d1',
    platform: 'linux',
    osVersion: '22.04',
    agentVersion: '1.0',
  });

  await table.put({
    pk: 'DEVICE#d1',
    sk: 'INVENTORY',
    diskSpace: 500000000,
  });

  await table.put({
    pk: 'DEVICE#d1',
    sk: 'POSTURE',
    firewallEnabled: true,
  });

  for (let i = 0; i < 25; i++) {
    await table.put({
      pk: 'DEVICE#d1',
      sk: `CMD#${String(i).padStart(2, '0')}`,
      commandId: `cmd-${i}`,
      issuedAt: 1000 + i * 100, // Distinct issuedAt values
    });
  }

  // When an admin GETs /admin/api/v1/devices/d1
  const response = await makeRequest(router, 'GET', '/admin/api/v1/devices/d1', {
    headers: { authorization: 'Bearer valid-token' },
  });

  // Then profile, inventory and posture are returned
  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert(body.profile);
  assert(body.inventory);
  assert(body.posture);

  // And commands holds the 20 highest issuedAt items in issuedAt-descending order
  assert.strictEqual(body.commands.length, 20);
  for (let i = 1; i < body.commands.length; i++) {
    assert(
      body.commands[i - 1].issuedAt >= body.commands[i].issuedAt,
      'Commands should be ordered by issuedAt descending',
    );
  }
});

// ============================================================================
// Scenario: Command without issuedAt sorts last
// ============================================================================

test('Scenario: Command without issuedAt sorts last', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  // Given device d1 with 3 commands, one with no issuedAt
  await table.put({
    pk: 'DEVICE#d1',
    sk: 'PROFILE',
    deviceId: 'd1',
    hostname: 'host-d1',
    platform: 'linux',
    osVersion: '22.04',
    agentVersion: '1.0',
  });

  await table.put({
    pk: 'DEVICE#d1',
    sk: 'CMD#01',
    commandId: 'cmd-1',
    issuedAt: 1000,
  });

  await table.put({
    pk: 'DEVICE#d1',
    sk: 'CMD#02',
    commandId: 'cmd-2',
    issuedAt: 2000,
  });

  // Command without issuedAt
  await table.put({
    pk: 'DEVICE#d1',
    sk: 'CMD#03',
    commandId: 'cmd-3',
  });

  // When an admin GETs /admin/api/v1/devices/d1
  const response = await makeRequest(router, 'GET', '/admin/api/v1/devices/d1', {
    headers: { authorization: 'Bearer valid-token' },
  });

  // Then all 3 commands are returned and the one without issuedAt is last
  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.commands.length, 3);
  assert.strictEqual(body.commands[2].commandId, 'cmd-3');
});

// ============================================================================
// Scenario: Admin sees findings on the device detail (TASK-030)
// ============================================================================

test('Scenario: Admin sees findings on the device detail', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  await table.put({
    pk: 'DEVICE#d1',
    sk: 'PROFILE',
    deviceId: 'd1',
    hostname: 'host-d1',
    platform: 'windows',
    osVersion: '11',
    agentVersion: '1.0',
  });
  await table.put({ pk: 'DEVICE#d1', sk: 'INVENTORY' });
  await table.put({ pk: 'DEVICE#d1', sk: 'POSTURE' });

  // Given d1 has 55 stored findings with distinct detectedAt values, two
  // sharing the newest detectedAt with findingIds "b" and "a"
  for (let i = 0; i < 53; i++) {
    const key = deviceAntivirusFinding('d1', `old-${String(i).padStart(2, '0')}`);
    await table.put({
      ...key,
      deviceId: 'd1',
      findingId: `old-${String(i).padStart(2, '0')}`,
      threatName: 'T',
      severity: 'low',
      detectedAt: `2026-09-${String(10 + (i % 20)).padStart(2, '0')}T00:00:00Z`,
      resources: [],
      remediated: false,
      firstReportedAt: '2026-09-01T00:00:00Z',
      lastReportedAt: '2026-09-01T00:00:00Z',
    });
  }
  const newest = '2026-10-02T12:00:00Z';
  await table.put({
    ...deviceAntivirusFinding('d1', 'b'),
    deviceId: 'd1',
    findingId: 'b',
    threatName: 'T',
    severity: 'low',
    detectedAt: newest,
    resources: [],
    remediated: false,
    firstReportedAt: newest,
    lastReportedAt: newest,
  });
  await table.put({
    ...deviceAntivirusFinding('d1', 'a'),
    deviceId: 'd1',
    findingId: 'a',
    threatName: 'T',
    severity: 'low',
    detectedAt: newest,
    resources: [],
    remediated: false,
    firstReportedAt: newest,
    lastReportedAt: newest,
  });

  // When an admin GETs /admin/api/v1/devices/d1
  const response = await makeRequest(router, 'GET', '/admin/api/v1/devices/d1', {
    headers: { authorization: 'Bearer valid-token' },
  });

  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);

  // Then antivirusFindings holds 50 entries, newest first, "a" before "b"
  assert.strictEqual(body.antivirusFindings.length, 50);
  assert.strictEqual(body.antivirusFindings[0].findingId, 'a');
  assert.strictEqual(body.antivirusFindings[1].findingId, 'b');
  for (let i = 1; i < body.antivirusFindings.length; i++) {
    assert.ok(
      body.antivirusFindings[i - 1].detectedAt >= body.antivirusFindings[i].detectedAt,
      'findings should be sorted by detectedAt descending',
    );
  }

  // With no pk, sk, gsi1pk or gsi1sk
  for (const finding of body.antivirusFindings) {
    assert.strictEqual(finding.pk, undefined);
    assert.strictEqual(finding.sk, undefined);
    assert.strictEqual(finding.gsi1pk, undefined);
    assert.strictEqual(finding.gsi1sk, undefined);
  }

  // And profile, inventory, posture and commands are still present
  assert.ok(body.profile);
  assert.ok(body.inventory);
  assert.ok(body.posture);
  assert.ok(Array.isArray(body.commands));
});

test('Scenario: A device with no findings returns antivirusFindings []', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  await table.put({
    pk: 'DEVICE#d1',
    sk: 'PROFILE',
    deviceId: 'd1',
    hostname: 'host-d1',
    platform: 'windows',
    osVersion: '11',
    agentVersion: '1.0',
  });

  const response = await makeRequest(router, 'GET', '/admin/api/v1/devices/d1', {
    headers: { authorization: 'Bearer valid-token' },
  });

  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.deepStrictEqual(body.antivirusFindings, []);
});

// ============================================================================
// Scenario: Unknown device detail
// ============================================================================

test('Scenario: Unknown device detail', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  // When an admin GETs /admin/api/v1/devices/nope
  const response = await makeRequest(router, 'GET', '/admin/api/v1/devices/nope', {
    headers: { authorization: 'Bearer valid-token' },
  });

  // Then the status is 404 and the error is not_found
  assert.strictEqual(response.statusCode, 404);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'not_found');
});

// ============================================================================
// Scenario: Audit range query
// ============================================================================

test('Scenario: Audit range query', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerAuditRoutes(router, { verifier, table });

  // Given entries on three consecutive days
  const day1 = '2026-10-01';
  const day2 = '2026-10-02';
  const day3 = '2026-10-03';

  // Add audit items for each day
  for (let i = 0; i < 5; i++) {
    await table.put({
      pk: `AUDIT#${day1}`,
      sk: `${String(1000 + i).padStart(13, '0')}-00000001`,
      action: 'test.action',
      actor: 'system',
      target: 'test',
      at: `${day1}T10:00:${String(i).padStart(2, '0')}Z`,
    });
  }

  for (let i = 0; i < 5; i++) {
    await table.put({
      pk: `AUDIT#${day2}`,
      sk: `${String(2000 + i).padStart(13, '0')}-00000002`,
      action: 'test.action',
      actor: 'system',
      target: 'test',
      at: `${day2}T10:00:${String(i).padStart(2, '0')}Z`,
    });
  }

  for (let i = 0; i < 5; i++) {
    await table.put({
      pk: `AUDIT#${day3}`,
      sk: `${String(3000 + i).padStart(13, '0')}-00000003`,
      action: 'test.action',
      actor: 'system',
      target: 'test',
      at: `${day3}T10:00:${String(i).padStart(2, '0')}Z`,
    });
  }

  // When an admin queries from day one to day two
  const response = await makeRequest(router, 'GET', '/admin/api/v1/audit', {
    headers: { authorization: 'Bearer valid-token' },
    query: {
      from: `${day1}T00:00:00Z`,
      to: `${day2}T23:59:59Z`,
    },
  });

  // Then only those days' entries are returned, newest day first and newest seq first within a day
  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.items.length, 10);
});

// ============================================================================
// Scenario: Inverted audit range is refused
// ============================================================================

test('Scenario: Inverted audit range is refused', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerAuditRoutes(router, { verifier, table });

  // When an admin queries with from after to
  const response = await makeRequest(router, 'GET', '/admin/api/v1/audit', {
    headers: { authorization: 'Bearer valid-token' },
    query: {
      from: '2026-10-03T00:00:00Z',
      to: '2026-10-01T00:00:00Z',
    },
  });

  // Then the status is 400 and the error is invalid_request
  assert.strictEqual(response.statusCode, 400);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'invalid_request');
});

// ============================================================================
// Scenario: Non-ISO audit bound is refused
// ============================================================================

test('Scenario: Non-ISO audit bound is refused', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerAuditRoutes(router, { verifier, table });

  // When an admin queries with from "yesterday"
  const response = await makeRequest(router, 'GET', '/admin/api/v1/audit', {
    headers: { authorization: 'Bearer valid-token' },
    query: {
      from: 'yesterday',
      to: '2026-10-02T00:00:00Z',
    },
  });

  // Then the status is 400 and the error is invalid_request
  assert.strictEqual(response.statusCode, 400);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'invalid_request');
});

// ============================================================================
// Scenario: Out-of-range limit is refused
// ============================================================================

test('Scenario: Out-of-range limit is refused', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  // When an admin lists devices with limit=500
  const response = await makeRequest(router, 'GET', '/admin/api/v1/devices', {
    headers: { authorization: 'Bearer valid-token' },
    query: { limit: '500' },
  });

  // Then the status is 400 and the error is invalid_request
  assert.strictEqual(response.statusCode, 400);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'invalid_request');
});

// ============================================================================
// Scenario: Secrets never leave the API
// ============================================================================

test('Scenario: Secrets never leave the API', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  const now = new Date('2026-10-02T10:00:00Z').toISOString().replace(/\.\d{3}Z$/, 'Z');

  // Add a device with secrets that should not leak
  await table.put({
    pk: 'DEVICE#d1',
    sk: 'PROFILE',
    deviceId: 'd1',
    hostname: 'host-d1',
    platform: 'linux',
    osVersion: '22.04',
    agentVersion: '1.0',
    lastSeenAt: now,
    secretEnc: 'should-not-appear',
    enrollmentTokenHash: 'should-not-appear',
    gsi1pk: 'DEVICE',
    gsi1sk: now,
  });

  // When an admin reads the device list
  const listResponse = await makeRequest(router, 'GET', '/admin/api/v1/devices', {
    headers: { authorization: 'Bearer valid-token' },
  });

  assert.strictEqual(listResponse.statusCode, 200);
  const listBody = JSON.parse(listResponse.body);

  // Then no response body contains secretEnc or any enrollment token hash
  for (const item of listBody.items) {
    assert(!item.secretEnc, 'secretEnc should not appear in list response');
    assert(!item.enrollmentTokenHash, 'enrollmentTokenHash should not appear in list response');
  }

  // And a device detail
  const detailResponse = await makeRequest(router, 'GET', '/admin/api/v1/devices/d1', {
    headers: { authorization: 'Bearer valid-token' },
  });

  assert.strictEqual(detailResponse.statusCode, 200);
  const detailBody = JSON.parse(detailResponse.body);

  assert(!detailBody.profile.secretEnc, 'secretEnc should not appear in detail profile');
  assert(!detailBody.profile.enrollmentTokenHash, 'enrollmentTokenHash should not appear in detail profile');
});

// ============================================================================
// Scenario: Invalid Authorization header format is refused
// ============================================================================

test('Scenario: Invalid Authorization header format is refused', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  // When using an Authorization header that is not of the Bearer form
  const response = await makeRequest(router, 'GET', '/admin/api/v1/devices', {
    headers: { authorization: 'Basic dXNlcjpwYXNz' },
  });

  // Then it is refused with the same 401 unauthorized
  assert.strictEqual(response.statusCode, 401);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.error, 'unauthorized');
});

// ============================================================================
// Scenario: Invalid limit values are refused
// ============================================================================

test('Scenario: Invalid limit values are refused', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerDeviceRoutes(router, { verifier, table });

  // Test limit = 0
  let response = await makeRequest(router, 'GET', '/admin/api/v1/devices', {
    headers: { authorization: 'Bearer valid-token' },
    query: { limit: '0' },
  });
  assert.strictEqual(response.statusCode, 400);

  // Test limit with non-decimal characters
  response = await makeRequest(router, 'GET', '/admin/api/v1/devices', {
    headers: { authorization: 'Bearer valid-token' },
    query: { limit: '50.5' },
  });
  assert.strictEqual(response.statusCode, 400);

  // Test negative limit
  response = await makeRequest(router, 'GET', '/admin/api/v1/devices', {
    headers: { authorization: 'Bearer valid-token' },
    query: { limit: '-10' },
  });
  assert.strictEqual(response.statusCode, 400);
});

// ============================================================================
// Scenario: Same-day audit range
// ============================================================================

test('Scenario: Same-day audit range returns entries for that day', async (t) => {
  const router = createRouter();
  const table = new FakeTable();
  const verifier = new StubVerifier();

  registerAuditRoutes(router, { verifier, table });

  const day = '2026-10-02';

  // Add audit items for the day
  for (let i = 0; i < 3; i++) {
    await table.put({
      pk: `AUDIT#${day}`,
      sk: `${String(1000 + i).padStart(13, '0')}-0000000${i}`,
      action: 'test.action',
      actor: 'system',
      target: 'test',
      at: `${day}T10:00:${String(i).padStart(2, '0')}Z`,
    });
  }

  // When an admin queries from and to the same UTC day
  const response = await makeRequest(router, 'GET', '/admin/api/v1/audit', {
    headers: { authorization: 'Bearer valid-token' },
    query: {
      from: `${day}T08:00:00Z`,
      to: `${day}T18:00:00Z`,
    },
  });

  // Then that day's entries are returned
  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.strictEqual(body.items.length, 3);
});
