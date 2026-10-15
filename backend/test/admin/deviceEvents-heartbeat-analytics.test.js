/**
 * E2E and unit tests for TASK-067 (History view): the device events written by
 * the heartbeat and analytics-collection switches. Tests implement the
 * ticket's Gherkin scenarios (Scenario Outline, AC8) in Given/When/Then style
 * using node:test. All database calls are mocked; no real DB connection is
 * ever made.
 */
import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const { handleHeartbeatSet } = await import(`file://${join(__dirname, '../../dist/admin/heartbeat.js')}`);
const { handleAnalyticsCollectionSet } = await import(`file://${join(__dirname, '../../dist/admin/analytics.js')}`);
const { deviceProfile } = await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);
const { FakeTable } = await import('../helpers/fakeTable.js');

const claims = { preferred_username: 'alice@x' };

function profile(deviceId) {
  return { ...deviceProfile(deviceId), deviceId, hostname: `host-${deviceId}` };
}

function eventsOf(table, deviceId) {
  const { pk } = deviceProfile(deviceId);
  return table.all().filter((item) => item.pk === pk && item.sk.startsWith('EVENT#'));
}

function heartbeatRequest(deviceId, body) {
  return { params: { deviceId }, query: {}, headers: {}, body: JSON.stringify(body), claims };
}

function analyticsRequest(deviceId, body) {
  return { params: { deviceId }, query: {}, headers: {}, body: JSON.stringify(body), claims };
}

// ============================================================================
// Scenario Outline: Heartbeat and analytics switches are recorded (AC8)
// ============================================================================

const outline = [
  {
    action: 'turns heartbeat on every 300 seconds',
    type: 'heartbeat.changed',
    summary: 'Heartbeat turned on (every 300 seconds)',
    call: (table, now) =>
      handleHeartbeatSet(heartbeatRequest('dev-1', { enabled: true, intervalSeconds: 300 }), { table, now: () => now }),
  },
  {
    action: 'turns heartbeat off',
    type: 'heartbeat.changed',
    summary: 'Heartbeat turned off',
    call: (table, now) =>
      handleHeartbeatSet(heartbeatRequest('dev-1', { enabled: false, intervalSeconds: 300 }), { table, now: () => now }),
  },
  {
    action: 'turns analytics collection off',
    type: 'analytics_collection.changed',
    summary: 'Analytics collection turned off',
    call: (table, now) =>
      handleAnalyticsCollectionSet(analyticsRequest('dev-1', { enabled: false }), { table, now: () => now }),
  },
];

for (const { action, type, summary } of outline) {
  test(`Scenario Outline: Heartbeat and analytics switches are recorded (AC8) - ${action}`, async () => {
    const table = new FakeTable();
    table.seed(profile('dev-1'));
    const now = new Date('2026-10-12T01:00:00Z');

    const result = await outline.find((entry) => entry.action === action).call(table, now);
    assert.strictEqual(result.statusCode, 200);

    const events = eventsOf(table, 'dev-1');
    assert.strictEqual(events.length, 1);
    assert.strictEqual(events[0].type, type);
    assert.strictEqual(events[0].summary, summary);
    assert.strictEqual(events[0].source, 'admin');
  });
}

test('Unit: analytics collection turned on is recorded (AC8)', async () => {
  const table = new FakeTable();
  table.seed(profile('dev-1'));
  const result = await handleAnalyticsCollectionSet(analyticsRequest('dev-1', { enabled: true }), {
    table,
    now: () => new Date('2026-10-12T01:00:00Z'),
  });
  assert.strictEqual(result.statusCode, 200);
  const events = eventsOf(table, 'dev-1');
  assert.strictEqual(events.length, 1);
  assert.strictEqual(events[0].summary, 'Analytics collection turned on');
});

// ============================================================================
// Scenario: An invalid heartbeat request records nothing (AC8)
// ============================================================================

test('Scenario: An invalid heartbeat request records nothing (AC8)', async () => {
  const table = new FakeTable();
  table.seed(profile('dev-1'));

  // When an admin sets heartbeat interval 7 seconds for "dev-1"
  const result = await handleHeartbeatSet(heartbeatRequest('dev-1', { enabled: true, intervalSeconds: 7 }), {
    table,
    now: () => new Date('2026-10-12T01:00:00Z'),
  });

  // Then the response is 400 and no EVENT# item is written
  assert.strictEqual(result.statusCode, 400);
  assert.strictEqual(eventsOf(table, 'dev-1').length, 0);
});

test('Unit: an invalid analytics-collection request records nothing (AC8)', async () => {
  const table = new FakeTable();
  table.seed(profile('dev-1'));
  const result = await handleAnalyticsCollectionSet(analyticsRequest('dev-1', { enabled: 'yes' }), {
    table,
    now: () => new Date('2026-10-12T01:00:00Z'),
  });
  assert.strictEqual(result.statusCode, 400);
  assert.strictEqual(eventsOf(table, 'dev-1').length, 0);
});

test('Unit: an unknown device writes no heartbeat event', async () => {
  const table = new FakeTable();
  const result = await handleHeartbeatSet(heartbeatRequest('ghost', { enabled: true, intervalSeconds: 300 }), {
    table,
    now: () => new Date('2026-10-12T01:00:00Z'),
  });
  assert.strictEqual(result.statusCode, 404);
  assert.strictEqual(eventsOf(table, 'ghost').length, 0);
});
