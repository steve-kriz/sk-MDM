/**
 * E2E and unit tests for TASK-070 (agent-reported actions): the agent's
 * `agentActions` array becomes one `source: 'agent'` device event per kept
 * entry, through `recordAgentActions` / `sanitiseAgentActions` in
 * backend/src/routes/checkin.ts. Tests implement the ticket's Gherkin
 * scenarios for AC16-AC19. Mock all database calls -- no real DB connections.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const { createCheckInHandler, MAX_AGENT_ACTIONS } = await import(
  `file://${join(__dirname, '../../dist/routes/checkin.js')}`
);
const { deviceProfile, DEVICE_EVENT_SK_PREFIX } = await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);
const { FakeTable, PutFailingTable, captureWarnings } = await import('../helpers/fakeTable.js');

const randomHex = (bytes = 32) => randomBytes(bytes).toString('hex');

const EVENT_SK_PREFIX = DEVICE_EVENT_SK_PREFIX ?? 'EVENT#';

function agentEventsOf(table, deviceId) {
  const { pk } = deviceProfile(deviceId);
  return table.all().filter((item) => item.pk === pk && item.sk.startsWith(EVENT_SK_PREFIX) && item.source === 'agent');
}

const fullBody = {
  collectedAt: '2026-10-12T01:00:00Z',
  agentVersion: '1.4.0',
  inventory: {
    hardware: { manufacturer: 'Dell', model: 'OptiPlex', serialNumber: 'S1', cpu: 'i7', ramBytes: 1, diskBytes: 1 },
    os: { name: 'Windows', version: '11', build: '22621', architecture: 'x86_64' },
    software: [],
    warnings: [],
  },
  posture: {
    diskEncryption: { enabled: true, method: 'bitlocker' },
    firewall: { enabled: true },
    antivirus: { name: 'Microsoft Defender', enabled: true, definitionsAgeDays: 1 },
    screenLock: { enabled: true, timeoutSeconds: 300 },
    osUpdates: { pendingCount: 0, lastInstalledAt: null },
    warnings: [],
  },
};

function checkInRequest(deviceId, body) {
  return {
    method: 'POST',
    path: `/api/v1/devices/${deviceId}/checkin`,
    query: {},
    headers: {
      'x-mdm-device-id': deviceId,
      'x-mdm-timestamp': Math.floor(Date.now() / 1000).toString(),
      'x-mdm-nonce': randomHex(16),
      'x-mdm-signature': randomHex(32),
    },
    params: { deviceId },
    body: JSON.stringify(body),
  };
}

function handlerFor(table, now) {
  return createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => now,
    verifyDevice: async (req) => ({ ok: true, deviceId: req.params.deviceId }),
  });
}

function withAgentActions(agentActions) {
  return { ...fullBody, agentActions };
}

function profile(deviceId) {
  return { ...deviceProfile(deviceId), deviceId, platform: 'windows' };
}

// ============================================================================
// Scenario Outline: Each action type becomes one agent event (AC16)
// ============================================================================

test('Scenario Outline: Each action type becomes one agent event (AC16)', async () => {
  const cases = [
    { type: 'enforce.firewall_enabled', details: {}, summary: 'Firewall turned on by policy' },
    { type: 'enforce.antivirus_enabled', details: {}, summary: 'Antivirus real-time protection turned on by policy' },
    { type: 'enforce.domains_updated', details: { blockedCount: '4' }, summary: 'Blocked domains updated: 4 names blocked' },
    { type: 'enforce.domains_updated', details: { blockedCount: '0' }, summary: 'Blocked domains cleared' },
    { type: 'enforce.domains_updated', details: { blockedCount: 'lots' }, summary: 'Blocked domains updated' },
    {
      type: 'agent.update_rolled_back',
      details: { installedVersion: '1.5.0', runningVersion: '1.4.9' },
      summary: 'Agent update to 1.5.0 rolled back',
    },
    { type: 'agent.update_rolled_back', details: {}, summary: 'Agent update rolled back' },
  ];

  for (const { type, details, summary } of cases) {
    await test(`${type} ${JSON.stringify(details)}`, async () => {
      const table = new FakeTable();
      table.seed(profile('dev-1'));
      const now = new Date('2026-10-12T01:05:00Z');

      const occurredAt = '2026-10-12T01:02:03.456Z';
      const result = await handlerFor(table, now)(
        checkInRequest('dev-1', withAgentActions([{ type, occurredAt, details }])),
      );
      assert.strictEqual(result.statusCode, 200, JSON.stringify(result.body));

      const events = agentEventsOf(table, 'dev-1');
      assert.strictEqual(events.length, 1, `expected exactly one agent event, got ${JSON.stringify(events)}`);
      const event = events[0];
      assert.strictEqual(event.source, 'agent');
      assert.strictEqual(event.actor, null);
      assert.strictEqual(event.type, type);
      assert.strictEqual(event.summary, summary);
      // occurredAt normalised to seconds: the ".456" is dropped.
      assert.strictEqual(event.occurredAt, '2026-10-12T01:02:03Z');

      const expectedEventId = createHash('sha256').update(`${type}\n2026-10-12T01:02:03Z`).digest('hex').slice(0, 32);
      assert.strictEqual(event.eventId, expectedEventId);
      assert.strictEqual(event.sk, `${EVENT_SK_PREFIX}2026-10-12T01:02:03Z#${expectedEventId}`);
    });
  }
});

// ============================================================================
// Scenario Outline: Malformed actions are dropped without refusing the
// check-in (AC17)
// ============================================================================

test('Scenario Outline: Malformed actions are dropped without refusing the check-in (AC17)', async () => {
  const now = new Date('2026-10-12T01:00:00Z');
  const futureAt = new Date(now.getTime() + 2 * 24 * 60 * 60 * 1000).toISOString();
  const tooOldAt = new Date(now.getTime() - 31 * 24 * 60 * 60 * 1000).toISOString();

  const cases = [
    { name: 'a non-array value', value: 'not-an-array', stored: 0 },
    {
      name: 'an unknown type',
      value: [{ type: 'enforce.firewall_disabled', occurredAt: '2026-10-12T00:59:00Z', details: {} }],
      stored: 0,
    },
    {
      name: 'an unparseable occurredAt',
      value: [{ type: 'enforce.firewall_enabled', occurredAt: 'yesterday', details: {} }],
      stored: 0,
    },
    {
      name: 'occurredAt 2 days ahead',
      value: [{ type: 'enforce.firewall_enabled', occurredAt: futureAt, details: {} }],
      stored: 0,
    },
    {
      name: 'occurredAt 31 days ago',
      value: [{ type: 'enforce.firewall_enabled', occurredAt: tooOldAt, details: {} }],
      stored: 0,
    },
    { name: 'a string entry', value: ['a string entry'], stored: 0 },
    {
      name: '25 valid actions with distinct occurredAt, only 20 stored',
      value: Array.from({ length: 25 }, (_, i) => ({
        type: 'enforce.firewall_enabled',
        occurredAt: new Date(now.getTime() - i * 1000).toISOString(),
        details: {},
      })),
      stored: MAX_AGENT_ACTIONS,
    },
  ];

  for (const { name, value, stored } of cases) {
    await test(name, async () => {
      const table = new FakeTable();
      table.seed(profile('dev-1'));

      const result = await handlerFor(table, now)(checkInRequest('dev-1', withAgentActions(value)));

      assert.strictEqual(result.statusCode, 200, `expected 200 for ${name}, got ${JSON.stringify(result.body)}`);
      assert.strictEqual(agentEventsOf(table, 'dev-1').length, stored, `expected ${stored} stored events for ${name}`);
    });
  }
});

test('Edge: a non-object entry is dropped without refusing the check-in (AC17)', async () => {
  const table = new FakeTable();
  table.seed(profile('dev-1'));
  const now = new Date('2026-10-12T01:00:00Z');

  const result = await handlerFor(table, now)(
    checkInRequest('dev-1', withAgentActions([42, null, { type: 'enforce.firewall_enabled', occurredAt: '2026-10-12T00:59:00Z', details: {} }])),
  );
  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(agentEventsOf(table, 'dev-1').length, 1);
});

// ============================================================================
// Scenario: Details are sanitised (AC17)
// ============================================================================

test('Scenario: Details are sanitised (AC17)', async () => {
  const table = new FakeTable();
  table.seed(profile('dev-1'));
  const now = new Date('2026-10-12T01:00:00Z');

  const details = { blockedCount: '3', n: 5 };
  for (let i = 1; i <= 9; i += 1) {
    details[`k${i}`] = i === 9 ? 'x'.repeat(300) : `v${i}`;
  }

  const result = await handlerFor(table, now)(
    checkInRequest(
      'dev-1',
      withAgentActions([{ type: 'enforce.domains_updated', occurredAt: '2026-10-12T00:59:00Z', details }]),
    ),
  );
  assert.strictEqual(result.statusCode, 200, JSON.stringify(result.body));

  const events = agentEventsOf(table, 'dev-1');
  assert.strictEqual(events.length, 1);
  const stored = events[0].details;

  // Only string values are kept: "n" (a number) is dropped.
  assert.strictEqual(stored.n, undefined);
  // At most 8 entries are kept (blockedCount + 7 of the 9 k* string keys).
  assert.strictEqual(Object.keys(stored).length, 8);
  assert.strictEqual(stored.blockedCount, '3');
  // Every stored value is a string of at most 256 characters.
  for (const value of Object.values(stored)) {
    assert.strictEqual(typeof value, 'string');
    assert.ok(value.length <= 256, `value ${JSON.stringify(value)} longer than 256 characters`);
  }
});

// ============================================================================
// Scenario: A spool re-send writes no second event (AC18)
// ============================================================================

test('Scenario: A spool re-send writes no second event (AC18)', async () => {
  const table = new FakeTable();
  table.seed(profile('dev-1'));
  const now = new Date('2026-10-12T01:00:00Z');

  const body = withAgentActions([
    { type: 'enforce.firewall_enabled', occurredAt: '2026-10-12T00:59:00Z', details: {} },
    { type: 'enforce.domains_updated', occurredAt: '2026-10-12T00:59:01Z', details: { blockedCount: '2' } },
  ]);

  const first = await handlerFor(table, now)(checkInRequest('dev-1', body));
  assert.strictEqual(first.statusCode, 200);
  const firstEvents = agentEventsOf(table, 'dev-1');
  assert.strictEqual(firstEvents.length, 2);
  const firstSks = firstEvents.map((e) => e.sk).sort();

  // When the same body is posted again (a spool re-send)
  const second = await handlerFor(table, now)(checkInRequest('dev-1', body));
  assert.strictEqual(second.statusCode, 200);

  // Then exactly two agent EVENT# items exist, with the same sk as before
  const secondEvents = agentEventsOf(table, 'dev-1');
  assert.strictEqual(secondEvents.length, 2);
  assert.deepStrictEqual(secondEvents.map((e) => e.sk).sort(), firstSks);
});

test('Edge: two entries in one body with the same type and normalised occurredAt collapse into one item (AC18)', async () => {
  const table = new FakeTable();
  table.seed(profile('dev-1'));
  const now = new Date('2026-10-12T01:00:00Z');

  // Both occurredAt values normalise to the same second.
  const result = await handlerFor(table, now)(
    checkInRequest(
      'dev-1',
      withAgentActions([
        { type: 'enforce.firewall_enabled', occurredAt: '2026-10-12T00:59:00.000Z', details: {} },
        { type: 'enforce.firewall_enabled', occurredAt: '2026-10-12T00:59:00.900Z', details: {} },
      ]),
    ),
  );
  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(agentEventsOf(table, 'dev-1').length, 1);
});

// ============================================================================
// Scenario: A check-in without actions writes no agent event (AC19)
// ============================================================================

test('Scenario: A check-in without actions writes no agent event (AC19)', async () => {
  const table = new FakeTable();
  table.seed(profile('dev-1'));
  const now = new Date('2026-10-12T01:00:00Z');

  const withoutActions = await handlerFor(table, now)(checkInRequest('dev-1', fullBody));
  const withEmptyActions = (() => {
    const tableB = new FakeTable();
    tableB.seed(profile('dev-1'));
    return { tableB };
  })();

  assert.strictEqual(withoutActions.statusCode, 200);
  assert.strictEqual(agentEventsOf(table, 'dev-1').length, 0);

  // And the response body is unchanged relative to the same request made
  // against a device with nothing agent-action-related stored.
  const control = await handlerFor(withEmptyActions.tableB, now)(checkInRequest('dev-1', fullBody));
  assert.deepStrictEqual(withoutActions.body, control.body);
});

// ============================================================================
// Scenario: A failing event store still answers 200 (AC19)
// ============================================================================

test('Scenario: A failing event store still answers 200 (AC19)', async () => {
  const workingTable = new FakeTable();
  workingTable.seed(profile('dev-1'));
  const now = new Date('2026-10-12T01:00:00Z');
  const body = withAgentActions([{ type: 'enforce.firewall_enabled', occurredAt: '2026-10-12T00:59:00Z', details: {} }]);

  const workingResult = await handlerFor(workingTable, now)(checkInRequest('dev-1', body));
  assert.strictEqual(workingResult.statusCode, 200);

  // Given a table whose put throws for any sk starting "EVENT#"
  const failingTable = new PutFailingTable(EVENT_SK_PREFIX);
  failingTable.seed(profile('dev-1'));

  let failingResult;
  const warnings = await captureWarnings(async () => {
    failingResult = await handlerFor(failingTable, now)(checkInRequest('dev-1', body));
  });

  // Then the response is 200 with the same body as with a working table
  assert.strictEqual(failingResult.statusCode, 200, JSON.stringify(failingResult.body));
  assert.deepStrictEqual(failingResult.body, workingResult.body);
  assert.strictEqual(agentEventsOf(failingTable, 'dev-1').length, 0);
  // And the failure is logged, not thrown out of the handler.
  assert.ok(warnings.some((line) => line.includes('device event not recorded')), `expected a warn line, got ${JSON.stringify(warnings)}`);
});
