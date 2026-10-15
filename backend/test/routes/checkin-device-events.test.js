/**
 * E2E and unit tests for TASK-067 (History view): the device events derived
 * during check-in (agent version changes, posture switches, Defender
 * protections applied, scheduled antivirus scans) and the check-in's
 * never-fails guarantee around them. Tests implement the ticket's Gherkin
 * scenarios (AC11-AC15, AC17) in Given/When/Then style using node:test. All
 * database calls are mocked; no real DB connection is ever made.
 */
import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const { createCheckInHandler } = await import(`file://${join(__dirname, '../../dist/routes/checkin.js')}`);
const { handleDeviceDetail } = await import(`file://${join(__dirname, '../../dist/admin/devices.js')}`);
const {
  deviceProfile,
  devicePosture,
  deviceDefenderHardening,
  deviceAntivirusScan,
} = await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);
const { FakeTable, PutFailingTable } = await import('../helpers/fakeTable.js');
const { assertValidDynamoExpressions } = await import('../helpers/dynamoExpressions.js');

const randomHex = (bytes = 32) => randomBytes(bytes).toString('hex');

const fullBody = {
  collectedAt: '2026-10-11T08:00:00Z',
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

function eventsOf(table, deviceId, type) {
  const { pk } = deviceProfile(deviceId);
  return table
    .all()
    .filter((item) => item.pk === pk && String(item.sk).startsWith('EVENT#') && (type === undefined || item.type === type));
}

function seedProfile(table, deviceId, extra = {}) {
  table.seed({ ...deviceProfile(deviceId), deviceId, platform: 'windows', ...extra });
}

// ============================================================================
// Scenario: An agent version change is recorded (AC11)
// ============================================================================

test('Scenario: An agent version change is recorded (AC11)', async () => {
  const table = new FakeTable();
  // Given the stored profile agentVersion is "1.4.0"
  seedProfile(table, 'dev-1', { agentVersion: '1.4.0' });
  const now = new Date('2026-10-11T09:00:00Z');

  // When a check-in posts agentVersion "1.5.0"
  const result = await handlerFor(table, now)(checkInRequest('dev-1', { ...fullBody, agentVersion: '1.5.0' }));
  assert.strictEqual(result.statusCode, 200);

  // Then one "agent.version_changed" event has the right summary
  const events = eventsOf(table, 'dev-1', 'agent.version_changed');
  assert.strictEqual(events.length, 1);
  assert.strictEqual(events[0].summary, 'Agent version changed from 1.4.0 to 1.5.0');
  assert.deepStrictEqual(events[0].details, { from: '1.4.0', to: '1.5.0' });
  assert.strictEqual(events[0].source, 'system');
});

// ============================================================================
// Scenario Outline: No version event without a real change (AC11)
// ============================================================================

const versionOutline = [
  { stored: undefined, posted: '1.5.0' },
  { stored: '1.5.0', posted: '1.5.0' },
  { stored: '1.5.0', posted: undefined },
];

for (const { stored, posted } of versionOutline) {
  test(`Scenario Outline: No version event without a real change (AC11) - stored ${stored} posted ${posted}`, async () => {
    const table = new FakeTable();
    seedProfile(table, 'dev-1', stored === undefined ? {} : { agentVersion: stored });
    const now = new Date('2026-10-11T09:00:00Z');
    const body = { ...fullBody };
    if (posted === undefined) {
      delete body.agentVersion;
    } else {
      body.agentVersion = posted;
    }
    const result = await handlerFor(table, now)(checkInRequest('dev-1', body));
    assert.strictEqual(result.statusCode, 200);
    assert.strictEqual(eventsOf(table, 'dev-1', 'agent.version_changed').length, 0);
  });
}

// ============================================================================
// Scenario: Posture switches are recorded (AC12)
// ============================================================================

test('Scenario: Posture switches are recorded (AC12)', async () => {
  const table = new FakeTable();
  seedProfile(table, 'dev-1');
  // Given the stored posture has antivirus.enabled false, firewall.enabled
  // true, diskEncryption.enabled true
  table.seed({
    ...devicePosture('dev-1'),
    deviceId: 'dev-1',
    antivirus: { enabled: false },
    firewall: { enabled: true },
    diskEncryption: { enabled: true },
  });
  const now = new Date('2026-10-11T09:00:00Z');

  // When a check-in posts antivirus.enabled true, firewall.enabled false,
  // diskEncryption.enabled true
  const body = {
    ...fullBody,
    posture: {
      ...fullBody.posture,
      antivirus: { ...fullBody.posture.antivirus, enabled: true },
      firewall: { enabled: false },
      diskEncryption: { ...fullBody.posture.diskEncryption, enabled: true },
    },
  };
  const result = await handlerFor(table, now)(checkInRequest('dev-1', body));
  assert.strictEqual(result.statusCode, 200);

  // Then events "Antivirus turned on" and "Firewall turned off" are written
  // with source "system"
  const events = eventsOf(table, 'dev-1', 'posture.changed');
  const summaries = events.map((event) => event.summary).sort();
  assert.deepStrictEqual(summaries, ['Antivirus turned on', 'Firewall turned off']);
  assert.ok(events.every((event) => event.source === 'system'));
  assert.deepStrictEqual(
    events.find((event) => event.summary === 'Antivirus turned on').details,
    { setting: 'antivirus', from: 'false', to: 'true' },
  );

  // And no "Disk encryption" event is written (unchanged)
  assert.ok(!events.some((event) => event.summary.startsWith('Disk encryption')));
});

// ============================================================================
// Scenario: First posture report records nothing (AC12)
// ============================================================================

test('Scenario: First posture report records nothing (AC12)', async () => {
  const table = new FakeTable();
  // Given the device has no stored POSTURE item
  seedProfile(table, 'dev-1');
  const now = new Date('2026-10-11T09:00:00Z');

  // When a check-in posts antivirus.enabled true
  const result = await handlerFor(table, now)(checkInRequest('dev-1', fullBody));
  assert.strictEqual(result.statusCode, 200);

  // Then no "posture.changed" event is written
  assert.strictEqual(eventsOf(table, 'dev-1', 'posture.changed').length, 0);
});

// ============================================================================
// Scenario: Defender protections applied are recorded once (AC13)
// ============================================================================

test('Scenario: Defender protections applied are recorded once (AC13)', async () => {
  const table = new FakeTable();
  seedProfile(table, 'dev-1');
  const T1 = '2026-10-10T00:00:00Z';
  // Given the stored DEFENDERHARDENING evaluatedAt is T1
  table.seed({ ...deviceDefenderHardening('dev-1'), deviceId: 'dev-1', evaluatedAt: T1, items: [] });
  const now = new Date('2026-10-11T09:00:00Z');
  const T2 = '2026-10-11T08:00:00Z';

  // When a check-in posts defenderHardening evaluatedAt T2 with
  // realTimeMonitoring "applied", puaProtection "ok", signatureUpdate "applied"
  const body = {
    ...fullBody,
    defenderHardening: {
      evaluatedAt: T2,
      items: [
        { item: 'realTimeMonitoring', state: 'applied' },
        { item: 'puaProtection', state: 'ok' },
        { item: 'signatureUpdate', state: 'applied' },
      ],
    },
  };
  const result = await handlerFor(table, now)(checkInRequest('dev-1', body));
  assert.strictEqual(result.statusCode, 200);

  // Then one "defender.protections_applied" event has the right summary,
  // details.items (a string) and occurredAt T2
  const events = eventsOf(table, 'dev-1', 'defender.protections_applied');
  assert.strictEqual(events.length, 1);
  assert.strictEqual(events[0].summary, 'Defender protections applied: realTimeMonitoring, signatureUpdate');
  assert.strictEqual(events[0].details.items, 'realTimeMonitoring, signatureUpdate');
  assert.strictEqual(events[0].details.evaluatedAt, T2);
  assert.strictEqual(events[0].occurredAt, T2);

  // When the same body is posted again
  const again = await handlerFor(table, now)(checkInRequest('dev-1', body));
  assert.strictEqual(again.statusCode, 200);

  // Then no second "defender.protections_applied" event exists
  assert.strictEqual(eventsOf(table, 'dev-1', 'defender.protections_applied').length, 1);
});

// ============================================================================
// Scenario: A fractional-seconds evaluatedAt is normalised for occurredAt only (AC2, AC13)
// ============================================================================

test('Scenario: A fractional-seconds evaluatedAt is normalised for occurredAt only (AC2, AC13)', async () => {
  const table = new FakeTable();
  seedProfile(table, 'dev-1');
  const T1 = '2026-10-10T00:00:00Z';
  table.seed({ ...deviceDefenderHardening('dev-1'), deviceId: 'dev-1', evaluatedAt: T1, items: [] });
  const now = new Date('2026-10-11T09:00:00Z');
  const rawEvaluatedAt = '2026-10-12T01:02:03.456Z';

  const body = {
    ...fullBody,
    defenderHardening: { evaluatedAt: rawEvaluatedAt, items: [{ item: 'realTimeMonitoring', state: 'applied' }] },
  };
  const result = await handlerFor(table, now)(checkInRequest('dev-1', body));
  assert.strictEqual(result.statusCode, 200);

  const events = eventsOf(table, 'dev-1', 'defender.protections_applied');
  assert.strictEqual(events.length, 1);
  // One "defender.protections_applied" event has occurredAt
  // "2026-10-12T01:02:03Z", an sk starting "EVENT#2026-10-12T01:02:03Z#"
  assert.strictEqual(events[0].occurredAt, '2026-10-12T01:02:03Z');
  assert.match(events[0].sk, /^EVENT#2026-10-12T01:02:03Z#/);
  // ttl epoch(2026-10-12T01:02:03Z)+2592000
  assert.strictEqual(events[0].ttl, Math.floor(Date.parse('2026-10-12T01:02:03Z') / 1000) + 2592000);
  // Its eventId is the first 32 hex characters of
  // sha256("defender.protections_applied\n2026-10-12T01:02:03.456Z")
  const expectedEventId = createHash('sha256')
    .update(`defender.protections_applied\n${rawEvaluatedAt}`)
    .digest('hex')
    .slice(0, 32);
  assert.strictEqual(events[0].eventId, expectedEventId);

  // When the same body is posted again, no second event exists
  const again = await handlerFor(table, now)(checkInRequest('dev-1', body));
  assert.strictEqual(again.statusCode, 200);
  assert.strictEqual(eventsOf(table, 'dev-1', 'defender.protections_applied').length, 1);
});

// ============================================================================
// Scenario: A block with nothing applied records nothing (AC13)
// ============================================================================

test('Scenario: A block with nothing applied records nothing (AC13)', async () => {
  const table = new FakeTable();
  seedProfile(table, 'dev-1');
  const now = new Date('2026-10-11T09:00:00Z');

  const body = {
    ...fullBody,
    defenderHardening: {
      evaluatedAt: '2026-10-11T08:00:00Z',
      items: [
        { item: 'realTimeMonitoring', state: 'ok' },
        { item: 'puaProtection', state: 'failed' },
      ],
    },
  };
  const result = await handlerFor(table, now)(checkInRequest('dev-1', body));
  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(eventsOf(table, 'dev-1', 'defender.protections_applied').length, 0);
});

// ============================================================================
// Scenario Outline: A new scan result is recorded (AC14)
// ============================================================================

const scanOutline = [
  { result: 'clean', n: 0, summary: 'Quick scan completed: clean' },
  { result: 'threats_found', n: 2, summary: 'Quick scan completed: 2 threats found' },
  { result: 'failed', n: 0, summary: 'Quick scan failed' },
  { result: 'timeout', n: 0, summary: 'Quick scan timed out' },
];

for (const { result: scanResult, n, summary } of scanOutline) {
  test(`Scenario Outline: A new scan result is recorded (AC14) - ${scanResult}`, async () => {
    const table = new FakeTable();
    seedProfile(table, 'dev-1');
    const S1 = '2026-10-10T00:00:00Z';
    // Given the stored AVSCAN startedAt is S1
    table.seed({ ...deviceAntivirusScan('dev-1'), deviceId: 'dev-1', startedAt: S1, result: 'clean', threatsFound: 0 });
    const now = new Date('2026-10-11T09:00:00Z');
    const S2 = '2026-10-11T08:00:00Z';
    const C2 = '2026-10-11T08:05:00Z';

    // When a check-in posts antivirusScan result, threatsFound, startedAt S2,
    // completedAt C2
    const body = {
      ...fullBody,
      antivirusScan: { scanType: 'quick', result: scanResult, threatsFound: n, startedAt: S2, completedAt: C2 },
    };
    const outcome = await handlerFor(table, now)(checkInRequest('dev-1', body));
    assert.strictEqual(outcome.statusCode, 200);

    // Then one "antivirus.scan" event has the right summary, details and occurredAt C2
    const events = eventsOf(table, 'dev-1', 'antivirus.scan');
    assert.strictEqual(events.length, 1);
    assert.strictEqual(events[0].summary, summary);
    assert.strictEqual(events[0].details.threatsFound, String(n));
    assert.strictEqual(events[0].details.result, scanResult);
    assert.strictEqual(events[0].occurredAt, C2);
  });
}

// ============================================================================
// Scenario: An unchanged or unsupported scan records nothing (AC14)
// ============================================================================

test('Scenario: An unchanged or unsupported scan records nothing (AC14)', async () => {
  const table = new FakeTable();
  seedProfile(table, 'dev-1');
  const S1 = '2026-10-10T00:00:00Z';
  table.seed({ ...deviceAntivirusScan('dev-1'), deviceId: 'dev-1', startedAt: S1, result: 'clean', threatsFound: 0 });
  const now = new Date('2026-10-11T09:00:00Z');

  // When a check-in posts the stored scan again with startedAt S1
  const unchanged = {
    ...fullBody,
    antivirusScan: { scanType: 'quick', result: 'clean', threatsFound: 0, startedAt: S1, completedAt: null },
  };
  const first = await handlerFor(table, now)(checkInRequest('dev-1', unchanged));
  assert.strictEqual(first.statusCode, 200);
  assert.strictEqual(eventsOf(table, 'dev-1', 'antivirus.scan').length, 0);

  // And a check-in posts result "unsupported" with startedAt null
  const unsupported = {
    ...fullBody,
    antivirusScan: { scanType: 'quick', result: 'unsupported', threatsFound: 0, startedAt: null, completedAt: null },
  };
  const second = await handlerFor(table, now)(checkInRequest('dev-1', unsupported));
  assert.strictEqual(second.statusCode, 200);

  // Then no "antivirus.scan" event is written
  assert.strictEqual(eventsOf(table, 'dev-1', 'antivirus.scan').length, 0);
});

// ============================================================================
// Scenario: Event derivation never changes the check-in answer (AC15)
// ============================================================================

test('Scenario: Event derivation never changes the check-in answer (AC15)', async () => {
  const now = new Date('2026-10-11T09:00:00Z');
  const body = {
    ...fullBody,
    agentVersion: '1.5.0',
    posture: { ...fullBody.posture, antivirus: { ...fullBody.posture.antivirus, enabled: false } },
    antivirusScan: { scanType: 'quick', result: 'clean', threatsFound: 0, startedAt: '2026-10-11T08:00:00Z', completedAt: '2026-10-11T08:05:00Z' },
  };

  function seeded(table) {
    seedProfile(table, 'dev-1', { agentVersion: '1.4.0' });
    table.seed({ ...devicePosture('dev-1'), deviceId: 'dev-1', antivirus: { enabled: true } });
  }

  const workingTable = new FakeTable();
  seeded(workingTable);
  const workingResult = await handlerFor(workingTable, now)(checkInRequest('dev-1', body));
  assert.strictEqual(workingResult.statusCode, 200);

  // Given a table whose put throws for any sk starting "EVENT#"
  const failingTable = new PutFailingTable('EVENT#');
  seeded(failingTable);

  // When a check-in arrives that changes agentVersion, posture and carries a new scan
  const failingResult = await handlerFor(failingTable, now)(checkInRequest('dev-1', body));

  // Then the response is 200 and its body equals the body produced with a working table
  assert.strictEqual(failingResult.statusCode, 200);
  assert.deepStrictEqual(failingResult.body, workingResult.body);
  assert.strictEqual(failingTable.withSkPrefix('EVENT#').length, 0);
});

// ============================================================================
// Scenario: A quiet check-in writes no events (AC15)
// ============================================================================

test('Scenario: A quiet check-in writes no events (AC15)', async () => {
  const table = new FakeTable();
  seedProfile(table, 'dev-1', { agentVersion: '1.4.0' });
  table.seed({
    ...devicePosture('dev-1'),
    deviceId: 'dev-1',
    antivirus: { enabled: true },
    firewall: { enabled: true },
    diskEncryption: { enabled: true },
  });
  const hardeningAt = '2026-10-10T00:00:00Z';
  table.seed({ ...deviceDefenderHardening('dev-1'), deviceId: 'dev-1', evaluatedAt: hardeningAt, items: [] });
  const scanAt = '2026-10-10T00:00:00Z';
  table.seed({ ...deviceAntivirusScan('dev-1'), deviceId: 'dev-1', startedAt: scanAt, result: 'clean', threatsFound: 0 });
  const now = new Date('2026-10-11T09:00:00Z');

  // When a check-in arrives with the same agentVersion, posture, hardening
  // evaluatedAt and scan startedAt as stored
  const body = {
    ...fullBody,
    agentVersion: '1.4.0',
    defenderHardening: { evaluatedAt: hardeningAt, items: [{ item: 'realTimeMonitoring', state: 'applied' }] },
    antivirusScan: { scanType: 'quick', result: 'clean', threatsFound: 0, startedAt: scanAt, completedAt: null },
  };
  const result = await handlerFor(table, now)(checkInRequest('dev-1', body));
  assert.strictEqual(result.statusCode, 200);

  // Then no item with an sk starting "EVENT#" is written
  assert.strictEqual(table.withSkPrefix('EVENT#').length, 0);
});

// ============================================================================
// Scenario: Expressions pass the reserved-word validator (AC17)
// ============================================================================

/** The same validating fake used by checkin-dynamo-expressions.test.js. */
class ValidatingTable {
  constructor() {
    this.items = new Map();
  }
  keyOf(key) {
    return `${key.pk}|${key.sk}`;
  }
  seed(item) {
    this.items.set(this.keyOf(item), { ...item });
  }
  async get(key) {
    return this.items.get(this.keyOf(key));
  }
  async put(item, fields) {
    assertValidDynamoExpressions(fields);
    this.items.set(this.keyOf(item), { ...item });
  }
  async putIfAbsent(item) {
    if (this.items.has(this.keyOf(item))) return { written: false };
    this.items.set(this.keyOf(item), { ...item });
    return { written: true };
  }
  async update(key, fields) {
    assertValidDynamoExpressions(fields);
    const updated = { ...(this.items.get(this.keyOf(key)) ?? {}), ...key };
    this.items.set(this.keyOf(key), updated);
    return updated;
  }
  async query(request) {
    assertValidDynamoExpressions(request);
    const values = request.ExpressionAttributeValues ?? {};
    return { items: [...this.items.values()].filter((item) => item.pk === values[':pk']), cursor: null };
  }
  async delete(key) {
    this.items.delete(this.keyOf(key));
  }
}

test('Scenario: Expressions pass the reserved-word validator (AC17)', async () => {
  const table = new ValidatingTable();
  table.seed({ ...deviceProfile('dev-1'), deviceId: 'dev-1', platform: 'windows', agentVersion: '1.4.0' });
  table.seed({ ...devicePosture('dev-1'), deviceId: 'dev-1', antivirus: { enabled: false } });
  table.seed({ ...deviceDefenderHardening('dev-1'), deviceId: 'dev-1', evaluatedAt: '2026-10-10T00:00:00Z', items: [] });
  table.seed({ ...deviceAntivirusScan('dev-1'), deviceId: 'dev-1', startedAt: '2026-10-10T00:00:00Z', result: 'clean', threatsFound: 0 });
  const now = new Date('2026-10-11T09:00:00Z');

  // When a check-in deriving every event type is handled
  const body = {
    ...fullBody,
    agentVersion: '1.5.0',
    posture: { ...fullBody.posture, antivirus: { ...fullBody.posture.antivirus, enabled: true } },
    defenderHardening: {
      evaluatedAt: '2026-10-11T08:00:00Z',
      items: [{ item: 'realTimeMonitoring', state: 'applied' }],
    },
    antivirusScan: {
      scanType: 'quick',
      result: 'threats_found',
      threatsFound: 1,
      startedAt: '2026-10-11T08:00:00Z',
      completedAt: '2026-10-11T08:05:00Z',
    },
  };
  // Then no ValidationException is raised
  const result = await handlerFor(table, now)(checkInRequest('dev-1', body));
  assert.strictEqual(result.statusCode, 200, JSON.stringify(result.body));

  // And the device detail is read without a ValidationException either
  const detail = await handleDeviceDetail(
    { params: { deviceId: 'dev-1' }, query: {}, headers: {} },
    { table, now: () => now },
  );
  assert.strictEqual(detail.statusCode, 200);
  assert.ok(detail.body.deviceEvents.length > 0);
});
