/**
 * E2E tests for TASK-069 (software changes history): the check-in handler's
 * derivation of `software.*` events from the diff between the stored and
 * posted inventory. Tests implement the ticket's Gherkin scenarios
 * (AC4-AC14) in Given/When/Then style using node:test, following the
 * fake-table and signed-request patterns of checkin-agent-errors.test.js and
 * checkin-device-events.test.js. All database calls are mocked; no real DB
 * connection is ever made.
 */
import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const { createCheckInHandler } = await import(`file://${join(__dirname, '../../dist/routes/checkin.js')}`);
const { deviceProfile, deviceInventory } = await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);
const { FakeTable } = await import('../helpers/fakeTable.js');
const { assertValidDynamoExpressions } = await import('../helpers/dynamoExpressions.js');

const randomHex = (bytes = 32) => randomBytes(bytes).toString('hex');

const fullBody = {
  collectedAt: '2026-10-12T02:00:00Z',
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

function seedProfile(table, deviceId, extra = {}) {
  table.seed({ ...deviceProfile(deviceId), deviceId, platform: 'windows', ...extra });
}

function seedInventory(table, deviceId, fields) {
  table.seed({ ...deviceInventory(deviceId), deviceId, ...fields });
}

function softwareEventsOf(table, deviceId) {
  const { pk } = deviceProfile(deviceId);
  return table
    .all()
    .filter((item) => item.pk === pk && String(item.sk).startsWith('EVENT#') && String(item.type).startsWith('software.'));
}

function softwareOf(n, prefix = 'Pkg') {
  return Array.from({ length: n }, (_, i) => ({ name: `${prefix}${i}`, version: '1' }));
}

/** Capture every `console.warn` line made during `fn`, restoring it afterwards. */
async function captureWarnings(fn) {
  const warnings = [];
  const original = console.warn;
  console.warn = (line) => warnings.push(line);
  try {
    await fn();
  } finally {
    console.warn = original;
  }
  return warnings;
}

// ============================================================================
// Scenario: The stored list is read before it is overwritten (AC4)
// ============================================================================

test('Scenario: The stored list is read before it is overwritten (AC4)', async () => {
  const table = new FakeTable();
  seedProfile(table, 'dev-1');
  // Given the stored software is [{"name":"A","version":"1"}]
  seedInventory(table, 'dev-1', { software: [{ name: 'A', version: '1' }], collectedAt: '2026-10-12T01:00:00Z' });

  // Track the order operations happen in on the table.
  const order = [];
  const originalGet = table.get.bind(table);
  const originalPut = table.put.bind(table);
  table.get = async (key) => {
    order.push({ op: 'get', sk: key.sk });
    return originalGet(key);
  };
  table.put = async (item, fields) => {
    order.push({ op: 'put', sk: item.sk });
    return originalPut(item, fields);
  };

  const now = new Date('2026-10-12T02:00:05Z');
  // When "dev-1" checks in later with software [{"name":"A","version":"2"}]
  const body = { ...fullBody, inventory: { ...fullBody.inventory, software: [{ name: 'A', version: '2' }] } };
  const result = await handlerFor(table, now)(checkInRequest('dev-1', body));
  assert.strictEqual(result.statusCode, 200);

  // Then the INVENTORY get happens before the INVENTORY put
  const getIndex = order.findIndex((entry) => entry.op === 'get' && entry.sk === 'INVENTORY');
  const putIndex = order.findIndex((entry) => entry.op === 'put' && entry.sk === 'INVENTORY');
  assert.ok(getIndex !== -1 && putIndex !== -1 && getIndex < putIndex, `expected get before put, got ${JSON.stringify(order)}`);

  // And one "software.updated" event is written after the INVENTORY put
  const eventPutIndex = order.findIndex((entry) => entry.op === 'put' && String(entry.sk).startsWith('EVENT#'));
  assert.ok(eventPutIndex !== -1 && eventPutIndex > putIndex);
  const events = softwareEventsOf(table, 'dev-1');
  assert.strictEqual(events.length, 1);
  assert.strictEqual(events[0].type, 'software.updated');

  // And the stored INVENTORY item has the same attributes as a check-in
  // without this feature would store: no new attribute is added.
  const inventoryItem = table.get ? await originalGet(deviceInventory('dev-1')) : undefined;
  const allowedKeys = new Set([
    'pk', 'sk', 'gsi1pk', 'gsi1sk', 'deviceId', 'collectedAt', 'hardware', 'os', 'software',
    'firmware', 'disks', 'physicalDisks', 'network', 'join', 'warnings',
  ]);
  assert.ok(Object.keys(inventoryItem).every((key) => allowedKeys.has(key)), `unexpected key in ${JSON.stringify(inventoryItem)}`);
});

// ============================================================================
// Scenario Outline: No baseline means no events (AC5)
// ============================================================================

const noBaselineOutline = [
  { name: 'absent', seed: null },
  { name: 'present with software []', seed: { software: [], collectedAt: '2026-10-12T01:00:00Z' } },
  { name: 'present with software missing', seed: { collectedAt: '2026-10-12T01:00:00Z' } },
  { name: 'present with collectedAt "not-a-date"', seed: { software: [{ name: 'A', version: '1' }], collectedAt: 'not-a-date' } },
];

for (const { name, seed } of noBaselineOutline) {
  test(`Scenario Outline: No baseline means no events (AC5) - ${name}`, async () => {
    const table = new FakeTable();
    seedProfile(table, 'dev-1');
    if (seed !== null) {
      seedInventory(table, 'dev-1', seed);
    }
    const now = new Date('2026-10-12T02:00:05Z');

    // When "dev-1" checks in later with 300 software entries
    const body = { ...fullBody, inventory: { ...fullBody.inventory, software: softwareOf(300) } };
    const result = await handlerFor(table, now)(checkInRequest('dev-1', body));
    assert.strictEqual(result.statusCode, 200);

    // Then no event with a type starting "software." is written
    assert.strictEqual(softwareEventsOf(table, 'dev-1').length, 0);
  });
}

// ============================================================================
// Scenario Outline: A failed collection is not read as everything removed (AC6)
// ============================================================================

const failedCollectionOutline = [
  { name: 'inventory.software missing', build: (inv) => { delete inv.software; } },
  { name: 'inventory.software null', build: (inv) => { inv.software = null; } },
  { name: 'inventory.software []', build: (inv) => { inv.software = []; } },
  { name: '3 software entries and inventory.warnings ["software:timeout"]', build: (inv) => { inv.software = softwareOf(3); inv.warnings = ['software:timeout']; } },
  { name: '3 software entries and inventory.warnings ["software"]', build: (inv) => { inv.software = softwareOf(3); inv.warnings = ['software']; } },
];

for (const { name, build } of failedCollectionOutline) {
  test(`Scenario Outline: A failed collection is not read as everything removed (AC6) - ${name}`, async () => {
    const table = new FakeTable();
    seedProfile(table, 'dev-1');
    // Given the stored software holds 150 entries
    seedInventory(table, 'dev-1', { software: softwareOf(150, 'Stored'), collectedAt: '2026-10-12T01:00:00Z' });
    const now = new Date('2026-10-12T02:00:05Z');

    const inventory = { ...fullBody.inventory };
    build(inventory);
    const body = { ...fullBody, inventory };
    const result = await handlerFor(table, now)(checkInRequest('dev-1', body));
    assert.strictEqual(result.statusCode, 200);

    // Then no event with a type starting "software." is written
    assert.strictEqual(softwareEventsOf(table, 'dev-1').length, 0);
    // And the INVENTORY item is written as today
    assert.ok(table.puts.some((item) => item.sk === 'INVENTORY'));
  });
}

// ============================================================================
// Scenario Outline: An older or equal collectedAt writes no events (AC7)
// ============================================================================

const staleOutline = ['2026-10-12T00:30:00Z', '2026-10-12T01:00:00Z'];

for (const collectedAt of staleOutline) {
  test(`Scenario Outline: An older or equal collectedAt writes no events (AC7) - ${collectedAt}`, async () => {
    const table = new FakeTable();
    seedProfile(table, 'dev-1');
    // Given the stored software is [{"name":"A","version":"2"}]
    seedInventory(table, 'dev-1', { software: [{ name: 'A', version: '2' }], collectedAt: '2026-10-12T01:00:00Z' });
    const now = new Date('2026-10-12T02:00:05Z');

    // When "dev-1" checks in with collectedAt <collectedAt> and software [{"name":"A","version":"1"}]
    const body = { ...fullBody, collectedAt, inventory: { ...fullBody.inventory, software: [{ name: 'A', version: '1' }] } };
    const result = await handlerFor(table, now)(checkInRequest('dev-1', body));
    assert.strictEqual(result.statusCode, 200);

    // Then no event with a type starting "software." is written
    assert.strictEqual(softwareEventsOf(table, 'dev-1').length, 0);
    // And the INVENTORY item is written as today
    assert.ok(table.puts.some((item) => item.sk === 'INVENTORY'));
  });
}

// ============================================================================
// Scenario: A spool re-send writes no duplicate (AC9)
// ============================================================================

test('Scenario: A spool re-send writes no duplicate (AC9)', async () => {
  const table = new FakeTable();
  seedProfile(table, 'dev-1');
  // Given the stored software is [{"name":"A","version":"1"}]
  seedInventory(table, 'dev-1', { software: [{ name: 'A', version: '1' }], collectedAt: '2026-10-12T01:00:00Z' });
  const now = new Date('2026-10-12T02:00:05Z');
  const body = { ...fullBody, collectedAt: '2026-10-12T02:00:00Z', inventory: { ...fullBody.inventory, software: [{ name: 'A', version: '2' }] } };

  // When "dev-1" posts a body with collectedAt "2026-10-12T02:00:00Z" and
  // software [{"name":"A","version":"2"}] twice
  const first = await handlerFor(table, now)(checkInRequest('dev-1', body));
  assert.strictEqual(first.statusCode, 200);
  const second = await handlerFor(table, now)(checkInRequest('dev-1', body));
  assert.strictEqual(second.statusCode, 200);

  // Then exactly one "software.updated" EVENT# item exists for "dev-1"
  const events = softwareEventsOf(table, 'dev-1').filter((event) => event.type === 'software.updated');
  assert.strictEqual(events.length, 1);
});

// ============================================================================
// Scenario: A failing stored read does not refuse the check-in (AC10a)
// ============================================================================

class GetFailingForSkTable extends FakeTable {
  constructor(failingSk) {
    super();
    this.failingSk = failingSk;
  }
  async get(key) {
    if (key.sk === this.failingSk) {
      throw new Error('simulated get failure');
    }
    return super.get(key);
  }
}

test('Scenario: A failing stored read does not refuse the check-in (AC10a)', async () => {
  const now = new Date('2026-10-12T02:00:05Z');
  const body = { ...fullBody, inventory: { ...fullBody.inventory, software: [{ name: 'A', version: '2' }] } };

  function seeded(table) {
    seedProfile(table, 'dev-1');
    seedInventory(table, 'dev-1', { software: [{ name: 'A', version: '1' }], collectedAt: '2026-10-12T01:00:00Z' });
  }

  const workingTable = new FakeTable();
  seeded(workingTable);
  const workingResult = await handlerFor(workingTable, now)(checkInRequest('dev-1', body));
  assert.strictEqual(workingResult.statusCode, 200);

  // Given the get of the INVENTORY item throws
  const failingTable = new GetFailingForSkTable('INVENTORY');
  seeded(failingTable);

  let warnings;
  let failingResult;
  await (async () => {
    warnings = await captureWarnings(async () => {
      failingResult = await handlerFor(failingTable, now)(checkInRequest('dev-1', body));
    });
  })();

  // Then the response is 200 with the same body as with a working table
  assert.strictEqual(failingResult.statusCode, 200);
  assert.deepStrictEqual(failingResult.body, workingResult.body);

  // And exactly one console.warn line has msg "software changes not derived" and deviceId "dev-1"
  const notDerived = warnings.filter((line) => {
    try {
      const parsed = JSON.parse(line);
      return parsed.msg === 'software changes not derived' && parsed.deviceId === 'dev-1';
    } catch {
      return false;
    }
  });
  assert.strictEqual(notDerived.length, 1);

  // And no event with a type starting "software." is written
  assert.strictEqual(softwareEventsOf(failingTable, 'dev-1').length, 0);

  // And the INVENTORY put still happens
  assert.ok(failingTable.puts.some((item) => item.sk === 'INVENTORY'));
});

// ============================================================================
// Scenario: A failing event put does not refuse the check-in (AC10b)
// ============================================================================

class FirstEventPutFailingTable extends FakeTable {
  constructor() {
    super();
    this.eventPutAttempts = 0;
  }
  async put(item, fields) {
    if (typeof item.sk === 'string' && item.sk.startsWith('EVENT#')) {
      this.eventPutAttempts += 1;
      if (this.eventPutAttempts === 1) {
        throw new Error('simulated put failure');
      }
    }
    return super.put(item, fields);
  }
}

test('Scenario: A failing event put does not refuse the check-in (AC10b)', async () => {
  const now = new Date('2026-10-12T02:00:05Z');
  // Given the stored software is [{"name":"A","version":"1"},{"name":"B","version":"1"}]
  // When "dev-1" checks in later with software [{"name":"A","version":"2"},{"name":"B","version":"2"}]
  // -> two "software.updated" changes, sorted by key: A before B.
  const body = {
    ...fullBody,
    inventory: { ...fullBody.inventory, software: [{ name: 'A', version: '2' }, { name: 'B', version: '2' }] },
  };

  function seeded(table) {
    seedProfile(table, 'dev-1');
    seedInventory(table, 'dev-1', {
      software: [{ name: 'A', version: '1' }, { name: 'B', version: '1' }],
      collectedAt: '2026-10-12T01:00:00Z',
    });
  }

  const workingTable = new FakeTable();
  seeded(workingTable);
  const workingResult = await handlerFor(workingTable, now)(checkInRequest('dev-1', body));
  assert.strictEqual(workingResult.statusCode, 200);

  // And the put of the first software EVENT# item throws
  const failingTable = new FirstEventPutFailingTable();
  seeded(failingTable);

  let warnings;
  let failingResult;
  warnings = await captureWarnings(async () => {
    failingResult = await handlerFor(failingTable, now)(checkInRequest('dev-1', body));
  });

  // Then the response is 200 with the same body as with a working table
  assert.strictEqual(failingResult.statusCode, 200);
  assert.deepStrictEqual(failingResult.body, workingResult.body);

  // And a put of the second software EVENT# item is still attempted (A failed, B succeeded)
  assert.strictEqual(softwareEventsOf(failingTable, 'dev-1').length, 1);
  assert.strictEqual(softwareEventsOf(failingTable, 'dev-1')[0].summary, 'Updated B from 1 to 2');

  // And no console.warn line has msg "software changes not derived"
  assert.ok(!warnings.some((line) => line.includes('software changes not derived')));

  // And exactly one console.warn line has msg "device event not recorded"
  const notRecorded = warnings.filter((line) => {
    try {
      return JSON.parse(line).msg === 'device event not recorded';
    } catch {
      return false;
    }
  });
  assert.strictEqual(notRecorded.length, 1);
});

// ============================================================================
// Scenario: An unchanged list in a different form writes nothing (AC11)
// ============================================================================

test('Scenario: An unchanged list in a different form writes nothing (AC11)', async () => {
  const table = new FakeTable();
  seedProfile(table, 'dev-1');
  // Given the stored software is [{"name":"Git","version":"2","publisher":"A"},{"name":"Zoom","version":"5"}]
  seedInventory(table, 'dev-1', {
    software: [{ name: 'Git', version: '2', publisher: 'A' }, { name: 'Zoom', version: '5' }],
    collectedAt: '2026-10-12T01:00:00Z',
  });
  const now = new Date('2026-10-12T02:00:05Z');

  // When "dev-1" checks in later with [{"name":"zoom ","version":"5"},{"name":"GIT","version":"2","publisher":"B","installedAt":"2026-01-01T00:00:00Z"}]
  const body = {
    ...fullBody,
    inventory: {
      ...fullBody.inventory,
      software: [
        { name: 'zoom ', version: '5' },
        { name: 'GIT', version: '2', publisher: 'B', installedAt: '2026-01-01T00:00:00Z' },
      ],
    },
  };
  const result = await handlerFor(table, now)(checkInRequest('dev-1', body));
  assert.strictEqual(result.statusCode, 200);

  // Then no event with a type starting "software." is written
  assert.strictEqual(softwareEventsOf(table, 'dev-1').length, 0);
});

// ============================================================================
// Scenario: A refused check-in writes nothing (AC11)
// ============================================================================

test('Scenario: A refused check-in writes nothing (AC11)', async () => {
  const table = new FakeTable();
  seedProfile(table, 'dev-1');
  seedInventory(table, 'dev-1', { software: [{ name: 'A', version: '1' }], collectedAt: '2026-10-12T01:00:00Z' });
  const now = new Date('2026-10-12T02:00:05Z');

  // When "dev-1" posts a body with inventory.software[0].version ""
  const body = { ...fullBody, inventory: { ...fullBody.inventory, software: [{ name: 'A', version: '' }] } };
  const result = await handlerFor(table, now)(checkInRequest('dev-1', body));

  // Then the response is 400
  assert.strictEqual(result.statusCode, 400);

  // And no event with a type starting "software." is written
  assert.strictEqual(softwareEventsOf(table, 'dev-1').length, 0);
});

// ============================================================================
// Scenario: Long and hostile names are cut and stored verbatim (AC12)
// ============================================================================

test('Scenario: Long and hostile names are cut and stored verbatim (AC12)', async () => {
  const table = new FakeTable();
  seedProfile(table, 'dev-1');
  // Given the stored software is [{"name":"A","version":"1"}]
  seedInventory(table, 'dev-1', { software: [{ name: 'A', version: '1' }], collectedAt: '2026-10-12T01:00:00Z' });
  const now = new Date('2026-10-12T02:00:05Z');

  const longName = 'L'.repeat(300);
  const hostileName = '<script>x</script>';
  // When "dev-1" checks in later adding a software entry with a 300-character
  // name and one named "<script>x</script>"
  const body = {
    ...fullBody,
    inventory: {
      ...fullBody.inventory,
      software: [
        { name: 'A', version: '1' },
        { name: longName, version: '1' },
        { name: hostileName, version: '1' },
      ],
    },
  };
  const result = await handlerFor(table, now)(checkInRequest('dev-1', body));
  assert.strictEqual(result.statusCode, 200);

  const events = softwareEventsOf(table, 'dev-1');
  const longEvent = events.find((event) => event.details.name.startsWith('L'));
  const hostileEvent = events.find((event) => event.details.name.includes('script'));

  // Then the long entry's stored summary has 256 characters and its details.name has 256 characters
  assert.ok(longEvent, 'expected an event for the long name');
  assert.strictEqual(longEvent.summary.length, 256);
  assert.strictEqual(longEvent.details.name.length, 256);

  // And the other entry's stored details.name is "<script>x</script>"
  assert.ok(hostileEvent, 'expected an event for the hostile name');
  assert.strictEqual(hostileEvent.details.name, hostileName);
});

// ============================================================================
// Scenario: Expressions pass the reserved-word validator (AC13)
// ============================================================================

/** The same validating fake used by checkin-dynamo-expressions.test.js. */
class ValidatingTable {
  constructor() {
    this.items = new Map();
    this.getCalls = [];
  }
  keyOf(key) {
    return `${key.pk}|${key.sk}`;
  }
  seed(item) {
    this.items.set(this.keyOf(item), { ...item });
  }
  async get(key) {
    this.getCalls.push(key);
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

test('Scenario: Expressions pass the reserved-word validator (AC13)', async () => {
  // Given the ValidatingTable ... holding a stored INVENTORY item
  const table = new ValidatingTable();
  table.seed({ ...deviceProfile('dev-1'), deviceId: 'dev-1', platform: 'windows' });
  table.seed({ ...deviceInventory('dev-1'), deviceId: 'dev-1', software: [{ name: 'A', version: '1' }], collectedAt: '2026-10-12T01:00:00Z' });
  const now = new Date('2026-10-12T02:00:05Z');

  // When a later check-in with changed software is handled
  const body = { ...fullBody, inventory: { ...fullBody.inventory, software: [{ name: 'A', version: '2' }] } };
  const result = await handlerFor(table, now)(checkInRequest('dev-1', body));

  // Then no ValidationException is raised
  assert.strictEqual(result.statusCode, 200, JSON.stringify(result.body));

  // And the stored INVENTORY read is a plain key get with no ProjectionExpression
  const inventoryGet = table.getCalls.find((key) => key.sk === 'INVENTORY');
  assert.ok(inventoryGet, 'expected an INVENTORY get call');
  assert.deepStrictEqual(Object.keys(inventoryGet).sort(), ['pk', 'sk']);
});
