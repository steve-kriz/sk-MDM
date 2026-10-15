/**
 * Unit tests for TASK-069 (software changes history): the pure
 * `softwareChanges(stored, posted)` diff (AC1, AC2) and the
 * `recordSoftwareChanges` helper's event shape and cap behaviour (AC3, AC8,
 * AC9). All database calls are mocked with a minimal in-memory `{put}` fake;
 * no real DB connection is ever made.
 */
import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const { softwareChanges, recordSoftwareChanges, MAX_SOFTWARE_EVENTS_PER_CHECKIN } = await import(
  `file://${join(__dirname, '../dist/softwareChanges.js')}`
);

/** A minimal `{put}` fake: the only seam `recordSoftwareChanges` needs. */
class PutCapturingTable {
  constructor() {
    this.puts = [];
  }
  async put(item) {
    this.puts.push({ ...item });
  }
}

function sha256Of(input) {
  return createHash('sha256').update(input, 'utf8').digest('hex').slice(0, 32);
}

// ============================================================================
// Unit: MAX_SOFTWARE_EVENTS_PER_CHECKIN (AC1)
// ============================================================================

test('Unit: MAX_SOFTWARE_EVENTS_PER_CHECKIN is 20 (AC1)', () => {
  assert.strictEqual(MAX_SOFTWARE_EVENTS_PER_CHECKIN, 20);
});

// ============================================================================
// Scenario: Installs, removals and updates are derived by name (AC1)
// ============================================================================

test('Scenario: Installs, removals and updates are derived by name (AC1)', () => {
  // Given the stored software is [{"name":"Zoom","version":"5.1"},{"name":"7-Zip","version":"23.01"}]
  const stored = [
    { name: 'Zoom', version: '5.1' },
    { name: '7-Zip', version: '23.01' },
  ];
  // When softwareChanges is computed against posted [...]
  const posted = [
    { name: ' zoom ', version: '5.2', publisher: 'Zoom Inc' },
    { name: 'Git', version: '2.44' },
  ];
  const result = softwareChanges(stored, posted);

  // Then the changes are removed "7-Zip" "23.01", installed "Git" "2.44", and
  // updated "zoom" from "5.1" to "5.2" with publisher "Zoom Inc" -- in AC2 sort
  // order (key ascending: "7-zip" < "git" < "zoom")
  assert.deepStrictEqual(result, [
    { type: 'software.removed', key: '7-zip', name: '7-Zip', version: '23.01' },
    { type: 'software.installed', key: 'git', name: 'Git', version: '2.44' },
    { type: 'software.updated', key: 'zoom', name: 'zoom', from: '5.1', to: '5.2', publisher: 'Zoom Inc' },
  ]);
});

// ============================================================================
// Scenario: Several versions of one name are compared as sets (AC1)
// ============================================================================

test('Scenario: Several versions of one name are compared as sets (AC1)', () => {
  // Given the stored software has "VC Runtime" versions "14.1" and "14.2"
  const stored = [
    { name: 'VC Runtime', version: '14.1' },
    { name: 'VC Runtime', version: '14.2' },
  ];
  // When softwareChanges is computed against posted "VC Runtime" versions "14.2" and "14.3"
  const posted = [
    { name: 'VC Runtime', version: '14.2' },
    { name: 'VC Runtime', version: '14.3' },
  ];
  const result = softwareChanges(stored, posted);

  // Then the changes are exactly removed "VC Runtime" "14.1" and installed "VC Runtime" "14.3"
  assert.deepStrictEqual(result, [
    { type: 'software.removed', key: 'vc runtime', name: 'VC Runtime', version: '14.1' },
    { type: 'software.installed', key: 'vc runtime', name: 'VC Runtime', version: '14.3' },
  ]);
  // And there is no "software.updated" change
  assert.ok(!result.some((entry) => entry.type === 'software.updated'));
});

// ============================================================================
// Scenario: Invalid stored entries are ignored (AC1)
// ============================================================================

test('Scenario: Invalid stored entries are ignored (AC1)', () => {
  // Given the stored software is [{"name":"","version":"1"},{"name":"A","version":5},"junk",{"name":"B","version":"1"}]
  const stored = [{ name: '', version: '1' }, { name: 'A', version: 5 }, 'junk', { name: 'B', version: '1' }];
  // When softwareChanges is computed against posted [{"name":"B","version":"1"}]
  const posted = [{ name: 'B', version: '1' }];
  const result = softwareChanges(stored, posted);

  // Then there are no changes
  assert.deepStrictEqual(result, []);
});

// ============================================================================
// Scenario: Changes are sorted deterministically (AC2)
// ============================================================================

test('Scenario: Changes are sorted deterministically (AC2)', () => {
  // Constructed so softwareChanges yields installed "b" "1", removed "a" "2",
  // installed "a" "3" (key "a" has two versions on each side, so it is not
  // treated as a 1-to-1 update) and updated "c" from "1" to "2".
  const stored = [
    { name: 'A', version: '2' },
    { name: 'A', version: '4' },
    { name: 'C', version: '1' },
  ];
  const posted = [
    { name: 'A', version: '3' },
    { name: 'A', version: '4' },
    { name: 'B', version: '1' },
    { name: 'C', version: '2' },
  ];
  const result = softwareChanges(stored, posted);

  // Then their order is removed "a" "2", installed "a" "3", installed "b" "1", updated "c"
  assert.deepStrictEqual(
    result.map((entry) => ({ type: entry.type, key: entry.key })),
    [
      { type: 'software.removed', key: 'a' },
      { type: 'software.installed', key: 'a' },
      { type: 'software.installed', key: 'b' },
      { type: 'software.updated', key: 'c' },
    ],
  );
});

// ============================================================================
// Scenario Outline: Each change becomes one system event (AC3)
// ============================================================================

const changeEventOutline = [
  {
    stored: [{ name: 'A', version: '1' }],
    posted: [{ name: 'A', version: '1' }, { name: 'Git', version: '2' }],
    type: 'software.installed',
    summary: 'Installed Git 2',
    hashInput: 'software.installed\n2026-10-12T02:00:00.123Z\ngit\n\n2',
  },
  {
    stored: [{ name: 'A', version: '1' }, { name: 'Git', version: '2' }],
    posted: [{ name: 'A', version: '1' }],
    type: 'software.removed',
    summary: 'Removed Git 2',
    hashInput: 'software.removed\n2026-10-12T02:00:00.123Z\ngit\n2\n',
  },
  {
    stored: [{ name: 'Git', version: '2' }],
    posted: [{ name: 'Git', version: '3' }],
    type: 'software.updated',
    summary: 'Updated Git from 2 to 3',
    hashInput: 'software.updated\n2026-10-12T02:00:00.123Z\ngit\n2\n3',
  },
];

for (const { stored, posted, type, summary, hashInput } of changeEventOutline) {
  test(`Scenario Outline: Each change becomes one system event (AC3) - ${type}`, async () => {
    const table = new PutCapturingTable();
    const storedItem = { software: stored, collectedAt: '2026-10-12T01:00:00Z' };
    const postedInventory = { software: posted };
    const collectedAt = '2026-10-12T02:00:00.123Z';

    // When "dev-1" checks in with collectedAt "2026-10-12T02:00:00.123Z" and software <posted>
    await recordSoftwareChanges(table, 'dev-1', storedItem, postedInventory, collectedAt);

    // Then one event "<type>" is written with source "system", actor null,
    // summary "<summary>" and occurredAt "2026-10-12T02:00:00Z"
    assert.strictEqual(table.puts.length, 1);
    const event = table.puts[0];
    assert.strictEqual(event.type, type);
    assert.strictEqual(event.source, 'system');
    assert.strictEqual(event.actor, null);
    assert.strictEqual(event.summary, summary);
    assert.strictEqual(event.occurredAt, '2026-10-12T02:00:00Z');

    // And its eventId is the first 32 hex characters of sha256 "<hashInput>"
    assert.strictEqual(event.eventId, sha256Of(hashInput));
  });
}

// ============================================================================
// Scenario: Twenty changes are written individually (AC8)
// ============================================================================

test('Scenario: Twenty changes are written individually (AC8)', async () => {
  // Given a baseline with one unchanged entry, and 20 new installs posted.
  const stored = [{ name: 'Keep', version: '1' }];
  const posted = [
    { name: 'Keep', version: '1' },
    ...Array.from({ length: 20 }, (_, i) => ({ name: `Pkg${String(i).padStart(2, '0')}`, version: '1' })),
  ];
  assert.strictEqual(softwareChanges(stored, posted).length, 20);

  const table = new PutCapturingTable();
  const storedItem = { software: stored, collectedAt: '2026-10-12T01:00:00Z' };
  await recordSoftwareChanges(table, 'dev-1', storedItem, { software: posted }, '2026-10-12T02:00:00Z');

  // Then exactly 20 events with a type starting "software." are written and
  // none is "software.more_changes"
  const softwareEvents = table.puts.filter((event) => event.type.startsWith('software.'));
  assert.strictEqual(softwareEvents.length, 20);
  assert.ok(!softwareEvents.some((event) => event.type === 'software.more_changes'));
});

// ============================================================================
// Scenario: A large diff is capped with one summary event (AC8)
// ============================================================================

test('Scenario: A large diff is capped with one summary event (AC8)', async () => {
  // 30 installed, 5 removed, 2 updated -- 37 changes in total.
  const removedKeys = Array.from({ length: 5 }, (_, i) => `Rem${String(i).padStart(2, '0')}`);
  const updatedKeys = ['Upd01', 'Upd02'];
  const installedKeys = Array.from({ length: 30 }, (_, i) => `Pkg${String(i).padStart(2, '0')}`);

  const stored = [
    ...removedKeys.map((name) => ({ name, version: '1' })),
    ...updatedKeys.map((name) => ({ name, version: '1' })),
  ];
  const posted = [
    ...installedKeys.map((name) => ({ name, version: '1' })),
    ...updatedKeys.map((name) => ({ name, version: '2' })),
  ];

  const allChanges = softwareChanges(stored, posted);
  assert.strictEqual(allChanges.length, 37);
  const firstTwenty = allChanges.slice(0, 20);
  const rest = allChanges.slice(20);
  assert.strictEqual(rest.length, 17);

  const table = new PutCapturingTable();
  const collectedAt = '2026-10-12T02:00:00Z';
  const storedItem = { software: stored, collectedAt: '2026-10-12T01:00:00Z' };
  await recordSoftwareChanges(table, 'dev-1', storedItem, { software: posted }, collectedAt);

  // Then exactly 21 events with a type starting "software." are written
  const softwareEvents = table.puts.filter((event) => event.type.startsWith('software.'));
  assert.strictEqual(softwareEvents.length, 21);

  // And 20 of them are the first 20 changes in sorted order
  const individual = softwareEvents.filter((event) => event.type !== 'software.more_changes');
  assert.strictEqual(individual.length, 20);
  assert.deepStrictEqual(
    individual.map((event) => event.type),
    firstTwenty.map((entry) => entry.type),
  );

  // And one is "software.more_changes" whose summary counts the 17 changes not
  // written individually, split into installed, removed and updated
  const more = softwareEvents.find((event) => event.type === 'software.more_changes');
  assert.ok(more, 'expected a software.more_changes event');
  const installedCount = rest.filter((e) => e.type === 'software.installed').length;
  const removedCount = rest.filter((e) => e.type === 'software.removed').length;
  const updatedCount = rest.filter((e) => e.type === 'software.updated').length;
  assert.strictEqual(installedCount + removedCount + updatedCount, 17);
  assert.strictEqual(
    more.summary,
    `And 17 more software changes (${installedCount} installed, ${removedCount} removed, ${updatedCount} updated)`,
  );
  // And its details hold those three counts as decimal strings
  assert.deepStrictEqual(more.details, {
    installed: String(installedCount),
    removed: String(removedCount),
    updated: String(updatedCount),
  });
  assert.strictEqual(more.eventId, sha256Of(`software.more_changes\n${collectedAt}`));
  assert.strictEqual(more.occurredAt, collectedAt);
});

// ============================================================================
// Scenario: A spool re-send writes no duplicate (AC9) -- the underlying
// determinism: identical inputs always yield the identical eventId, so a
// repeated write overwrites rather than duplicating.
// ============================================================================

test('Scenario: A spool re-send writes no duplicate (AC9) -- deterministic eventIds', async () => {
  const storedItem = { software: [{ name: 'A', version: '1' }], collectedAt: '2026-10-12T01:00:00Z' };
  const postedInventory = { software: [{ name: 'A', version: '2' }] };
  const collectedAt = '2026-10-12T02:00:00Z';

  const first = new PutCapturingTable();
  await recordSoftwareChanges(first, 'dev-1', storedItem, postedInventory, collectedAt);
  const second = new PutCapturingTable();
  await recordSoftwareChanges(second, 'dev-1', storedItem, postedInventory, collectedAt);

  // The same inputs produce the identical eventId every time.
  assert.strictEqual(first.puts.length, 1);
  assert.strictEqual(second.puts.length, 1);
  assert.strictEqual(first.puts[0].eventId, second.puts[0].eventId);
});

// ============================================================================
// Edge: AC5-AC7 guards, exercised directly against recordSoftwareChanges
// (handler-level coverage of the same guards lives in
// checkin-software-events.test.js).
// ============================================================================

test('Edge: no baseline (absent stored item) derives nothing (AC5)', async () => {
  const table = new PutCapturingTable();
  await recordSoftwareChanges(table, 'dev-1', undefined, { software: [{ name: 'A', version: '1' }] }, '2026-10-12T02:00:00Z');
  assert.strictEqual(table.puts.length, 0);
});

test('Edge: an unusable stored collectedAt derives nothing (AC5)', async () => {
  const table = new PutCapturingTable();
  const storedItem = { software: [{ name: 'A', version: '1' }], collectedAt: 'not-a-date' };
  await recordSoftwareChanges(table, 'dev-1', storedItem, { software: [{ name: 'A', version: '2' }] }, '2026-10-12T02:00:00Z');
  assert.strictEqual(table.puts.length, 0);
});

test('Edge: a posted software probe failure warning derives nothing (AC6)', async () => {
  const table = new PutCapturingTable();
  const storedItem = { software: [{ name: 'A', version: '1' }], collectedAt: '2026-10-12T01:00:00Z' };
  const postedInventory = { software: [{ name: 'A', version: '2' }], warnings: ['software:timeout'] };
  await recordSoftwareChanges(table, 'dev-1', storedItem, postedInventory, '2026-10-12T02:00:00Z');
  assert.strictEqual(table.puts.length, 0);
});

test('Edge: a posted collectedAt that is not strictly newer derives nothing (AC7)', async () => {
  const table = new PutCapturingTable();
  const storedItem = { software: [{ name: 'A', version: '2' }], collectedAt: '2026-10-12T01:00:00Z' };
  const postedInventory = { software: [{ name: 'A', version: '1' }] };
  await recordSoftwareChanges(table, 'dev-1', storedItem, postedInventory, '2026-10-12T01:00:00Z');
  assert.strictEqual(table.puts.length, 0);
});
