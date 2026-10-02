/**
 * Unit tests for the audit trail module (TASK-006).
 * Tests appendAudit, seq generation, and audit item structure.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const {
  appendAudit,
  isoUtc,
  toUtcDate,
  utcDay,
  auditSeq,
  SEQ_PATTERN,
  SEQ_MILLIS_DIGITS,
  SEQ_SUFFIX_BYTES,
} = await import(`file://${join(__dirname, '../dist/audit.js')}`);

const { audit: auditKey } = await import(`file://${join(__dirname, '../dist/db/keys.js')}`);

// Mock table for testing
class FakeTable {
  constructor() {
    this.items = [];
  }

  async put(item) {
    this.items.push({ ...item });
  }

  lastItem() {
    return this.items[this.items.length - 1];
  }
}

// ============================================================================
// Unit: toUtcDate accepts a Date
// ============================================================================
test('Unit: toUtcDate accepts a Date', () => {
  const date = new Date('2026-10-02T09:00:00Z');
  const result = toUtcDate(date);
  assert(result instanceof Date);
  assert.strictEqual(result.toISOString(), '2026-10-02T09:00:00.000Z');
});

// ============================================================================
// Unit: toUtcDate accepts epoch milliseconds
// ============================================================================
test('Unit: toUtcDate accepts epoch milliseconds', () => {
  const epochMs = 1725274800000; // 2026-10-02T09:00:00Z
  const result = toUtcDate(epochMs);
  assert(result instanceof Date);
});

// ============================================================================
// Unit: toUtcDate accepts ISO-8601 string
// ============================================================================
test('Unit: toUtcDate accepts ISO-8601 string', () => {
  const iso = '2026-10-02T09:00:00Z';
  const result = toUtcDate(iso);
  assert(result instanceof Date);
  assert.strictEqual(result.getUTCFullYear(), 2026);
});

// ============================================================================
// Unit: toUtcDate calls a clock function
// ============================================================================
test('Unit: toUtcDate calls a clock function', () => {
  const date = new Date('2026-10-02T09:00:00Z');
  const clock = () => date;
  const result = toUtcDate(clock);
  assert.strictEqual(result.toISOString(), date.toISOString());
});

// ============================================================================
// Unit: isoUtc renders timestamps without milliseconds
// ============================================================================
test('Unit: isoUtc renders timestamps without milliseconds', () => {
  const date = new Date('2026-10-02T09:00:00.123Z');
  const result = isoUtc(date);
  assert.strictEqual(result, '2026-10-02T09:00:00Z');
});

// ============================================================================
// Unit: utcDay extracts YYYY-MM-DD
// ============================================================================
test('Unit: utcDay extracts YYYY-MM-DD', () => {
  const date = new Date('2026-10-02T09:00:00Z');
  const result = utcDay(date);
  assert.strictEqual(result, '2026-10-02');
});

// ============================================================================
// Unit: auditSeq generates time-ordered sequence
// ============================================================================
test('Unit: auditSeq generates time-ordered sequence', () => {
  const date = new Date('2026-10-02T09:00:00.000Z');
  const seq = auditSeq(date);

  // Should match pattern ^[0-9]{13}-[0-9a-f]{8}$
  assert.match(seq, SEQ_PATTERN);

  // Should have 13-digit epoch millis padded with zeros
  const parts = seq.split('-');
  assert.strictEqual(parts[0].length, SEQ_MILLIS_DIGITS);
  assert.match(parts[0], /^[0-9]{13}$/);
  assert.match(parts[1], /^[0-9a-f]{8}$/);
});

// ============================================================================
// Scenario: appendAudit writes one dated item with the admin field set
// ============================================================================
test('Scenario: appendAudit writes one dated item with the admin field set', async (t) => {
  // When appendAudit runs with action "group.created", actor "admin@example.com", target "g1", detail {name:"Finance"} and now 2026-10-02T09:00:00Z
  const table = new FakeTable();
  const now = new Date('2026-10-02T09:00:00Z');

  const item = await appendAudit(table, {
    action: 'group.created',
    actor: 'admin@example.com',
    target: 'g1',
    detail: { name: 'Finance' },
    now,
  });

  // Then one item is written with pk "AUDIT#2026-10-02" storing action, actor, target, detail and at "2026-10-02T09:00:00Z"
  assert.strictEqual(table.items.length, 1);
  const written = table.lastItem();

  assert.strictEqual(written.pk, 'AUDIT#2026-10-02');
  assert.strictEqual(written.action, 'group.created');
  assert.strictEqual(written.actor, 'admin@example.com');
  assert.strictEqual(written.target, 'g1');
  assert.deepStrictEqual(written.detail, { name: 'Finance' });
  assert.strictEqual(written.at, '2026-10-02T09:00:00Z');
});

// ============================================================================
// Scenario: appendAudit omits an absent detail
// ============================================================================
test('Scenario: appendAudit omits an absent detail', async (t) => {
  // When appendAudit runs with no detail argument
  const table = new FakeTable();
  const now = new Date('2026-10-02T09:00:00Z');

  await appendAudit(table, {
    action: 'device.checked-in',
    actor: 'device:d1',
    target: 'd1',
    now,
  });

  // Then the written item has no detail attribute
  const written = table.lastItem();
  assert.strictEqual(written.detail, undefined, 'detail should be omitted when not supplied');
});

// ============================================================================
// Scenario: Sequence is unique and time ordered
// ============================================================================
test('Scenario: Sequence is unique and time ordered', async (t) => {
  // When appendAudit is called twice with the same now and once with a now one millisecond later
  const table = new FakeTable();
  const now1 = new Date('2026-10-02T09:00:00.000Z');
  const now2 = new Date('2026-10-02T09:00:00.001Z');

  const item1 = await appendAudit(table, {
    action: 'action1',
    actor: 'actor1',
    target: 't1',
    now: now1,
  });

  const item2 = await appendAudit(table, {
    action: 'action2',
    actor: 'actor2',
    target: 't2',
    now: now1,
  });

  const item3 = await appendAudit(table, {
    action: 'action3',
    actor: 'actor3',
    target: 't3',
    now: now2,
  });

  // Then all three seq values match "^[0-9]{13}-[0-9a-f]{8}$"
  assert.match(item1.sk, SEQ_PATTERN);
  assert.match(item2.sk, SEQ_PATTERN);
  assert.match(item3.sk, SEQ_PATTERN);

  // the first two differ
  assert.notStrictEqual(item1.sk, item2.sk, 'seq should be unique even for same now');

  // and the later call's seq sorts after both
  assert(item3.sk > item1.sk, 'later call seq should sort after earlier');
  assert(item3.sk > item2.sk, 'later call seq should sort after earlier');
});

// ============================================================================
// Unit: appendAudit with device actor
// ============================================================================
test('Unit: appendAudit with device actor', async (t) => {
  // Given a device-initiated audit entry
  const table = new FakeTable();
  const now = new Date('2026-10-02T09:00:00Z');

  const item = await appendAudit(table, {
    action: 'device.enrolled',
    actor: 'device:d1',
    target: 'd1',
    detail: { hardwareUuid: 'HW-1', platform: 'windows', agentVersion: '1.0.0' },
    now,
  });

  // Then the actor is stored exactly as passed
  assert.strictEqual(item.actor, 'device:d1');
  assert.strictEqual(item.action, 'device.enrolled');
  assert.deepStrictEqual(item.detail, { hardwareUuid: 'HW-1', platform: 'windows', agentVersion: '1.0.0' });
});

// ============================================================================
// Unit: auditSeq two calls with same now produce different seq
// ============================================================================
test('Unit: auditSeq two calls with same now produce different seq', () => {
  const date = new Date('2026-10-02T09:00:00.000Z');

  const seq1 = auditSeq(date);
  const seq2 = auditSeq(date);

  assert.notStrictEqual(seq1, seq2, 'seq should differ for same now due to random suffix');
  assert.strictEqual(seq1.split('-')[0], seq2.split('-')[0], 'epoch part should be same');
  assert.notStrictEqual(seq1.split('-')[1], seq2.split('-')[1], 'random part should differ');
});

// ============================================================================
// Unit: seq prefix padding
// ============================================================================
test('Unit: seq prefix padding', () => {
  // A small epoch ms should be padded to 13 digits
  const smallDate = new Date(1000); // 1 second = 1000ms
  const seq = auditSeq(smallDate);
  const parts = seq.split('-');
  assert.strictEqual(parts[0].length, 13);
  assert.strictEqual(parts[0], '0000000001000');
});

// ============================================================================
// Unit: appendAudit returns the written item
// ============================================================================
test('Unit: appendAudit returns the written item', async (t) => {
  const table = new FakeTable();
  const now = new Date('2026-10-02T09:00:00Z');

  const returned = await appendAudit(table, {
    action: 'test.action',
    actor: 'admin@test.com',
    target: 'target-id',
    detail: { foo: 'bar' },
    now,
  });

  assert.strictEqual(returned.action, 'test.action');
  assert.strictEqual(returned.actor, 'admin@test.com');
  assert.strictEqual(returned.target, 'target-id');
  assert.deepStrictEqual(returned.detail, { foo: 'bar' });
});

// ============================================================================
// Unit: appendAudit with null now function parameter
// ============================================================================
test('Unit: appendAudit resolves clock function', async (t) => {
  const table = new FakeTable();
  const now = () => new Date('2026-10-02T10:30:45Z');

  const item = await appendAudit(table, {
    action: 'test',
    actor: 'tester',
    target: 'subject',
    now,
  });

  assert.strictEqual(item.at, '2026-10-02T10:30:45Z');
});
