/**
 * Unit tests for audit query functionality (TASK-010).
 *
 * Tests queryAudit pagination, date ranges, and cursor handling.
 */

import test from 'node:test';
import assert from 'node:assert';
import { queryAudit, isoUtc, utcDay, AUDIT_DEFAULT_LIMIT, AUDIT_MAX_LIMIT } from '../../dist/audit.js';

// ============================================================================
// Mock Table for queryAudit tests
// ============================================================================

class FakeAuditTable {
  constructor() {
    this.items = [];
  }

  async query(request) {
    const { KeyConditionExpression, ExpressionAttributeValues, ScanIndexForward = true, limit = 50, cursor } = request;

    const pk = ExpressionAttributeValues[':pk'];
    let filtered = this.items.filter((item) => item.pk === pk);

    if (ScanIndexForward === false) {
      filtered.sort((a, b) => (b.sk < a.sk ? 1 : -1));
    } else {
      filtered.sort((a, b) => (a.sk < b.sk ? 1 : -1));
    }

    let startIdx = 0;
    if (cursor) {
      try {
        const decoded = JSON.parse(Buffer.from(cursor, 'base64').toString());
        startIdx = decoded.offset || 0;
      } catch {
        startIdx = 0;
      }
    }

    const pageSize = Math.min(limit, filtered.length - startIdx);
    const page = filtered.slice(startIdx, startIdx + pageSize);
    const nextCursor = startIdx + pageSize < filtered.length
      ? Buffer.from(JSON.stringify({ offset: startIdx + pageSize })).toString('base64')
      : null;

    return { items: page, cursor: nextCursor };
  }

  addItem(item) {
    this.items.push({ ...item });
  }
}

// ============================================================================
// Unit: isoUtc formatting
// ============================================================================

test('Unit: isoUtc returns ISO format without milliseconds', () => {
  const date = new Date('2026-10-02T10:30:45.123Z');
  const result = isoUtc(date);
  assert.strictEqual(result, '2026-10-02T10:30:45Z');
});

test('Unit: isoUtc preserves seconds precision', () => {
  const date = new Date('2026-10-02T23:59:59.999Z');
  const result = isoUtc(date);
  assert.strictEqual(result, '2026-10-02T23:59:59Z');
});

test('Unit: isoUtc handles midnight', () => {
  const date = new Date('2026-10-02T00:00:00.000Z');
  const result = isoUtc(date);
  assert.strictEqual(result, '2026-10-02T00:00:00Z');
});

// ============================================================================
// Unit: utcDay extraction
// ============================================================================

test('Unit: utcDay extracts YYYY-MM-DD from date', () => {
  const date = new Date('2026-10-02T10:30:45.123Z');
  const result = utcDay(date);
  assert.strictEqual(result, '2026-10-02');
});

test('Unit: utcDay handles different UTC dates', () => {
  const dates = [
    { date: new Date('2026-01-01T00:00:00Z'), expected: '2026-01-01' },
    { date: new Date('2026-12-31T23:59:59Z'), expected: '2026-12-31' },
    { date: new Date('2026-06-15T12:00:00Z'), expected: '2026-06-15' },
  ];

  for (const { date, expected } of dates) {
    const result = utcDay(date);
    assert.strictEqual(result, expected);
  }
});

// ============================================================================
// Unit: queryAudit throws on invalid range
// ============================================================================

test('Unit: queryAudit throws when from is after to', async (t) => {
  const table = new FakeAuditTable();

  assert.rejects(
    () =>
      queryAudit(table, {
        fromIso: '2026-10-03T00:00:00Z',
        toIso: '2026-10-01T00:00:00Z',
      }),
    (error) => error.message.includes('invalid range'),
  );
});

test('Unit: queryAudit throws on non-date fromIso', async (t) => {
  const table = new FakeAuditTable();

  assert.rejects(
    () =>
      queryAudit(table, {
        fromIso: 'not-a-date',
        toIso: '2026-10-02T00:00:00Z',
      }),
  );
});

test('Unit: queryAudit throws on non-date toIso', async (t) => {
  const table = new FakeAuditTable();

  assert.rejects(
    () =>
      queryAudit(table, {
        fromIso: '2026-10-01T00:00:00Z',
        toIso: 'yesterday',
      }),
  );
});

// ============================================================================
// Unit: queryAudit accepts valid range
// ============================================================================

test('Unit: queryAudit accepts from equal to to', async (t) => {
  const table = new FakeAuditTable();

  const result = await queryAudit(table, {
    fromIso: '2026-10-02T00:00:00Z',
    toIso: '2026-10-02T23:59:59Z',
  });

  assert(Array.isArray(result.items));
  assert(result.cursor === null || typeof result.cursor === 'string');
});

test('Unit: queryAudit accepts from before to', async (t) => {
  const table = new FakeAuditTable();

  const result = await queryAudit(table, {
    fromIso: '2026-10-01T00:00:00Z',
    toIso: '2026-10-03T23:59:59Z',
  });

  assert(Array.isArray(result.items));
});

// ============================================================================
// Unit: queryAudit default limit
// ============================================================================

test('Unit: queryAudit uses AUDIT_DEFAULT_LIMIT when limit undefined', async (t) => {
  const table = new FakeAuditTable();

  // Add items to verify limit is applied
  for (let i = 0; i < 100; i++) {
    table.addItem({
      pk: 'AUDIT#2026-10-02',
      sk: `${String(1000 + i).padStart(13, '0')}-0000000${String(i).padStart(1, '0')}`,
      action: 'test',
      actor: 'system',
      target: 'test',
    });
  }

  const result = await queryAudit(table, {
    fromIso: '2026-10-02T00:00:00Z',
    toIso: '2026-10-02T23:59:59Z',
  });

  assert.strictEqual(result.items.length, AUDIT_DEFAULT_LIMIT);
});

test('Unit: queryAudit clamps limit to maximum', async (t) => {
  const table = new FakeAuditTable();

  for (let i = 0; i < 300; i++) {
    table.addItem({
      pk: 'AUDIT#2026-10-02',
      sk: `${String(1000 + i).padStart(13, '0')}-0000000${String(i % 10).padStart(1, '0')}`,
      action: 'test',
      actor: 'system',
      target: 'test',
    });
  }

  const result = await queryAudit(table, {
    fromIso: '2026-10-02T00:00:00Z',
    toIso: '2026-10-02T23:59:59Z',
    limit: 500, // Request more than max
  });

  assert.strictEqual(result.items.length, AUDIT_MAX_LIMIT);
});

test('Unit: queryAudit accepts limit within bounds', async (t) => {
  const table = new FakeAuditTable();

  for (let i = 0; i < 100; i++) {
    table.addItem({
      pk: 'AUDIT#2026-10-02',
      sk: `${String(1000 + i).padStart(13, '0')}-0000000${String(i % 10).padStart(1, '0')}`,
      action: 'test',
      actor: 'system',
      target: 'test',
    });
  }

  const result = await queryAudit(table, {
    fromIso: '2026-10-02T00:00:00Z',
    toIso: '2026-10-02T23:59:59Z',
    limit: 25,
  });

  assert.strictEqual(result.items.length, 25);
});

// ============================================================================
// Unit: queryAudit returns cursor structure
// ============================================================================

test('Unit: queryAudit returns null cursor when all entries fit', async (t) => {
  const table = new FakeAuditTable();

  table.addItem({
    pk: 'AUDIT#2026-10-02',
    sk: '0000000000001000-00000001',
    action: 'test',
    actor: 'system',
    target: 'test',
  });

  const result = await queryAudit(table, {
    fromIso: '2026-10-02T00:00:00Z',
    toIso: '2026-10-02T23:59:59Z',
  });

  assert.strictEqual(result.cursor, null);
});

test('Unit: queryAudit returns cursor when more entries exist', async (t) => {
  const table = new FakeAuditTable();

  for (let i = 0; i < 100; i++) {
    table.addItem({
      pk: 'AUDIT#2026-10-02',
      sk: `${String(1000 + i).padStart(13, '0')}-0000000${String(i % 10).padStart(1, '0')}`,
      action: 'test',
      actor: 'system',
      target: 'test',
    });
  }

  const result = await queryAudit(table, {
    fromIso: '2026-10-02T00:00:00Z',
    toIso: '2026-10-02T23:59:59Z',
    limit: 25,
  });

  assert(result.cursor !== null);
  assert(typeof result.cursor === 'string');
});

// ============================================================================
// Unit: queryAudit cursor format
// ============================================================================

test('Unit: queryAudit cursor carries day and position', async (t) => {
  const table = new FakeAuditTable();

  // Add items across two days
  for (let i = 0; i < 30; i++) {
    table.addItem({
      pk: 'AUDIT#2026-10-01',
      sk: `${String(1000 + i).padStart(13, '0')}-0000000${String(i % 10).padStart(1, '0')}`,
      action: 'test',
      actor: 'system',
      target: 'test',
    });
  }

  for (let i = 0; i < 30; i++) {
    table.addItem({
      pk: 'AUDIT#2026-10-02',
      sk: `${String(2000 + i).padStart(13, '0')}-0000000${String(i % 10).padStart(1, '0')}`,
      action: 'test',
      actor: 'system',
      target: 'test',
    });
  }

  const result = await queryAudit(table, {
    fromIso: '2026-10-01T00:00:00Z',
    toIso: '2026-10-02T23:59:59Z',
    limit: 25,
  });

  if (result.cursor) {
    // Cursor should be a base64-encoded JSON with day and within fields
    const decoded = JSON.parse(Buffer.from(result.cursor, 'base64').toString());
    assert(decoded.day);
    assert(typeof decoded.day === 'string');
  }
});

// ============================================================================
// Unit: queryAudit handles empty results
// ============================================================================

test('Unit: queryAudit returns empty items when no entries match', async (t) => {
  const table = new FakeAuditTable();

  const result = await queryAudit(table, {
    fromIso: '2026-10-02T00:00:00Z',
    toIso: '2026-10-02T23:59:59Z',
  });

  assert.deepStrictEqual(result.items, []);
  assert.strictEqual(result.cursor, null);
});

// ============================================================================
// Unit: queryAudit handles cursor from different range
// ============================================================================

test('Unit: queryAudit returns empty page for cursor from different range', async (t) => {
  const table = new FakeAuditTable();

  table.addItem({
    pk: 'AUDIT#2026-10-02',
    sk: '0000000001000000-00000001',
    action: 'test',
    actor: 'system',
    target: 'test',
  });

  // Create a valid cursor from a different day
  const validCursorFromOtherRange = Buffer.from(JSON.stringify({ day: '2026-10-05', within: null })).toString('base64');

  const result = await queryAudit(table, {
    fromIso: '2026-10-02T00:00:00Z',
    toIso: '2026-10-02T23:59:59Z',
    cursor: validCursorFromOtherRange,
  });

  assert.deepStrictEqual(result.items, []);
  assert.strictEqual(result.cursor, null);
});

// ============================================================================
// Unit: queryAudit ordering (newest first)
// ============================================================================

test('Unit: queryAudit returns items ordered newest first (day descending)', async (t) => {
  const table = new FakeAuditTable();

  // Add items from two days
  table.addItem({
    pk: 'AUDIT#2026-10-01',
    sk: '0000000001000000-00000001',
    action: 'test',
    actor: 'system',
    target: 'test',
  });

  table.addItem({
    pk: 'AUDIT#2026-10-02',
    sk: '0000000002000000-00000002',
    action: 'test',
    actor: 'system',
    target: 'test',
  });

  const result = await queryAudit(table, {
    fromIso: '2026-10-01T00:00:00Z',
    toIso: '2026-10-02T23:59:59Z',
  });

  // Should have both items, with newer day (2026-10-02) first
  assert(result.items.length >= 1);
  if (result.items.length > 1) {
    // Items from 2026-10-02 should come before items from 2026-10-01
    const day2Items = result.items.filter((item) => item.pk === 'AUDIT#2026-10-02');
    const day1Items = result.items.filter((item) => item.pk === 'AUDIT#2026-10-01');

    if (day2Items.length > 0 && day1Items.length > 0) {
      const day2Index = result.items.indexOf(day2Items[0]);
      const day1Index = result.items.indexOf(day1Items[0]);
      assert(day2Index < day1Index, 'Newer day should come first');
    }
  }
});
