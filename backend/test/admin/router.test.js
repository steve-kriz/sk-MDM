/**
 * Unit tests for admin router utilities (TASK-010).
 *
 * Tests individual functions: parseLimit, isUsableCursor, readCursor, isIsoUtc, bearerToken.
 */

import test from 'node:test';
import assert from 'node:assert';
import {
  parseLimit,
  isUsableCursor,
  readCursor,
  isIsoUtc,
  bearerToken,
  DEFAULT_LIMIT,
  MAX_LIMIT,
  BEARER_PREFIX,
} from '../../dist/admin/router.js';

// ============================================================================
// Unit: parseLimit default
// ============================================================================

test('Unit: parseLimit returns DEFAULT_LIMIT when undefined', () => {
  const result = parseLimit(undefined);
  assert.strictEqual(result, DEFAULT_LIMIT);
});

test('Unit: parseLimit returns DEFAULT_LIMIT when empty string', () => {
  const result = parseLimit('');
  assert.strictEqual(result, DEFAULT_LIMIT);
});

// ============================================================================
// Unit: parseLimit valid values
// ============================================================================

test('Unit: parseLimit accepts valid integer 50', () => {
  const result = parseLimit('50');
  assert.strictEqual(result, 50);
});

test('Unit: parseLimit accepts minimum 1', () => {
  const result = parseLimit('1');
  assert.strictEqual(result, 1);
});

test('Unit: parseLimit accepts maximum 200', () => {
  const result = parseLimit('200');
  assert.strictEqual(result, 200);
});

// ============================================================================
// Unit: parseLimit invalid values
// ============================================================================

test('Unit: parseLimit rejects 0', () => {
  const result = parseLimit('0');
  assert.strictEqual(result, null);
});

test('Unit: parseLimit rejects negative numbers', () => {
  const result = parseLimit('-10');
  assert.strictEqual(result, null);
});

test('Unit: parseLimit rejects values above maximum', () => {
  const result = parseLimit('500');
  assert.strictEqual(result, null);
});

test('Unit: parseLimit rejects decimals', () => {
  const result = parseLimit('50.5');
  assert.strictEqual(result, null);
});

test('Unit: parseLimit rejects non-numeric strings', () => {
  const result = parseLimit('abc');
  assert.strictEqual(result, null);
});

test('Unit: parseLimit rejects strings with exponent notation', () => {
  const result = parseLimit('1e2');
  assert.strictEqual(result, null);
});

test('Unit: parseLimit rejects strings with leading signs', () => {
  const result = parseLimit('+50');
  assert.strictEqual(result, null);
});

// ============================================================================
// Unit: isUsableCursor
// ============================================================================

test('Unit: isUsableCursor accepts undefined', () => {
  const result = isUsableCursor(undefined);
  assert.strictEqual(result, true);
});

test('Unit: isUsableCursor accepts null', () => {
  const result = isUsableCursor(null);
  assert.strictEqual(result, true);
});

test('Unit: isUsableCursor accepts empty string', () => {
  const result = isUsableCursor('');
  assert.strictEqual(result, true);
});

test('Unit: isUsableCursor accepts valid cursor', () => {
  // A valid cursor is a base64-encoded JSON object
  const validCursor = Buffer.from(JSON.stringify({ offset: 10 })).toString('base64');
  const result = isUsableCursor(validCursor);
  assert.strictEqual(result, true);
});

test('Unit: isUsableCursor rejects invalid base64', () => {
  const result = isUsableCursor('not-valid-base64!!!');
  assert.strictEqual(result, false);
});

// ============================================================================
// Unit: readCursor
// ============================================================================

test('Unit: readCursor returns null for undefined', () => {
  const result = readCursor(undefined);
  assert.strictEqual(result, null);
});

test('Unit: readCursor returns null for empty string', () => {
  const result = readCursor('');
  assert.strictEqual(result, null);
});

test('Unit: readCursor returns the cursor when provided', () => {
  const cursor = 'some-cursor-value';
  const result = readCursor(cursor);
  assert.strictEqual(result, cursor);
});

// ============================================================================
// Unit: isIsoUtc
// ============================================================================

test('Unit: isIsoUtc accepts 2026-10-02T07:15:00Z', () => {
  const result = isIsoUtc('2026-10-02T07:15:00Z');
  assert.strictEqual(result, true);
});

test('Unit: isIsoUtc accepts ISO timestamp with milliseconds', () => {
  const result = isIsoUtc('2026-10-02T07:15:00.123Z');
  assert.strictEqual(result, true);
});

test('Unit: isIsoUtc rejects undefined', () => {
  const result = isIsoUtc(undefined);
  assert.strictEqual(result, false);
});

test('Unit: isIsoUtc rejects "yesterday"', () => {
  const result = isIsoUtc('yesterday');
  assert.strictEqual(result, false);
});

test('Unit: isIsoUtc rejects date without time', () => {
  const result = isIsoUtc('2026-10-02');
  assert.strictEqual(result, false);
});

test('Unit: isIsoUtc rejects date without Z suffix', () => {
  const result = isIsoUtc('2026-10-02T07:15:00');
  assert.strictEqual(result, false);
});

test('Unit: isIsoUtc rejects invalid date', () => {
  const result = isIsoUtc('2026-13-32T25:61:61Z');
  assert.strictEqual(result, false);
});

test('Unit: isIsoUtc accepts various valid ISO timestamps', () => {
  const validTimestamps = [
    '2020-01-01T00:00:00Z',
    '2025-12-31T23:59:59Z',
    '2026-06-15T12:30:45Z',
    '2026-06-15T12:30:45.000Z',
    '2026-06-15T12:30:45.999Z',
  ];

  for (const ts of validTimestamps) {
    const result = isIsoUtc(ts);
    assert.strictEqual(result, true, `Should accept ${ts}`);
  }
});

// ============================================================================
// Unit: bearerToken
// ============================================================================

test('Unit: bearerToken extracts token from Authorization header', () => {
  const headers = { authorization: 'Bearer my-token-123' };
  const result = bearerToken(headers);
  assert.strictEqual(result, 'my-token-123');
});

test('Unit: bearerToken is case-insensitive for header name', () => {
  const headers = { Authorization: 'Bearer my-token-123' };
  const result = bearerToken(headers);
  assert.strictEqual(result, 'my-token-123');
});

test('Unit: bearerToken returns null when no Authorization header', () => {
  const headers = { other: 'value' };
  const result = bearerToken(headers);
  assert.strictEqual(result, null);
});

test('Unit: bearerToken returns null for missing headers object', () => {
  const result = bearerToken(undefined);
  assert.strictEqual(result, null);
});

test('Unit: bearerToken returns null when Authorization is not a string', () => {
  const headers = { authorization: 123 };
  const result = bearerToken(headers);
  assert.strictEqual(result, null);
});

test('Unit: bearerToken returns null for non-Bearer scheme', () => {
  const headers = { authorization: 'Basic dXNlcjpwYXNz' };
  const result = bearerToken(headers);
  assert.strictEqual(result, null);
});

test('Unit: bearerToken returns null when Bearer prefix is present but no token', () => {
  const headers = { authorization: 'Bearer ' };
  const result = bearerToken(headers);
  assert.strictEqual(result, null);
});

test('Unit: bearerToken returns null when Bearer prefix is present but only whitespace', () => {
  const headers = { authorization: 'Bearer   ' };
  const result = bearerToken(headers);
  assert.strictEqual(result, null);
});

test('Unit: bearerToken trims whitespace after Bearer prefix', () => {
  const headers = { authorization: 'Bearer  my-token-123  ' };
  const result = bearerToken(headers);
  assert.strictEqual(result, 'my-token-123');
});

test('Unit: bearerToken handles mixed case Bearer', () => {
  const headers = { Authorization: 'bearer my-token-123' };
  const result = bearerToken(headers);
  // The check is case-sensitive for the Bearer part, so this should fail
  assert.strictEqual(result, null);
});
