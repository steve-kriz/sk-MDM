/**
 * Unit tests for TASK-044's heartbeat key builder and frequency constants
 * (`backend/src/db/keys.ts`, `backend/src/config/intervals.ts`). (AC5)
 */

import test from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const { deviceHeartbeatSettings } = await import('../../dist/db/keys.js');
const { HEARTBEAT_INTERVAL_OPTIONS_SECONDS, HEARTBEAT_DEFAULT_INTERVAL_SECONDS } = await import(
  '../../dist/config/intervals.js'
);

// ============================================================================
// Scenario: TS types carry the heartbeat fields (AC3)
// ============================================================================

test('Scenario: backend/src/contract/types.ts declares the heartbeat fields', () => {
  const source = readFileSync(join(__dirname, '../../src/contract/types.ts'), 'utf8');
  assert.match(source, /heartbeatIntervalSeconds\?:\s*number/);
  assert.match(source, /interface HeartbeatRequest/);
  assert.match(source, /interface HeartbeatResponse/);
});

test('Scenario: Heartbeat settings key', () => {
  const key = deviceHeartbeatSettings('d1');
  assert.deepStrictEqual(key, { pk: 'DEVICE#d1', sk: 'HEARTBEAT' });
});

test('Scenario: Heartbeat settings key rejects an id containing #', () => {
  assert.throws(() => deviceHeartbeatSettings('bad#id'), /invalid id/);
});

test('Scenario: Heartbeat interval constants are pinned', () => {
  assert.deepStrictEqual([...HEARTBEAT_INTERVAL_OPTIONS_SECONDS], [60, 300, 900, 1800, 3600]);
  assert.strictEqual(HEARTBEAT_DEFAULT_INTERVAL_SECONDS, 300);
});
