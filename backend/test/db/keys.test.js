/**
 * Unit tests for the DynamoDB key builders in db/keys.ts.
 * These tests ensure the single-table layout is correctly implemented.
 */

import test from 'node:test';
import assert from 'node:assert';
import {
  assertValidId,
  deviceProfile,
  deviceInventory,
  devicePosture,
  deviceCommand,
  deviceByHardware,
  group,
  groupMember,
  policy,
  policyAssignment,
  enrollmentToken,
  nonce,
  audit,
  deviceListIndex,
  groupIndex,
  KEY_SEPARATOR,
  GSI1_NAME,
} from '../../dist/db/keys.js';

test('Unit: deviceProfile builds the correct key', () => {
  const key = deviceProfile('dev-7');
  assert.deepStrictEqual(key, { pk: 'DEVICE#dev-7', sk: 'PROFILE' });
});

test('Unit: deviceInventory builds the correct key', () => {
  const key = deviceInventory('dev-123');
  assert.deepStrictEqual(key, { pk: 'DEVICE#dev-123', sk: 'INVENTORY' });
});

test('Unit: devicePosture builds the correct key', () => {
  const key = devicePosture('device-abc');
  assert.deepStrictEqual(key, { pk: 'DEVICE#device-abc', sk: 'POSTURE' });
});

test('Unit: deviceCommand builds the correct key', () => {
  const key = deviceCommand('d1', 'c9');
  assert.deepStrictEqual(key, { pk: 'DEVICE#d1', sk: 'CMD#c9' });
});

test('Unit: group builds the correct key', () => {
  const key = group('grp-1');
  assert.deepStrictEqual(key, { pk: 'GROUP#grp-1', sk: 'PROFILE' });
});

test('Unit: groupMember builds the correct key', () => {
  const key = groupMember('g1', 'd1');
  assert.deepStrictEqual(key, { pk: 'GROUP#g1', sk: 'MEMBER#d1' });
});

test('Unit: policy builds the correct key', () => {
  const key = policy('pol-123');
  assert.deepStrictEqual(key, { pk: 'POLICY#pol-123', sk: 'PROFILE' });
});

test('Unit: policyAssignment builds the correct key', () => {
  const key = policyAssignment('p1', 'g1');
  assert.deepStrictEqual(key, { pk: 'POLICY#p1', sk: 'ASSIGN#g1' });
});

test('Unit: enrollmentToken builds the correct key', () => {
  const key = enrollmentToken('token-xyz');
  assert.deepStrictEqual(key, { pk: 'ENROLLTOKEN#token-xyz', sk: 'PROFILE' });
});

test('Unit: nonce builds the correct key', () => {
  const key = nonce('d1', 'nonce123');
  assert.deepStrictEqual(key, { pk: 'NONCE#d1', sk: 'nonce123' });
});

test('Unit: audit builds the correct key with string seq', () => {
  const key = audit('2026-10-02', '5');
  assert.deepStrictEqual(key, { pk: 'AUDIT#2026-10-02', sk: '5' });
});

test('Unit: audit builds the correct key with number seq', () => {
  const key = audit('2026-10-02', 5);
  assert.deepStrictEqual(key, { pk: 'AUDIT#2026-10-02', sk: '5' });
});

test('Unit: deviceListIndex builds the correct gsi1 attributes', () => {
  const key = deviceListIndex('2026-10-02T00:00:00Z');
  assert.deepStrictEqual(key, { gsi1pk: 'DEVICE', gsi1sk: '2026-10-02T00:00:00Z' });
});

test('Unit: groupIndex builds the correct gsi1 attributes', () => {
  const key = groupIndex('g1', 'd1');
  assert.deepStrictEqual(key, { gsi1pk: 'GROUP#g1', gsi1sk: 'DEVICE#d1' });
});

test('Unit: assertValidId rejects ids containing KEY_SEPARATOR', () => {
  assert.throws(
    () => assertValidId('bad#id'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: bad#id');
      return true;
    }
  );
});

test('Unit: assertValidId rejects ids with multiple separators', () => {
  assert.throws(
    () => assertValidId('a#b#c'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: a#b#c');
      return true;
    }
  );
});

test('Unit: assertValidId accepts valid ids', () => {
  assert.strictEqual(assertValidId('dev-7'), 'dev-7');
  assert.strictEqual(assertValidId('simple'), 'simple');
  assert.strictEqual(assertValidId('with-dashes'), 'with-dashes');
  assert.strictEqual(assertValidId('with_underscores'), 'with_underscores');
});

test('E2E Scenario: Entity keys follow the single-table layout', () => {
  const key = deviceCommand('d1', 'c9');
  assert.deepStrictEqual(key, { pk: 'DEVICE#d1', sk: 'CMD#c9' });
});

test('E2E Scenario: Index attributes are built for listing', () => {
  const key = deviceListIndex('2026-10-02T00:00:00Z');
  assert.strictEqual(key.gsi1pk, 'DEVICE');
  assert.strictEqual(key.gsi1sk, '2026-10-02T00:00:00Z');
});

test('E2E Scenario: Separator in an id is rejected', () => {
  assert.throws(
    () => deviceProfile('bad#id'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: bad#id');
      return true;
    }
  );
});

test('Unit: KEY_SEPARATOR is exported correctly', () => {
  assert.strictEqual(KEY_SEPARATOR, '#');
});

test('Unit: GSI1_NAME is exported correctly', () => {
  assert.strictEqual(GSI1_NAME, 'gsi1');
});

test('Unit: deviceByHardware builds the correct key', () => {
  const key = deviceByHardware('HW-1');
  assert.deepStrictEqual(key, { pk: 'HWUUID#HW-1', sk: 'POINTER' });
});

test('Unit: deviceByHardware accepts various hardware uuid formats', () => {
  const key1 = deviceByHardware('HW-1');
  assert.deepStrictEqual(key1, { pk: 'HWUUID#HW-1', sk: 'POINTER' });

  const key2 = deviceByHardware('uuid-12345-abcde');
  assert.deepStrictEqual(key2, { pk: 'HWUUID#uuid-12345-abcde', sk: 'POINTER' });

  const key3 = deviceByHardware('simple');
  assert.deepStrictEqual(key3, { pk: 'HWUUID#simple', sk: 'POINTER' });
});

test('Unit: deviceByHardware rejects ids containing KEY_SEPARATOR', () => {
  assert.throws(
    () => deviceByHardware('bad#id'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: bad#id');
      return true;
    }
  );
});

test('Unit: deviceByHardware rejects ids with multiple separators', () => {
  assert.throws(
    () => deviceByHardware('a#b#c'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: a#b#c');
      return true;
    }
  );
});

test('E2E Scenario: Hardware pointer key shape and validation', () => {
  const key = deviceByHardware('HW-1');
  assert.deepStrictEqual(key, { pk: 'HWUUID#HW-1', sk: 'POINTER' });

  assert.throws(
    () => deviceByHardware('bad#id'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: bad#id');
      return true;
    }
  );
});
