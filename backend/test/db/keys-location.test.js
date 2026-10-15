/**
 * Unit tests for TASK-056: the `deviceLocation` key builder
 * (`backend/src/db/keys.ts`).
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { deviceLocation } from '../../dist/db/keys.js';

test('Unit: deviceLocation builds pk "DEVICE#<deviceId>" and sk "LOCATION"', () => {
  const key = deviceLocation('dev-1');
  assert.deepStrictEqual(key, { pk: 'DEVICE#dev-1', sk: 'LOCATION' });
});

test('Unit: deviceLocation rejects a deviceId containing the separator', () => {
  assert.throws(
    () => deviceLocation('dev#1'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: dev#1');
      return true;
    },
  );
});
