/**
 * Unit test for TASK-060's deviceDefenderHardening key builder
 * (backend/src/db/keys.ts), modelled on the deviceAntivirusStatus tests beside
 * it in backend/test/db/keys.test.js.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { deviceDefenderHardening } = await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);

test('Unit: deviceDefenderHardening builds the correct key', () => {
  const key = deviceDefenderHardening('d1');
  assert.deepStrictEqual(key, { pk: 'DEVICE#d1', sk: 'DEFENDERHARDENING' });
});

test('Unit: deviceDefenderHardening rejects a deviceId containing the separator', () => {
  assert.throws(
    () => deviceDefenderHardening('bad#id'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: bad#id');
      return true;
    },
  );
});
