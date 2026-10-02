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
  agentRelease,
  AGENT_RELEASE_PLATFORMS,
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

// ============================================================================
// TASK-022: Agent Release Key Builder Tests
// ============================================================================

test('Unit: agentRelease builds the correct key for windows-amd64', () => {
  const key = agentRelease('windows-amd64');
  assert.deepStrictEqual(key, { pk: 'AGENTRELEASE', sk: 'windows-amd64' });
});

test('Unit: agentRelease builds the correct key for windows-arm64', () => {
  const key = agentRelease('windows-arm64');
  assert.deepStrictEqual(key, { pk: 'AGENTRELEASE', sk: 'windows-arm64' });
});

test('Unit: agentRelease builds the correct key for darwin-amd64', () => {
  const key = agentRelease('darwin-amd64');
  assert.deepStrictEqual(key, { pk: 'AGENTRELEASE', sk: 'darwin-amd64' });
});

test('Unit: agentRelease builds the correct key for darwin-arm64', () => {
  const key = agentRelease('darwin-arm64');
  assert.deepStrictEqual(key, { pk: 'AGENTRELEASE', sk: 'darwin-arm64' });
});

test('Unit: agentRelease rejects invalid platform linux-amd64', () => {
  assert.throws(
    () => agentRelease('linux-amd64'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: linux-amd64');
      return true;
    }
  );
});

test('Unit: agentRelease rejects invalid platform windows-ppc64', () => {
  assert.throws(
    () => agentRelease('windows-ppc64'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: windows-ppc64');
      return true;
    }
  );
});

test('Unit: agentRelease rejects invalid platform darwin-x86', () => {
  assert.throws(
    () => agentRelease('darwin-x86'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: darwin-x86');
      return true;
    }
  );
});

test('Unit: agentRelease rejects invalid platform with separator', () => {
  assert.throws(
    () => agentRelease('windows#amd64'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: windows#amd64');
      return true;
    }
  );
});

test('Unit: AGENT_RELEASE_PLATFORMS contains exactly four platforms', () => {
  assert.strictEqual(AGENT_RELEASE_PLATFORMS.length, 4);
  assert(AGENT_RELEASE_PLATFORMS.includes('windows-amd64'));
  assert(AGENT_RELEASE_PLATFORMS.includes('windows-arm64'));
  assert(AGENT_RELEASE_PLATFORMS.includes('darwin-amd64'));
  assert(AGENT_RELEASE_PLATFORMS.includes('darwin-arm64'));
});

test('Unit: agentRelease uses AGENTRELEASE partition for all platforms', () => {
  for (const platform of AGENT_RELEASE_PLATFORMS) {
    const key = agentRelease(platform);
    assert.strictEqual(key.pk, 'AGENTRELEASE');
    assert.strictEqual(key.sk, platform);
  }
});

test('E2E Scenario: All four release platforms are buildable', () => {
  const platforms = ['windows-amd64', 'windows-arm64', 'darwin-amd64', 'darwin-arm64'];

  for (const platform of platforms) {
    const key = agentRelease(platform);
    assert.strictEqual(key.pk, 'AGENTRELEASE');
    assert.strictEqual(key.sk, platform);
  }
});

test('E2E Scenario: Release platform rejection follows TASK-004 convention', () => {
  // Invalid platforms should throw with "invalid id: <value>" message
  const invalidPlatforms = [
    'linux-amd64',
    'freebsd-amd64',
    'android-arm64',
    'ios-arm64',
    '',
    'windows',
    'darwin',
  ];

  for (const platform of invalidPlatforms) {
    assert.throws(
      () => agentRelease(platform),
      (err) => err.message === `invalid id: ${platform}`,
      `Platform ${platform} should throw with correct message`,
    );
  }
});
