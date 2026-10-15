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
  deviceAntivirusFinding,
  deviceAntivirusScan,
  deviceAntivirusStatus,
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
  deviceAnalytics,
  analyticsListIndex,
  deviceBootHistory,
  deviceAppCrash,
  appCrashListIndex,
  inventoryListIndex,
  APP_CRASH_SK_PREFIX,
  AGENT_RELEASE_PLATFORMS,
  KEY_SEPARATOR,
  GSI1_NAME,
  application,
  applicationListIndex,
} from '../../dist/db/keys.js';

// ============================================================================
// TASK-049 (AC1): application() and applicationListIndex()
// ============================================================================

test('Scenario: Application keys -- application() and applicationListIndex() build the documented shape', () => {
  // When I call application("app-0123456789abcdef") and applicationListIndex("7-Zip")
  const key = application('app-0123456789abcdef');
  const index = applicationListIndex('7-Zip');

  // Then they return {pk, sk} and {gsi1pk, gsi1sk} as documented
  assert.deepStrictEqual(key, { pk: 'APPLICATION#app-0123456789abcdef', sk: 'PROFILE' });
  assert.deepStrictEqual(index, { gsi1pk: 'APPLICATION', gsi1sk: '7-Zip' });
});

test('Scenario (failure): An invalid application id cannot form a key -- empty id throws', () => {
  // When I call application("")
  // Then an Error is thrown
  assert.throws(() => application(''));
});

test('Scenario (failure): An invalid application id cannot form a key -- id containing "#" throws', () => {
  // When I call application("a#b")
  // Then an Error is thrown, as script() does through assertValidId
  assert.throws(() => application('a#b'), (err) => {
    assert.strictEqual(err.message, 'invalid id: a#b');
    return true;
  });
});

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

test('Unit: deviceAntivirusFinding builds the correct key', () => {
  const key = deviceAntivirusFinding('d1', 'f1');
  assert.deepStrictEqual(key, { pk: 'DEVICE#d1', sk: 'AVFINDING#f1' });
});

test('Unit: deviceAntivirusFinding rejects a findingId containing the separator', () => {
  assert.throws(
    () => deviceAntivirusFinding('d1', 'bad#id'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: bad#id');
      return true;
    }
  );
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

test('Unit: policyListIndex puts a policy into the POLICY gsi1 partition, sorted by name', async () => {
  const { policyListIndex } = await import('../../dist/db/keys.js');
  assert.deepStrictEqual(policyListIndex('Baseline'), { gsi1pk: 'POLICY', gsi1sk: 'Baseline' });
  // Distinct from a policy's own `POLICY#<id>` partition.
  assert.notStrictEqual(policyListIndex('x').gsi1pk, policy('x').pk);
});

// ============================================================================
// TASK-055 AC25: Antivirus scan key builder
// ============================================================================

test('Unit: deviceAntivirusScan builds the correct key', () => {
  const key = deviceAntivirusScan('d1');
  assert.deepStrictEqual(key, { pk: 'DEVICE#d1', sk: 'AVSCAN' });
});

test('Unit: deviceAntivirusScan rejects a deviceId containing the separator', () => {
  assert.throws(
    () => deviceAntivirusScan('bad#id'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: bad#id');
      return true;
    }
  );
});

// ============================================================================
// TASK-058 AC18: Antivirus status key builder
// ============================================================================

test('Unit: deviceAntivirusStatus builds the correct key', () => {
  const key = deviceAntivirusStatus('d1');
  assert.deepStrictEqual(key, { pk: 'DEVICE#d1', sk: 'AVSTATUS' });
});

test('Unit: deviceAntivirusStatus rejects a deviceId containing the separator', () => {
  assert.throws(
    () => deviceAntivirusStatus('bad#id'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: bad#id');
      return true;
    }
  );
});

test('Unit: deviceAntivirusStatus is distinct from deviceAntivirusScan', () => {
  assert.notStrictEqual(deviceAntivirusStatus('d1').sk, deviceAntivirusScan('d1').sk);
});

// ============================================================================
// TASK-034: Analytics Key Builder Tests
// ============================================================================

test('Unit: deviceAnalytics builds the correct key', () => {
  const key = deviceAnalytics('d1');
  assert.deepStrictEqual(key, { pk: 'DEVICE#d1', sk: 'ANALYTICS' });
});

test('Unit: deviceAnalytics rejects a deviceId containing the separator', () => {
  assert.throws(
    () => deviceAnalytics('bad#id'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: bad#id');
      return true;
    }
  );
});

test('Unit: analyticsListIndex builds the correct gsi1 key', () => {
  const key = analyticsListIndex('d1');
  assert.deepStrictEqual(key, { gsi1pk: 'ANALYTICS', gsi1sk: 'd1' });
});

test('Unit: analyticsListIndex rejects a deviceId containing the separator', () => {
  assert.throws(
    () => analyticsListIndex('bad#id'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: bad#id');
      return true;
    }
  );
});

test('Unit: deviceBootHistory builds the correct key', () => {
  const key = deviceBootHistory('d1');
  assert.deepStrictEqual(key, { pk: 'DEVICE#d1', sk: 'BOOTHISTORY' });
});

test('Unit: deviceBootHistory rejects a deviceId containing the separator', () => {
  assert.throws(
    () => deviceBootHistory('bad#id'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: bad#id');
      return true;
    }
  );
});

test('Unit: deviceAppCrash builds the correct key', () => {
  const key = deviceAppCrash('d1', '2026-10-02T06:58:12Z', 'abc');
  assert.deepStrictEqual(key, { pk: 'DEVICE#d1', sk: 'APPCRASH#2026-10-02T06:58:12Z#abc' });
});

test('Unit: deviceAppCrash rejects a deviceId containing the separator', () => {
  assert.throws(
    () => deviceAppCrash('bad#id', '2026-10-02T06:58:12Z', 'abc'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: bad#id');
      return true;
    }
  );
});

test('Unit: deviceAppCrash rejects an occurredAt containing the separator', () => {
  assert.throws(
    () => deviceAppCrash('d1', '2026-10-02#bad', 'abc'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: 2026-10-02#bad');
      return true;
    }
  );
});

test('Unit: deviceAppCrash rejects an eventId containing the separator', () => {
  assert.throws(
    () => deviceAppCrash('d1', '2026-10-02T06:58:12Z', 'a#b'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: a#b');
      return true;
    }
  );
});

test('Unit: appCrashListIndex builds the correct gsi1 key', () => {
  const key = appCrashListIndex('2026-10-02T06:58:12Z', 'd1');
  assert.deepStrictEqual(key, { gsi1pk: 'APPCRASH', gsi1sk: '2026-10-02T06:58:12Z#d1' });
});

test('Unit: appCrashListIndex rejects an occurredAt containing the separator', () => {
  assert.throws(
    () => appCrashListIndex('2026-10-02#bad', 'd1'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: 2026-10-02#bad');
      return true;
    }
  );
});

test('Unit: appCrashListIndex rejects a deviceId containing the separator', () => {
  assert.throws(
    () => appCrashListIndex('2026-10-02T06:58:12Z', 'bad#id'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: bad#id');
      return true;
    }
  );
});

test('Unit: APP_CRASH_SK_PREFIX is exported correctly', () => {
  assert.strictEqual(APP_CRASH_SK_PREFIX, 'APPCRASH#');
});

test('E2E Scenario: Analytics key builders produce the pinned keys', () => {
  // deviceAnalytics
  assert.deepStrictEqual(deviceAnalytics('d1'), { pk: 'DEVICE#d1', sk: 'ANALYTICS' });

  // analyticsListIndex
  assert.deepStrictEqual(analyticsListIndex('d1'), { gsi1pk: 'ANALYTICS', gsi1sk: 'd1' });

  // deviceBootHistory
  assert.deepStrictEqual(deviceBootHistory('d1'), { pk: 'DEVICE#d1', sk: 'BOOTHISTORY' });

  // deviceAppCrash
  assert.deepStrictEqual(deviceAppCrash('d1', '2026-10-02T06:58:12Z', 'abc'),
    { pk: 'DEVICE#d1', sk: 'APPCRASH#2026-10-02T06:58:12Z#abc' });

  // appCrashListIndex
  assert.deepStrictEqual(appCrashListIndex('2026-10-02T06:58:12Z', 'd1'),
    { gsi1pk: 'APPCRASH', gsi1sk: '2026-10-02T06:58:12Z#d1' });

  // APP_CRASH_SK_PREFIX
  assert.strictEqual(APP_CRASH_SK_PREFIX, 'APPCRASH#');
});

test('E2E Scenario: Analytics key builders reject ids carrying the separator', () => {
  // deviceAnalytics
  assert.throws(() => deviceAnalytics('bad#id'), (err) => err.message === 'invalid id: bad#id');

  // deviceBootHistory
  assert.throws(() => deviceBootHistory('bad#id'), (err) => err.message === 'invalid id: bad#id');

  // deviceAppCrash
  assert.throws(() => deviceAppCrash('d1', '2026-10-02T06:58:12Z', 'a#b'), (err) => err.message === 'invalid id: a#b');

  // analyticsListIndex
  assert.throws(() => analyticsListIndex('bad#id'), (err) => err.message === 'invalid id: bad#id');

  // appCrashListIndex
  assert.throws(() => appCrashListIndex('2026-10-02T06:58:12Z', 'bad#id'), (err) => err.message === 'invalid id: bad#id');
});

// ============================================================================
// TASK-038: Software List Index Key Builder Tests
// ============================================================================

test('Unit: inventoryListIndex builds the correct gsi1 key (AC1)', () => {
  const key = inventoryListIndex('dev-7');
  assert.deepStrictEqual(key, { gsi1pk: 'INVENTORY', gsi1sk: 'dev-7' });
});

test('Unit: inventoryListIndex works with various device ids', () => {
  const key1 = inventoryListIndex('d1');
  assert.deepStrictEqual(key1, { gsi1pk: 'INVENTORY', gsi1sk: 'd1' });

  const key2 = inventoryListIndex('device-abc');
  assert.deepStrictEqual(key2, { gsi1pk: 'INVENTORY', gsi1sk: 'device-abc' });

  const key3 = inventoryListIndex('dev-123-xyz');
  assert.deepStrictEqual(key3, { gsi1pk: 'INVENTORY', gsi1sk: 'dev-123-xyz' });
});

test('Unit: inventoryListIndex rejects a deviceId containing the separator (AC1, failure)', () => {
  assert.throws(
    () => inventoryListIndex('a#b'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: a#b');
      return true;
    }
  );
});

test('Unit: inventoryListIndex rejects deviceIds with multiple separators', () => {
  assert.throws(
    () => inventoryListIndex('a#b#c'),
    (err) => {
      assert.strictEqual(err.message, 'invalid id: a#b#c');
      return true;
    }
  );
});

test('E2E Scenario: Inventory list key builder produces the pinned keys', () => {
  assert.deepStrictEqual(inventoryListIndex('d1'), { gsi1pk: 'INVENTORY', gsi1sk: 'd1' });
  assert.deepStrictEqual(inventoryListIndex('dev-7'), { gsi1pk: 'INVENTORY', gsi1sk: 'dev-7' });
});

test('E2E Scenario: Inventory list key builder rejects invalid ids', () => {
  assert.throws(() => inventoryListIndex('bad#id'), (err) => err.message === 'invalid id: bad#id');
  assert.throws(() => inventoryListIndex('a#b#c'), (err) => err.message === 'invalid id: a#b#c');
});
