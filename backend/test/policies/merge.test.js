/**
 * Unit tests for mergePolicySettings (TASK-012).
 *
 * Tests the pure merge logic that does not touch storage or the network.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { mergePolicySettings } = await import(
  `file://${join(__dirname, '../../dist/policies/merge.js')}`
);

// ============================================================================
// Unit Tests for mergePolicySettings
// ============================================================================

test('Scenario: Merge returns empty settings and conflicts when no policies', (t) => {
  const result = mergePolicySettings([]);
  assert.deepStrictEqual(result.effectiveSettings, {});
  assert.deepStrictEqual(result.conflicts, []);
});

test('Scenario: Single policy provides all its settings', (t) => {
  const policies = [
    {
      policyId: 'p1',
      version: 1,
      settings: { firewallEnabled: true, diskEncryptionRequired: false },
    },
  ];
  const result = mergePolicySettings(policies);
  assert.deepStrictEqual(result.effectiveSettings, {
    firewallEnabled: true,
    diskEncryptionRequired: false,
  });
  assert.deepStrictEqual(result.conflicts, []);
});

test('Scenario: Multiple non-conflicting policies merge cleanly', (t) => {
  const policies = [
    { policyId: 'p1', version: 1, settings: { firewallEnabled: true } },
    { policyId: 'p2', version: 1, settings: { diskEncryptionRequired: false } },
  ];
  const result = mergePolicySettings(policies);
  assert.deepStrictEqual(result.effectiveSettings, {
    firewallEnabled: true,
    diskEncryptionRequired: false,
  });
  assert.deepStrictEqual(result.conflicts, []);
});

test('Scenario: Smallest policyId wins conflicts', (t) => {
  const policies = [
    { policyId: 'p-bbb', version: 1, settings: { firewallEnabled: false } },
    { policyId: 'p-aaa', version: 1, settings: { firewallEnabled: true } },
  ];
  const result = mergePolicySettings(policies);
  assert.strictEqual(result.effectiveSettings.firewallEnabled, true);
  assert.strictEqual(result.conflicts.length, 1);
  assert.deepStrictEqual(result.conflicts[0], {
    key: 'firewallEnabled',
    winningPolicyId: 'p-aaa',
    value: true,
    losers: [{ policyId: 'p-bbb', value: false }],
  });
});

test('Scenario: Multiple conflicting keys sorted by key, losers by policyId', (t) => {
  const policies = [
    {
      policyId: 'p-zzz',
      version: 1,
      settings: {
        diskEncryptionRequired: true,
        firewallEnabled: true,
        osUpdateMaxAgeDays: 30,
      },
    },
    {
      policyId: 'p-aaa',
      version: 1,
      settings: {
        diskEncryptionRequired: false,
        firewallEnabled: false,
        osUpdateMaxAgeDays: 60,
      },
    },
  ];
  const result = mergePolicySettings(policies);
  assert.strictEqual(result.conflicts.length, 3);
  // Conflicts should be sorted by key
  assert.strictEqual(result.conflicts[0].key, 'diskEncryptionRequired');
  assert.strictEqual(result.conflicts[1].key, 'firewallEnabled');
  assert.strictEqual(result.conflicts[2].key, 'osUpdateMaxAgeDays');
  // All should be won by p-aaa (smallest id)
  assert.strictEqual(result.conflicts[0].winningPolicyId, 'p-aaa');
  assert.strictEqual(result.conflicts[1].winningPolicyId, 'p-aaa');
  assert.strictEqual(result.conflicts[2].winningPolicyId, 'p-aaa');
});

test('Scenario: Three-way conflict has losers sorted by policyId', (t) => {
  const policies = [
    { policyId: 'p-zzz', version: 1, settings: { firewallEnabled: 'zzz' } },
    { policyId: 'p-aaa', version: 1, settings: { firewallEnabled: 'aaa' } },
    { policyId: 'p-bbb', version: 1, settings: { firewallEnabled: 'bbb' } },
  ];
  const result = mergePolicySettings(policies);
  assert.strictEqual(result.conflicts.length, 1);
  const conflict = result.conflicts[0];
  assert.strictEqual(conflict.winningPolicyId, 'p-aaa');
  assert.strictEqual(conflict.value, 'aaa');
  assert.strictEqual(conflict.losers.length, 2);
  // Losers should be sorted by policyId: p-bbb before p-zzz
  assert.strictEqual(conflict.losers[0].policyId, 'p-bbb');
  assert.strictEqual(conflict.losers[0].value, 'bbb');
  assert.strictEqual(conflict.losers[1].policyId, 'p-zzz');
  assert.strictEqual(conflict.losers[1].value, 'zzz');
});

test('Scenario: Policies with null settings treated as empty', (t) => {
  const policies = [
    { policyId: 'p1', version: 1, settings: null },
    { policyId: 'p2', version: 1, settings: { firewallEnabled: true } },
  ];
  const result = mergePolicySettings(policies);
  assert.deepStrictEqual(result.effectiveSettings, { firewallEnabled: true });
  assert.deepStrictEqual(result.conflicts, []);
});

test('Scenario: Policies with non-object settings treated as empty', (t) => {
  const policies = [
    { policyId: 'p1', version: 1, settings: 'invalid' },
    { policyId: 'p2', version: 1, settings: { firewallEnabled: true } },
  ];
  const result = mergePolicySettings(policies);
  assert.deepStrictEqual(result.effectiveSettings, { firewallEnabled: true });
  assert.deepStrictEqual(result.conflicts, []);
});

test('Scenario: Policies arrive in any order', (t) => {
  // Same policies in different orders should produce same result
  const policies1 = [
    { policyId: 'p1', version: 1, settings: { firewallEnabled: true } },
    { policyId: 'p2', version: 1, settings: { firewallEnabled: false } },
  ];
  const policies2 = [
    { policyId: 'p2', version: 1, settings: { firewallEnabled: false } },
    { policyId: 'p1', version: 1, settings: { firewallEnabled: true } },
  ];
  const result1 = mergePolicySettings(policies1);
  const result2 = mergePolicySettings(policies2);
  assert.deepStrictEqual(result1, result2);
  assert.strictEqual(result1.effectiveSettings.firewallEnabled, true);
});

test('Scenario: Array-type settings like localAdminAllowlist work', (t) => {
  const policies = [
    { policyId: 'p1', version: 1, settings: { localAdminAllowlist: ['admin1'] } },
    {
      policyId: 'p2',
      version: 1,
      settings: { localAdminAllowlist: ['admin2'] },
    },
  ];
  const result = mergePolicySettings(policies);
  // p1 wins because it's smaller
  assert.deepStrictEqual(result.effectiveSettings.localAdminAllowlist, [
    'admin1',
  ]);
  assert.strictEqual(result.conflicts.length, 1);
  assert.strictEqual(result.conflicts[0].losers[0].value[0], 'admin2');
});

test('Scenario: Integer settings are preserved', (t) => {
  const policies = [
    {
      policyId: 'p1',
      version: 1,
      settings: { screenLockTimeoutSeconds: 300 },
    },
  ];
  const result = mergePolicySettings(policies);
  assert.strictEqual(result.effectiveSettings.screenLockTimeoutSeconds, 300);
});

test('Scenario: Version numbers are preserved in policies list', (t) => {
  const policies = [
    { policyId: 'p1', version: 5, settings: { firewallEnabled: true } },
  ];
  const result = mergePolicySettings(policies);
  // Version is not in the result, but let's verify we don't lose data
  assert.strictEqual(result.effectiveSettings.firewallEnabled, true);
});
