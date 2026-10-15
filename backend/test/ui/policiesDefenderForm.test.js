/**
 * E2E cucumber-style tests for TASK-060, the Defender protection controls in
 * the policy create/edit forms (backend/src/ui/views/policies.js), AC3, AC4
 * and the SETTING_KEYS/POLICY_SETTING_KEYS equality half of AC6. No database
 * is touched: these are pure render-function tests.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

const policiesView = await import('../../dist/ui/views/policies.js');
const policiesAdmin = await import('../../dist/admin/policies.js');

test('Scenario: Policy form renders the Defender controls with stored values', async (t) => {
  // Given a policy with defenderNetworkProtection true and
  // defenderRansomwareProtection "audit"
  const editing = {
    policyId: 'p1',
    name: 'Policy 1',
    version: 1,
    settings: { defenderNetworkProtection: true, defenderRansomwareProtection: 'audit' },
  };

  // When the edit form is rendered
  const html = policiesView.render({ items: [editing], editing });

  // Then there is a checkbox named defenderNetworkProtection that is checked
  const networkCheckbox = html.match(/<input[^>]*name="defenderNetworkProtection"[^>]*>/)?.[0];
  assert.ok(networkCheckbox, 'expected a defenderNetworkProtection checkbox');
  assert.ok(networkCheckbox.includes('checked'), 'defenderNetworkProtection checkbox should be checked');

  // And the checkboxes for the other four boolean Defender keys are unchecked
  for (const key of ['defenderRealTimeProtection', 'defenderCloudProtection', 'defenderReputationProtection', 'defenderDailySignatureUpdate']) {
    const checkbox = html.match(new RegExp(`<input[^>]*name="${key}"[^>]*>`))?.[0];
    assert.ok(checkbox, `expected a ${key} checkbox`);
    assert.ok(!checkbox.includes('checked'), `${key} checkbox should not be checked, got ${checkbox}`);
  }

  // And the select defenderRansomwareProtection has options "", "audit",
  // "block" with "audit" selected
  const select = html.match(/<select[^>]*name="defenderRansomwareProtection"[^>]*>[\s\S]*?<\/select>/)?.[0];
  assert.ok(select, 'expected a defenderRansomwareProtection select');
  assert.ok(select.includes('<option value=""'));
  assert.ok(select.includes('<option value="audit" selected>'), select);
  assert.ok(select.includes('<option value="block">'));
});

test('Scenario: Ransomware select carries the Controlled folder access warning', async (t) => {
  // When the create form is rendered
  const html = policiesView.render({ items: [], name: '' });

  // Then the defenderRansomwareProtection select is followed by a hint
  // containing "Controlled folder access can block legitimate applications"
  const selectIndex = html.indexOf('name="defenderRansomwareProtection"');
  assert.ok(selectIndex >= 0, 'expected the defenderRansomwareProtection select');
  const after = html.slice(selectIndex);
  const hintMatch = after.match(/<p class="hint">([^<]*)<\/p>/);
  assert.ok(hintMatch, 'expected a hint paragraph after the select');
  assert.ok(
    hintMatch[1].includes('Controlled folder access can block legitimate applications'),
    `hint text = ${hintMatch[1]}`,
  );
});

test('Scenario: Unchecked defender boolean and a blank select render as unselected/unchecked on the create form', async (t) => {
  // An empty state (nothing stored) renders every Defender checkbox
  // unchecked and the select's blank option selected.
  const html = policiesView.render({ items: [], name: '' });
  for (const key of policiesView.DEFENDER_BOOLEAN_KEYS) {
    const checkbox = html.match(new RegExp(`<input[^>]*name="${key}"[^>]*>`))?.[0];
    assert.ok(checkbox, `expected a ${key} checkbox`);
    assert.ok(!checkbox.includes('checked'), `${key} should be unchecked by default`);
  }
  const select = html.match(/<select[^>]*name="defenderRansomwareProtection"[^>]*>[\s\S]*?<\/select>/)?.[0];
  assert.ok(select.includes('<option value="" selected>'), select);
});

test('Scenario: SETTING_KEYS equals the backend POLICY_SETTING_KEYS', async (t) => {
  // SETTING_KEYS in policies.js equals POLICY_SETTING_KEYS in policies.ts
  assert.deepStrictEqual(policiesView.SETTING_KEYS, policiesAdmin.POLICY_SETTING_KEYS);
  assert.strictEqual(policiesView.SETTING_KEYS.length, 16);
});
