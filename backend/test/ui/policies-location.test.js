/**
 * E2E cucumber-style tests for TASK-056: the `locationTracking` checkbox in
 * the policy create/edit forms (`src/ui/views/policies.js`). Pure view
 * rendering, no database involved.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

const policiesModule = await import('../../dist/ui/views/policies.js');

// ============================================================================
// Scenario: Policy form offers the locationTracking checkbox
// ============================================================================

test('Scenario: The edit form renders a checked locationTracking checkbox', () => {
  const html = policiesModule.render({
    items: [],
    editing: { policyId: 'p1', name: 'Policy', settings: { locationTracking: true } },
  });

  const inputMatch = html.match(/<input id="edit-location-tracking" name="locationTracking" type="checkbox"[^>]*>/);
  assert.ok(inputMatch, 'expected a locationTracking checkbox in the edit form');
  assert.ok(inputMatch[0].includes('checked'));
});

test('Scenario: The edit form renders an unchecked locationTracking checkbox when the setting is false', () => {
  const html = policiesModule.render({
    items: [],
    editing: { policyId: 'p1', name: 'Policy', settings: { locationTracking: false } },
  });

  const inputMatch = html.match(/<input id="edit-location-tracking" name="locationTracking" type="checkbox"[^>]*>/);
  assert.ok(inputMatch, 'expected a locationTracking checkbox in the edit form');
  assert.ok(!inputMatch[0].includes('checked'));
});

test('Scenario: The create form also renders the locationTracking checkbox', () => {
  const html = policiesModule.render({ items: [] });
  const inputMatch = html.match(/<input id="location-tracking" name="locationTracking" type="checkbox"[^>]*>/);
  assert.ok(inputMatch, 'expected a locationTracking checkbox in the create form');
});

// ============================================================================
// Scenario: settingsOf coerces locationTracking to a boolean
// ============================================================================

test('Scenario: settingsOf coerces a "true" string locationTracking to boolean true', () => {
  const settings = policiesModule.settingsOf({ settings: { locationTracking: 'true' } });
  assert.strictEqual(settings.locationTracking, true);
});

test('Scenario: settingsOf coerces an actual boolean true unchanged', () => {
  const settings = policiesModule.settingsOf({ settings: { locationTracking: true } });
  assert.strictEqual(settings.locationTracking, true);
});

test('Scenario: settingsOf coerces anything else falsy for locationTracking to false', () => {
  const settings = policiesModule.settingsOf({ settings: { locationTracking: 'false' } });
  assert.strictEqual(settings.locationTracking, false);
});

test('Scenario: settingsOf omits locationTracking when the field is absent', () => {
  const settings = policiesModule.settingsOf({ settings: {} });
  assert.strictEqual('locationTracking' in settings, false);
});

test('Unit: SETTING_KEYS includes locationTracking', () => {
  assert.ok(policiesModule.SETTING_KEYS.includes('locationTracking'));
});
