/**
 * E2E cucumber-style tests for TASK-063: the collapsed "Errors" section on the
 * device detail page (`backend/src/ui/views/deviceDetail.js`). Pure view
 * rendering, no database involved.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

const deviceDetailModule = await import('../../dist/ui/views/deviceDetail.js');

function errorsSectionOf(html) {
  const match = html.match(/<section class="panel" id="detail-errors">[\s\S]*?<\/section>/);
  assert.ok(match, 'expected a #detail-errors section');
  return match[0];
}

function baseState(overrides = {}) {
  return {
    profile: { deviceId: 'dev-1', timeZone: 'Australia/Sydney' },
    agentErrors: [],
    ...overrides,
  };
}

const twoEntries = [
  {
    signature: 'sig-1',
    level: 'warn',
    component: 'enforce',
    message: 'policy enforcement failed',
    fields: { error: 'exit status 1', status: '503' },
    count: 3,
    firstSeenAt: '2026-10-11T09:00:00Z',
    lastSeenAt: '2026-10-11T09:30:00Z',
  },
  {
    signature: 'sig-2',
    level: 'error',
    component: 'update',
    message: 'agent update failed',
    fields: {},
    count: 1,
    firstSeenAt: '2026-10-11T08:15:00Z',
    lastSeenAt: '2026-10-11T08:15:00Z',
  },
];

// ============================================================================
// Scenario: The Errors section renders collapsed with its table (AC18)
// ============================================================================

test('Scenario: The Errors section renders collapsed with its table (AC18)', () => {
  const state = baseState({ agentErrors: twoEntries });
  const html = deviceDetailModule.render(state);

  // Then a section with id "detail-errors" contains a details element with
  // data-section "detail-errors" and no open attribute
  const section = errorsSectionOf(html);
  assert.ok(section.includes('<details class="expandable device-section" data-section="detail-errors">'));
  assert.ok(!section.includes('data-section="detail-errors" open'));

  // And it appears after "detail-login-history" and before "detail-analytics"
  const loginIndex = html.indexOf('id="detail-login-history"');
  const errorsIndex = html.indexOf('id="detail-errors"');
  const analyticsIndex = html.indexOf('id="detail-analytics"');
  assert.ok(loginIndex !== -1 && errorsIndex !== -1 && analyticsIndex !== -1, 'expected all three sections to be present');
  assert.ok(loginIndex < errorsIndex, 'Errors must come after Login history');
  assert.ok(errorsIndex < analyticsIndex, 'Errors must come before Analytics');

  // And its table header is Last seen, Level, Component, Message, Count,
  // First seen, Details
  const headerMatch = section.match(/<thead><tr>([\s\S]*?)<\/tr><\/thead>/);
  assert.ok(headerMatch, 'expected a table header');
  const headers = [...headerMatch[1].matchAll(/<th>(.*?)<\/th>/g)].map((m) => m[1]);
  assert.deepStrictEqual(headers, ['Last seen', 'Level', 'Component', 'Message', 'Count', 'First seen', 'Details']);

  // And a row's Details cell reads "error=exit status 1; status=503"
  assert.ok(section.includes('error=exit status 1; status=503'), section);

  // Two rows rendered, one per entry.
  const rows = section.match(/<tr class="agent-error">/g) ?? [];
  assert.strictEqual(rows.length, 2);

  // Times are formatted with formatDeviceTime in the device time zone.
  const expectedTime = deviceDetailModule.formatDeviceTime('2026-10-11T09:30:00Z', 'Australia/Sydney');
  assert.ok(section.includes(expectedTime), section);
});

// ============================================================================
// Scenario: No errors shows the empty message (AC19)
// ============================================================================

test('Scenario: No errors shows the empty message (AC19)', () => {
  const state = baseState({ agentErrors: [] });
  const html = deviceDetailModule.render(state);
  const section = errorsSectionOf(html);

  assert.ok(section.includes('<p class="empty">No agent errors in the last 30 days</p>'));
});

// ============================================================================
// Scenario: Device-supplied text is escaped (AC20)
// ============================================================================

test('Scenario: Device-supplied text is escaped (AC20)', () => {
  const state = baseState({
    agentErrors: [
      {
        signature: 'sig-xss',
        level: 'warn',
        component: '<b>comp</b>',
        message: '<img src=x onerror=alert(1)>',
        fields: { '<key>': '<value>' },
        count: 1,
        firstSeenAt: '2026-10-11T09:00:00Z',
        lastSeenAt: '2026-10-11T09:00:00Z',
      },
    ],
  });
  const html = deviceDetailModule.render(state);
  const section = errorsSectionOf(html);

  // Then the HTML contains the escaped message and no <img element
  assert.ok(section.includes('&lt;img src=x onerror=alert(1)&gt;'), section);
  assert.ok(!section.includes('<img'), section);

  // And the component and field keys/values are escaped too.
  assert.ok(section.includes('&lt;b&gt;comp&lt;/b&gt;'), section);
  assert.ok(!section.includes('<b>comp</b>'), section);
  assert.ok(section.includes('&lt;key&gt;=&lt;value&gt;'), section);
});

// A fields value missing or null renders an empty Details cell rather than
// breaking (Edge and Failure Cases: the table must not break on missing fields).
test('Edge: a missing or null fields value renders an empty Details cell', () => {
  const state = baseState({
    agentErrors: [
      {
        signature: 'sig-missing',
        level: 'warn',
        component: 'enforce',
        message: 'no fields here',
        fields: null,
        count: 1,
        firstSeenAt: '2026-10-11T09:00:00Z',
        lastSeenAt: '2026-10-11T09:00:00Z',
      },
      {
        signature: 'sig-undefined',
        level: 'warn',
        component: 'enforce',
        message: 'fields omitted entirely',
        count: 1,
        firstSeenAt: '2026-10-11T09:00:00Z',
        lastSeenAt: '2026-10-11T09:00:00Z',
      },
    ],
  });
  const html = deviceDetailModule.render(state);
  const section = errorsSectionOf(html);
  // No crash, and a Details cell is present and empty for both rows.
  assert.ok(section.includes('<td class="col-fields"></td>'), section);
  const emptyCells = section.match(/<td class="col-fields"><\/td>/g) ?? [];
  assert.strictEqual(emptyCells.length, 2);
});

// ============================================================================
// Scenario: An opened Errors section survives a refresh (AC21)
// ============================================================================

test('Scenario: An opened Errors section survives a refresh (AC21)', () => {
  // Given the admin opened the Errors section
  // When the view renders again with openSections ["detail-errors"]
  const openState = baseState({ agentErrors: twoEntries, openSections: ['detail-errors'] });
  const openHtml = deviceDetailModule.render(openState);
  const openSection = errorsSectionOf(openHtml);

  // Then the Errors details element has the open attribute
  assert.ok(openSection.includes('<details class="expandable device-section" data-section="detail-errors" open>'), openSection);

  // When the hash changes to another device (simulated: a fresh render with
  // no openSections for the new device)
  const collapsedState = baseState({ agentErrors: twoEntries });
  const collapsedHtml = deviceDetailModule.render(collapsedState);
  const collapsedSection = errorsSectionOf(collapsedHtml);

  // Then the Errors details element renders without the open attribute
  assert.ok(collapsedSection.includes('<details class="expandable device-section" data-section="detail-errors">'));
  assert.ok(!collapsedSection.includes('data-section="detail-errors" open'));
});
