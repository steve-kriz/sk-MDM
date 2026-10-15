/**
 * E2E cucumber-style tests for TASK-060 AC126: the Defender protection policy
 * panel in backend/src/ui/views/deviceDetail.js. No database or browser is
 * touched: these are pure render-function tests.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

const deviceDetailModule = await import('../../dist/ui/views/deviceDetail.js');

test('Scenario: Device detail renders the panel', async (t) => {
  // Given defenderHardening items [controlledFolderAccess tamper_blocked,
  // puaProtection applied, networkProtection failed with detail "<b>x</b>"]
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    defenderHardening: {
      reportedAt: '2026-10-11T10:00:00Z',
      items: [
        { item: 'controlledFolderAccess', state: 'tamper_blocked' },
        { item: 'puaProtection', state: 'applied' },
        { item: 'networkProtection', state: 'failed', detail: '<b>x</b>' },
      ],
    },
  });

  // When the device detail view renders
  // Then section#detail-defender-hardening has heading "Defender protection policy"
  assert.ok(html.includes('<section class="panel" id="detail-defender-hardening">'));
  assert.ok(html.includes('<h3>Defender protection policy</h3>'));

  // And the row "Ransomware protection (Controlled folder access)" shows
  // <span class="off">Blocked by Tamper Protection</span>
  assert.ok(
    html.includes('<th>Ransomware protection (Controlled folder access)</th>') &&
      html.includes('<span class="off">Blocked by Tamper Protection</span>'),
    html,
  );

  // And the networkProtection row shows "&lt;b&gt;x&lt;/b&gt;" (HTML-escaped)
  assert.ok(html.includes('&lt;b&gt;x&lt;/b&gt;'));
  assert.ok(!html.includes('<b>x</b>'), 'the raw detail markup should never be unescaped');

  // puaProtection "applied" is not wrapped in <span class="off">
  const puaRowMatch = html.match(/<tr class="defender-hardening-item">\s*<th>Potentially unwanted app blocking<\/th>[\s\S]*?<\/tr>/);
  assert.ok(puaRowMatch, 'expected a puaProtection row');
  assert.ok(!puaRowMatch[0].includes('class="off"'), puaRowMatch[0]);
});

test('Scenario: Device detail with nothing required or no block', async (t) => {
  // Given defenderHardening with items []
  const htmlEmpty = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    defenderHardening: { reportedAt: '2026-10-11T10:00:00Z', items: [] },
  });
  // Then the panel shows "No Defender protection settings are required by policy"
  assert.ok(htmlEmpty.includes('<section class="panel" id="detail-defender-hardening">'));
  assert.ok(htmlEmpty.includes('No Defender protection settings are required by policy'));

  // Given defenderHardening null
  const htmlNull = deviceDetailModule.render({ profile: { deviceId: 'd1' }, defenderHardening: null });
  // Then there is no section#detail-defender-hardening
  assert.ok(!htmlNull.includes('id="detail-defender-hardening"'));
});

test('Scenario (edge): An absent defenderHardening also renders no section', async (t) => {
  const html = deviceDetailModule.render({ profile: { deviceId: 'd1' } });
  assert.ok(!html.includes('id="detail-defender-hardening"'));
});
