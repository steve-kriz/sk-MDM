/**
 * Unit tests for the device page's Refresh button render (TASK-057).
 *
 * These exercise `deviceDetailView.render()` directly -- a pure string
 * builder -- with no DOM, no app.js event handlers and no database. The
 * interactive behaviour (click through app.js) is covered by the e2e
 * scenarios in test/ui/deviceRefresh.e2e.test.js.
 */

import test from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const deviceDetailView = await import('../../dist/ui/views/deviceDetail.js');

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const stylesPath = path.join(__dirname, '../../src/ui/public/styles.css');

function baseProfile(overrides = {}) {
  return { deviceId: 'dev-1', hostname: 'PC-1', ...overrides };
}

/** The slice of `html` between the opening tag of `id` and its matching `</section>`. */
function sectionHtml(html, id) {
  const start = html.indexOf(`id="${id}"`);
  assert.ok(start !== -1, `expected to find section#${id}`);
  const sectionStart = html.lastIndexOf('<section', start);
  const end = html.indexOf('</section>', start) + '</section>'.length;
  return html.slice(sectionStart, end);
}

// ============================================================================
// AC1: Refresh button sits before Delete device in div.profile-actions
// ============================================================================

test('Unit: AC1 section#detail-profile has exactly one refresh-device button before open-delete-device, escaped id', () => {
  const html = deviceDetailView.render({ profile: baseProfile() });
  const profile = sectionHtml(html, 'detail-profile');

  const actionsStart = profile.indexOf('<div class="profile-actions">');
  assert.ok(actionsStart !== -1, 'expected a div.profile-actions');
  const actions = profile.slice(actionsStart);

  const refreshMatches = [...actions.matchAll(/<button[^>]*class="refresh-device"[^>]*>/g)];
  assert.strictEqual(refreshMatches.length, 1, 'expected exactly one refresh-device button');
  assert.match(refreshMatches[0][0], /data-device-id="dev-1"/);

  const refreshIndex = actions.indexOf('class="refresh-device"');
  const deleteIndex = actions.indexOf('class="open-delete-device"');
  assert.ok(refreshIndex !== -1 && deleteIndex !== -1 && refreshIndex < deleteIndex, 'refresh must come before delete');

  assert.match(actions, /<button type="button" class="refresh-device" data-device-id="dev-1">Refresh<\/button>/);
});

test('Unit: AC1 (edge) the refresh-device data-device-id is HTML-escaped', () => {
  const html = deviceDetailView.render({ profile: baseProfile({ deviceId: '<b>&"x' }) });
  const profile = sectionHtml(html, 'detail-profile');
  assert.match(profile, /<button type="button" class="refresh-device" data-device-id="&lt;b&gt;&amp;&quot;x">Refresh<\/button>/);
});

// ============================================================================
// AC2: The Delete device button markup and position are unchanged
// ============================================================================

test('Unit: AC2 open-delete-device markup is unchanged, and profile-actions is the last element of the section', () => {
  const html = deviceDetailView.render({ profile: baseProfile() });
  const profile = sectionHtml(html, 'detail-profile');

  assert.match(profile, /<button type="button" class="open-delete-device" data-device-id="dev-1">Delete device<\/button>/);
  assert.match(profile, /<div class="profile-actions">[\s\S]*<\/div>\s*<\/section>$/);

  const buttonMatches = [...profile.matchAll(/<button[^>]*class="open-delete-device"[^>]*>/g)];
  assert.strictEqual(buttonMatches.length, 1, 'expected exactly one open-delete-device button');
});

// ============================================================================
// AC3: .profile-actions keeps display/justify-content and gains gap
// ============================================================================

test('Unit: AC3 styles.css .profile-actions keeps display flex, justify-content flex-end, and has gap 0.5rem', () => {
  const css = readFileSync(stylesPath, 'utf8');
  const match = /\.profile-actions\s*\{([^}]*)\}/.exec(css);
  assert.ok(match !== null, 'expected a .profile-actions rule');
  assert.match(match[1], /display:\s*flex/);
  assert.match(match[1], /justify-content:\s*flex-end/);
  assert.match(match[1], /gap:\s*0\.5rem/);
});

// ============================================================================
// AC4: refreshing state toggles disabled/"Refreshing..." vs enabled/"Refresh"
// ============================================================================

test('Unit: AC4 refreshing true renders disabled "Refreshing..."', () => {
  const html = deviceDetailView.render({ profile: baseProfile(), refreshing: true });
  const profile = sectionHtml(html, 'detail-profile');
  assert.match(
    profile,
    /<button type="button" class="refresh-device" data-device-id="dev-1" disabled>Refreshing\.\.\.<\/button>/,
  );
});

test('Unit: AC4 refreshing false (and absent) renders enabled "Refresh" with no disabled attribute', () => {
  const htmlFalse = deviceDetailView.render({ profile: baseProfile(), refreshing: false });
  const profileFalse = sectionHtml(htmlFalse, 'detail-profile');
  assert.match(profileFalse, /<button type="button" class="refresh-device" data-device-id="dev-1">Refresh<\/button>/);
  assert.ok(!profileFalse.includes('disabled>Refresh'));

  const htmlAbsent = deviceDetailView.render({ profile: baseProfile() });
  const profileAbsent = sectionHtml(htmlAbsent, 'detail-profile');
  assert.match(profileAbsent, /<button type="button" class="refresh-device" data-device-id="dev-1">Refresh<\/button>/);
});
