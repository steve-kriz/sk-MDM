/**
 * Unit tests for the delete-device confirmation popup (TASK-051).
 *
 * These exercise `deviceDetailView.render()` directly -- a pure string
 * builder -- with no DOM, no app.js event handlers and no database. The
 * interactive behaviour (click/input/keydown/submit through app.js) is
 * covered by the e2e scenarios in test/ui/deleteDevicePopup.e2e.test.js.
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
// AC1: Delete button at the bottom right of the Profile panel
// ============================================================================

test('Unit: AC1 section#detail-profile ends with div.profile-actions containing one open-delete-device button', () => {
  const html = deviceDetailView.render({ profile: baseProfile() });
  const profile = sectionHtml(html, 'detail-profile');

  // The actions div is the last element child before </section>.
  assert.match(profile, /<div class="profile-actions">[\s\S]*<\/div>\s*<\/section>$/);

  const actionsStart = profile.indexOf('<div class="profile-actions">');
  const actions = profile.slice(actionsStart);
  const buttonMatches = [...actions.matchAll(/<button[^>]*class="open-delete-device"[^>]*>/g)];
  assert.strictEqual(buttonMatches.length, 1, 'expected exactly one open-delete-device button');
  assert.match(buttonMatches[0][0], /data-device-id="dev-1"/);
  assert.match(actions, /<button type="button" class="open-delete-device" data-device-id="dev-1">Delete device<\/button>/);
});

test('Unit: AC1 styles.css gives .profile-actions display flex and justify-content flex-end', () => {
  const css = readFileSync(stylesPath, 'utf8');
  const match = /\.profile-actions\s*\{([^}]*)\}/.exec(css);
  assert.ok(match !== null, 'expected a .profile-actions rule');
  assert.match(match[1], /display:\s*flex/);
  assert.match(match[1], /justify-content:\s*flex-end/);
});

// ============================================================================
// AC2: The inline type-the-hostname form is gone from the Manage panel
// ============================================================================

test('Unit: AC2 rendered HTML has no form.delete-device or input#delete-device-hostname while closed', () => {
  const html = deviceDetailView.render({ profile: baseProfile() });
  assert.ok(!html.includes('class="delete-device"'));
  assert.ok(!html.includes('id="delete-device-hostname"'));
});

test('Unit: AC2 section#detail-manage still contains form.edit-device', () => {
  const html = deviceDetailView.render({ profile: baseProfile() });
  const manage = sectionHtml(html, 'detail-manage');
  assert.ok(manage.includes('class="edit-device"'));
});

// ============================================================================
// AC3: The popup is not rendered while closed
// ============================================================================

test('Unit: AC3 render with no deleteDialog state outputs no #delete-device-dialog', () => {
  const html = deviceDetailView.render({ profile: baseProfile() });
  assert.ok(!html.includes('id="delete-device-dialog"'));
});

test('Unit: AC3 render with deleteDialog.open !== true outputs no #delete-device-dialog (edge)', () => {
  const html = deviceDetailView.render({
    profile: baseProfile(),
    deleteDialog: { open: false, typedHostname: 'PC-1', error: null },
  });
  assert.ok(!html.includes('id="delete-device-dialog"'));
});

// ============================================================================
// AC5: The popup has the confirmation form
// ============================================================================

test('Unit: AC5 open popup shows heading, device name in <strong>, and the confirmation form', () => {
  const html = deviceDetailView.render({
    profile: baseProfile(),
    deleteDialog: { open: true, typedHostname: '', error: null },
  });

  assert.match(html, /<div class="modal-backdrop">[\s\S]*<div class="modal" id="delete-device-dialog" role="dialog" aria-modal="true"/);
  assert.match(html, /<h3[^>]*>Delete device<\/h3>/);
  assert.match(html, /<strong>PC-1<\/strong>/);
  assert.match(html, /<form class="delete-device">/);
  assert.match(html, /<input type="hidden" name="deviceId" value="dev-1">/);
  assert.match(html, /<input id="delete-device-hostname" name="typedHostname" value="" autocomplete="off">/);
  assert.match(html, /<button type="button" class="cancel-delete-device">Cancel<\/button>/);
  assert.match(html, /<button type="submit" class="delete"[^>]*>Delete device<\/button>/);
});

// ============================================================================
// AC6: Device name falls back to the device id
// ============================================================================

test('Unit: AC6 popup names the hostname when present', () => {
  const html = deviceDetailView.render({
    profile: baseProfile({ hostname: 'PC-1' }),
    deleteDialog: { open: true, typedHostname: '', error: null },
  });
  assert.match(html, /<strong>PC-1<\/strong>/);
});

test('Unit: AC6 popup falls back to the device id when hostname is null, undefined or empty (edge)', () => {
  for (const hostname of [null, undefined, '']) {
    const html = deviceDetailView.render({
      profile: baseProfile({ deviceId: 'dev-2', hostname }),
      deleteDialog: { open: true, typedHostname: '', error: null },
    });
    assert.match(html, /<strong>dev-2<\/strong>/, `expected device id fallback for hostname=${JSON.stringify(hostname)}`);
  }
});

// ============================================================================
// AC7: A hostname with HTML characters is escaped
// ============================================================================

test('Unit: AC7 a hostname with <, & and " is HTML-escaped in the popup, with no unescaped copy (edge)', () => {
  const html = deviceDetailView.render({
    profile: baseProfile({ deviceId: 'dev-3', hostname: '<b>&"x' }),
    deleteDialog: { open: true, typedHostname: '', error: null },
  });
  assert.ok(html.includes('&lt;b&gt;&amp;&quot;x'));
  assert.ok(!html.includes('<b>&"x'));
});

// ============================================================================
// AC8: Delete button starts disabled
// ============================================================================

test('Unit: AC8 button.delete has the disabled attribute when the popup is first rendered', () => {
  const html = deviceDetailView.render({
    profile: baseProfile(),
    deleteDialog: { open: true, typedHostname: '', error: null },
  });
  assert.match(html, /<button type="submit" class="delete" disabled>Delete device<\/button>/);
});

test('Unit: AC8 (contrast) button.delete has no disabled attribute once the typed value matches', () => {
  const html = deviceDetailView.render({
    profile: baseProfile(),
    deleteDialog: { open: true, typedHostname: 'PC-1', error: null },
  });
  assert.match(html, /<button type="submit" class="delete">Delete device<\/button>/);
});

// ============================================================================
// AC14 (render half): a freshly (re)opened popup has no leftover state
// ============================================================================

test('Unit: AC14 a freshly opened dialog state renders an empty input, no error paragraph and a disabled button', () => {
  const html = deviceDetailView.render({
    profile: baseProfile(),
    deleteDialog: { open: true, typedHostname: '', error: null },
  });
  assert.match(html, /<input id="delete-device-hostname" name="typedHostname" value="" autocomplete="off">/);
  assert.ok(!html.includes('delete-device-error'));
  assert.match(html, /<button type="submit" class="delete" disabled>/);
});

// ============================================================================
// AC18/AC19 (render half): the popup shows its own error paragraph
// ============================================================================

test('Unit: AC18 the popup shows p.error.delete-device-error with the given error text', () => {
  const html = deviceDetailView.render({
    profile: baseProfile(),
    deleteDialog: { open: true, typedHostname: 'PC-1', error: 'not_found' },
  });
  assert.match(html, /<p class="error delete-device-error">not_found<\/p>/);
  assert.ok(!html.includes('<p class="error">'), 'no page banner should appear alongside the popup error');
});
