/**
 * E2E cucumber-style and unit tests for the hash-status column, Retry button
 * and install-select filtering TASK-050 adds to the admin UI views (AC14,
 * AC16): `backend/src/ui/views/applications.js` and
 * `backend/src/ui/views/deviceDetail.js`.
 *
 * Pure view-rendering functions: no database or network access at all.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

const applicationsModule = await import('../../dist/ui/views/applications.js');
const deviceDetailModule = await import('../../dist/ui/views/deviceDetail.js');

// ============================================================================
// AC14
// ============================================================================

test('Scenario: Admin view status column and form', () => {
  // Given items: a pending URL app, a ready upload app, and a failed URL app
  // with hashError "http_404"
  const html = applicationsModule.render({
    items: [
      { applicationId: 'app-1', name: 'Pending URL', platform: 'windows', installerType: 'msi', source: 'url', description: '', hashStatus: 'pending', hashError: null },
      { applicationId: 'app-2', name: 'Ready Upload', platform: 'windows', installerType: 'msi', source: 'upload', description: '', hashStatus: 'ready', hashError: null },
      { applicationId: 'app-3', name: 'Failed URL', platform: 'windows', installerType: 'msi', source: 'url', description: '', hashStatus: 'failed', hashError: 'http_404' },
    ],
    dialog: { open: true, mode: 'create' },
  });

  // When render runs
  // Then there is no element named "sha256"
  assert.ok(!html.includes('name="sha256"'), 'no element should be named sha256');
  assert.ok(!html.includes('sha256 (url source'), 'no legacy sha256 label');

  // And the status cells read "Hashing…", "Ready" and "Failed: http_404"
  assert.match(html, /<td class="col-status">Hashing…<\/td>/);
  assert.match(html, /<td class="col-status">Ready<\/td>/);
  assert.match(html, /<td class="col-status">Failed: http_404<\/td>/);

  // And the pending and failed URL rows have button.retry-application-hash,
  // and the upload row has none
  const rowOf = (id) => html.slice(html.indexOf(`data-application-id="${id}"`), html.indexOf('</tr>', html.indexOf(`data-application-id="${id}"`)));
  assert.match(rowOf('app-1'), /class="retry-application-hash" data-application-id="app-1"/);
  assert.match(rowOf('app-3'), /class="retry-application-hash" data-application-id="app-3"/);
  assert.ok(!rowOf('app-2').includes('retry-application-hash'), 'a ready upload row must not offer Retry');
});

test('Unit: COLUMNS is the documented list', () => {
  assert.deepEqual(applicationsModule.COLUMNS, ['name', 'platform', 'installerType', 'source', 'status', 'description', '']);
});

test('Unit: a failed hashError is HTML-escaped', () => {
  const html = applicationsModule.render({
    items: [
      { applicationId: 'app-1', name: 'X', platform: 'windows', installerType: 'msi', source: 'url', description: '', hashStatus: 'failed', hashError: '<script>alert(1)</script>' },
    ],
  });
  assert.ok(!html.includes('<script>alert(1)</script>'), 'hashError must be escaped');
  assert.match(html, /Failed: &lt;script&gt;/);
});

test('Scenario: URL create request without sha256', () => {
  // When createUrlRequest(...)
  const request = applicationsModule.createUrlRequest({ name: 'Zoom', url: 'https://zoom.us/x.msi', installerType: 'msi', description: '', installArgs: '' });

  // Then it returns POST /admin/api/v1/applications with the documented body and no sha256 key
  assert.deepEqual(request, {
    method: 'POST',
    path: '/admin/api/v1/applications',
    body: { source: 'url', name: 'Zoom', description: null, url: 'https://zoom.us/x.msi', installerType: 'msi', installArgs: null },
  });
  assert.equal('sha256' in request.body, false);
});

const incompleteCalls = [
  { name: 'createUrlRequest with an empty url', call: () => applicationsModule.createUrlRequest({ name: 'Zoom', url: '', installerType: 'msi' }) },
  { name: 'retryHashRequest with an empty applicationId', call: () => applicationsModule.retryHashRequest({ applicationId: '' }) },
];

for (const { name, call } of incompleteCalls) {
  test(`Scenario Outline: View helpers refuse incomplete input -- ${name}`, () => {
    assert.strictEqual(call(), null);
  });
}

test('Unit: retryHashRequest builds the documented request', () => {
  assert.deepEqual(applicationsModule.retryHashRequest({ applicationId: 'app 2' }), {
    method: 'POST',
    path: '/admin/api/v1/applications/app%202/retry-hash',
  });
});

// ============================================================================
// AC16
// ============================================================================

test('Scenario: Install select lists only ready applications', () => {
  // Given windows device dev-1 and windows applications "7-Zip" ready and "Zoom" pending
  const html = deviceDetailModule.render({
    profile: { deviceId: 'dev-1', hostname: 'PC-1', platform: 'windows' },
    applications: [
      { applicationId: 'app-1', name: '7-Zip', hashStatus: 'ready' },
      { applicationId: 'app-2', name: 'Zoom', hashStatus: 'pending' },
    ],
  });

  // When the device page renders
  // Then select[name=applicationId] offers "7-Zip" and not "Zoom"
  const section = html.slice(html.indexOf('id="detail-software"'), html.indexOf('id="detail-posture"'));
  assert.match(section, /<option value="app-1">7-Zip<\/option>/);
  assert.ok(!section.includes('Zoom'), 'a pending application must not be offered');
});

test('Scenario (edge): No ready application for the platform', () => {
  // Given windows device dev-1 whose only windows application is failed
  const html = deviceDetailModule.render({
    profile: { deviceId: 'dev-1', hostname: 'PC-1', platform: 'windows' },
    applications: [{ applicationId: 'app-1', name: 'Zoom', hashStatus: 'failed' }],
  });

  // When the device page renders
  // Then section#detail-software contains "No applications for this platform"
  const section = html.slice(html.indexOf('id="detail-software"'), html.indexOf('id="detail-posture"'));
  assert.match(section, /No applications for this platform/);
});
