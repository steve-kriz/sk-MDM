/**
 * Unit tests for the Applications screen's add/edit popup
 * (backend/src/ui/views/applications.js): rendering and `updateRequest`.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

const view = await import('../../dist/ui/views/applications.js');

const URL_APP = {
  applicationId: 'app-tv',
  name: 'Team "Viewer"',
  description: 'Remote <support>',
  source: 'url',
  url: 'https://download.teamviewer.com/TeamViewer_Setup_x64.exe',
  installerType: 'exe',
  platform: 'windows',
  installArgs: null,
  hashStatus: 'ready',
};

test('Scenario: The screen shows Add and a per-row Edit, and no popup until one is opened', () => {
  const html = view.render({ items: [URL_APP] });
  assert.match(html, /<button type="button" class="open-create-application">Add application<\/button>/);
  assert.match(html, /<button type="button" class="edit-application" data-application-id="app-tv">Edit<\/button>/);
  assert.doesNotMatch(html, /id="application-dialog"/);
});

test('Scenario: The create popup offers every field and the silent-switch hint', () => {
  const html = view.render({ items: [], dialog: { open: true, mode: 'create' } });
  assert.match(html, /role="dialog" aria-modal="true"/);
  assert.match(html, /<form class="create-application">/);
  for (const field of ['source', 'name', 'description', 'file', 'url', 'installerType', 'installArgs']) {
    assert.ok(html.includes(`name="${field}"`), field);
  }
  assert.ok(html.includes('exe installers need a silent switch, e.g. /S'));
  assert.match(html, /class="cancel-application-dialog">Cancel<\/button>/);
  assert.match(html, /<button type="submit" class="create">Add application<\/button>/);
});

test('Scenario: The edit popup for a URL app is pre-filled and escaped', () => {
  const html = view.render({ items: [URL_APP], dialog: { open: true, mode: 'edit', applicationId: 'app-tv' } });
  assert.match(html, /<form class="edit-application-form">/);
  assert.ok(html.includes('value="Team &quot;Viewer&quot;"'));
  assert.ok(html.includes('value="Remote &lt;support&gt;"'));
  assert.ok(html.includes('value="https://download.teamviewer.com/TeamViewer_Setup_x64.exe"'));
  assert.match(html, /<option value="exe" selected>exe<\/option>/);
  assert.doesNotMatch(html, /name="source"|name="file"/);
  assert.ok(html.includes('Changing the url hashes the installer again'));
  assert.match(html, /<button type="submit" class="save">Save<\/button>/);
});

test('Scenario: The popup shows its error, and an edit of a missing app shows nothing', () => {
  const html = view.render({
    items: [URL_APP],
    dialog: { open: true, mode: 'edit', applicationId: 'app-tv', error: 'invalid_request' },
  });
  assert.ok(html.includes('<p class="error application-dialog-error">invalid_request</p>'));
  const gone = view.render({ items: [], dialog: { open: true, mode: 'edit', applicationId: 'app-tv' } });
  assert.doesNotMatch(gone, /id="application-dialog"/);
});

test('Unit: updateRequest sends url fields only for a URL app', () => {
  const typed = { name: 'TeamViewer', description: '', url: 'https://x.example/t.exe', installerType: 'exe', installArgs: '/S' };
  assert.deepStrictEqual(view.updateRequest(typed, URL_APP), {
    method: 'PATCH',
    path: '/admin/api/v1/applications/app-tv',
    body: { name: 'TeamViewer', description: null, installArgs: '/S', url: 'https://x.example/t.exe', installerType: 'exe' },
  });
  assert.deepStrictEqual(view.updateRequest(typed, { applicationId: 'app-up', source: 'upload' }).body, {
    name: 'TeamViewer',
    description: null,
    installArgs: '/S',
  });
  assert.strictEqual(view.updateRequest({ name: '' }, URL_APP), null);
  assert.strictEqual(view.updateRequest(typed, {}), null);
});
