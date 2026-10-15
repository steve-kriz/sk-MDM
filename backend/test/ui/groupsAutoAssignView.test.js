/**
 * The Groups screen's per-group auto-assign select and its request
 * (`backend/src/ui/views/groups.js`), and that the Settings screen no longer
 * carries the old default-group form.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

const groups = await import('../../dist/ui/views/groups.js');
const settings = await import('../../dist/ui/views/settings.js');

const ITEMS = [
  { groupId: 'grp-a', name: 'All OfficeHQ', createdAt: '2026-01-01T00:00:00Z', autoAssignOwnership: 'officehq' },
  { groupId: 'grp-b', name: 'Personal <devices>', createdAt: '2026-01-01T00:00:00Z', autoAssignOwnership: 'byoc' },
  { groupId: 'grp-c', name: 'Manual', createdAt: '2026-01-01T00:00:00Z', autoAssignOwnership: null },
];

function rowOf(html, groupId) {
  const match = new RegExp(`<tr class="group" data-group-id="${groupId}">([\\s\\S]*?)</tr>`).exec(html);
  assert.ok(match, groupId);
  return match[1];
}

test('Scenario: Each group row offers None, OfficeHQ devices and BYOD devices, preselected', () => {
  const html = groups.render({ items: ITEMS });
  assert.ok(html.includes('<th>autoAssign</th>'));
  assert.match(rowOf(html, 'grp-a'), /<option value="officehq" selected>OfficeHQ devices<\/option>/);
  assert.match(rowOf(html, 'grp-b'), /<option value="byoc" selected>BYOD devices<\/option>/);
  assert.match(rowOf(html, 'grp-c'), /<option value="" selected>None<\/option>/);
  const b = rowOf(html, 'grp-b');
  assert.match(b, /<form class="auto-assign-group">/);
  assert.match(b, /<input type="hidden" name="groupId" value="grp-b">/);
  assert.ok(b.includes('Auto-assign devices to Personal &lt;devices&gt;'), 'the label is escaped');
  assert.match(b, /<button type="submit" class="save-auto-assign">Save<\/button>/);
});

test('Unit: autoAssignRequest sends None as null', () => {
  assert.deepStrictEqual(groups.autoAssignRequest({ groupId: 'grp-a', ownership: 'byoc' }), {
    method: 'PUT',
    path: '/admin/api/v1/groups/grp-a/auto-assign',
    body: { ownership: 'byoc' },
  });
  assert.deepStrictEqual(groups.autoAssignRequest({ groupId: 'grp-a', ownership: '' }).body, { ownership: null });
  assert.strictEqual(groups.autoAssignRequest({ ownership: 'byoc' }), null);
});

test('Scenario: Settings no longer shows the default-group form', () => {
  const html = settings.render({ collectionUrl: 'https://mdm.example/', onFailure: 'continue' });
  assert.ok(!html.includes('assignment-settings'));
  assert.strictEqual(settings.assignmentSettingsRequest, undefined);
});
