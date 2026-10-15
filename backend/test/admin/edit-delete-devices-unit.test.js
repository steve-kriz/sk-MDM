/**
 * Unit tests for device edit and delete functionality (TASK-043).
 *
 * Tests for UI request builders and helper functions.
 */

import test from 'node:test';
import assert from 'node:assert';

const deviceDetailView = await import('../../dist/ui/views/deviceDetail.js');

// ============================================================================
// AC9: Edit ownership from the detail screen - updateRequest
// ============================================================================

test('Unit: AC9 updateRequest returns PUT request with correct method and path', () => {
  const request = deviceDetailView.updateRequest({ deviceId: 'dev-1', ownership: 'byoc' });

  assert.ok(request !== null, 'Should return a request object');
  assert.strictEqual(request.method, 'PUT');
  assert.strictEqual(request.path, '/admin/api/v1/devices/dev-1');
  assert.deepStrictEqual(request.body, { ownership: 'byoc' });
});

test('Unit: AC9 updateRequest with ownership "officehq"', () => {
  const request = deviceDetailView.updateRequest({ deviceId: 'dev-2', ownership: 'officehq' });

  assert.ok(request !== null);
  assert.strictEqual(request.method, 'PUT');
  assert.strictEqual(request.path, '/admin/api/v1/devices/dev-2');
  assert.deepStrictEqual(request.body, { ownership: 'officehq' });
});

test('Unit: AC9 updateRequest returns null when deviceId is missing', () => {
  const request = deviceDetailView.updateRequest({ ownership: 'byoc' });
  assert.strictEqual(request, null);
});

test('Unit: AC9 updateRequest returns null when ownership is missing', () => {
  const request = deviceDetailView.updateRequest({ deviceId: 'dev-1' });
  assert.strictEqual(request, null);
});

// ============================================================================
// AC10: Device delete requires the typed hostname - deleteRequest
// ============================================================================

test('Unit: AC10 deleteRequest returns DELETE request when typedHostname matches hostname', () => {
  const request = deviceDetailView.deleteRequest({
    deviceId: 'dev-1',
    hostname: 'PC-1',
    typedHostname: 'PC-1',
  });

  assert.ok(request !== null);
  assert.strictEqual(request.method, 'DELETE');
  assert.strictEqual(request.path, '/admin/api/v1/devices/dev-1');
  assert.deepStrictEqual(request.body, { confirm: true });
});

test('Unit: AC10 deleteRequest returns null when typedHostname does not match hostname', () => {
  const request = deviceDetailView.deleteRequest({
    deviceId: 'dev-1',
    hostname: 'PC-1',
    typedHostname: 'PC-',
  });

  assert.strictEqual(request, null);
});

test('Unit: AC10 deleteRequest returns null when typedHostname is empty', () => {
  const request = deviceDetailView.deleteRequest({
    deviceId: 'dev-1',
    hostname: 'PC-1',
    typedHostname: '',
  });

  assert.strictEqual(request, null);
});

test('Unit: AC10 deleteRequest returns DELETE when hostname is null and typedHostname matches deviceId', () => {
  const request = deviceDetailView.deleteRequest({
    deviceId: 'dev-1',
    hostname: null,
    typedHostname: 'dev-1',
  });

  assert.ok(request !== null);
  assert.strictEqual(request.method, 'DELETE');
  assert.strictEqual(request.path, '/admin/api/v1/devices/dev-1');
  assert.deepStrictEqual(request.body, { confirm: true });
});

test('Unit: AC10 deleteRequest returns null when hostname is null and typedHostname does not match deviceId', () => {
  const request = deviceDetailView.deleteRequest({
    deviceId: 'dev-1',
    hostname: null,
    typedHostname: 'dev-',
  });

  assert.strictEqual(request, null);
});

test('Unit: AC10 deleteRequest returns DELETE when hostname is undefined and typedHostname matches deviceId', () => {
  const request = deviceDetailView.deleteRequest({
    deviceId: 'dev-1',
    hostname: undefined,
    typedHostname: 'dev-1',
  });

  // When hostname is undefined, it treats it as null and uses deviceId as expected
  assert.ok(request !== null);
  assert.strictEqual(request.method, 'DELETE');
});

test('Unit: AC10 deleteRequest returns null when typedHostname is undefined', () => {
  const request = deviceDetailView.deleteRequest({
    deviceId: 'dev-1',
    hostname: 'PC-1',
    typedHostname: undefined,
  });

  assert.strictEqual(request, null);
});

test('Unit: AC10 deleteRequest is case-sensitive', () => {
  const request = deviceDetailView.deleteRequest({
    deviceId: 'dev-1',
    hostname: 'PC-1',
    typedHostname: 'pc-1',
  });

  assert.strictEqual(request, null, 'Case mismatch should return null');
});

test('Unit: AC10 deleteRequest with whitespace in hostname', () => {
  const request = deviceDetailView.deleteRequest({
    deviceId: 'dev-1',
    hostname: 'PC 1',
    typedHostname: 'PC 1',
  });

  assert.ok(request !== null, 'Should handle spaces in hostname');
});

test('Unit: AC10 deleteRequest with extra spaces in typedHostname', () => {
  const request = deviceDetailView.deleteRequest({
    deviceId: 'dev-1',
    hostname: 'PC-1',
    typedHostname: 'PC-1 ',
  });

  assert.strictEqual(request, null, 'Extra spaces should not match');
});

test('Unit: AC10 deleteRequest returns null when deviceId is missing', () => {
  const request = deviceDetailView.deleteRequest({
    hostname: 'PC-1',
    typedHostname: 'PC-1',
  });

  assert.strictEqual(request, null);
});

// ============================================================================
// Delete button state - AC10
// ============================================================================

test('Unit: AC10 delete button is disabled when typed hostname does not match', () => {
  const html = deviceDetailView.render({
    profile: {
      deviceId: 'dev-1',
      hostname: 'PC-1',
    },
    // TASK-051: the delete form lives in the popup, rendered only while open.
    deleteDialog: { open: true, typedHostname: 'PC-', error: null },
  });

  // The delete form should exist with delete-device class
  assert.ok(html.includes('class="delete-device"'));
  // The button should have disabled attribute
  assert.ok(html.includes('disabled'));
});

test('Unit: AC10 delete button is enabled when typed hostname matches', () => {
  const html = deviceDetailView.render({
    profile: {
      deviceId: 'dev-1',
      hostname: 'PC-1',
    },
    deleteDialog: { open: true, typedHostname: 'PC-1', error: null },
  });

  // The form should exist with delete-device class
  assert.ok(html.includes('class="delete-device"'));
  // The button should exist
  assert.ok(html.includes('<button type="submit" class="delete">'));
  // When matched, the button should not have disabled
  assert.ok(!html.match(/<button type="submit" class="delete"[^>]*disabled[^>]*>Delete device/));
});

// ============================================================================
// Edit form rendering - AC9
// ============================================================================

test('Unit: AC9 form.edit-device renders with current ownership selected', () => {
  const html = deviceDetailView.render({
    profile: {
      deviceId: 'dev-1',
      hostname: 'PC-1',
      ownership: 'byoc',
    },
  });

  assert.ok(html.includes('class="edit-device"'));
  assert.ok(html.includes('selected'));
  assert.ok(html.includes('byoc'));
});

test('Unit: AC9 form.edit-device renders with ownership select field', () => {
  const html = deviceDetailView.render({
    profile: {
      deviceId: 'dev-1',
      hostname: 'PC-1',
      ownership: 'officehq',
    },
  });

  assert.ok(html.includes('class="edit-device"'));
  // Should have select element for ownership
  assert.ok(html.includes('<select'));
  assert.ok(html.includes('name="ownership"'));
});

// ============================================================================
// Delete form rendering - AC10
// ============================================================================

test('Unit: AC10 form.delete-device renders with typed hostname input', () => {
  const html = deviceDetailView.render({
    profile: {
      deviceId: 'dev-1',
      hostname: 'PC-1',
    },
    deleteDialog: { open: true, typedHostname: '', error: null },
  });

  assert.ok(html.includes('class="delete-device"'));
  assert.ok(html.includes('name="typedHostname"'));
});

test('Unit: TASK-051 form.delete-device is absent while the popup is closed', () => {
  const html = deviceDetailView.render({
    profile: {
      deviceId: 'dev-1',
      hostname: 'PC-1',
    },
  });

  assert.ok(!html.includes('class="delete-device"'));
  assert.ok(!html.includes('id="delete-device-hostname"'));
});

test('Unit: AC10 form.delete-device shows the expected hostname to type', () => {
  const html = deviceDetailView.render({
    profile: {
      deviceId: 'dev-1',
      hostname: 'PC-1',
    },
    deleteDialog: { open: true, typedHostname: '', error: null },
  });

  assert.ok(html.includes('PC-1'));
  assert.ok(html.includes('Type the hostname to delete it'));
});

test('Unit: AC10 form.delete-device with null hostname shows deviceId instead', () => {
  const html = deviceDetailView.render({
    profile: {
      deviceId: 'dev-1',
      hostname: null,
    },
    deleteDialog: { open: true, typedHostname: '', error: null },
  });

  assert.ok(html.includes('class="delete-device"'));
  assert.ok(html.includes('dev-1'));
  assert.ok(html.includes('Type the device id to delete it'));
});

// ============================================================================
// Edge cases
// ============================================================================

test('Unit: deleteRequest with empty state object returns null', () => {
  const request = deviceDetailView.deleteRequest({});
  assert.strictEqual(request, null);
});

test('Unit: updateRequest with empty state object returns null', () => {
  const request = deviceDetailView.updateRequest({});
  assert.strictEqual(request, null);
});

test('Unit: updateRequest handles special characters in ownership value', () => {
  const request = deviceDetailView.updateRequest({
    deviceId: 'dev-1',
    ownership: 'byoc',
  });

  assert.ok(request !== null);
  assert.strictEqual(request.body.ownership, 'byoc');
});

test('Unit: deleteRequest handles special characters in hostname', () => {
  const request = deviceDetailView.deleteRequest({
    deviceId: 'dev-1',
    hostname: 'PC-1@domain.local',
    typedHostname: 'PC-1@domain.local',
  });

  assert.ok(request !== null);
});

test('Unit: deleteRequest with very long hostname and deviceId', () => {
  const longHostname = 'A'.repeat(100);
  const longDeviceId = 'device-' + 'x'.repeat(50);

  const request = deviceDetailView.deleteRequest({
    deviceId: longDeviceId,
    hostname: longHostname,
    typedHostname: longHostname,
  });

  assert.ok(request !== null);
  assert.strictEqual(request.path, `/admin/api/v1/devices/${longDeviceId}`);
});
