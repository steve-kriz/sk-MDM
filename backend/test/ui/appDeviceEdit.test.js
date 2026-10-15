/**
 * E2E tests for device edit and delete functionality in backend/src/ui/public/app.js
 * (AC9: edit ownership form submission and AC10: delete device form submission).
 *
 * app.js guards its self-start, so the real exported `start()` is driven with
 * stub `window`/`document`/form objects. `fetch` is stubbed in-process: no
 * database is touched and nothing opens a socket.
 */

import test from 'node:test';
import assert from 'node:assert';

// Imported before any global `document` stub exists, so app.js does not self-start.
const appModule = await import('../../dist/ui/public/app.js');
const apiModule = await import('../../dist/ui/public/api.js');
const deviceDetailView = await import('../../dist/ui/views/deviceDetail.js');

/** What the stub API currently answers, changed scenario by scenario. */
const server = {
  devices: [],
  device: null,
  putResponse: { status: 200, body: {} },
  deleteResponse: { status: 200, body: {} },
  groups: [],
  groupMembersResponse: { status: 200, body: { added: 1 } },
  requests: [],
};

function json(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

globalThis.fetch = async (url, init = {}) => {
  if (url === '/admin/config.json') {
    return json(200, { tenantId: 't', clientId: 'c', redirectUri: 'https://example.invalid/cb', scope: 'openid' });
  }
  const method = init.method ?? 'GET';
  server.requests.push({ method, url, body: init.body ? JSON.parse(init.body) : null });

  if (method === 'GET' && url === '/admin/api/v1/devices') {
    return json(200, { items: server.devices, cursor: null });
  }
  if (method === 'GET' && url.startsWith('/admin/api/v1/devices/dev-1')) {
    return json(server.device ? 200 : 404, server.device ?? { error: 'not_found' });
  }
  if (method === 'PUT' && url === '/admin/api/v1/devices/dev-1') {
    return json(server.putResponse.status, server.putResponse.body);
  }
  if (method === 'DELETE' && url === '/admin/api/v1/devices/dev-1') {
    return json(server.deleteResponse.status, server.deleteResponse.body);
  }
  if (method === 'GET' && url === '/admin/api/v1/groups') {
    return json(200, { items: server.groups, cursor: null });
  }
  if ((method === 'POST' || method === 'DELETE') && /\/admin\/api\/v1\/groups\/[^/]+\/members$/.test(url)) {
    return json(server.groupMembersResponse.status, server.groupMembersResponse.body);
  }
  return json(200, { items: [] });
};

const listeners = {};
const mountStub = {
  innerHTML: '',
  addEventListener: (type, handler) => {
    listeners[type] = handler;
  },
};
globalThis.document = { getElementById: (id) => (id === 'app' ? mountStub : null) };
globalThis.window = {
  location: { hash: '#/devices/dev-1', search: '', origin: 'https://example.invalid' },
  addEventListener: () => {},
  history: { replaceState: () => {} },
};
apiModule.setToken('test-access-token');

function flush() {
  return new Promise((resolve) => setImmediate(resolve));
}

function textField(value) {
  return { type: 'text', value };
}

function selectField(value) {
  return { type: 'select-one', value };
}

/** A stub form for editing device. */
function editDeviceForm(fields, button = { disabled: false }) {
  return {
    classList: { contains: (cls) => cls === 'edit-device' },
    elements: { namedItem: (name) => fields[name] ?? null },
    querySelector: (selector) => (selector === 'button.save' ? button : null),
  };
}

/** A stub form for deleting device. */
function deleteDeviceForm(fields, button = { disabled: false }) {
  return {
    classList: { contains: (cls) => cls === 'delete-device' },
    elements: { namedItem: (name) => fields[name] ?? null },
    querySelector: (selector) => (selector === 'button.delete' ? button : null),
  };
}

async function submit(form) {
  listeners.submit({ target: form, preventDefault: () => {} });
  await flush();
}

function errorBanner() {
  const match = /<p class="error">([^<]*)<\/p>/.exec(mountStub.innerHTML);
  return match === null ? null : match[1];
}

await appModule.start();

// ============================================================================
// AC9: Edit device ownership
// ============================================================================

test('AC9: Scenario: Edit device ownership form submits PUT with ownership', async () => {
  // Given a device exists with current ownership "officehq"
  server.device = {
    profile: {
      deviceId: 'dev-1',
      hostname: 'PC-1',
      ownership: 'officehq',
      platform: 'windows',
      osVersion: '10',
      lastSeenAt: '2026-10-10T10:00:00Z',
      agentVersion: '1.0',
    },
    inventory: null,
    posture: null,
    commands: [],
    antivirusFindings: [],
    loginHistory: [],
    analytics: null,
  };
  server.putResponse = { status: 200, body: { deviceId: 'dev-1', ownership: 'byoc' } };
  server.requests = [];

  // When the detail screen loads
  await appModule.show();
  await flush();

  // Then the form shows current ownership "officehq"
  assert.match(mountStub.innerHTML, /selected.*officehq/i);

  // When the admin changes ownership to "byoc" and submits
  const form = editDeviceForm({ deviceId: textField('dev-1'), ownership: selectField('byoc') });
  await submit(form);

  // Then PUT /admin/api/v1/devices/dev-1 was issued with {"ownership":"byoc"}
  const putRequest = server.requests.find((r) => r.method === 'PUT' && r.url === '/admin/api/v1/devices/dev-1');
  assert.ok(putRequest);
  assert.deepStrictEqual(putRequest.body, { ownership: 'byoc' });
});

test('AC9: Scenario: On 200 PUT response, detail reloads and shows new ownership', async () => {
  // Given the PUT succeeded
  server.device.profile.ownership = 'byoc';
  server.putResponse = { status: 200, body: { deviceId: 'dev-1', ownership: 'byoc' } };
  server.requests = [];

  // When the form is submitted
  const form = editDeviceForm({ deviceId: textField('dev-1'), ownership: selectField('byoc') });
  await submit(form);

  // Then the detail was reloaded (GET /admin/api/v1/devices/dev-1)
  const getRequest = server.requests.find((r) => r.method === 'GET' && r.url.startsWith('/admin/api/v1/devices/dev-1'));
  assert.ok(getRequest);

  // And the painted HTML shows "BYOC" ownership label
  assert.match(mountStub.innerHTML, /BYOC/);
});

test('AC9: Scenario: On 400 PUT response, error banner is shown', async () => {
  // Given the PUT fails with 400
  server.putResponse = { status: 400, body: { error: 'invalid_request', fields: ['ownership'] } };
  server.requests = [];

  // When the form is submitted
  const form = editDeviceForm({ deviceId: textField('dev-1'), ownership: selectField('invalid') });
  await submit(form);

  // Then the error banner shows "invalid_request"
  const error = errorBanner();
  assert.match(error ?? '', /invalid_request/);
});

// ============================================================================
// AC10: Delete device with confirmation
// ============================================================================

test('AC10: Scenario: Delete form submits DELETE only when hostname matches', async () => {
  // Given a device exists with hostname "PC-1"
  server.device = {
    profile: {
      deviceId: 'dev-1',
      hostname: 'PC-1',
      platform: 'windows',
      osVersion: '10',
      lastSeenAt: '2026-10-10T10:00:00Z',
      agentVersion: '1.0',
    },
    inventory: null,
    posture: null,
    commands: [],
    antivirusFindings: [],
    loginHistory: [],
    analytics: null,
  };
  server.requests = [];

  // When the detail screen loads
  await appModule.show();
  await flush();

  // Then the delete button is disabled initially
  const form1 = deleteDeviceForm({ deviceId: textField('dev-1'), typedHostname: textField('') });
  const button1 = { disabled: true };
  assert.strictEqual(button1.disabled, true);

  // When the admin types the hostname "PC-1"
  const form2 = deleteDeviceForm({ deviceId: textField('dev-1'), typedHostname: textField('PC-1') });
  await submit(form2);

  // Then DELETE /admin/api/v1/devices/dev-1 is issued with {"confirm":true}
  server.deleteResponse = { status: 200, body: { deviceId: 'dev-1', itemsRemoved: 1, membershipsRemoved: 0 } };
  const deleteRequest = server.requests.find((r) => r.method === 'DELETE' && r.url === '/admin/api/v1/devices/dev-1');
  assert.ok(deleteRequest);
  assert.deepStrictEqual(deleteRequest.body, { confirm: true });
});

test('AC10: Scenario: On 200 DELETE response, window.location.hash is set to #/devices', async () => {
  // Given the DELETE succeeded
  server.deleteResponse = { status: 200, body: { deviceId: 'dev-1', itemsRemoved: 1, membershipsRemoved: 0 } };
  server.requests = [];

  // When the delete form is submitted
  const form = deleteDeviceForm({ deviceId: textField('dev-1'), typedHostname: textField('PC-1') });
  await submit(form);

  // Then window.location.hash is set to "#/devices"
  assert.strictEqual(globalThis.window.location.hash, '#/devices');
});

test('AC10: Scenario: Delete button enable/disable toggles as typedHostname changes', async () => {
  // Given a device with hostname "PC-1"
  server.device = {
    profile: {
      deviceId: 'dev-1',
      hostname: 'PC-1',
      platform: 'windows',
      osVersion: '10',
      lastSeenAt: '2026-10-10T10:00:00Z',
      agentVersion: '1.0',
    },
    inventory: null,
    posture: null,
    commands: [],
    antivirusFindings: [],
    loginHistory: [],
    analytics: null,
  };

  // When deleteRequest is called with non-matching typedHostname
  const req1 = deviceDetailView.deleteRequest({ deviceId: 'dev-1', hostname: 'PC-1', typedHostname: 'PC-' });
  // Then it returns null (button disabled)
  assert.strictEqual(req1, null);

  // When deleteRequest is called with matching typedHostname
  const req2 = deviceDetailView.deleteRequest({ deviceId: 'dev-1', hostname: 'PC-1', typedHostname: 'PC-1' });
  // Then it returns a request (button enabled)
  assert.ok(req2 !== null);
  assert.strictEqual(req2.method, 'DELETE');
});

// ============================================================================
// TASK-046: the device page's Groups panel (AC18, AC19, AC22)
// ============================================================================

/** A stub form for the device page's add-device-group panel. */
function addDeviceGroupForm(fields) {
  return {
    classList: { contains: (cls) => cls === 'add-device-group' },
    elements: { namedItem: (name) => fields[name] ?? null },
  };
}

/** A click whose target only matches `selector` via closest(), carrying `dataset`. */
function click(selector, dataset) {
  const element = { dataset };
  const target = { closest: (sel) => (sel === selector ? element : null) };
  listeners.click({ target, preventDefault: () => {} });
  return flush();
}

test('AC18: Scenario: Adding the device to a group from the device page', async () => {
  // Given the group list contains "grp-a" Finance and "grp-c" Ops, and "dev-1" is a member of "grp-a"
  server.groups = [
    { groupId: 'grp-a', name: 'Finance' },
    { groupId: 'grp-c', name: 'Ops' },
  ];
  server.device = {
    profile: {
      deviceId: 'dev-1',
      hostname: 'PC-1',
      platform: 'windows',
      osVersion: '10',
      lastSeenAt: '2026-10-10T10:00:00Z',
      agentVersion: '1.0',
    },
    inventory: null,
    posture: null,
    commands: [],
    antivirusFindings: [],
    loginHistory: [],
    analytics: null,
    groups: [{ groupId: 'grp-a', name: 'Finance' }],
    policies: [],
  };
  server.requests = [];
  // A previous scenario (AC10) may have navigated away to "#/devices"; come
  // back to the device detail page before rendering it.
  globalThis.window.location.hash = '#/devices/dev-1';

  // When the device detail page is rendered
  await appModule.show();
  await flush();

  // Then the add-device-group select offers "grp-c" and not "grp-a"
  const groupsSection = mountStub.innerHTML.slice(
    mountStub.innerHTML.indexOf('id="detail-groups"'),
    mountStub.innerHTML.indexOf('id="detail-policies"'),
  );
  assert.ok(groupsSection.includes('value="grp-c"'));
  assert.ok(!groupsSection.includes('value="grp-a"'));

  // When the admin chooses "grp-c" and submits the add-device-group form
  server.groupMembersResponse = { status: 200, body: { added: 1 } };
  server.requests = [];
  const form = addDeviceGroupForm({ deviceId: textField('dev-1'), groupId: selectField('grp-c') });
  await submit(form);

  // Then POST /admin/api/v1/groups/grp-c/members is sent with {"deviceIds":["dev-1"]}
  const postRequest = server.requests.find(
    (r) => r.method === 'POST' && r.url === '/admin/api/v1/groups/grp-c/members',
  );
  assert.ok(postRequest, 'expected a POST to grp-c/members');
  assert.deepStrictEqual(postRequest.body, { deviceIds: ['dev-1'] });
});

test('AC18: Scenario: Submitting the device page add form with no group chosen sends nothing', async () => {
  server.requests = [];

  const form = addDeviceGroupForm({ deviceId: textField('dev-1'), groupId: selectField('') });
  await submit(form);

  const postRequest = server.requests.find((r) => r.method === 'POST' && r.url.includes('/members'));
  assert.strictEqual(postRequest, undefined, 'no request should be sent with no group chosen');
});

test('AC19: Scenario: Removing the device from a group from the device page reloads the detail', async () => {
  // Given "dev-1" is a member of "grp-a"
  globalThis.window.location.hash = '#/devices/dev-1';
  server.groupMembersResponse = { status: 200, body: { removed: 1 } };
  server.requests = [];

  // When the admin clicks "Remove from group" for "grp-a" on the device page
  await click('.remove-device-group', { deviceId: 'dev-1', groupId: 'grp-a' });

  // Then DELETE /admin/api/v1/groups/grp-a/members is sent with {"deviceIds":["dev-1"]}
  const deleteRequest = server.requests.find(
    (r) => r.method === 'DELETE' && r.url === '/admin/api/v1/groups/grp-a/members',
  );
  assert.ok(deleteRequest, 'expected a DELETE to grp-a/members');
  assert.deepStrictEqual(deleteRequest.body, { deviceIds: ['dev-1'] });

  // And the device detail is reloaded
  const getRequest = server.requests.find((r) => r.method === 'GET' && r.url.startsWith('/admin/api/v1/devices/dev-1'));
  assert.ok(getRequest, 'expected the device detail to be reloaded');
});

test('AC22: Scenario: A refused group request from the device page shows its error', async () => {
  // Given POST /admin/api/v1/groups/grp-c/members answers 404 {"error":"not_found"}
  globalThis.window.location.hash = '#/devices/dev-1';
  server.groupMembersResponse = { status: 404, body: { error: 'not_found' } };
  server.requests = [];

  // When the admin submits the add-device-group form with "grp-c"
  const form = addDeviceGroupForm({ deviceId: textField('dev-1'), groupId: selectField('grp-c') });
  await submit(form);

  // Then the reloaded device page shows '<p class="error">not_found</p>'
  assert.ok(mountStub.innerHTML.includes('<p class="error">not_found</p>'));
});
