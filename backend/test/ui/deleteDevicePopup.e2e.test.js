/**
 * E2E cucumber-style tests for TASK-051: delete-device confirmation popup.
 *
 * Implements the ticket's Gherkin scenarios (Given/When/Then) by driving the
 * real exported `app.js` handlers (`start`, `show`, `paint`, and the
 * `click`/`input`/`keydown`/`submit` listeners captured off a stub mount
 * element) against a stub `window`/`document` and an in-process `fetch` stub.
 * No database is touched and nothing opens a socket.
 */

import test from 'node:test';
import assert from 'node:assert';

// Imported before any global `document` stub exists, so app.js does not self-start.
const appModule = await import('../../dist/ui/public/app.js');
const apiModule = await import('../../dist/ui/public/api.js');

// ----------------------------------------------------------------------------
// Stub server: devices keyed by id, plus a scriptable DELETE response.
// ----------------------------------------------------------------------------

const server = {
  devices: {
    'dev-1': { profile: { deviceId: 'dev-1', hostname: 'PC-1', platform: 'other', agentVersion: '1.0' } },
    'dev-2': { profile: { deviceId: 'dev-2', hostname: null, platform: 'other', agentVersion: '1.0' } },
    'dev-3': { profile: { deviceId: 'dev-3', hostname: '<b>&"x', platform: 'other', agentVersion: '1.0' } },
  },
  deleteResponse: { status: 200, body: { deviceId: 'dev-1', itemsRemoved: 1, membershipsRemoved: 0 } },
  deleteShouldReject: false,
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

  const deviceMatch = /^\/admin\/api\/v1\/devices\/([^/?]+)/.exec(url);
  if (method === 'DELETE' && deviceMatch) {
    server.requests.push({ method, url, body: init.body ? JSON.parse(init.body) : null });
    if (server.deleteShouldReject) {
      throw new Error('network error');
    }
    return json(server.deleteResponse.status, server.deleteResponse.body);
  }
  server.requests.push({ method, url, body: init.body ? JSON.parse(init.body) : null });

  if (method === 'GET' && url === '/admin/api/v1/devices') {
    return json(200, { items: [], cursor: null });
  }
  if (method === 'GET' && deviceMatch) {
    const device = server.devices[deviceMatch[1]];
    return json(device ? 200 : 404, device ?? { error: 'not_found' });
  }
  if (method === 'GET' && url === '/admin/api/v1/groups') {
    return json(200, { items: [], cursor: null });
  }
  return json(200, { items: [] });
};

// ----------------------------------------------------------------------------
// Stub DOM: a mount element that records listeners, plus a focusable
// #delete-device-hostname that is `null` unless a test asks for one.
// ----------------------------------------------------------------------------

const listeners = {};
const mountStub = {
  innerHTML: '',
  addEventListener: (type, handler) => {
    listeners[type] = handler;
  },
};
let hostnameInputStub = null;
globalThis.document = {
  getElementById: (id) => {
    if (id === 'app') return mountStub;
    if (id === 'delete-device-hostname') return hostnameInputStub;
    return null;
  },
};
globalThis.window = {
  location: { hash: '#/devices/dev-1', search: '', origin: 'https://example.invalid' },
  addEventListener: () => {},
  history: { replaceState: () => {} },
};
apiModule.setToken('test-access-token');

function flush() {
  return new Promise((resolve) => setImmediate(resolve));
}

/** A click whose target matches exactly `selector` through `closest()`. Never `undefined`. */
function click(selector) {
  const target = { closest: (sel) => (sel === selector ? {} : null) };
  listeners.click({ target, preventDefault: () => {} });
  return flush();
}

function textField(value) {
  return { type: 'text', value };
}

/** A stub `form.delete-device`, with a `button.delete` whose `.disabled` tests can read. */
function deleteDeviceForm(fields, button = { disabled: false }) {
  return {
    classList: { contains: (cls) => cls === 'delete-device' },
    elements: { namedItem: (name) => fields[name] ?? null },
    querySelector: (selector) => (selector === 'button.delete' ? button : null),
  };
}

/** An `input` event targeting `form.delete-device`. */
function typeInto(form) {
  return { target: { closest: (sel) => (sel === 'form.delete-device' ? form : null) } };
}

async function submit(form) {
  listeners.submit({ target: form, preventDefault: () => {} });
  await flush();
}

function repaint() {
  appModule.paint('devices', 'dev-1');
}

function dialogHtml() {
  const start = mountStub.innerHTML.indexOf('id="delete-device-dialog"');
  if (start === -1) return null;
  const backdropStart = mountStub.innerHTML.lastIndexOf('<div class="modal-backdrop">', start);
  return mountStub.innerHTML.slice(backdropStart);
}

await appModule.start();

// ============================================================================
// Background: an admin is signed in, device "dev-1" exists with hostname
// "PC-1", and the admin is on "#/devices/dev-1".
// ============================================================================

async function goToDeviceOne() {
  globalThis.window.location.hash = '#/devices/dev-1';
  server.requests = [];
  await appModule.show();
  await flush();
}

test('Background: the admin lands on the device detail page for dev-1', async () => {
  await goToDeviceOne();
  assert.ok(mountStub.innerHTML.includes('id="screen-device-detail"'));
  assert.ok(mountStub.innerHTML.includes('PC-1'));
});

// ============================================================================
// AC4: Clicking Delete device opens the popup without a request
// ============================================================================

test('Scenario: AC4 clicking "button.open-delete-device" opens the popup without a request', async () => {
  await goToDeviceOne();
  server.requests = [];

  // When the admin clicks "button.open-delete-device"
  await click('.open-delete-device');

  // Then the page shows div.modal-backdrop wrapping div#delete-device-dialog
  // with role "dialog" and aria-modal "true"
  const dialog = dialogHtml();
  assert.ok(dialog !== null);
  assert.match(dialog, /<div class="modal" id="delete-device-dialog" role="dialog" aria-modal="true"/);

  // And no HTTP request was sent
  assert.strictEqual(server.requests.length, 0);
});

// ============================================================================
// AC9: Delete button enables only on an exact match
// ============================================================================

test('Scenario Outline: AC9 "PC-1" enables the Delete button and is stored', async () => {
  await goToDeviceOne();
  await click('.open-delete-device');

  const button = { disabled: true };
  const form = deleteDeviceForm({ deviceId: textField('dev-1'), typedHostname: textField('PC-1') }, button);
  listeners.input(typeInto(form));

  // Then button.delete disabled is false
  assert.strictEqual(button.disabled, false);

  // And state.detail.deleteDialog.typedHostname is "PC-1" (observed via a forced repaint)
  repaint();
  assert.match(dialogHtml(), /<input id="delete-device-hostname" name="typedHostname" value="PC-1" autocomplete="off">/);
});

test('Scenario Outline: AC9 "pc-1" (wrong case) keeps the Delete button disabled', async () => {
  await goToDeviceOne();
  await click('.open-delete-device');

  const button = { disabled: false };
  const form = deleteDeviceForm({ deviceId: textField('dev-1'), typedHostname: textField('pc-1') }, button);
  listeners.input(typeInto(form));

  assert.strictEqual(button.disabled, true);
  repaint();
  assert.match(dialogHtml(), /value="pc-1"/);
});

test('Scenario Outline: AC9 "PC-" (partial) keeps the Delete button disabled', async () => {
  await goToDeviceOne();
  await click('.open-delete-device');

  const button = { disabled: false };
  const form = deleteDeviceForm({ deviceId: textField('dev-1'), typedHostname: textField('PC-') }, button);
  listeners.input(typeInto(form));

  assert.strictEqual(button.disabled, true);
});

test('Scenario: AC9 a trailing space keeps Delete disabled (edge)', async () => {
  await goToDeviceOne();
  await click('.open-delete-device');

  const button = { disabled: false };
  const form = deleteDeviceForm({ deviceId: textField('dev-1'), typedHostname: textField('PC-1 ') }, button);
  listeners.input(typeInto(form));

  assert.strictEqual(button.disabled, true);
  repaint();
  assert.match(dialogHtml(), /value="PC-1 "/);
});

test('Scenario: AC9 a leading space keeps Delete disabled (edge)', async () => {
  await goToDeviceOne();
  await click('.open-delete-device');

  const button = { disabled: false };
  const form = deleteDeviceForm({ deviceId: textField('dev-1'), typedHostname: textField(' PC-1') }, button);
  listeners.input(typeInto(form));

  assert.strictEqual(button.disabled, true);
  repaint();
  assert.match(dialogHtml(), /value=" PC-1"/);
});

// ============================================================================
// AC10: Focus
// ============================================================================

test('Scenario: AC10 the name input is focused when the popup opens', async () => {
  await goToDeviceOne();
  let focusCalls = 0;
  hostnameInputStub = { focus: () => { focusCalls += 1; } };

  await click('.open-delete-device');

  assert.strictEqual(focusCalls, 1);
  hostnameInputStub = null;
});

test('Scenario: AC10 focus is skipped when the input is not found (edge)', async () => {
  await goToDeviceOne();
  hostnameInputStub = null;

  await assert.doesNotReject(() => click('.open-delete-device'));
  assert.ok(dialogHtml() !== null, 'the popup is still rendered');
});

// ============================================================================
// AC11: Cancel closes the popup without deleting
// ============================================================================

test('Scenario: AC11 clicking "button.cancel-delete-device" closes the popup without deleting', async () => {
  await goToDeviceOne();
  await click('.open-delete-device');
  const button = { disabled: true };
  listeners.input(typeInto(deleteDeviceForm({ deviceId: textField('dev-1'), typedHostname: textField('PC-1') }, button)));
  server.requests = [];

  // When the admin clicks "button.cancel-delete-device"
  await click('.cancel-delete-device');

  // Then the page contains no #delete-device-dialog
  assert.strictEqual(dialogHtml(), null);
  // And no HTTP request was sent
  assert.strictEqual(server.requests.length, 0);
  // And window.location.hash is "#/devices/dev-1"
  assert.strictEqual(globalThis.window.location.hash, '#/devices/dev-1');
});

// ============================================================================
// AC12: Escape closes the popup without deleting
// ============================================================================

test('Scenario: AC12 Escape closes the popup without deleting', async () => {
  await goToDeviceOne();
  await click('.open-delete-device');
  server.requests = [];

  // When a keydown with key "Escape" is dispatched
  listeners.keydown({ key: 'Escape' });
  await flush();

  // Then the page contains no #delete-device-dialog
  assert.strictEqual(dialogHtml(), null);
  assert.strictEqual(server.requests.length, 0);
});

test('Scenario: AC12 Escape with no popup open does nothing (edge)', async () => {
  await goToDeviceOne();
  // The popup is not open (a fresh load never opens it).
  server.requests = [];
  const before = mountStub.innerHTML;

  listeners.keydown({ key: 'Escape' });
  await flush();

  assert.strictEqual(server.requests.length, 0);
  // No repaint should have been triggered by a no-op Escape.
  assert.strictEqual(mountStub.innerHTML, before);
});

// ============================================================================
// AC13: Clicking the backdrop leaves the popup open (edge)
// ============================================================================

test('Scenario: AC13 clicking the backdrop leaves the popup open (edge)', async () => {
  await goToDeviceOne();
  await click('.open-delete-device');
  const openHtml = dialogHtml();
  server.requests = [];

  // When the admin clicks div.modal-backdrop outside div#delete-device-dialog
  await click('.modal-backdrop');

  // Then the popup is still rendered (unchanged) and no request was sent
  assert.strictEqual(dialogHtml(), openHtml);
  assert.strictEqual(server.requests.length, 0);
});

// ============================================================================
// AC14: Reopening after cancel starts fresh
// ============================================================================

test('Scenario: AC14 reopening after Cancel renders an empty, disabled, error-free popup', async () => {
  await goToDeviceOne();
  await click('.open-delete-device');
  const button = { disabled: true };
  listeners.input(typeInto(deleteDeviceForm({ deviceId: textField('dev-1'), typedHostname: textField('PC-1') }, button)));
  await click('.cancel-delete-device');

  // When the admin clicks "button.open-delete-device" again
  await click('.open-delete-device');

  const dialog = dialogHtml();
  assert.match(dialog, /<input id="delete-device-hostname" name="typedHostname" value="" autocomplete="off">/);
  assert.ok(!dialog.includes('delete-device-error'));
  assert.match(dialog, /<button type="submit" class="delete" disabled>/);
});

// ============================================================================
// AC15: Confirming with the hostname sends the delete
// ============================================================================

test('Scenario: AC15 confirming with the hostname sends exactly one DELETE', async () => {
  await goToDeviceOne();
  await click('.open-delete-device');
  server.requests = [];
  server.deleteResponse = { status: 200, body: { deviceId: 'dev-1', itemsRemoved: 1, membershipsRemoved: 0 } };

  // When the admin types "PC-1" and submits form.delete-device
  const form = deleteDeviceForm({ deviceId: textField('dev-1'), typedHostname: textField('PC-1') });
  await submit(form);

  // Then exactly one DELETE /admin/api/v1/devices/dev-1 was sent with {"confirm":true}
  const deletes = server.requests.filter((r) => r.method === 'DELETE' && r.url === '/admin/api/v1/devices/dev-1');
  assert.strictEqual(deletes.length, 1);
  assert.deepStrictEqual(deletes[0].body, { confirm: true });
});

test('Scenario: AC15 confirming a hostname-less device with its id sends exactly one DELETE', async () => {
  // Given device "dev-2" has no hostname and its popup is open
  globalThis.window.location.hash = '#/devices/dev-2';
  server.requests = [];
  await appModule.show();
  await flush();
  await click('.open-delete-device');
  server.requests = [];
  server.deleteResponse = { status: 200, body: { deviceId: 'dev-2', itemsRemoved: 1, membershipsRemoved: 0 } };

  // When the admin types "dev-2" and submits
  const form = deleteDeviceForm({ deviceId: textField('dev-2'), typedHostname: textField('dev-2') });
  await submit(form);

  const deletes = server.requests.filter((r) => r.method === 'DELETE' && r.url === '/admin/api/v1/devices/dev-2');
  assert.strictEqual(deletes.length, 1);
  assert.deepStrictEqual(deletes[0].body, { confirm: true });
});

// ============================================================================
// AC16: A non-matching submit sends nothing (failure)
// ============================================================================

for (const typed of ['', 'PC-', 'pc-1', 'PC-1 ', ' PC-1']) {
  test(`Scenario Outline: AC16 submitting "${typed}" sends nothing and keeps the popup open (failure)`, async () => {
    await goToDeviceOne();
    await click('.open-delete-device');
    server.requests = [];

    const form = deleteDeviceForm({ deviceId: textField('dev-1'), typedHostname: textField(typed) });
    await submit(form);

    assert.strictEqual(server.requests.filter((r) => r.method === 'DELETE').length, 0, 'no DELETE request was sent');
    assert.ok(dialogHtml() !== null, 'the popup is still open');
  });
}

// ============================================================================
// AC17: A successful delete returns to the device list
// ============================================================================

test('Scenario: AC17 a successful delete returns to the device list', async () => {
  await goToDeviceOne();
  await click('.open-delete-device');
  server.deleteResponse = { status: 200, body: { deviceId: 'dev-1', itemsRemoved: 1, membershipsRemoved: 0 } };

  const form = deleteDeviceForm({ deviceId: textField('dev-1'), typedHostname: textField('PC-1') });
  await submit(form);

  // Then window.location.hash is "#/devices" and the dialog is cleared
  assert.strictEqual(globalThis.window.location.hash, '#/devices');
  assert.strictEqual(dialogHtml(), null);
});

// ============================================================================
// AC18: A refused delete shows the error inside the popup (failure)
// ============================================================================

const refusals = [
  { status: 404, body: { error: 'not_found' }, shown: 'not_found' },
  { status: 409, body: { error: 'confirmation_required' }, shown: 'confirmation_required' },
  { status: 500, body: {}, shown: 'request_failed' },
];

for (const { status, body, shown } of refusals) {
  test(`Scenario Outline: AC18 a ${status} DELETE shows "${shown}" inside the popup (failure)`, async () => {
    await goToDeviceOne();
    await click('.open-delete-device');
    server.deleteResponse = { status, body };
    server.deleteShouldReject = false;

    const form = deleteDeviceForm({ deviceId: textField('dev-1'), typedHostname: textField('PC-1') });
    await submit(form);

    // Then the popup is still open and shows the error
    const dialog = dialogHtml();
    assert.ok(dialog !== null, 'the popup is still open');
    assert.match(dialog, new RegExp(`<p class="error delete-device-error">${shown}</p>`));
    // The typed text is kept
    assert.match(dialog, /value="PC-1"/);
    // The hash is unchanged
    assert.strictEqual(globalThis.window.location.hash, '#/devices/dev-1');
    // No duplicate top-level banner outside the popup
    assert.ok(!mountStub.innerHTML.slice(0, mountStub.innerHTML.indexOf('id="screen-device-detail"')).includes('<p class="error">'));
    const beforeDialog = mountStub.innerHTML.slice(0, mountStub.innerHTML.indexOf('class="modal-backdrop"'));
    assert.ok(!beforeDialog.includes('<p class="error">'));
  });
}

// ============================================================================
// AC19: A network failure shows request_failed in the popup (failure)
// ============================================================================

test('Scenario: AC19 a rejected DELETE shows "request_failed" and does not throw (failure)', async () => {
  await goToDeviceOne();
  await click('.open-delete-device');
  server.deleteShouldReject = true;

  const form = deleteDeviceForm({ deviceId: textField('dev-1'), typedHostname: textField('PC-1') });
  await assert.doesNotReject(() => submit(form));

  const dialog = dialogHtml();
  assert.ok(dialog !== null);
  assert.match(dialog, /<p class="error delete-device-error">request_failed<\/p>/);
  assert.strictEqual(globalThis.window.location.hash, '#/devices/dev-1');
  const beforeDialog = mountStub.innerHTML.slice(0, mountStub.innerHTML.indexOf('class="modal-backdrop"'));
  assert.ok(!beforeDialog.includes('<p class="error">'));

  server.deleteShouldReject = false;
});

// ============================================================================
// AC6/AC7 sanity through the full app flow (escaping and the id fallback)
// ============================================================================

test('Scenario: AC6 the popup names the device id when a device has no hostname', async () => {
  globalThis.window.location.hash = '#/devices/dev-2';
  await appModule.show();
  await flush();
  await click('.open-delete-device');

  const dialog = dialogHtml();
  assert.match(dialog, /<strong>dev-2<\/strong>/);
});

test('Scenario: AC7 a hostname with HTML characters is escaped in the popup (edge)', async () => {
  globalThis.window.location.hash = '#/devices/dev-3';
  await appModule.show();
  await flush();
  await click('.open-delete-device');

  const dialog = dialogHtml();
  assert.ok(dialog.includes('&lt;b&gt;&amp;&quot;x'));
  assert.ok(!dialog.includes('<b>&"x'));
});
