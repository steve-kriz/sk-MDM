/**
 * E2E cucumber-style tests for TASK-057: the device page's Refresh button.
 *
 * Implements the ticket's Gherkin scenarios (Given/When/Then) by driving the
 * real exported `app.js` handlers (`start`, `show`, `paint`, and the
 * `click`/`input` listeners captured off a stub mount element) against a stub
 * `window`/`document` and an in-process `fetch` stub. No database is touched
 * and nothing opens a socket.
 *
 * Render-only scenarios (AC1-AC4: button markup, escaping, the Delete button
 * staying unchanged, the CSS gap) are covered in
 * test/admin/device-refresh-unit.test.js. This file covers the interactive
 * scenarios AC5-AC17.
 */

import test from 'node:test';
import assert from 'node:assert';

// Imported before any global `document` stub exists, so app.js does not self-start.
const appModule = await import('../../dist/ui/public/app.js');
const apiModule = await import('../../dist/ui/public/api.js');

// ----------------------------------------------------------------------------
// Stub server: one device, plus overrides and a gate the tests control.
// ----------------------------------------------------------------------------

function defaultDevice() {
  return {
    profile: {
      deviceId: 'dev-1',
      hostname: 'PC-1',
      platform: 'other',
      agentVersion: '1.0',
      lastSeenAt: '2026-10-11T08:00:00Z',
    },
  };
}

const server = {
  device: defaultDevice(),
  deviceOverride: null, // {status, body} forces the GET /devices/dev-1 response
  rejectAll: false,
  scripts: { items: [] },
  applications: { items: [] },
  groups: { items: [] },
  requests: [],
  gate: null, // {promise, resolve} holds GET /devices/dev-1 open until released
};

function json(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

/** A promise the test controls the resolution of. */
function deferred() {
  let resolve;
  const promise = new Promise((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

globalThis.fetch = async (url, init = {}) => {
  if (url === '/admin/config.json') {
    return json(200, { tenantId: 't', clientId: 'c', redirectUri: 'https://example.invalid/cb', scope: 'openid' });
  }
  const method = init.method ?? 'GET';
  server.requests.push({ method, url });

  if (server.rejectAll) {
    throw new Error('network error');
  }

  const deviceMatch = /^\/admin\/api\/v1\/devices\/([^/?]+)$/.exec(url);
  if (method === 'GET' && deviceMatch && deviceMatch[1] === 'dev-1') {
    if (server.gate) {
      await server.gate.promise;
    }
    if (server.deviceOverride) {
      return json(server.deviceOverride.status, server.deviceOverride.body);
    }
    return json(200, server.device);
  }
  if (method === 'GET' && url.startsWith('/admin/api/v1/scripts')) {
    return json(200, server.scripts);
  }
  if (method === 'GET' && url.startsWith('/admin/api/v1/applications')) {
    return json(200, server.applications);
  }
  if (method === 'GET' && url === '/admin/api/v1/groups') {
    return json(200, server.groups);
  }
  if (method === 'GET' && /\/heartbeats$/.test(url)) {
    return json(200, { items: [] });
  }
  return json(200, { items: [] });
};

// ----------------------------------------------------------------------------
// Stub DOM and deterministic waits.
// ----------------------------------------------------------------------------

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

/** Bounded polling: never a single blind flush for an async outcome. */
async function waitUntil(predicate, tries = 100) {
  for (let i = 0; i < tries; i += 1) {
    if (predicate()) {
      return;
    }
    await flush();
  }
  throw new Error('condition not met within the poll bound');
}

/**
 * A click whose target matches exactly `selector` through `closest()`, with
 * an optional `dataset`. The click listener itself is void-returning
 * (fire-and-forget), so its synchronous prefix (state writes and `paint`)
 * has already run by the time this call returns; `flush()` lets any
 * already-resolvable microtasks settle before the caller inspects results.
 */
function click(selector, dataset) {
  const element = dataset ? { dataset } : {};
  const target = { closest: (sel) => (sel === selector ? element : null) };
  listeners.click({ target, preventDefault: () => {} });
  return flush();
}

function textField(value) {
  return { type: 'text', value };
}

function deleteDeviceForm(fields, button = { disabled: false }) {
  return {
    classList: { contains: (cls) => cls === 'delete-device' },
    elements: { namedItem: (name) => fields[name] ?? null },
    querySelector: (selector) => (selector === 'button.delete' ? button : null),
  };
}

function typeInto(form) {
  return { target: { closest: (sel) => (sel === 'form.delete-device' ? form : null) } };
}

/** The top-level page banner `paint()` renders from `state.error`. */
function banner() {
  const match = /<p class="error">([^<]*)<\/p>/.exec(mountStub.innerHTML);
  return match === null ? null : match[1];
}

await appModule.start();

// ============================================================================
// Background: the admin is on "#/devices/dev-1" with device "dev-1" loaded:
// hostname "PC-1", platform "other", lastSeenAt "2026-10-11T08:00:00Z".
// ============================================================================

async function goToDeviceOne() {
  globalThis.window.location.hash = '#/devices/dev-1';
  server.device = defaultDevice();
  server.deviceOverride = null;
  server.rejectAll = false;
  server.gate = null;
  server.scripts = { items: [] };
  server.applications = { items: [] };
  server.groups = { items: [] };
  server.requests = [];
  await appModule.show();
  await flush();
}

test('Background: the admin lands on the device detail page for dev-1', async () => {
  await goToDeviceOne();
  assert.ok(mountStub.innerHTML.includes('PC-1'));
  assert.match(mountStub.innerHTML, /<button type="button" class="refresh-device" data-device-id="dev-1">Refresh<\/button>/);
});

// ============================================================================
// AC5: Refresh repeats the device page requests and shows the loading state first
// ============================================================================

test('Scenario: AC5 Refresh repeats the device page requests and shows the loading state first', async () => {
  await goToDeviceOne();
  server.requests = [];
  const gate = deferred();
  server.gate = gate;

  // When the operator clicks the Refresh button (holding GET /devices/dev-1 open)
  const pending = click('.refresh-device');

  // Then the painted page shows the refresh-device button disabled and labelled "Refreshing..."
  assert.match(
    mountStub.innerHTML,
    /<button type="button" class="refresh-device" data-device-id="dev-1" disabled>Refreshing\.\.\.<\/button>/,
  );

  // When the stub server releases the response
  gate.resolve();
  await pending;
  await waitUntil(() => server.requests.some((r) => r.url === '/admin/api/v1/groups'));

  // Then the requests made are GET /devices/dev-1 then GET /groups, in that order
  const deviceIndex = server.requests.findIndex((r) => r.method === 'GET' && r.url === '/admin/api/v1/devices/dev-1');
  const groupsIndex = server.requests.findIndex((r) => r.method === 'GET' && r.url === '/admin/api/v1/groups');
  assert.ok(deviceIndex !== -1 && groupsIndex !== -1 && deviceIndex < groupsIndex);
  assert.strictEqual(server.requests.filter((r) => r.url === '/admin/api/v1/devices/dev-1').length, 1);
  assert.strictEqual(server.requests.filter((r) => r.url.startsWith('/admin/api/v1/scripts')).length, 0);
  assert.strictEqual(server.requests.filter((r) => r.url.startsWith('/admin/api/v1/applications')).length, 0);

  server.gate = null;
});

test('Scenario: AC5 Edge: platform changed to windows since the page loaded', async () => {
  await goToDeviceOne();
  // Given the stub server now returns platform "windows" for "dev-1"
  server.device = { profile: { ...server.device.profile, platform: 'windows' } };
  server.scripts = { items: [{ scriptId: 's1', name: 'Script 1' }] };
  server.applications = { items: [{ applicationId: 'a1', name: 'App 1' }] };
  server.requests = [];

  // When the operator clicks the Refresh button
  await click('.refresh-device');
  await waitUntil(() => server.requests.some((r) => r.url === '/admin/api/v1/groups'));

  // Then the requests made are GET /devices/dev-1, GET /scripts?platform=windows,
  // GET /applications?platform=windows and GET /groups
  const urls = server.requests.map((r) => r.url);
  assert.ok(urls.includes('/admin/api/v1/devices/dev-1'));
  assert.ok(urls.includes('/admin/api/v1/scripts?platform=windows'));
  assert.ok(urls.includes('/admin/api/v1/applications?platform=windows'));
  assert.ok(urls.includes('/admin/api/v1/groups'));
});

// ============================================================================
// AC6: Refresh never contacts the agent or sends a write
// ============================================================================

test('Scenario: AC6 Refresh never contacts the agent or sends a write', async () => {
  await goToDeviceOne();
  server.requests = [];

  await click('.refresh-device');
  await waitUntil(() => server.requests.some((r) => r.url === '/admin/api/v1/groups'));

  assert.ok(server.requests.length > 0);
  for (const request of server.requests) {
    assert.strictEqual(request.method, 'GET');
    assert.ok(!/checkin|commands|heartbeat/i.test(request.url), `unexpected path: ${request.url}`);
  }
});

// ============================================================================
// AC7: Fresh data is painted after a successful refresh
// ============================================================================

test('Scenario: AC7 Fresh data is painted after a successful refresh', async () => {
  await goToDeviceOne();
  // Given the stub server now returns hostname "PC-1-renamed" and a new lastSeenAt for "dev-1"
  server.device = {
    profile: { ...server.device.profile, hostname: 'PC-1-renamed', lastSeenAt: '2026-10-11T09:30:00Z' },
  };

  // When the operator clicks the Refresh button
  await click('.refresh-device');
  await waitUntil(() => mountStub.innerHTML.includes('PC-1-renamed'));

  // Then the painted page shows "PC-1-renamed"
  assert.ok(mountStub.innerHTML.includes('PC-1-renamed'));
  // And the refresh-device button is enabled and labelled "Refresh"
  assert.match(mountStub.innerHTML, /<button type="button" class="refresh-device" data-device-id="dev-1">Refresh<\/button>/);
  // And the address bar is still "#/devices/dev-1"
  assert.strictEqual(globalThis.window.location.hash, '#/devices/dev-1');
});

// ============================================================================
// AC8: A successful refresh resets the page state like a fresh load
// ============================================================================

test('Scenario: AC8 A successful refresh resets the page state like a fresh load', async () => {
  await goToDeviceOne();
  // Given the Analytics history expander is open
  await click('.heartbeat-history summary', { deviceId: 'dev-1' });
  assert.match(mountStub.innerHTML, /<details class="expandable heartbeat-history" data-device-id="dev-1" open>/);

  server.requests = [];

  // When the operator clicks the Refresh button and the refresh succeeds
  await click('.refresh-device');
  await waitUntil(() => server.requests.some((r) => r.url === '/admin/api/v1/groups'));

  // Then state.detail has no deleteDialog and no heartbeatHistory (rendered: no open expander, no dialog)
  assert.ok(!mountStub.innerHTML.includes('id="delete-device-dialog"'));
  assert.ok(!/<details class="expandable heartbeat-history"[^>]*\bopen\b/.test(mountStub.innerHTML));
  // And state.detail.runCommand is an empty object (rendered: the Queue form shows no kept draft)
  assert.match(mountStub.innerHTML, /<input id="queue-script-hostname" name="typedHostname" value="" autocomplete="off">/);
});

// ============================================================================
// AC9: A successful refresh clears an earlier banner
// ============================================================================

test('Scenario: AC9 A successful refresh clears an earlier banner', async () => {
  await goToDeviceOne();
  // Given the page shows the banner "request_failed" from an earlier action
  server.deviceOverride = { status: 500, body: {} };
  await click('.refresh-device');
  await waitUntil(() => banner() === 'request_failed');
  assert.strictEqual(banner(), 'request_failed');

  // When the operator clicks the Refresh button and the refresh succeeds
  server.deviceOverride = null;
  await click('.refresh-device');
  await waitUntil(() => banner() === null);

  // Then the painted page contains no element with class "error"
  assert.strictEqual(banner(), null);
  assert.ok(!mountStub.innerHTML.includes('class="error"'));
});

// ============================================================================
// AC10: Failure on GET /devices/{id}
// ============================================================================

test('Scenario: AC10 Failure: device request returns 404', async () => {
  await goToDeviceOne();
  // Given the stub server returns 404 with body {"error":"not_found"} for GET /devices/dev-1
  server.deviceOverride = { status: 404, body: { error: 'not_found' } };
  server.requests = [];

  // When the operator clicks the Refresh button
  await click('.refresh-device');
  await waitUntil(() => banner() !== null);

  // Then the painted page still shows hostname "PC-1"
  assert.ok(mountStub.innerHTML.includes('PC-1'));
  // And the banner reads "not_found"
  assert.strictEqual(banner(), 'not_found');
  // And the refresh-device button is enabled and labelled "Refresh"
  assert.match(mountStub.innerHTML, /<button type="button" class="refresh-device" data-device-id="dev-1">Refresh<\/button>/);
});

test('Scenario: AC10 Failure: device request returns 500 with no error field', async () => {
  await goToDeviceOne();
  // Given the stub server returns 500 with body {} for GET /devices/dev-1
  server.deviceOverride = { status: 500, body: {} };
  server.requests = [];

  await click('.refresh-device');
  await waitUntil(() => banner() !== null);

  // Then the banner reads "request_failed"
  assert.strictEqual(banner(), 'request_failed');
  // And the painted page still shows hostname "PC-1"
  assert.ok(mountStub.innerHTML.includes('PC-1'));
});

// ============================================================================
// AC11: Failure: the network rejects during the refresh
// ============================================================================

test('Scenario: AC11 Failure: the network rejects during the refresh', async () => {
  await goToDeviceOne();
  // Given the stub fetch rejects every request with "network error"
  server.rejectAll = true;
  server.requests = [];

  let unhandled = false;
  const onUnhandled = () => {
    unhandled = true;
  };
  process.once('unhandledRejection', onUnhandled);

  // When the operator clicks the Refresh button
  await click('.refresh-device');
  await waitUntil(() => banner() !== null);
  // A few more turns for any unhandled rejection to surface, if one were raised.
  await flush();
  await flush();

  // Then the painted page still shows hostname "PC-1"
  assert.ok(mountStub.innerHTML.includes('PC-1'));
  // And the banner reads "request_failed"
  assert.strictEqual(banner(), 'request_failed');
  // And the refresh-device button is enabled and labelled "Refresh"
  assert.match(mountStub.innerHTML, /<button type="button" class="refresh-device" data-device-id="dev-1">Refresh<\/button>/);
  // And no unhandled promise rejection is raised
  assert.strictEqual(unhandled, false, 'no unhandled promise rejection should be raised');

  process.removeListener('unhandledRejection', onUnhandled);
  server.rejectAll = false;
});

// ============================================================================
// AC12: Retrying after a failure succeeds
// ============================================================================

test('Scenario: AC12 Retrying after a failure succeeds', async () => {
  await goToDeviceOne();
  // Given a refresh has failed with banner "request_failed"
  server.deviceOverride = { status: 500, body: {} };
  await click('.refresh-device');
  await waitUntil(() => banner() === 'request_failed');

  // And the stub server now answers normally with hostname "PC-1-renamed"
  server.deviceOverride = null;
  server.device = { profile: { ...server.device.profile, hostname: 'PC-1-renamed' } };
  server.requests = [];

  // When the operator clicks the Refresh button again
  await click('.refresh-device');
  await waitUntil(() => mountStub.innerHTML.includes('PC-1-renamed'));

  // Then GET /devices/dev-1 is requested again
  assert.strictEqual(server.requests.filter((r) => r.url === '/admin/api/v1/devices/dev-1').length, 1);
  // And the painted page shows "PC-1-renamed" and no banner
  assert.ok(mountStub.innerHTML.includes('PC-1-renamed'));
  assert.strictEqual(banner(), null);
});

// ============================================================================
// AC13: Edge: double click while a refresh is in flight
// ============================================================================

test('Scenario: AC13 Edge: double click while a refresh is in flight', async () => {
  await goToDeviceOne();
  const gate = deferred();
  server.gate = gate;
  server.requests = [];

  // When the operator clicks the Refresh button twice
  await click('.refresh-device');
  await click('.refresh-device');

  // And the stub server releases the response
  gate.resolve();
  await waitUntil(() => server.requests.some((r) => r.url === '/admin/api/v1/groups'));

  // Then GET /devices/dev-1 was requested exactly once for the refresh
  assert.strictEqual(server.requests.filter((r) => r.url === '/admin/api/v1/devices/dev-1').length, 1);

  server.gate = null;
});

// ============================================================================
// AC14: Edge: Refresh is ignored while the delete popup is open
// ============================================================================

test('Scenario: AC14 Edge: Refresh is ignored while the delete popup is open', async () => {
  await goToDeviceOne();
  // Given the delete-device popup is open with typed text "PC"
  await click('.open-delete-device');
  const button = { disabled: true };
  listeners.input(typeInto(deleteDeviceForm({ deviceId: textField('dev-1'), typedHostname: textField('PC') }, button)));
  server.requests = [];

  // When a click on the Refresh button reaches the click handler
  await click('.refresh-device');

  // Then no request is made
  assert.strictEqual(server.requests.length, 0);
  // And state.detail.deleteDialog is open with typedHostname "PC" (observed via a forced repaint)
  appModule.paint('devices', 'dev-1');
  assert.ok(mountStub.innerHTML.includes('id="delete-device-dialog"'));
  assert.match(mountStub.innerHTML, /value="PC"/);
});

// ============================================================================
// AC15: Edge: operator navigates away before the refresh resolves
// ============================================================================

test('Scenario: AC15 Edge: operator navigates away before the refresh resolves', async () => {
  await goToDeviceOne();
  const gate = deferred();
  server.gate = gate;
  server.requests = [];

  // When the operator clicks the Refresh button
  await click('.refresh-device');
  const beforeHtml = mountStub.innerHTML;

  // And the address bar changes to "#/devices"
  globalThis.window.location.hash = '#/devices';

  // And the stub server releases the response with hostname "PC-1-renamed"
  server.device = { profile: { ...server.device.profile, hostname: 'PC-1-renamed' } };
  gate.resolve();
  await waitUntil(() => server.requests.some((r) => r.url === '/admin/api/v1/groups'));
  await flush();
  await flush();

  // Then the refresh does not paint the page (unchanged since the "Refreshing..." paint)
  assert.strictEqual(mountStub.innerHTML, beforeHtml);
  // And state.detail is not replaced with the refreshed data
  assert.ok(!mountStub.innerHTML.includes('PC-1-renamed'));

  globalThis.window.location.hash = '#/devices/dev-1';
  server.gate = null;
});

// ============================================================================
// AC16: No polling after a refresh
// ============================================================================

test('Scenario: AC16 No polling after a refresh', async () => {
  await goToDeviceOne();
  server.requests = [];

  // When the operator clicks the Refresh button and the refresh succeeds
  await click('.refresh-device');
  await waitUntil(() => server.requests.some((r) => r.url === '/admin/api/v1/groups'));
  const countAfterSuccess = server.requests.length;

  // And several event-loop turns pass with no user action
  for (let i = 0; i < 10; i += 1) {
    await flush();
  }

  // Then no further request is made
  assert.strictEqual(server.requests.length, countAfterSuccess);
});

test('Scenario: AC16 app.js has no setInterval or setTimeout for this feature', async () => {
  const { readFileSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const path = await import('node:path');
  const src = readFileSync(
    path.join(path.dirname(fileURLToPath(import.meta.url)), '../../src/ui/public/app.js'),
    'utf8',
  );
  assert.ok(!/\bsetInterval\s*\(/.test(src));
  assert.ok(!/\bsetTimeout\s*\(/.test(src));
});

// ============================================================================
// AC17: Initial page load is unchanged (regression)
// ============================================================================

test('Scenario: AC17 Initial page load is unchanged', async () => {
  await goToDeviceOne();

  // Then the requests made are GET /devices/dev-1 then GET /groups
  const deviceIndex = server.requests.findIndex((r) => r.method === 'GET' && r.url === '/admin/api/v1/devices/dev-1');
  const groupsIndex = server.requests.findIndex((r) => r.method === 'GET' && r.url === '/admin/api/v1/groups');
  assert.ok(deviceIndex !== -1 && groupsIndex !== -1 && deviceIndex < groupsIndex);
  assert.strictEqual(server.requests.filter((r) => r.url.startsWith('/admin/api/v1/scripts')).length, 0);
  assert.strictEqual(server.requests.filter((r) => r.url.startsWith('/admin/api/v1/applications')).length, 0);

  // And state.detail has runCommand equal to an empty object and allGroups from GET /groups
  assert.match(mountStub.innerHTML, /<input id="queue-script-hostname" name="typedHostname" value="" autocomplete="off">/);
});

test('Scenario: AC17 Edge: a non-2xx GET /devices/{id} on initial load is not guarded (unchanged legacy behaviour)', async () => {
  globalThis.window.location.hash = '#/devices/dev-1';
  server.device = defaultDevice();
  server.deviceOverride = { status: 404, body: { error: 'not_found' } };
  server.rejectAll = false;
  server.gate = null;
  server.requests = [];

  await appModule.show();
  await flush();

  // The legacy load() does not check `ok`; it still paints from the (empty) body.
  assert.ok(!mountStub.innerHTML.includes('PC-1'));

  server.deviceOverride = null;
  await goToDeviceOne();
});
