/**
 * E2E cucumber-style tests for TASK-062: the device detail page's section
 * expanders (app-level, AC9-AC13). Implements the ticket's Gherkin scenarios
 * (Given/When/Then) by driving the real exported `app.js` handlers (`start`,
 * `show`, `paint`, and the `click`/`submit` listeners captured off a stub
 * mount element, plus the `hashchange` listener captured off a stub window)
 * against a stub `window`/`document` and an in-process `fetch` stub. No
 * database is touched and nothing opens a socket.
 *
 * Render-only scenarios (AC1-AC8: markup, collapsed-by-default, nested
 * expanders) are covered in test/ui/deviceSections.test.js.
 */

import test from 'node:test';
import assert from 'node:assert';

// Imported before any global `document` stub exists, so app.js does not self-start.
const appModule = await import('../../dist/ui/public/app.js');
const apiModule = await import('../../dist/ui/public/api.js');

// ----------------------------------------------------------------------------
// Stub server: two devices, plus per-device overrides and gates.
// ----------------------------------------------------------------------------

function defaultDevices() {
  return {
    'dev-1': {
      profile: { deviceId: 'dev-1', hostname: 'PC-1', platform: 'other', agentVersion: '1.0' },
      inventory: { software: [{ name: 'App A', version: '1.0' }, { name: 'App B', version: '2.0' }] },
    },
    'dev-2': {
      profile: { deviceId: 'dev-2', hostname: 'PC-2', platform: 'other', agentVersion: '1.0' },
    },
  };
}

const server = {
  devices: defaultDevices(),
  deviceOverride: {}, // {id: {status, body}} forces the GET /devices/{id} response
  rejectAll: false,
  gate: {}, // {id: {promise, resolve}} holds GET /devices/{id} open until released
  requests: [],
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
  if (method === 'GET' && deviceMatch) {
    const id = deviceMatch[1];
    if (server.gate[id]) {
      await server.gate[id].promise;
    }
    if (server.deviceOverride[id]) {
      return json(server.deviceOverride[id].status, server.deviceOverride[id].body);
    }
    const device = server.devices[id];
    return json(device ? 200 : 404, device ?? { error: 'not_found' });
  }
  if (method === 'GET' && url.startsWith('/admin/api/v1/scripts')) {
    return json(200, { items: [] });
  }
  if (method === 'GET' && url.startsWith('/admin/api/v1/applications')) {
    return json(200, { items: [] });
  }
  if (method === 'GET' && url === '/admin/api/v1/groups') {
    return json(200, { items: [] });
  }
  if (method === 'GET' && /\/heartbeats$/.test(url)) {
    return json(200, { items: [] });
  }
  if ((method === 'POST' || method === 'DELETE') && /\/groups\/[^/]+\/members$/.test(url)) {
    return json(200, {});
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

const windowListeners = {};
globalThis.window = {
  location: { hash: '#/devices/dev-1', search: '', origin: 'https://example.invalid' },
  addEventListener: (type, handler) => {
    windowListeners[type] = handler;
  },
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

/** A click whose target matches exactly `selector` through `closest()`, with an optional dataset. */
function click(selector, dataset) {
  const element = dataset ? { dataset } : {};
  const result = { prevented: false };
  listeners.click({
    target: { closest: (sel) => (sel === selector ? element : null) },
    preventDefault: () => {
      result.prevented = true;
    },
  });
  return flush().then(() => result);
}

/**
 * A click whose target's `closest('summary')` returns a stub summary whose
 * `parentElement` matches `details.device-section` (TASK-062's seam: the
 * handler reads `closest('summary').parentElement`, never the real DOM).
 */
function clickSectionSummary(sectionId, open) {
  const sectionDetails = { matches: (sel) => sel === 'details.device-section', dataset: { section: sectionId }, open };
  const result = { prevented: false };
  listeners.click({
    target: { closest: (sel) => (sel === 'summary' ? { parentElement: sectionDetails } : null) },
    preventDefault: () => {
      result.prevented = true;
    },
  });
  return flush().then(() => result);
}

/**
 * A click on a nested summary (command output, or the inner Software list)
 * whose parent is not a `details.device-section`.
 */
function clickNestedSummary() {
  const nestedDetails = { matches: () => false, dataset: {}, open: false };
  const result = { prevented: false };
  listeners.click({
    target: { closest: (sel) => (sel === 'summary' ? { parentElement: nestedDetails } : null) },
    preventDefault: () => {
      result.prevented = true;
    },
  });
  return flush().then(() => result);
}

/** A click on the Analytics history summary (TASK-044's existing handler). */
function clickHeartbeatHistorySummary(deviceId) {
  const result = { prevented: false };
  listeners.click({
    target: { closest: (sel) => (sel === '.heartbeat-history summary' ? { dataset: { deviceId } } : null) },
    preventDefault: () => {
      result.prevented = true;
    },
  });
  return flush().then(() => result);
}

function textField(value) {
  return { type: 'text', value };
}

/** A stub form, matched by class, reading named fields. */
function formWithFields(className, fields) {
  return {
    classList: { contains: (cls) => cls === className },
    elements: { namedItem: (name) => fields[name] ?? null },
  };
}

function submit(form) {
  listeners.submit({ target: form, preventDefault: () => {} });
  return flush();
}

/** The exact tag TASK-062 renders for an open device-section expander. */
function openTag(id) {
  return `<details class="expandable device-section" data-section="${id}" open>`;
}

/** The 17 section ids named in the ticket. */
const ALL_SECTION_IDS = [
  'detail-manage',
  'detail-groups',
  'detail-policies',
  'detail-credential',
  'detail-inventory',
  'detail-software',
  'detail-posture',
  'detail-run-command',
  'detail-queue',
  'detail-commands',
  'detail-antivirus-status',
  'detail-defender-hardening',
  'detail-antivirus-findings',
  'detail-antivirus-scan',
  'detail-location',
  'detail-login-history',
  'detail-analytics',
];

function assertNoneOpen() {
  for (const id of ALL_SECTION_IDS) {
    assert.ok(!mountStub.innerHTML.includes(openTag(id)), `expected "${id}" to not be open`);
  }
}

function assertOnlyOpen(...openIds) {
  for (const id of ALL_SECTION_IDS) {
    if (openIds.includes(id)) {
      assert.ok(mountStub.innerHTML.includes(openTag(id)), `expected "${id}" to be open`);
    } else {
      assert.ok(!mountStub.innerHTML.includes(openTag(id)), `expected "${id}" to not be open`);
    }
  }
}

/**
 * Navigate the stub address bar to a device page as a real hashchange would:
 * clears recorded sections, then reloads. The mount is blanked first so the
 * wait below cannot be satisfied by a stale paint left over from a previous
 * test or a previous device.
 */
async function goToDevice(id) {
  mountStub.innerHTML = '';
  globalThis.window.location.hash = `#/devices/${id}`;
  windowListeners.hashchange();
  await waitUntil(() => mountStub.innerHTML.includes('id="screen-device-detail"') && mountStub.innerHTML.includes('data-device-id="' + id + '"'));
}

function resetServer() {
  server.devices = defaultDevices();
  server.deviceOverride = {};
  server.rejectAll = false;
  server.gate = {};
  server.requests = [];
}

await appModule.start();

// ============================================================================
// Background: the admin is on "#/devices/dev-1" with device "dev-1" loaded.
// ============================================================================

test('Background: the admin lands on the device detail page for dev-1', async () => {
  resetServer();
  await goToDevice('dev-1');
  assert.ok(mountStub.innerHTML.includes('PC-1'));
});

// ============================================================================
// AC9: Clicking a section summary records the toggle without repainting
// ============================================================================

test('Scenario: AC9 Clicking a section summary records the toggle without repainting', async () => {
  resetServer();
  // Given the device page is shown and all sections are collapsed
  await goToDevice('dev-1');
  assertNoneOpen();
  const before = mountStub.innerHTML;
  const requestsBefore = server.requests.length;

  // When the admin clicks the summary of the "detail-groups" expander whose open is false
  const result = await clickSectionSummary('detail-groups', false);

  // Then preventDefault is not called
  assert.strictEqual(result.prevented, false);
  // And no request is sent and the mount's innerHTML is unchanged
  assert.strictEqual(server.requests.length, requestsBefore);
  assert.strictEqual(mountStub.innerHTML, before);

  // When the next repaint happens
  appModule.paint('devices', 'dev-1');

  // Then the Groups expander renders with " open"
  assertOnlyOpen('detail-groups');
});

test('Scenario: AC9 Edge: Clicking an open section\'s summary records it closed', async () => {
  resetServer();
  await goToDevice('dev-1');
  // Given "detail-groups" is recorded open
  await clickSectionSummary('detail-groups', false);
  appModule.paint('devices', 'dev-1');
  assertOnlyOpen('detail-groups');

  // When the admin clicks its summary whose open is true
  await clickSectionSummary('detail-groups', true);
  // And the next repaint happens
  appModule.paint('devices', 'dev-1');

  // Then the Groups expander renders without " open"
  assertNoneOpen();
});

// ============================================================================
// AC10: Nested summaries do not touch the section set
// ============================================================================

test('Scenario: AC10 Nested summaries do not touch the section set', async () => {
  resetServer();
  await goToDevice('dev-1');
  // Given "detail-analytics" is recorded open
  await clickSectionSummary('detail-analytics', false);
  appModule.paint('devices', 'dev-1');
  assertOnlyOpen('detail-analytics');

  const requestsBefore = server.requests.length;
  // When the admin clicks the Analytics history summary
  await clickHeartbeatHistorySummary('dev-1');
  await waitUntil(() => server.requests.length > requestsBefore);

  // Then GET /devices/dev-1/heartbeats is sent and the page repaints
  assert.ok(server.requests.some((r) => r.url === '/admin/api/v1/devices/dev-1/heartbeats'));
  // And the Analytics expander is still open and no other section opened
  assertOnlyOpen('detail-analytics');

  // When the admin clicks a command output summary
  const before = mountStub.innerHTML;
  await clickNestedSummary();

  // Then the recorded set is unchanged
  appModule.paint('devices', 'dev-1');
  assertOnlyOpen('detail-analytics');
  assert.strictEqual(mountStub.innerHTML.includes(openTag('detail-analytics')), true);
  void before;
});

test('Scenario: AC10 Edge: Clicking the inner Software list summary does not touch the section set', async () => {
  resetServer();
  await goToDevice('dev-1');
  // Given "detail-software" is recorded open and the device reports 2 software entries
  await clickSectionSummary('detail-software', false);
  appModule.paint('devices', 'dev-1');
  assertOnlyOpen('detail-software');

  const before = mountStub.innerHTML;
  const requestsBefore = server.requests.length;

  // When the admin clicks the inner Software list summary
  const result = await clickNestedSummary();

  // Then preventDefault is not called, no request is sent and the mount's innerHTML is unchanged
  assert.strictEqual(result.prevented, false);
  assert.strictEqual(server.requests.length, requestsBefore);
  assert.strictEqual(mountStub.innerHTML, before);

  // And the recorded set still contains "detail-software" and nothing else
  appModule.paint('devices', 'dev-1');
  assertOnlyOpen('detail-software');
});

// ============================================================================
// AC11: Open sections survive in-page repaints
// ============================================================================

async function openGroupsAndSoftware() {
  await goToDevice('dev-1');
  await clickSectionSummary('detail-groups', false);
  await clickSectionSummary('detail-software', false);
  appModule.paint('devices', 'dev-1');
  assertOnlyOpen('detail-groups', 'detail-software');
}

test('Scenario Outline: AC11 Open sections survive in-page repaints - the admin clicks Refresh and the reload succeeds', async () => {
  resetServer();
  await openGroupsAndSoftware();
  await click('.refresh-device');
  await waitUntil(() => server.requests.some((r) => r.url === '/admin/api/v1/groups'));
  assertOnlyOpen('detail-groups', 'detail-software');
});

test('Scenario Outline: AC11 Open sections survive in-page repaints - the admin clicks Refresh and the reload fails', async () => {
  resetServer();
  await openGroupsAndSoftware();
  server.deviceOverride['dev-1'] = { status: 500, body: {} };
  await click('.refresh-device');
  await waitUntil(() => /class="error"/.test(mountStub.innerHTML));
  assertOnlyOpen('detail-groups', 'detail-software');
});

test('Scenario Outline: AC11 Open sections survive in-page repaints - the admin removes the device from a group', async () => {
  resetServer();
  await openGroupsAndSoftware();
  await click('.remove-device-group', { deviceId: 'dev-1', groupId: 'g-1' });
  await waitUntil(() => mountStub.innerHTML.includes('PC-1'));
  assertOnlyOpen('detail-groups', 'detail-software');
});

test('Scenario Outline: AC11 Open sections survive in-page repaints - the admin submits the add-to-group form', async () => {
  resetServer();
  await openGroupsAndSoftware();
  await submit(formWithFields('add-device-group', { deviceId: textField('dev-1'), groupId: textField('g-1') }));
  assertOnlyOpen('detail-groups', 'detail-software');
});

test('Scenario Outline: AC11 Open sections survive in-page repaints - the admin opens the delete popup', async () => {
  resetServer();
  await openGroupsAndSoftware();
  await click('.open-delete-device');
  assertOnlyOpen('detail-groups', 'detail-software');
  assert.ok(mountStub.innerHTML.includes('id="delete-device-dialog"'));
});

test('Scenario Outline: AC11 Open sections survive in-page repaints - the admin cancels the delete popup', async () => {
  resetServer();
  await openGroupsAndSoftware();
  await click('.open-delete-device');
  await click('.cancel-delete-device');
  assertOnlyOpen('detail-groups', 'detail-software');
  assert.ok(!mountStub.innerHTML.includes('id="delete-device-dialog"'));
});

test('Scenario Outline: AC11 Open sections survive in-page repaints - the admin expands Analytics history', async () => {
  resetServer();
  await openGroupsAndSoftware();
  await clickHeartbeatHistorySummary('dev-1');
  await waitUntil(() => mountStub.innerHTML.includes('class="expandable heartbeat-history" data-device-id="dev-1" open>'));
  assertOnlyOpen('detail-groups', 'detail-software');
});

// ============================================================================
// AC12: Navigating away and back starts collapsed
// ============================================================================

test('Scenario: AC12 Navigating away and back starts collapsed', async () => {
  resetServer();
  await goToDevice('dev-1');
  // Given "detail-groups" is recorded open on "#/devices/dev-1"
  await clickSectionSummary('detail-groups', false);
  appModule.paint('devices', 'dev-1');
  assertOnlyOpen('detail-groups');

  // When the hash changes to "#/devices" and then to "#/devices/dev-1"
  globalThis.window.location.hash = '#/devices';
  windowListeners.hashchange();
  await waitUntil(() => !mountStub.innerHTML.includes('id="screen-device-detail"'));

  globalThis.window.location.hash = '#/devices/dev-1';
  windowListeners.hashchange();
  await waitUntil(() => mountStub.innerHTML.includes('PC-1'));

  // Then no device-section expander renders with " open"
  assertNoneOpen();
});

test('Scenario: AC12 Edge: Moving to another device starts collapsed', async () => {
  resetServer();
  await goToDevice('dev-1');
  // Given "detail-groups" is recorded open on "#/devices/dev-1"
  await clickSectionSummary('detail-groups', false);
  appModule.paint('devices', 'dev-1');
  assertOnlyOpen('detail-groups');

  // When the hash changes to "#/devices/dev-2"
  globalThis.window.location.hash = '#/devices/dev-2';
  windowListeners.hashchange();
  await waitUntil(() => mountStub.innerHTML.includes('PC-2'));

  // Then no device-section expander renders with " open"
  assertNoneOpen();
});

// ============================================================================
// AC13 (failure): A late Refresh result does not reopen sections on another device
// ============================================================================

test('Scenario: AC13 A late Refresh result does not reopen sections on another device', async () => {
  resetServer();
  await goToDevice('dev-1');
  // Given "detail-groups" is recorded open on "#/devices/dev-1"
  await clickSectionSummary('detail-groups', false);
  appModule.paint('devices', 'dev-1');
  assertOnlyOpen('detail-groups');

  // And a Refresh for dev-1 is in flight
  const gate = deferred();
  server.gate['dev-1'] = gate;
  const pending = click('.refresh-device');

  // When the hash changes to "#/devices/dev-2"
  globalThis.window.location.hash = '#/devices/dev-2';
  windowListeners.hashchange();
  await waitUntil(() => mountStub.innerHTML.includes('PC-2'));

  // and then the dev-1 reload completes
  gate.resolve();
  await pending;
  await flush();
  await flush();

  // Then dev-2's page renders no device-section expander with " open"
  assert.ok(mountStub.innerHTML.includes('PC-2'));
  assertNoneOpen();

  server.gate['dev-1'] = null;
});
