/**
 * E2E cucumber-style tests for the Groups screen's device lookup wiring in
 * backend/src/ui/public/app.js (TASK-046, AC23-AC35).
 *
 * app.js guards its self-start, so the real exported `start()` is driven with
 * stub `window`/`document`/form/event objects, following the pattern in
 * test/ui/appDeviceEdit.test.js. `fetch` is stubbed in-process: no database is
 * touched and nothing opens a socket.
 */

import test from 'node:test';
import assert from 'node:assert';

// Imported before any global `document` stub exists, so app.js does not self-start.
const appModule = await import('../../dist/ui/public/app.js');
const apiModule = await import('../../dist/ui/public/api.js');

/** What the stub API currently answers, changed scenario by scenario. */
const server = {
  groupItems: [
    { groupId: 'grp-a', name: 'Sales', createdAt: '2026-01-01T00:00:00Z' },
    { groupId: 'grp-c', name: 'Ops', createdAt: '2026-01-01T00:00:00Z' },
  ],
  devicePages: [{ items: [{ deviceId: 'dev-1', hostname: 'PC-01' }], cursor: null }],
  devicesStatus: 200,
  membershipResponse: { status: 200, body: { added: 1 } },
  removeResponse: { status: 200, body: { removed: 1 } },
  requests: [],
};

function json(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

let devicePageIndex = 0;

globalThis.fetch = async (url, init = {}) => {
  if (url === '/admin/config.json') {
    return json(200, { tenantId: 't', clientId: 'c', redirectUri: 'https://example.invalid/cb', scope: 'openid' });
  }
  const method = init.method ?? 'GET';
  server.requests.push({ method, url, body: init.body ? JSON.parse(init.body) : null });

  if (method === 'GET' && url === '/admin/api/v1/groups') {
    return json(200, { items: server.groupItems, cursor: null });
  }
  if (method === 'GET' && url === '/admin/api/v1/scripts') {
    return json(200, { items: [] });
  }
  if (method === 'GET' && url.startsWith('/admin/api/v1/devices')) {
    if (server.devicesStatus !== 200) {
      return json(server.devicesStatus, { error: 'server_error' });
    }
    const page = server.devicePages[devicePageIndex] ?? { items: [], cursor: null };
    devicePageIndex += 1;
    return json(200, page);
  }
  if (method === 'POST' && /\/admin\/api\/v1\/groups\/[^/]+\/members$/.test(url)) {
    return json(server.membershipResponse.status, server.membershipResponse.body);
  }
  if (method === 'DELETE' && /\/admin\/api\/v1\/groups\/[^/]+\/members$/.test(url)) {
    return json(server.removeResponse.status, server.removeResponse.body);
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
const focusCalls = [];
const memberLookupStub = { focus: () => focusCalls.push(true) };
globalThis.document = {
  getElementById: (id) => {
    if (id === 'app') return mountStub;
    if (id === 'member-lookup') return memberLookupStub;
    return null;
  },
};
globalThis.window = {
  location: { hash: '#/groups', search: '', origin: 'https://example.invalid' },
  addEventListener: () => {},
  history: { replaceState: () => {} },
};
apiModule.setToken('test-access-token');

function flush() {
  return new Promise((resolve) => setImmediate(resolve));
}

/** A lookup `<input class="device-lookup">` Enter keydown event. */
function enterOn(text, chosenGroupId) {
  const form = {
    elements: {
      namedItem: (name) => (name === 'groupId' ? { type: 'select-one', value: chosenGroupId ?? '' } : null),
    },
  };
  const target = {
    value: text,
    classList: { contains: (cls) => cls === 'device-lookup' },
    closest: (sel) => (sel === 'form' ? form : null),
  };
  let defaultPrevented = false;
  listeners.keydown({ key: 'Enter', target, preventDefault: () => (defaultPrevented = true) });
  return { defaultPrevented };
}

/** A non-Enter or non-lookup keydown, to show onKeyDown ignores it. */
function keyOn(key, isLookup) {
  const target = { value: 'x', classList: { contains: (cls) => isLookup && cls === 'device-lookup' } };
  let defaultPrevented = false;
  listeners.keydown({ key, target, preventDefault: () => (defaultPrevented = true) });
  return { defaultPrevented };
}

/** A click whose target only matches `selector` via closest(), carrying `dataset`. */
function click(selector, dataset) {
  const element = { dataset };
  const target = { closest: (sel) => (sel === selector ? element : null) };
  listeners.click({ target, preventDefault: () => {} });
  return flush();
}

/** The `form.add-members` submit, sending the group chosen in `#member-group`. */
function submitAddMembers(chosenGroupId) {
  const form = {
    classList: { contains: (cls) => cls === 'add-members' },
    elements: { namedItem: (name) => (name === 'groupId' ? { type: 'select-one', value: chosenGroupId ?? '' } : null) },
  };
  listeners.submit({ target: form, preventDefault: () => {} });
  return flush();
}

/** The `.remove-members` button click, outside any form (reads state.groups.memberGroupId directly via the form). */
function clickRemoveMembers(chosenGroupId) {
  const form = {
    elements: { namedItem: (name) => (name === 'groupId' ? { type: 'select-one', value: chosenGroupId ?? '' } : null) },
  };
  const element = { closest: (sel) => (sel === 'form' ? form : null) };
  const target = { closest: (sel) => (sel === '.remove-members' ? element : null) };
  listeners.click({ target, preventDefault: () => {} });
  return flush();
}

function pendingIds() {
  const matches = [...mountStub.innerHTML.matchAll(/<li data-device-id="([^"]+)"/g)];
  return matches.map((m) => m[1]);
}

function lookupMessage() {
  const match = /<p class="lookup-message">([^<]*)<\/p>/.exec(mountStub.innerHTML);
  return match === null ? null : match[1];
}

function lookupValue() {
  const match = /<input id="member-lookup"[^>]*value="([^"]*)"/.exec(mountStub.innerHTML);
  return match === null ? null : match[1];
}

await appModule.start();

async function loadGroupsScreen() {
  globalThis.window.location.hash = '#/groups';
  devicePageIndex = 0;
  server.requests = [];
  await appModule.show();
  await flush();
  // `load('groups')` deliberately keeps `state.groups.pending` across a
  // reload (AC35), so a previous scenario's pending list otherwise leaks into
  // the next one. Starting clean here, through the same x a user would click,
  // keeps each scenario independent without reaching into app.js internals.
  for (const id of pendingIds()) {
    await click('.remove-pending', { deviceId: id });
  }
}

/** Every POST/DELETE sent to a group's membership route. */
function membershipCalls() {
  return server.requests.filter((r) => /\/admin\/api\/v1\/groups\/[^/]+\/members$/.test(r.url));
}

// ============================================================================
// AC23
// ============================================================================

test('AC23: Scenario: The Groups screen loads every device for the lookup', async () => {
  server.devicesStatus = 200;
  server.devicePages = [
    { items: [{ deviceId: 'dev-1', hostname: 'PC-01' }], cursor: 'c1' },
    { items: [{ deviceId: 'dev-2', hostname: 'PC-02' }], cursor: null },
  ];
  await loadGroupsScreen();

  const deviceRequests = server.requests.filter((r) => r.method === 'GET' && r.url.startsWith('/admin/api/v1/devices'));
  assert.strictEqual(deviceRequests.length, 2);
  assert.ok(deviceRequests[0].url.includes('limit=200'));
  assert.ok(!deviceRequests[0].url.includes('cursor='), 'the first page should not carry a cursor');
  assert.ok(deviceRequests[1].url.includes('cursor=c1'));

  const formHtml = mountStub.innerHTML.slice(mountStub.innerHTML.indexOf('form class="add-members"'));
  assert.match(formHtml, /<input id="member-lookup" class="device-lookup"[^>]*list="member-device-options"/);
  assert.ok(!formHtml.slice(0, formHtml.indexOf('</form>')).includes('<textarea'));
  const datalist = mountStub.innerHTML.slice(mountStub.innerHTML.indexOf('<datalist'), mountStub.innerHTML.indexOf('</datalist>'));
  assert.strictEqual((datalist.match(/<option/g) || []).length, 2);
  assert.ok(mountStub.innerHTML.includes('<p class="empty">No devices selected</p>'));
});

// ============================================================================
// AC24
// ============================================================================

test('AC24: Scenario Outline: Enter adds the one matching device to the list', async () => {
  for (const text of ['PC-01', 'pc-01', ' PC-01', 'dev-1']) {
    server.devicesStatus = 200;
    server.devicePages = [{ items: [{ deviceId: 'dev-1', hostname: 'PC-01' }, { deviceId: 'dev-2', hostname: 'PC-02' }], cursor: null }];
    await loadGroupsScreen();

    focusCalls.length = 0;
    server.requests = [];
    const { defaultPrevented } = enterOn(text);

    assert.deepStrictEqual(pendingIds(), ['dev-1'], `text ${text} should add dev-1`);
    assert.strictEqual(lookupValue(), '', 'the lookup textbox should be empty');
    assert.strictEqual(defaultPrevented, true, 'Enter must preventDefault');
    assert.strictEqual(server.requests.length, 0, 'no request should be sent');
    assert.ok(focusCalls.length > 0, '#member-lookup should be refocused');
  }
});

// ============================================================================
// AC25
// ============================================================================

test('AC25: Scenario: Enter with no matching device', async () => {
  server.devicesStatus = 200;
  server.devicePages = [{ items: [{ deviceId: 'dev-1', hostname: 'PC-01' }], cursor: null }];
  await loadGroupsScreen();

  enterOn('PC-99');

  assert.deepStrictEqual(pendingIds(), []);
  assert.strictEqual(lookupValue(), 'PC-99');
  assert.strictEqual(lookupMessage(), 'No device matches &quot;PC-99&quot;');
});

// ============================================================================
// AC26
// ============================================================================

test('AC26: Scenario: Enter with a hostname shared by several devices', async () => {
  server.devicesStatus = 200;
  server.devicePages = [
    { items: [{ deviceId: 'dev-1', hostname: 'PC-01' }, { deviceId: 'dev-7', hostname: 'PC-01' }], cursor: null },
  ];
  await loadGroupsScreen();

  enterOn('PC-01');
  assert.deepStrictEqual(pendingIds(), []);
  assert.strictEqual(lookupValue(), 'PC-01');
  assert.strictEqual(lookupMessage(), '&quot;PC-01&quot; matches 2 devices; enter the device id');

  enterOn('dev-7');
  assert.deepStrictEqual(pendingIds(), ['dev-7']);
});

// ============================================================================
// AC27
// ============================================================================

test('AC27: Scenario: Enter for a device already in the list', async () => {
  server.devicesStatus = 200;
  server.devicePages = [{ items: [{ deviceId: 'dev-1', hostname: 'PC-01' }], cursor: null }];
  await loadGroupsScreen();

  enterOn('PC-01');
  assert.deepStrictEqual(pendingIds(), ['dev-1']);

  enterOn('PC-01');
  assert.deepStrictEqual(pendingIds(), ['dev-1']);
  assert.strictEqual(lookupValue(), '');
  assert.strictEqual(lookupMessage(), 'PC-01 (dev-1) is already in the list');
});

// ============================================================================
// AC28
// ============================================================================

test('AC28: Scenario: Enter with an empty lookup does nothing', async () => {
  server.devicesStatus = 200;
  server.devicePages = [{ items: [{ deviceId: 'dev-1', hostname: 'PC-01' }], cursor: null }];
  await loadGroupsScreen();
  enterOn('PC-01');
  assert.deepStrictEqual(pendingIds(), ['dev-1']);

  enterOn('   ');
  assert.deepStrictEqual(pendingIds(), ['dev-1']);
  assert.ok(!mountStub.innerHTML.includes('lookup-message'));
});

test('Edge: a non-Enter key, or Enter outside the lookup, does nothing', async () => {
  server.devicesStatus = 200;
  server.devicePages = [{ items: [{ deviceId: 'dev-1', hostname: 'PC-01' }], cursor: null }];
  await loadGroupsScreen();

  const notEnter = keyOn('a', true);
  assert.strictEqual(notEnter.defaultPrevented, false);

  const enterElsewhere = keyOn('Enter', false);
  assert.strictEqual(enterElsewhere.defaultPrevented, false);
  assert.deepStrictEqual(pendingIds(), []);
});

// ============================================================================
// AC29
// ============================================================================

test('AC29: Scenario: The x button removes one device from the list', async () => {
  server.devicesStatus = 200;
  server.devicePages = [{ items: [{ deviceId: 'dev-1', hostname: 'PC-01' }, { deviceId: 'dev-2', hostname: 'PC-02' }], cursor: null }];
  await loadGroupsScreen();
  enterOn('PC-01');
  enterOn('PC-02');
  assert.deepStrictEqual(pendingIds(), ['dev-1', 'dev-2']);

  server.requests = [];
  await click('.remove-pending', { deviceId: 'dev-1' });

  assert.deepStrictEqual(pendingIds(), ['dev-2']);
  assert.strictEqual(server.requests.length, 0, 'no request should be sent');
});

// ============================================================================
// AC30 / AC31 / AC32 / AC33
// ============================================================================

test('AC30: Scenario: Add to group sends the listed devices', async () => {
  server.devicesStatus = 200;
  server.devicePages = [{ items: [{ deviceId: 'dev-1', hostname: 'PC-01' }, { deviceId: 'dev-2', hostname: 'PC-02' }], cursor: null }];
  await loadGroupsScreen();
  enterOn('PC-01');
  enterOn('PC-02');

  server.membershipResponse = { status: 200, body: { added: 1 } };
  server.requests = [];
  await submitAddMembers('grp-a');

  const postRequest = server.requests.find((r) => r.method === 'POST' && r.url === '/admin/api/v1/groups/grp-a/members');
  assert.ok(postRequest);
  assert.deepStrictEqual(postRequest.body, { deviceIds: ['dev-1', 'dev-2'] });
  assert.deepStrictEqual(pendingIds(), []);
  assert.ok(mountStub.innerHTML.includes('<p class="added" data-added="1">1 device added</p>'));
});

test('AC31: Scenario: Remove from group sends the listed devices', async () => {
  server.devicesStatus = 200;
  server.devicePages = [{ items: [{ deviceId: 'dev-1', hostname: 'PC-01' }, { deviceId: 'dev-2', hostname: 'PC-02' }], cursor: null }];
  await loadGroupsScreen();
  enterOn('PC-01');
  enterOn('PC-02');

  server.removeResponse = { status: 200, body: { removed: 2 } };
  server.requests = [];
  await clickRemoveMembers('grp-a');

  const deleteRequest = server.requests.find((r) => r.method === 'DELETE' && r.url === '/admin/api/v1/groups/grp-a/members');
  assert.ok(deleteRequest);
  assert.deepStrictEqual(deleteRequest.body, { deviceIds: ['dev-1', 'dev-2'] });
  assert.deepStrictEqual(pendingIds(), []);
  assert.ok(mountStub.innerHTML.includes('<p class="removed" data-removed="2">2 devices removed</p>'));
});

test('AC32: Scenario Outline: Nothing is sent without a group or without devices', async () => {
  server.devicesStatus = 200;
  server.devicePages = [{ items: [{ deviceId: 'dev-1', hostname: 'PC-01' }], cursor: null }];

  // no group chosen, pending has dev-1 -> Add to group
  await loadGroupsScreen();
  enterOn('PC-01');
  server.requests = [];
  await submitAddMembers('');
  assert.strictEqual(membershipCalls().length, 0, 'no membership request should be sent');
  assert.deepStrictEqual(pendingIds(), ['dev-1']);

  // group chosen, empty pending -> Add to group
  devicePageIndex = 0;
  await loadGroupsScreen();
  server.requests = [];
  await submitAddMembers('grp-a');
  assert.strictEqual(membershipCalls().length, 0, 'no membership request should be sent');
  assert.deepStrictEqual(pendingIds(), []);

  // no group chosen, pending has dev-1 -> Remove from group
  devicePageIndex = 0;
  await loadGroupsScreen();
  enterOn('PC-01');
  server.requests = [];
  await clickRemoveMembers('');
  assert.strictEqual(membershipCalls().length, 0, 'no membership request should be sent');
  assert.deepStrictEqual(pendingIds(), ['dev-1']);

  // group chosen, empty pending -> Remove from group
  devicePageIndex = 0;
  await loadGroupsScreen();
  server.requests = [];
  await clickRemoveMembers('grp-a');
  assert.strictEqual(membershipCalls().length, 0, 'no membership request should be sent');
  assert.deepStrictEqual(pendingIds(), []);
});

test('AC33: Scenario: A refused membership request keeps the list', async () => {
  server.devicesStatus = 200;
  server.devicePages = [{ items: [{ deviceId: 'dev-1', hostname: 'PC-01' }, { deviceId: 'dev-2', hostname: 'PC-02' }], cursor: null }];
  await loadGroupsScreen();
  enterOn('PC-01');
  enterOn('PC-02');

  server.membershipResponse = { status: 404, body: { error: 'not_found' } };
  server.requests = [];
  await submitAddMembers('grp-a');

  assert.ok(mountStub.innerHTML.includes('<p class="error">not_found</p>'));
  assert.deepStrictEqual(pendingIds(), ['dev-1', 'dev-2']);
});

// ============================================================================
// AC34
// ============================================================================

test('AC34: Scenario: A failed device list read leaves the Groups screen usable', async () => {
  server.devicesStatus = 500;
  await loadGroupsScreen();

  assert.ok(mountStub.innerHTML.includes('form class="add-members"'));
  assert.ok(mountStub.innerHTML.includes('Sales'), 'the group list should still render');

  enterOn('PC-01');
  assert.strictEqual(lookupMessage(), 'No device matches &quot;PC-01&quot;');

  server.devicesStatus = 200;
});

// ============================================================================
// AC35
// ============================================================================

test('AC35: Scenario: Changing the group keeps the list and the lookup text', async () => {
  server.devicesStatus = 200;
  server.devicePages = [{ items: [{ deviceId: 'dev-1', hostname: 'PC-01' }], cursor: null }];
  await loadGroupsScreen();
  enterOn('PC-01');
  assert.deepStrictEqual(pendingIds(), ['dev-1']);

  // Type a lookup fragment that matches nothing (kept as-is after the Enter).
  enterOn('PC-0');
  assert.strictEqual(lookupValue(), 'PC-0');
  assert.deepStrictEqual(pendingIds(), ['dev-1']);

  // Changing the group select is handled by onInput, keeping pending and lookup.
  const select = { id: 'member-group', value: 'grp-c' };
  listeners.input({ target: select });
  await flush();

  assert.deepStrictEqual(pendingIds(), ['dev-1']);
  assert.strictEqual(lookupValue(), 'PC-0');
});
