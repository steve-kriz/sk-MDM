/**
 * E2E tests for TASK-044's heartbeat wiring in backend/src/ui/public/app.js:
 * the toggle/save buttons posting the setting, and the "Analytics history"
 * expander's summary click.
 *
 * app.js guards its self-start, so the real exported click handler is driven
 * with stub DOM click events and a stubbed `fetch`. No real network or
 * database connection is ever made.
 */

import test from 'node:test';
import assert from 'node:assert';

// Imported before any global `document` stub exists, so app.js does not self-start.
const appModule = await import('../../dist/ui/public/app.js');
const apiModule = await import('../../dist/ui/public/api.js');

const server = {
  gets: [],
  posts: [],
  heartbeatPostResponse: { status: 200, body: {} },
  heartbeatsGetResponse: { status: 200, body: { deviceId: 'd1', items: [] } },
};

function json(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

globalThis.fetch = async (url, init = {}) => {
  if (url === '/admin/config.json') {
    return json(200, { tenantId: 't', clientId: 'c', redirectUri: 'https://example.invalid/cb', scope: 'openid' });
  }
  const method = init.method ?? 'GET';
  if (method === 'POST' && url === '/admin/api/v1/devices/d1/heartbeat') {
    server.posts.push({ url, body: JSON.parse(init.body) });
    return json(server.heartbeatPostResponse.status, server.heartbeatPostResponse.body);
  }
  if (method === 'GET' && url === '/admin/api/v1/devices/d1/heartbeats') {
    server.gets.push(url);
    return json(server.heartbeatsGetResponse.status, server.heartbeatsGetResponse.body);
  }
  if (method === 'GET' && url.startsWith('/admin/api/v1/devices/d1')) {
    server.gets.push(url);
    return json(200, { profile: { deviceId: 'd1', hostname: 'PC-1' } });
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
  location: { hash: '#/devices/d1', search: '', origin: 'https://example.invalid' },
  addEventListener: () => {},
  history: { replaceState: () => {} },
};
apiModule.setToken('test-access-token');

function flush() {
  return new Promise((resolve) => setImmediate(resolve));
}

await appModule.start();

/** A stub `<form class="heartbeat-form">` holding deviceId/intervalSeconds. */
function heartbeatForm(deviceId, intervalSeconds) {
  const fields = {
    deviceId: { type: 'hidden', value: deviceId },
    intervalSeconds: { type: 'select-one', value: intervalSeconds },
  };
  return { elements: { namedItem: (name) => fields[name] ?? null } };
}

/** A click target whose `.closest('.heartbeat-toggle')` resolves to itself. */
function toggleClickTarget(dataEnabled, form) {
  const target = {
    dataset: { enabled: dataEnabled },
    closest: (selector) => {
      if (selector === '.heartbeat-toggle') return target;
      if (selector === 'form') return form;
      return null;
    },
  };
  return { target };
}

/** A click target whose `.closest('.heartbeat-save')` resolves to itself. */
function saveClickTarget(form) {
  const target = {
    closest: (selector) => {
      if (selector === '.heartbeat-toggle') return null;
      if (selector === '.heartbeat-save') return target;
      if (selector === 'form') return form;
      return null;
    },
  };
  return { target };
}

/** A click target for `.heartbeat-history summary`. */
function historySummaryClickTarget(deviceId) {
  const summary = { dataset: { deviceId } };
  const target = {
    closest: (selector) => {
      if (selector === '.heartbeat-history summary') return summary;
      if (selector === '.heartbeat-history') return summary;
      return null;
    },
  };
  return { target, preventDefaultCalled: false };
}

await appModule.show();

// ============================================================================
// Scenario Outline: Heartbeat buttons post the setting and reload (AC31)
// ============================================================================

test('Scenario Outline: Clicking .heartbeat-toggle with data-enabled true posts enabled:true and reloads', async () => {
  server.posts = [];
  server.gets = [];
  server.heartbeatPostResponse = { status: 200, body: {} };
  const form = heartbeatForm('d1', '900');
  const event = toggleClickTarget('true', form);

  await listeners.click(event);
  await flush();

  assert.strictEqual(server.posts.length, 1);
  assert.strictEqual(server.posts[0].url, '/admin/api/v1/devices/d1/heartbeat');
  assert.deepStrictEqual(server.posts[0].body, { enabled: true, intervalSeconds: 900 });
  assert.ok(server.gets.some((url) => url === '/admin/api/v1/devices/d1'), 'reloads the device after 2xx');
});

test('Scenario Outline: Clicking .heartbeat-toggle with data-enabled false posts enabled:false', async () => {
  server.posts = [];
  const form = heartbeatForm('d1', '900');
  const event = toggleClickTarget('false', form);

  await listeners.click(event);
  await flush();

  assert.strictEqual(server.posts.length, 1);
  assert.deepStrictEqual(server.posts[0].body, { enabled: false, intervalSeconds: 900 });
});

test('Scenario Outline: Clicking .heartbeat-save always posts enabled:true', async () => {
  server.posts = [];
  const form = heartbeatForm('d1', '900');
  const event = saveClickTarget(form);

  await listeners.click(event);
  await flush();

  assert.strictEqual(server.posts.length, 1);
  assert.deepStrictEqual(server.posts[0].body, { enabled: true, intervalSeconds: 900 });
});

// ============================================================================
// Scenario: Heartbeat setting failure shows the error banner (AC31)
// ============================================================================

test('Scenario: Heartbeat setting failure shows the error banner', async () => {
  server.heartbeatPostResponse = { status: 404, body: { error: 'not_found' } };
  const form = heartbeatForm('d1', '900');
  const event = toggleClickTarget('true', form);

  await listeners.click(event);
  await flush();

  assert.ok(mountStub.innerHTML.includes('<p class="error">not_found</p>'));
  server.heartbeatPostResponse = { status: 200, body: {} };
});

// ============================================================================
// Scenario Outline: Expanding and collapsing the analytics history (AC32)
// ============================================================================

test('Scenario Outline: Clicking a closed history summary fetches and opens it', async () => {
  server.gets = [];
  server.heartbeatsGetResponse = {
    status: 200,
    body: { deviceId: 'd1', items: [{ receivedAt: '2026-10-11T12:00:00Z', collectedAt: '2026-10-11T11:59:58Z' }] },
  };

  const { target } = historySummaryClickTarget('d1');
  let prevented = false;
  const event = { target, preventDefault: () => { prevented = true; } };

  await listeners.click(event);
  await flush();

  assert.strictEqual(prevented, true, 'event.preventDefault was called');
  assert.ok(server.gets.includes('/admin/api/v1/devices/d1/heartbeats'));
  assert.match(mountStub.innerHTML, /<tr class="heartbeat">/);
  assert.ok(mountStub.innerHTML.includes('open'), 'the history renders open');
});

test('Scenario Outline: A 503 on the history fetch opens it with the error', async () => {
  server.heartbeatsGetResponse = { status: 503, body: { error: 'heartbeat_store_unavailable' } };
  // Force the history closed first.
  const { target: closeTarget } = historySummaryClickTarget('d1');
  await listeners.click({ target: closeTarget, preventDefault: () => {} });
  await flush();

  const { target } = historySummaryClickTarget('d1');
  await listeners.click({ target, preventDefault: () => {} });
  await flush();

  assert.ok(mountStub.innerHTML.includes('<p class="error">heartbeat_store_unavailable</p>'));
  server.heartbeatsGetResponse = { status: 200, body: { deviceId: 'd1', items: [] } };
});

function historyIsOpen() {
  const match = /<details class="expandable heartbeat-history"[^>]*>/.exec(mountStub.innerHTML);
  return match !== null && match[0].includes('open');
}

test('Scenario Outline: Clicking an already-open history summary issues no request and closes it', async () => {
  server.heartbeatsGetResponse = { status: 200, body: { deviceId: 'd1', items: [] } };

  // Drive the history to a known open state, however the previous scenario left it.
  if (!historyIsOpen()) {
    const { target: openTarget } = historySummaryClickTarget('d1');
    await listeners.click({ target: openTarget, preventDefault: () => {} });
    await flush();
  }
  assert.ok(historyIsOpen());

  server.gets = [];
  const { target } = historySummaryClickTarget('d1');
  await listeners.click({ target, preventDefault: () => {} });
  await flush();

  assert.strictEqual(server.gets.includes('/admin/api/v1/devices/d1/heartbeats'), false, 'no request was issued');
  // The expander is now closed: no `open` attribute on the heartbeat-history element.
  const detailsMatch = /<details class="expandable heartbeat-history"[^>]*>/.exec(mountStub.innerHTML);
  assert.ok(detailsMatch);
  assert.ok(!detailsMatch[0].includes('open'));
});
