/**
 * E2E tests for the analytics collection toggle on the device detail screen of
 * backend/src/ui/public/app.js (TASK-040: clicking the toggle posts the new
 * state and reloads the detail; a failed post shows the error banner).
 *
 * app.js guards its self-start, so the real exported `start()` is driven with
 * stub `window`/`document` objects. `fetch` is stubbed in-process: no database
 * is touched and nothing opens a socket.
 */

import test from 'node:test';
import assert from 'node:assert';

// Imported before any global `document` stub exists, so app.js does not self-start.
const appModule = await import('../../dist/ui/public/app.js');
const apiModule = await import('../../dist/ui/public/api.js');

/** What the stub API currently answers, changed scenario by scenario. */
const server = {
  toggleResponse: { status: 200, body: {} },
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
  if (method === 'POST' && url === '/admin/api/v1/devices/d1/analytics-collection') {
    return json(server.toggleResponse.status, server.toggleResponse.body);
  }
  if (method === 'GET' && url === '/admin/api/v1/devices/d1') {
    return json(200, { profile: { deviceId: 'd1', hostname: 'PC-1' }, analyticsCollection: { enabled: true, updatedAt: null, updatedBy: null } });
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

/** A click on the toggle button carrying the given data attributes. */
async function clickToggle(enabled) {
  const button = { dataset: { deviceId: 'd1', enabled } };
  listeners.click({
    target: { closest: (selector) => (selector === '.analytics-collection-toggle' ? button : null) },
    preventDefault: () => {},
  });
  await flush();
  await flush();
}

await appModule.start();

for (const enabled of ['false', 'true']) {
  test(`Scenario Outline: Clicking the toggle with data-enabled "${enabled}" posts the new state and reloads`, async () => {
    server.toggleResponse = { status: 200, body: { deviceId: 'd1', analyticsEnabled: enabled === 'true' } };
    server.requests = [];

    await clickToggle(enabled);

    const postIndex = server.requests.findIndex(
      (r) => r.method === 'POST' && r.url === '/admin/api/v1/devices/d1/analytics-collection',
    );
    assert.notStrictEqual(postIndex, -1, 'the toggle POST was sent');
    assert.deepStrictEqual(server.requests[postIndex].body, { enabled: enabled === 'true' });
    const reloaded = server.requests
      .slice(postIndex + 1)
      .some((r) => r.method === 'GET' && r.url === '/admin/api/v1/devices/d1');
    assert.ok(reloaded, 'the device detail was reloaded after the POST');
  });
}

test('Scenario: Toggle failure shows the error banner', async () => {
  server.toggleResponse = { status: 404, body: { error: 'not_found' } };
  server.requests = [];

  await clickToggle('false');

  assert.ok(mountStub.innerHTML.includes('<p class="error">not_found</p>'), 'the error banner shows not_found');
});
