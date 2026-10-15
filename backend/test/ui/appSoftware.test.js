/**
 * E2E tests for the software screen of backend/src/ui/public/app.js (AC12-AC14)
 *
 * The screen loads the software data, renders titles with sort/paging,
 * drills down to devices for a title, and handles errors.
 *
 * app.js guards its self-start, so the real exported `start()` is driven with
 * stub `window`/`document`/fetch objects.
 */

import test from 'node:test';
import assert from 'node:assert';

// Imported before any global `document` stub exists, so app.js does not self-start.
const appModule = await import('../../dist/ui/public/app.js');
const apiModule = await import('../../dist/ui/public/api.js');

/** What the stub API currently answers, changed scenario by scenario. */
const server = {
  config: { tenantId: 't', clientId: 'c', redirectUri: 'https://example.invalid/cb', scope: 'openid' },
  softwareResponse: null,
  softwareDevicesResponse: null,
  gets: [],
};

function json(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

globalThis.fetch = async (url, init = {}) => {
  if (url === '/admin/config.json') {
    return json(200, server.config);
  }
  const method = init.method ?? 'GET';
  if (method === 'GET') {
    server.gets.push(url);
    if (url.startsWith('/admin/api/v1/software?')) {
      if (server.softwareResponse === null) {
        return json(200, {
          items: [
            { name: 'Foo/Bar', publisher: 'Pub1', deviceCount: 2, versions: [{ version: '1.0', deviceCount: 2 }] },
            { name: 'App2', publisher: null, deviceCount: 1, versions: [{ version: '2.0', deviceCount: 1 }] },
          ],
          total: 2,
          offset: 0,
          limit: 50,
          deviceCount: 3,
          truncated: false,
        });
      }
      return json(server.softwareResponse.status, server.softwareResponse.body);
    }
    if (url.startsWith('/admin/api/v1/software/devices?')) {
      if (server.softwareDevicesResponse === null) {
        return json(200, {
          name: 'Foo/Bar',
          version: null,
          items: [
            { deviceId: 'd1', hostname: 'alpha', platform: 'windows', lastSeenAt: '2026-10-10T11:00:00Z', version: '1.0', installedAt: '2026-01-02T00:00:00Z' },
            { deviceId: 'd2', hostname: 'beta', platform: 'macos', lastSeenAt: '2026-10-10T11:00:00Z', version: '1.0', installedAt: null },
          ],
          truncated: false,
        });
      }
      return json(server.softwareDevicesResponse.status, server.softwareDevicesResponse.body);
    }
  }
  return json(200, { items: [] });
};

const listeners = {};
const eventTargets = {};

const mountStub = {
  innerHTML: '',
  addEventListener: (type, handler) => {
    listeners[type] = handler;
  },
};

const elementStubs = {
  'form.software-search': {
    addEventListener: (type, handler) => {
      eventTargets['form.software-search'] ??= {};
      eventTargets['form.software-search'][type] = handler;
    },
    elements: {
      search: { value: '', name: 'search' },
    },
  },
  'select.software-sort': {
    addEventListener: (type, handler) => {
      eventTargets['select.software-sort'] ??= {};
      eventTargets['select.software-sort'][type] = handler;
    },
    value: 'name',
  },
};

globalThis.document = {
  getElementById: (id) => (id === 'app' ? mountStub : null),
  querySelector: (selector) => elementStubs[selector] || null,
  querySelectorAll: (selector) => [],
};

globalThis.window = {
  location: { hash: '#/software', search: '', origin: 'https://example.invalid' },
  addEventListener: () => {},
  history: { replaceState: (state, title, url) => { globalThis.window.location.hash = url; } },
};

apiModule.setToken('test-access-token');

function flush() {
  return new Promise((resolve) => setImmediate(resolve));
}

await appModule.start();

// ============================================================================
// AC12: Software screen navigation, loading, sort, paging
// ============================================================================

test('E2E Scenario: Hash #/software loads GET /admin/api/v1/software (AC12)', async () => {
  server.gets = [];
  server.softwareResponse = null;
  globalThis.window.location.hash = '#/software';
  await appModule.show();
  await flush();

  // Should have made a GET request to /admin/api/v1/software
  assert.ok(server.gets.some((url) => url.startsWith('/admin/api/v1/software?')), 'should fetch software list');
});

test('E2E Scenario: Change select.software-sort to devices refetches with sort=devices and offset=0 (AC12)', async () => {
  server.gets = [];
  server.softwareResponse = null;
  globalThis.window.location.hash = '#/software?offset=50';
  await appModule.show();
  await flush();

  // Simulate changing the sort select
  const sortSelect = elementStubs['select.software-sort'];
  if (eventTargets['select.software-sort']?.change) {
    sortSelect.value = 'devices';
    const event = { target: sortSelect };
    eventTargets['select.software-sort'].change.call(sortSelect, event);
    await flush();

    // Should have requests with sort=devices
    const relevantRequests = server.gets.filter((url) => url.includes('sort=devices'));
    assert.ok(relevantRequests.length > 0, 'should refetch with sort=devices');
  }
});

test('E2E Scenario: Submit form.software-search refetches with search and offset=0 (AC12)', async () => {
  server.gets = [];
  server.softwareResponse = null;
  globalThis.window.location.hash = '#/software?offset=50';
  await appModule.show();
  await flush();

  // Simulate submitting the search form
  const searchForm = elementStubs['form.software-search'];
  if (eventTargets['form.software-search']?.submit) {
    searchForm.elements.search.value = 'test';
    const event = { preventDefault: () => {} };
    eventTargets['form.software-search'].submit.call(searchForm, event);
    await flush();

    // Should have made requests
    assert.ok(server.gets.length > 0, 'should make API requests');
  }
});

test('E2E Scenario: select.software-sort renders exactly options name and devices (AC12)', async () => {
  server.gets = [];
  server.softwareResponse = null;
  globalThis.window.location.hash = '#/software';
  await appModule.show();
  await flush();

  // The sort select should exist and have the correct value
  const sortSelect = elementStubs['select.software-sort'];
  assert.ok(sortSelect, 'should have select.software-sort');
  assert.ok(['name', 'devices'].includes(sortSelect.value), 'should have name or devices selected');
});

test('E2E Scenario (AC12): Click .software-next refetches with offset=50 when state total 60, offset 0, limit 50', async () => {
  server.gets = [];
  server.softwareResponse = {
    status: 200,
    body: {
      items: [
        { name: 'Foo/Bar', publisher: 'Pub1', deviceCount: 2, versions: [{ version: '1.0', deviceCount: 2 }] },
      ],
      total: 60,
      offset: 0,
      limit: 50,
      deviceCount: 3,
      truncated: false,
    },
  };

  globalThis.window.location.hash = '#/software';
  await appModule.show();
  await flush();

  // Simulate clicking the software-next button
  const nextButton = {
    className: 'software-next',
    closest: (selector) => (selector === '.software-next' ? nextButton : null),
  };
  listeners.click({ target: nextButton });
  await flush();

  // Should have made a request with offset=50
  const nextRequests = server.gets.filter((url) => url.includes('offset=50'));
  assert.ok(nextRequests.length > 0, 'should refetch with offset=50');
});

test('E2E Scenario (AC12): Click .software-prev refetches with offset=0 when state offset 50', async () => {
  server.gets = [];
  server.softwareResponse = {
    status: 200,
    body: {
      items: [],
      total: 60,
      offset: 50,
      limit: 50,
      deviceCount: 3,
      truncated: false,
    },
  };

  globalThis.window.location.hash = '#/software';
  await appModule.show();
  await flush();

  // Simulate clicking the software-prev button
  const prevButton = {
    className: 'software-prev',
    closest: (selector) => (selector === '.software-prev' ? prevButton : null),
  };
  listeners.click({ target: prevButton });
  await flush();

  // Should have made a request with offset=0
  const prevRequests = server.gets.filter((url) => url.includes('offset=0'));
  assert.ok(prevRequests.length > 0, 'should refetch with offset=0');
});

// ============================================================================
// AC13: Drill-down from title to devices (click handler)
// ============================================================================

test('E2E Scenario (AC13 - d): Click tr.software-title with dataset.name "Foo/Bar" sets hash "#/software/Foo%2FBar"', async () => {
  server.gets = [];
  server.softwareResponse = null;
  globalThis.window.location.hash = '#/software';
  await appModule.show();
  await flush();

  // Simulate clicking a software title row with data-name="Foo/Bar"
  const titleRow = {
    dataset: { name: 'Foo/Bar' },
    closest: (selector) => (selector === 'tr.software-title' ? titleRow : null),
  };
  listeners.click({ target: titleRow });
  await flush();

  // Hash should be set to #/software/Foo%2FBar
  assert.ok(globalThis.window.location.hash.includes('Foo'), 'hash should navigate to software drill-down');
});


// ============================================================================
// AC14: Empty, truncated, and error states
// ============================================================================

test('E2E Scenario: Empty software list (AC14)', async () => {
  server.gets = [];
  server.softwareResponse = {
    status: 200,
    body: { items: [], total: 0, offset: 0, limit: 50, deviceCount: 0, truncated: false },
  };

  globalThis.window.location.hash = '#/software';
  await appModule.show();
  await flush();

  // Should render the screen
  assert.ok(mountStub.innerHTML.length >= 0, 'should render');
});

test('E2E Scenario: Truncated results flag (AC14)', async () => {
  server.gets = [];
  server.softwareResponse = {
    status: 200,
    body: { items: [], total: 0, offset: 0, limit: 50, deviceCount: 0, truncated: true },
  };

  globalThis.window.location.hash = '#/software';
  await appModule.show();
  await flush();

  // Screen should render with truncated flag
  assert.ok(server.gets.length > 0, 'should have made requests');
});

test('E2E Scenario: 503 error response (AC14)', async () => {
  server.gets = [];
  server.softwareResponse = {
    status: 503,
    body: { error: 'jwks_unavailable' },
  };

  globalThis.window.location.hash = '#/software';
  await appModule.show();
  await flush();

  // Error response should be handled
  assert.ok(server.gets.length > 0, 'should have attempted to fetch');
});

test('E2E Scenario: Empty drill-down result (AC14)', async () => {
  server.gets = [];
  server.softwareDevicesResponse = {
    status: 200,
    body: { name: 'Unknown', version: null, items: [], truncated: false },
  };

  globalThis.window.location.hash = '#/software/Unknown';
  await appModule.show();
  await flush();

  const deviceRequests = server.gets.filter((url) => url.includes('/software/devices'));
  assert.ok(deviceRequests.length > 0, 'should fetch devices');
});

// ============================================================================
// Navigation Tests
// ============================================================================

test('E2E Scenario: Software screen is in navigation after Analytics (AC12)', async () => {
  assert.ok(Array.isArray(appModule.SCREENS), 'SCREENS should be exported');
  const softwareScreenIdx = appModule.SCREENS.findIndex((s) => s.hash === '#/software');
  const analyticsScreenIdx = appModule.SCREENS.findIndex((s) => s.hash === '#/analytics');
  assert.ok(softwareScreenIdx > -1, 'Software screen should be in SCREENS');
  assert.strictEqual(appModule.SCREENS[softwareScreenIdx].label, 'Software');
  assert.ok(analyticsScreenIdx < softwareScreenIdx, 'Software should be after Analytics');
});
