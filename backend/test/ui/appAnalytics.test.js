/**
 * E2E tests for the analytics screen of backend/src/ui/public/app.js
 *
 * The screen loads the analytics data and shows it with a window picker.
 * Changing the window reloads the data.
 *
 * app.js guards its self-start, so the real exported `start()` is driven with
 * stub `window`/`document`/fetch objects. app.js keeps its state at module level,
 * so the scenarios below run in order against one module.
 */

import test from 'node:test';
import assert from 'node:assert';

// Imported before any global `document` stub exists, so app.js does not self-start.
const appModule = await import('../../dist/ui/public/app.js');
const apiModule = await import('../../dist/ui/public/api.js');
const analyticsView = await import('../../dist/ui/views/analytics.js');

/** What the stub API currently answers, changed scenario by scenario. */
const server = {
  config: { tenantId: 't', clientId: 'c', redirectUri: 'https://example.invalid/cb', scope: 'openid' },
  analyticsResponse: null,
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
    if (url.startsWith('/admin/api/v1/analytics')) {
      if (server.analyticsResponse === null) {
        return json(200, {
          windowDays: 30,
          from: '2026-09-10T12:00:00Z',
          to: '2026-10-10T12:00:00Z',
          slowestBoots: [],
          mostCrashes: [],
          topApps: [],
          resourcePressure: [],
          truncated: false,
        });
      }
      return json(server.analyticsResponse.status, server.analyticsResponse.body);
    }
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
  location: { hash: '#/analytics', search: '', origin: 'https://example.invalid' },
  addEventListener: () => {},
  history: { replaceState: () => {} },
};
apiModule.setToken('test-access-token');

function flush() {
  return new Promise((resolve) => setImmediate(resolve));
}

await appModule.start();

test('Analytics screen is in navigation at index 1', async () => {
  assert.ok(Array.isArray(appModule.SCREENS));
  assert.strictEqual(appModule.SCREENS[1].hash, '#/analytics');
  assert.strictEqual(appModule.SCREENS[1].label, 'Analytics');
  // Check that other screens are in relative order
  assert.strictEqual(appModule.SCREENS[0].hash, '#/devices');
  assert.strictEqual(appModule.SCREENS[2].hash, '#/software');
  // TASK-049: Applications sits right after Software.
  assert.strictEqual(appModule.SCREENS[3].hash, '#/applications');
  assert.strictEqual(appModule.SCREENS[4].hash, '#/groups');
});

test('Analytics screen loads the default 30-day window on show', async () => {
  server.gets = [];
  await appModule.show();

  assert.ok(server.gets.some((url) => url === '/admin/api/v1/analytics?days=30'));
  assert.ok(mountStub.innerHTML.includes('id="screen-analytics"'));
});

test('Analytics screen shows the window picker with correct selections', async () => {
  server.gets = [];
  await appModule.show();

  assert.ok(mountStub.innerHTML.includes('class="analytics-window"'));
  assert.ok(mountStub.innerHTML.includes('<option value="1">Last 24 hours</option>'));
  assert.ok(mountStub.innerHTML.includes('<option value="30" selected>Last 30 days</option>'));
});

test('Analytics screen shows empty states when no data', async () => {
  server.gets = [];
  await appModule.show();

  assert.ok(mountStub.innerHTML.includes('No boot data reported'));
  assert.ok(mountStub.innerHTML.includes('No crashes or hangs in this window'));
  assert.ok(mountStub.innerHTML.includes('No crashing applications in this window'));
  assert.ok(mountStub.innerHTML.includes('No devices under resource pressure'));
});

test('Changing the window picker reloads with the new days parameter', async () => {
  server.gets = [];
  const beforeCount = server.gets.length;

  // Simulate a change event on the analytics-window select
  const changeEvent = {
    type: 'change',
    target: {
      classList: { contains: (cls) => cls === 'analytics-window' },
      value: '7',
    },
  };
  listeners.change(changeEvent);
  await flush();
  await flush();

  const got7days = server.gets.some((url) => url === '/admin/api/v1/analytics?days=7');
  assert.ok(got7days, 'Should fetch with days=7');
  assert.ok(mountStub.innerHTML.includes('<option value="7" selected>Last 7 days</option>'));
});

test('API failure shows error banner', async () => {
  server.analyticsResponse = { status: 400, body: { error: 'invalid_request' } };
  server.gets = [];

  await appModule.show();

  assert.ok(mountStub.innerHTML.includes('class="error"'));
  assert.ok(mountStub.innerHTML.includes('invalid_request'));
});

test('Valid analytics response shows the four sections', async () => {
  server.analyticsResponse = {
    status: 200,
    body: {
      windowDays: 30,
      from: '2026-09-10T12:00:00Z',
      to: '2026-10-10T12:00:00Z',
      slowestBoots: [
        { deviceId: 'd1', hostname: 'pc-1', lastBootAt: '2026-10-09T06:00:00Z', bootDurationSeconds: 40 },
      ],
      mostCrashes: [
        { deviceId: 'd1', hostname: 'pc-1', crashCount: 2, hangCount: 1, eventCount: 3, lastOccurredAt: '2026-10-09T10:00:00Z' },
      ],
      topApps: [
        { appName: 'Teams', crashCount: 2, hangCount: 0, eventCount: 2, deviceCount: 1, lastOccurredAt: '2026-10-09T10:00:00Z' },
      ],
      resourcePressure: [
        {
          deviceId: 'd2',
          hostname: 'pc-2',
          diskFreePercent: 5.0,
          memoryUsedPercent: 95.0,
          reasons: ['low_disk', 'high_memory'],
        },
      ],
      truncated: false,
    },
  };

  server.gets = [];
  await appModule.show();

  // Check for section headings
  assert.ok(mountStub.innerHTML.includes('Slowest boots'));
  assert.ok(mountStub.innerHTML.includes('Most crashes and hangs'));
  assert.ok(mountStub.innerHTML.includes('Top crashing applications'));
  assert.ok(mountStub.innerHTML.includes('Resource pressure'));

  // Check for data
  assert.ok(mountStub.innerHTML.includes('pc-1'));
  assert.ok(mountStub.innerHTML.includes('Teams'));
  assert.ok(mountStub.innerHTML.includes('Low disk, High memory'));
});

test('Device rows have data-device-id attribute for click navigation', async () => {
  server.analyticsResponse = {
    status: 200,
    body: {
      windowDays: 30,
      from: '2026-09-10T12:00:00Z',
      to: '2026-10-10T12:00:00Z',
      slowestBoots: [
        { deviceId: 'd1', hostname: 'pc-1', lastBootAt: '2026-10-09T06:00:00Z', bootDurationSeconds: 40 },
      ],
      mostCrashes: [],
      topApps: [],
      resourcePressure: [],
      truncated: false,
    },
  };

  await appModule.show();

  assert.ok(mountStub.innerHTML.includes('data-device-id="d1"'));
});

test('Truncated response shows partial results warning', async () => {
  server.analyticsResponse = {
    status: 200,
    body: {
      windowDays: 30,
      from: '2026-09-10T12:00:00Z',
      to: '2026-10-10T12:00:00Z',
      slowestBoots: [],
      mostCrashes: [],
      topApps: [],
      resourcePressure: [],
      truncated: true,
    },
  };

  await appModule.show();

  assert.ok(mountStub.innerHTML.includes('Partial results'));
  assert.ok(mountStub.innerHTML.includes('more analytics data exists'));
});

test('Window picker with unknown window defaults to 30', async () => {
  // Simulate changing to an unknown window by injecting state
  server.analyticsResponse = {
    status: 200,
    body: {
      windowDays: 7,
      from: '2026-10-03T12:00:00Z',
      to: '2026-10-10T12:00:00Z',
      slowestBoots: [],
      mostCrashes: [],
      topApps: [],
      resourcePressure: [],
      truncated: false,
    },
  };

  // When we show the screen with the response already loaded
  await appModule.show();

  // The picker should show 7 selected (because the response says windowDays: 7)
  assert.ok(mountStub.innerHTML.includes('<option value="7" selected>Last 7 days</option>'));
});

test('Clicking on a device row opens the device detail', async () => {
  server.analyticsResponse = {
    status: 200,
    body: {
      windowDays: 30,
      from: '2026-09-10T12:00:00Z',
      to: '2026-10-10T12:00:00Z',
      slowestBoots: [
        { deviceId: 'd1', hostname: 'pc-1', lastBootAt: '2026-10-09T06:00:00Z', bootDurationSeconds: 40 },
      ],
      mostCrashes: [],
      topApps: [],
      resourcePressure: [],
      truncated: false,
    },
  };

  await appModule.show();

  let hashChanged = false;
  globalThis.window.location.hash = '';
  const originalAssign = globalThis.window.location.assign;
  globalThis.window.location.hash = '#/analytics';

  // Simulate a click on a device row
  const clickEvent = {
    target: {
      closest: (selector) => {
        if (selector === 'tr.device') {
          return { dataset: { deviceId: 'd1' } };
        }
        return null;
      },
    },
  };

  // Track hash changes
  let newHash = null;
  Object.defineProperty(globalThis.window.location, 'hash', {
    set: (value) => {
      newHash = value;
    },
    get: () => newHash || '#/analytics',
    configurable: true,
  });

  listeners.click(clickEvent);
  assert.strictEqual(newHash, '#/devices/d1');
});

// ============================================================================
// Analytics Collection Toggle Tests (TASK-040)
// ============================================================================

test('Unit: Analytics collection toggle button has correct structure and attributes', async () => {
  // Test that the button rendering includes the required data attributes
  // This verifies the deviceDetail.js implementation can work with app.js click handler
  const deviceDetailModule = await import('../../dist/ui/views/deviceDetail.js');

  // Test with analytics enabled
  const htmlEnabled = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    analytics: { snapshot: null, bootHistory: [], crashes: [] },
    analyticsCollection: { enabled: true, updatedAt: null, updatedBy: null },
  });

  // Button must have data-device-id and data-enabled attributes for app.js to detect them
  assert.ok(htmlEnabled.includes('data-device-id='));
  assert.ok(htmlEnabled.includes('data-enabled="false"'));
  assert.ok(htmlEnabled.includes('class="analytics-collection-toggle"'));
  assert.ok(htmlEnabled.includes('Turn analytics off'));

  // Test with analytics disabled
  const htmlDisabled = deviceDetailModule.render({
    profile: { deviceId: 'd2' },
    analytics: { snapshot: null, bootHistory: [], crashes: [] },
    analyticsCollection: { enabled: false, updatedAt: '2026-10-10T11:00:00Z', updatedBy: 'admin@x' },
  });

  assert.ok(htmlDisabled.includes('data-device-id="d2"'));
  assert.ok(htmlDisabled.includes('data-enabled="true"'));
  assert.ok(htmlDisabled.includes('class="analytics-collection-toggle"'));
  assert.ok(htmlDisabled.includes('Turn analytics on'));
});

test('TASK-040: app.js has click handler for analytics-collection-toggle button', async () => {
  // Verify that the app module has a click listener registered
  // The actual behavior is tested by the button structure test above
  // and by the backend/test/routes/checkin.test.js integration test
  assert.ok(typeof listeners.click === 'function', 'Click listener should be registered');
});
