/**
 * E2E tests for TASK-050's console wiring of the Retry action and the
 * sha256-free create form in `backend/src/ui/public/app.js` (AC15).
 *
 * app.js guards its self-start, so the real exported `start()` is driven with
 * stub `window`/`document`/form objects. `fetch` is stubbed in-process: no
 * database is touched and nothing opens a socket.
 */

import test from 'node:test';
import assert from 'node:assert';

const appModule = await import('../../dist/ui/public/app.js');
const apiModule = await import('../../dist/ui/public/api.js');

const server = {
  applications: [
    { applicationId: 'app 2', name: 'Zoom', platform: 'windows', installerType: 'msi', source: 'url', description: null, hashStatus: 'failed', hashError: 'http_404' },
  ],
  retryStatus: 202,
  retryBody: { applicationId: 'app 2', hashStatus: 'pending' },
  createResponse: { status: 201, body: { applicationId: 'app-3', hashStatus: 'pending' } },
  posts: [],
  gets: [],
};

function json(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

globalThis.fetch = async (url, init = {}) => {
  if (url === '/admin/config.json') {
    return json(200, { tenantId: 't', clientId: 'c', redirectUri: 'https://example.invalid/cb', scope: 'openid' });
  }
  const method = init.method ?? 'GET';

  if (method === 'GET') {
    server.gets.push(url);
    if (url.startsWith('/admin/api/v1/applications')) {
      return json(200, { items: server.applications });
    }
    return json(200, { items: [] });
  }

  if (method === 'POST' && url === '/admin/api/v1/applications') {
    server.posts.push({ url, body: JSON.parse(init.body) });
    return json(server.createResponse.status, server.createResponse.body);
  }
  if (method === 'POST' && /\/retry-hash$/.test(url)) {
    server.posts.push({ url, body: init.body ? JSON.parse(init.body) : undefined });
    return json(server.retryStatus, server.retryStatus === 202 ? server.retryBody : { error: server.retryError });
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
  location: { hash: '#/applications', search: '', origin: 'https://example.invalid' },
  addEventListener: () => {},
  history: { replaceState: () => {} },
};
apiModule.setToken('test-access-token');

/**
 * A snapshot of everything a submit/click handler could still be in the
 * middle of changing: request counts and the rendered markup. Comparing two
 * snapshots a few ticks apart is how `flush()` below knows the handler's
 * chained awaits have actually settled, rather than guessing a single
 * `setImmediate` is enough.
 */
function activitySnapshot() {
  return JSON.stringify({
    posts: server.posts.length,
    gets: server.gets.length,
    html: mountStub.innerHTML,
  });
}

/**
 * Wait for the event loop to go quiet after a simulated submit/click: real
 * `setTimeout` ticks (not just one `setImmediate`) so a handler that is still
 * awaiting something gets the time it needs, even under heavy parallel
 * test-file CPU load. Returns as soon as nothing observable has changed for a
 * few consecutive polls, or after a generous bound so a genuinely broken
 * handler still fails the test instead of hanging the suite.
 */
async function flush({ timeoutMs = 2000, stepMs = 5, quietStreak = 3 } = {}) {
  const start = Date.now();
  let previous = activitySnapshot();
  let stable = 0;
  for (;;) {
    await new Promise((resolve) => setTimeout(resolve, stepMs));
    const current = activitySnapshot();
    if (current === previous) {
      stable += 1;
      if (stable >= quietStreak) {
        return;
      }
    } else {
      stable = 0;
      previous = current;
    }
    if (Date.now() - start >= timeoutMs) {
      return;
    }
  }
}

function banner() {
  const match = /<p class="error">([^<]*)<\/p>/.exec(mountStub.innerHTML);
  return match === null ? null : match[1];
}

function textField(value) {
  return { type: 'text', value };
}

function createApplicationForm(fields) {
  return {
    classList: { contains: (cls) => cls === 'create-application' },
    elements: { namedItem: (name) => fields[name] ?? null },
  };
}

async function submit(form) {
  listeners.submit({ target: form, preventDefault: () => {} });
  await flush();
}

async function click(target) {
  listeners.click({ target, preventDefault: () => {} });
  await flush();
}

await appModule.start();

// ============================================================================
// AC15
// ============================================================================

test('Scenario: Retry from the console', async () => {
  // Given the Applications screen lists a failed URL application "app 2"
  window.location.hash = '#/applications';
  await appModule.show();
  assert.match(mountStub.innerHTML, /class="retry-application-hash" data-application-id="app 2"/);
  server.posts.length = 0;
  server.gets.length = 0;

  // When the admin clicks its Retry button and the API answers 202
  await click({ closest: (sel) => (sel === '.retry-application-hash' ? { dataset: { applicationId: 'app 2' } } : null) });

  // Then POST /admin/api/v1/applications/app%202/retry-hash was sent and the list reloaded
  assert.ok(server.posts.some((p) => p.url === '/admin/api/v1/applications/app%202/retry-hash'));
  assert.ok(server.gets.includes('/admin/api/v1/applications'), 'the list should reload');

  // And submitting form.create-application with source "url" sends a body without sha256
  server.posts.length = 0;
  const form = createApplicationForm({
    source: textField('url'),
    name: textField('Teams'),
    description: textField(''),
    url: textField('https://teams.example/x.msi'),
    installerType: textField('msi'),
    installArgs: textField(''),
  });
  await submit(form);
  const createCall = server.posts.find((p) => p.url === '/admin/api/v1/applications');
  assert.ok(createCall);
  assert.equal('sha256' in createCall.body, false);
});

test('Scenario (failure): Retry refused shows the banner', async () => {
  // Given retry-hash answers 409 hash_in_progress
  window.location.hash = '#/applications';
  await appModule.show();
  server.retryStatus = 409;
  server.retryError = 'hash_in_progress';

  // When the admin clicks Retry
  await click({ closest: (sel) => (sel === '.retry-application-hash' ? { dataset: { applicationId: 'app 2' } } : null) });

  // Then the banner shows "hash_in_progress"
  assert.match(banner() ?? '', /hash_in_progress/);
  server.retryStatus = 202;
});
