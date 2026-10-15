/**
 * E2E cucumber-style and unit tests for the signed-in Applications page
 * (TASK-049, AC13): `backend/src/ui/public/applications.js`.
 *
 * `start(deps)` takes every browser object as a parameter, so this file drives
 * it with stand-ins for `fetch`, `storage`, `location`, `history` and
 * `document` -- no real browser, no database, no network.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

const {
  start,
  renderApplications,
  bearerInit,
  outcomeFor,
  downloadPath,
  USER_TOKEN_KEY,
  APPS_STATE_KEY,
  APPS_VERIFIER_KEY,
  EMPTY_MESSAGE,
  FORBIDDEN_MESSAGE,
  LOAD_FAILED_MESSAGE,
  DOWNLOAD_FAILED_MESSAGE,
} = await import('../../dist/ui/public/applications.js');

const CONFIG = { tenantId: 't-1', clientId: 'c-9', redirectUri: 'https://mdm.example.com/applications', scope: 'api://c-9/MDM.User' };

/** An in-memory sessionStorage stand-in that records every key touched. */
function fakeStorage(initial = {}) {
  const data = new Map(Object.entries(initial));
  const keysTouched = new Set();
  return {
    getItem(key) {
      keysTouched.add(key);
      return data.has(key) ? data.get(key) : null;
    },
    setItem(key, value) {
      keysTouched.add(key);
      data.set(key, value);
    },
    removeItem(key) {
      keysTouched.add(key);
      data.delete(key);
    },
    keysTouched,
    data,
  };
}

function fakeLocation(search = '') {
  return { search, assignCalls: [], assign(url) { this.assignCalls.push(url); } };
}

function fakeHistory() {
  return { replaceStateCalls: [], replaceState(...args) { this.replaceStateCalls.push(args); } };
}

function fakeMount() {
  const listeners = {};
  return {
    innerHTML: '',
    addEventListener(type, handler) { listeners[type] = handler; },
    listeners,
  };
}

function fakeDocument(mount) {
  return { getElementById: (id) => (id === 'applications' ? mount : null) };
}

function json(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

/** A scriptable fetch: config always succeeds; everything else answers `answers`. */
function makeFetch({ listStatus = 200, listBody = { items: [] }, calls = [] } = {}) {
  return async (url, init) => {
    calls.push({ url, init });
    if (url === '/applications/config.json') {
      return json(200, CONFIG);
    }
    if (url === '/api/v1/applications') {
      return json(listStatus, listBody);
    }
    return json(200, {});
  };
}

// ============================================================================
// Pure functions
// ============================================================================

test('Scenario (edge): Empty list and pure helpers', () => {
  assert.ok(renderApplications([]).includes('No applications available'));
  assert.strictEqual(EMPTY_MESSAGE, 'No applications available');
  assert.strictEqual(outcomeFor(204), 'ok');
  assert.strictEqual(outcomeFor(401), 'reauthorize');
  assert.strictEqual(outcomeFor(403), 'forbidden');
  assert.strictEqual(outcomeFor(502), 'failed');
});

test('Unit: bearerInit and downloadPath', () => {
  assert.deepStrictEqual(bearerInit('T'), { headers: { accept: 'application/json', authorization: 'Bearer T' } });
  assert.strictEqual(downloadPath('app 1'), '/api/v1/applications/app%201/download');
});

// ============================================================================
// Scenario: Page renders the list and starts a download
// ============================================================================

test("Scenario: Page renders the list and starts a download", async () => {
  const storage = fakeStorage({ [USER_TOKEN_KEY]: 'T' });
  const calls = [];
  const fetchFn = makeFetch({
    listBody: { items: [{ applicationId: 'app 1', name: '<b>7-Zip</b>', description: null, platform: 'windows' }] },
    calls,
  });
  const mount = fakeMount();
  const location = fakeLocation();

  await start({ fetch: fetchFn, storage, location, history: fakeHistory(), document: fakeDocument(mount) });

  // Then the list request carried "authorization: Bearer T"
  const listCall = calls.find((c) => c.url === '/api/v1/applications');
  assert.strictEqual(listCall.init.headers.authorization, 'Bearer T');

  // And the page contains the escaped name, the em dash, the platform label and
  // a button.download-application with data-application-id "app 1"
  assert.ok(mount.innerHTML.includes('&lt;b&gt;7-Zip&lt;/b&gt;'));
  assert.ok(mount.innerHTML.includes('&mdash;'));
  assert.ok(mount.innerHTML.includes('Windows'));
  assert.ok(mount.innerHTML.includes('class="download-application" data-application-id="app 1"'));

  // When the Download button is clicked and the download API answers 200
  const downloadCalls = [];
  const fetchWithDownload = async (url, init) => {
    downloadCalls.push({ url, init });
    if (url === '/api/v1/applications/app%201/download') {
      return json(200, { url: 'https://bucket/presigned' });
    }
    return fetchFn(url, init);
  };
  // Re-run start with the download-aware fetch so the click handler closes
  // over it.
  const mount2 = fakeMount();
  await start({ fetch: fetchWithDownload, storage, location, history: fakeHistory(), document: fakeDocument(mount2) });
  await mount2.listeners.click({
    target: { closest: (sel) => (sel === '.download-application' ? { dataset: { applicationId: 'app 1' } } : null) },
  });

  // Then the request went to /api/v1/applications/app%201/download and
  // location.assign was called with "https://bucket/presigned"
  assert.ok(downloadCalls.some((c) => c.url === '/api/v1/applications/app%201/download'));
  assert.deepStrictEqual(location.assignCalls, ['https://bucket/presigned']);
});

// ============================================================================
// Scenario: No token starts sign-in with the MDM.User scope
// ============================================================================

test('Scenario: No token starts sign-in with the MDM.User scope', async () => {
  const storage = fakeStorage();
  const location = fakeLocation();
  const mount = fakeMount();

  await start({ fetch: makeFetch(), storage, location, history: fakeHistory(), document: fakeDocument(mount) });

  assert.strictEqual(location.assignCalls.length, 1);
  const url = new URL(location.assignCalls[0]);
  assert.strictEqual(url.searchParams.get('scope'), 'api://c-9/MDM.User');
  assert.strictEqual(url.searchParams.get('redirect_uri'), 'https://mdm.example.com/applications');

  // skmdm.accessToken was never read or written
  assert.ok(!storage.keysTouched.has('skmdm.accessToken'));
});

// ============================================================================
// Scenario Outline: Page reacts to API refusals
// ============================================================================

const refusalCases = [
  { status: 401, reaction: 'reauthorize' },
  { status: 403, reaction: 'forbidden' },
  { status: 500, reaction: 'failed' },
];

for (const { status, reaction } of refusalCases) {
  test(`Scenario Outline: Page reacts to API refusals -- ${status}`, async () => {
    const storage = fakeStorage({ [USER_TOKEN_KEY]: 'T' });
    const location = fakeLocation();
    const mount = fakeMount();

    await start({
      fetch: makeFetch({ listStatus: status, listBody: { error: 'x' } }),
      storage,
      location,
      history: fakeHistory(),
      document: fakeDocument(mount),
    });

    if (reaction === 'reauthorize') {
      assert.strictEqual(storage.data.has(USER_TOKEN_KEY), false, 'the token should be cleared');
      assert.strictEqual(location.assignCalls.length, 1);
      assert.ok(location.assignCalls[0].startsWith('https://login.microsoftonline.com/'));
    } else if (reaction === 'forbidden') {
      assert.strictEqual(storage.data.has(USER_TOKEN_KEY), false, 'the token should be cleared');
      assert.ok(mount.innerHTML.includes(FORBIDDEN_MESSAGE));
      assert.strictEqual(location.assignCalls.length, 0, 'no redirect should happen');
    } else {
      assert.ok(mount.innerHTML.includes(LOAD_FAILED_MESSAGE));
    }
  });
}

// ============================================================================
// Scenario (failure): Sign-in error redirect does not loop
// ============================================================================

test('Scenario (failure): Sign-in error redirect does not loop', async () => {
  const storage = fakeStorage({ [APPS_STATE_KEY]: 'state-1', [APPS_VERIFIER_KEY]: 'verifier-1' });
  const location = fakeLocation('?error=access_denied&state=state-1');
  const mount = fakeMount();

  await start({ fetch: makeFetch(), storage, location, history: fakeHistory(), document: fakeDocument(mount) });

  assert.ok(mount.innerHTML.includes('Sign-in failed: access_denied'));
  assert.strictEqual(location.assignCalls.length, 0);
});

// ============================================================================
// Download failure path
// ============================================================================

test('Unit: a download fetch that throws shows "Download could not be started"', async () => {
  const storage = fakeStorage({ [USER_TOKEN_KEY]: 'T' });
  const mount = fakeMount();
  const location = fakeLocation();
  const fetchFn = async (url, init) => {
    if (url === '/applications/config.json') return json(200, CONFIG);
    if (url === '/api/v1/applications') return json(200, { items: [] });
    if (url.startsWith('/api/v1/applications/app-1/download')) throw new Error('network down');
    return json(200, {});
  };

  await start({ fetch: fetchFn, storage, location, history: fakeHistory(), document: fakeDocument(mount) });
  await mount.listeners.click({
    target: { closest: (sel) => (sel === '.download-application' ? { dataset: { applicationId: 'app-1' } } : null) },
  });

  assert.ok(mount.innerHTML.includes(DOWNLOAD_FAILED_MESSAGE));
});
