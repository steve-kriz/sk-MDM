/**
 * TASK-041 AC17, AC18, AC19: the enrollment tokens screen (list + revoke) and
 * the device credential panel (disable / enable) driven through the real
 * exported `start()` of app.js.
 *
 * `window`, `document` and `fetch` are stubs; no database is touched and
 * nothing opens a socket.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

// Imported before any global `document` stub exists, so app.js does not self-start.
const appModule = await import('../../dist/ui/public/app.js');
const apiModule = await import('../../dist/ui/public/api.js');

const ACTIVE_TOKEN = {
  tokenId: 'tok-active',
  label: 'Office laptops',
  createdBy: 'admin@contoso.com',
  createdAt: '2026-10-01T00:00:00Z',
  maxUses: 5,
  useCount: 1,
  expiresAt: '2026-10-31T00:00:00Z',
  status: 'active',
  deviceIds: ['dev-1'],
  revokedAt: null,
};
const REVOKED_TOKEN = {
  tokenId: 'tok-revoked',
  label: 'Old batch',
  createdBy: 'admin@contoso.com',
  createdAt: '2026-09-01T00:00:00Z',
  maxUses: 1,
  useCount: 0,
  expiresAt: '2026-09-30T00:00:00Z',
  status: 'revoked',
  deviceIds: [],
  revokedAt: '2026-09-15T00:00:00Z',
};

/** What the stub API currently answers, changed scenario by scenario. */
const server = {
  tokens: [ACTIVE_TOKEN, REVOKED_TOKEN],
  device: null,
  revokeResponse: { status: 200, body: {} },
  createResponse: { status: 201, body: {} },
  disableResponse: { status: 200, body: {} },
  enableResponse: { status: 200, body: {} },
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
  const path = String(url).split('?')[0];
  server.requests.push({ method, url: path, body: init.body ? JSON.parse(init.body) : null });

  if (method === 'GET' && path === '/admin/api/v1/enrollment-tokens') {
    return json(200, { items: server.tokens, cursor: null });
  }
  if (method === 'POST' && path === '/admin/api/v1/enrollment-tokens') {
    return json(server.createResponse.status, server.createResponse.body);
  }
  if (method === 'POST' && /^\/admin\/api\/v1\/enrollment-tokens\/[^/]+\/revoke$/.test(path)) {
    return json(server.revokeResponse.status, server.revokeResponse.body);
  }
  if (method === 'POST' && path === '/admin/api/v1/devices/dev-1/disable') {
    return json(server.disableResponse.status, server.disableResponse.body);
  }
  if (method === 'POST' && path === '/admin/api/v1/devices/dev-1/enable') {
    return json(server.enableResponse.status, server.enableResponse.body);
  }
  if (method === 'GET' && path === '/admin/api/v1/devices/dev-1') {
    return json(server.device ? 200 : 404, server.device ?? { error: 'not_found' });
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
  location: { hash: '#/enrollment-tokens', search: '', origin: 'https://example.invalid' },
  addEventListener: () => {},
  history: { replaceState: () => {} },
};
apiModule.setToken('test-access-token');

function flush() {
  return new Promise((resolve) => setImmediate(resolve));
}

async function settle() {
  for (let i = 0; i < 5; i += 1) {
    await flush();
  }
}

/** A click whose target only matches `selector` via closest(). */
async function click(selector, dataset) {
  const element = { dataset };
  const target = { closest: (sel) => (sel === selector ? element : null) };
  listeners.click({ target, preventDefault: () => {} });
  await settle();
}

function errorBanner() {
  const match = /<p class="error">([^<]*)<\/p>/.exec(mountStub.innerHTML);
  return match === null ? null : match[1];
}

/** The `<tr>` for one token id, or null. */
function tokenRow(tokenId) {
  const match = new RegExp(`<tr class="token" data-token-id="${tokenId}">([\\s\\S]*?)</tr>`).exec(mountStub.innerHTML);
  return match === null ? null : match[1];
}

function deviceDetail(credential) {
  return {
    profile: {
      deviceId: 'dev-1',
      hostname: 'PC-1',
      platform: 'windows',
      osVersion: '11',
      lastSeenAt: '2026-10-10T10:00:00Z',
      agentVersion: '1.0',
    },
    inventory: null,
    posture: null,
    commands: [],
    antivirusFindings: [],
    loginHistory: [],
    analytics: null,
    credential,
  };
}

/** The credential panel's HTML, or null. */
function credentialPanel() {
  const match = /<section class="panel" id="detail-credential">([\s\S]*?)<\/section>/.exec(mountStub.innerHTML);
  return match === null ? null : match[1];
}

function fieldValue(html, label) {
  const match = new RegExp(`<span class="label">${label}</span><span class="value">([^<]*)</span>`).exec(html);
  return match === null ? null : match[1];
}

server.requests = [];
await appModule.start();
await settle();

// ============================================================================
// AC17
// ============================================================================

test('AC17 Scenario: #/enrollment-tokens loads the list and renders columns, device links and Revoke buttons', () => {
  // The list was loaded from GET /admin/api/v1/enrollment-tokens
  assert.ok(server.requests.some((r) => r.method === 'GET' && r.url === '/admin/api/v1/enrollment-tokens'));

  const html = mountStub.innerHTML;
  // Columns in order
  const header = /<thead><tr>([\s\S]*?)<\/tr><\/thead>/.exec(html);
  assert.ok(header, 'token table header rendered');
  const columns = [...header[1].matchAll(/<th>([^<]*)<\/th>/g)].map((m) => m[1]).filter((c) => c !== '');
  assert.deepEqual(columns, [
    'tokenId',
    'label',
    'createdBy',
    'createdAt',
    'maxUses',
    'useCount',
    'expiresAt',
    'status',
    'deviceIds',
  ]);

  // Device id renders as a link to its device page
  assert.match(html, /<a href="#\/devices\/dev-1">dev-1<\/a>/);

  // Active row has the Revoke button; revoked row has none
  const active = tokenRow('tok-active');
  const revoked = tokenRow('tok-revoked');
  assert.ok(active && revoked, 'both rows rendered');
  assert.match(active, /<button type="button" class="revoke-token" data-token-id="tok-active">Revoke<\/button>/);
  assert.doesNotMatch(revoked, /revoke-token/);
  assert.equal((html.match(/class="revoke-token"/g) ?? []).length, 1);
});

// ============================================================================
// AC18
// ============================================================================

test('AC18 Scenario: clicking .revoke-token posts the revoke and reloads the list', async () => {
  server.revokeResponse = { status: 200, body: { tokenId: 'tok-active', status: 'revoked', revokedAt: '2026-10-10T12:00:00Z' } };
  server.requests = [];

  await click('.revoke-token', { tokenId: 'tok-active' });

  const postIndex = server.requests.findIndex(
    (r) => r.method === 'POST' && r.url === '/admin/api/v1/enrollment-tokens/tok-active/revoke',
  );
  assert.ok(postIndex >= 0, 'POST revoke sent');
  const reloadIndex = server.requests.findIndex(
    (r, i) => i > postIndex && r.method === 'GET' && r.url === '/admin/api/v1/enrollment-tokens',
  );
  assert.ok(reloadIndex > postIndex, 'list reloaded after the revoke');
  assert.equal(errorBanner(), null);
});

test('AC18 Scenario: a failed revoke shows its error code in the banner', async () => {
  server.revokeResponse = { status: 409, body: { error: 'already_revoked' } };
  server.requests = [];

  await click('.revoke-token', { tokenId: 'tok-active' });

  assert.match(mountStub.innerHTML, /<p class="error">already_revoked<\/p>/);
});

test('AC18 Scenario: after creating a token the reloaded screen shows the one-time token and the list', async () => {
  server.createResponse = {
    status: 201,
    body: { tokenId: 'tok-new', token: 'mdm_et_secretvalue123', expiresAt: '2026-11-01T00:00:00Z', maxUses: 3 },
  };
  server.requests = [];

  const fields = {
    label: { type: 'text', value: 'New' },
    maxUses: { type: 'number', value: '3' },
    expiresAt: { type: 'text', value: '2026-11-01T00:00:00Z' },
  };
  const form = {
    classList: { contains: (cls) => cls === 'create-token' },
    elements: { namedItem: (name) => fields[name] ?? null },
    querySelector: () => null,
    closest: () => null,
  };
  listeners.submit({ target: form, preventDefault: () => {} });
  await settle();

  const postIndex = server.requests.findIndex((r) => r.method === 'POST' && r.url === '/admin/api/v1/enrollment-tokens');
  assert.ok(postIndex >= 0, 'create POST sent');
  assert.ok(
    server.requests.some((r, i) => i > postIndex && r.method === 'GET' && r.url === '/admin/api/v1/enrollment-tokens'),
    'list reloaded after create',
  );
  const html = mountStub.innerHTML;
  assert.match(html, /This token is shown once/);
  assert.match(html, /mdm_et_secretvalue123/);
  assert.ok(tokenRow('tok-active'), 'list still rendered alongside the one-time token');
});

// ============================================================================
// AC19
// ============================================================================

test('AC19 Scenario: a disabled device shows the credential panel with Enable; Enable posts and reloads', async () => {
  server.device = deviceDetail({
    status: 'disabled',
    disabledAt: '2026-10-09T08:00:00Z',
    disabledBy: 'admin@contoso.com',
    enrolledAt: '2026-10-01T00:00:00Z',
    enrollmentToken: null,
  });
  window.location.hash = '#/devices/dev-1';
  await appModule.show();
  await settle();

  const panel = credentialPanel();
  assert.ok(panel, 'section#detail-credential rendered');
  assert.match(panel, /<h3>Device credential<\/h3>/);
  assert.equal(fieldValue(panel, 'Status'), 'Disabled');
  assert.equal(fieldValue(panel, 'Disabled at'), '2026-10-09 08:00:00');
  assert.equal(fieldValue(panel, 'Disabled by'), 'admin@contoso.com');
  assert.equal(fieldValue(panel, 'Enrollment token'), '&mdash;');
  assert.equal(fieldValue(panel, 'Token label'), '&mdash;');
  assert.equal(fieldValue(panel, 'Token status'), '&mdash;');
  assert.match(panel, /<button type="button" class="enable-device" data-device-id="dev-1">/);
  assert.doesNotMatch(panel, /disable-device/);

  server.enableResponse = { status: 200, body: { deviceId: 'dev-1', credential: { status: 'active' } } };
  server.requests = [];
  await click('.enable-device', { deviceId: 'dev-1' });

  const postIndex = server.requests.findIndex((r) => r.method === 'POST' && r.url === '/admin/api/v1/devices/dev-1/enable');
  assert.ok(postIndex >= 0, 'POST enable sent');
  assert.ok(
    server.requests.some((r, i) => i > postIndex && r.method === 'GET' && r.url === '/admin/api/v1/devices/dev-1'),
    'detail reloaded after enable',
  );
  assert.equal(errorBanner(), null);
});

test('AC19 Scenario: a failed enable shows its error code in the banner', async () => {
  server.enableResponse = { status: 409, body: { error: 'not_disabled' } };
  await click('.enable-device', { deviceId: 'dev-1' });
  assert.match(mountStub.innerHTML, /<p class="error">not_disabled<\/p>/);
});

test('AC19 Scenario: an active device shows Active and Disable; Disable posts /disable and reloads', async () => {
  server.device = deviceDetail({
    status: 'active',
    disabledAt: null,
    disabledBy: null,
    enrolledAt: '2026-10-01T00:00:00Z',
    enrollmentToken: { tokenId: 'tok-active', label: 'Office laptops', createdBy: 'admin@contoso.com', status: 'active' },
  });
  await appModule.show();
  await settle();

  const panel = credentialPanel();
  assert.ok(panel);
  assert.equal(fieldValue(panel, 'Status'), 'Active');
  assert.equal(fieldValue(panel, 'Disabled at'), '&mdash;');
  assert.equal(fieldValue(panel, 'Disabled by'), '&mdash;');
  assert.equal(fieldValue(panel, 'Enrollment token'), 'tok-active');
  assert.equal(fieldValue(panel, 'Token label'), 'Office laptops');
  assert.equal(fieldValue(panel, 'Token status'), 'active');
  assert.match(panel, /<button type="button" class="disable-device" data-device-id="dev-1">/);
  assert.doesNotMatch(panel, /enable-device/);

  server.disableResponse = { status: 200, body: { deviceId: 'dev-1', credential: { status: 'disabled' } } };
  server.requests = [];
  await click('.disable-device', { deviceId: 'dev-1' });

  const postIndex = server.requests.findIndex((r) => r.method === 'POST' && r.url === '/admin/api/v1/devices/dev-1/disable');
  assert.ok(postIndex >= 0, 'POST disable sent');
  assert.ok(
    server.requests.some((r, i) => i > postIndex && r.method === 'GET' && r.url === '/admin/api/v1/devices/dev-1'),
    'detail reloaded after disable',
  );
});

test('AC19 Scenario: a failed disable shows its error code in the banner', async () => {
  server.disableResponse = { status: 409, body: { error: 'already_disabled' } };
  await click('.disable-device', { deviceId: 'dev-1' });
  assert.match(mountStub.innerHTML, /<p class="error">already_disabled<\/p>/);
});
