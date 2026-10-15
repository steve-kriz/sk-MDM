/**
 * E2E tests for TASK-049's console wiring in backend/src/ui/public/app.js:
 *
 *   - AC19: the Applications nav entry, the admin screen list and the
 *     create-application form
 *   - AC21: the upload flow (presigned PUT straight to S3, with no admin bearer)
 *   - AC22: the device page's install-application panel
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
    { applicationId: 'app-1', name: '7-Zip', platform: 'windows', installerType: 'msi', source: 'upload', description: null },
  ],
  deviceProfile: { deviceId: 'dev-1', hostname: 'PC-1', platform: 'windows' },
  uploadUrlResponse: { status: 200, body: { uploadKey: 'applications/aaaa/x.msi', url: 'https://bucket.s3.example/put', expiresInSeconds: 900 } },
  createResponse: { status: 201, body: { applicationId: 'app-2' } },
  deleteStatus: 204,
  installResponse: { status: 202, body: { commandId: 'cmd-1', seq: 1 } },
  patchResponse: { status: 200, body: { applicationId: 'app-1' } },
  patches: [],
  puts: [],
  posts: [],
  deletes: [],
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

  // The raw S3 PUT: an absolute URL, never carrying an admin bearer.
  if (method === 'PUT' && url.startsWith('https://')) {
    server.puts.push({ url, headers: init.headers, body: init.body });
    return json(server.putStatus ?? 200, {});
  }

  if (method === 'GET') {
    server.gets.push(url);
    if (url.startsWith('/admin/api/v1/applications')) {
      const platform = new URL(url, 'http://placeholder.invalid').searchParams.get('platform');
      const items = platform ? server.applications.filter((a) => a.platform === platform) : server.applications;
      return json(200, { items });
    }
    if (url.startsWith('/admin/api/v1/devices/dev-1') && !url.includes('/scripts') && !url.includes('/applications')) {
      return json(200, { profile: server.deviceProfile, commands: [] });
    }
    if (url.startsWith('/admin/api/v1/scripts')) {
      return json(200, { items: [] });
    }
    if (url.startsWith('/admin/api/v1/groups')) {
      return json(200, { items: [] });
    }
    if (url.startsWith('/admin/api/v1/settings/commands')) {
      return json(200, { onFailure: 'continue' });
    }
    return json(200, { items: [] });
  }

  if (method === 'POST' && url === '/admin/api/v1/applications/upload-url') {
    server.posts.push({ url, body: JSON.parse(init.body) });
    return json(server.uploadUrlResponse.status, server.uploadUrlResponse.body);
  }
  if (method === 'POST' && url === '/admin/api/v1/applications') {
    server.posts.push({ url, body: JSON.parse(init.body) });
    return json(server.createResponse.status, server.createResponse.body);
  }
  if (method === 'POST' && url === '/admin/api/v1/devices/dev-1/applications') {
    server.posts.push({ url, body: JSON.parse(init.body) });
    return json(server.installResponse.status, server.installResponse.body);
  }
  if (method === 'PATCH' && url.startsWith('/admin/api/v1/applications/')) {
    server.patches.push({ url, body: JSON.parse(init.body) });
    return json(server.patchResponse.status, server.patchResponse.body);
  }
  if (method === 'DELETE' && url.startsWith('/admin/api/v1/applications/')) {
    server.deletes.push(url);
    return json(server.deleteStatus, server.deleteStatus === 204 ? {} : { error: server.deleteError });
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
 * chained awaits (fetch -> response.json() -> WebCrypto digest -> state
 * update -> render) have actually settled, rather than guessing a single
 * `setImmediate` is enough.
 */
function activitySnapshot() {
  return JSON.stringify({
    posts: server.posts.length,
    puts: server.puts.length,
    deletes: server.deletes.length,
    patches: server.patches.length,
    gets: server.gets.length,
    html: mountStub.innerHTML,
  });
}

/**
 * Wait for the event loop to go quiet after a simulated submit/click: real
 * `setTimeout` ticks (not just one `setImmediate`) so a handler that is still
 * awaiting something -- including real async work like WebCrypto's digest,
 * which can take well over a tick under heavy parallel test-file CPU load --
 * gets the time it needs. Returns as soon as nothing observable has changed
 * for a few consecutive polls, or after a generous bound so a genuinely
 * broken handler still fails the test instead of hanging the suite.
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

function fileField(file) {
  return { type: 'file', files: file ? [file] : [] };
}

/** A stub `<form class="create-application">`. */
function createApplicationForm(fields) {
  return {
    classList: { contains: (cls) => cls === 'create-application' },
    elements: { namedItem: (name) => fields[name] ?? null },
  };
}

function installApplicationForm(fields) {
  return {
    classList: { contains: (cls) => cls === 'install-application' },
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
// AC19: the Applications nav entry and admin screen
// ============================================================================

test('Scenario: Applications admin screen -- nav entry right after Software, rows and form', async () => {
  const labels = appModule.SCREENS.map((s) => s.label);
  const softwareIndex = labels.indexOf('Software');
  const applicationsIndex = labels.indexOf('Applications');
  assert.strictEqual(applicationsIndex, softwareIndex + 1, 'Applications must come right after Software');
  assert.strictEqual(appModule.SCREENS[applicationsIndex].hash, '#/applications');

  window.location.hash = '#/applications';
  server.gets.length = 0;
  await appModule.show();

  assert.ok(server.gets.includes('/admin/api/v1/applications'), 'GET /admin/api/v1/applications');
  assert.match(mountStub.innerHTML, /tr class="application" data-application-id="app-1"/);
  assert.match(mountStub.innerHTML, /class="delete-application" data-application-id="app-1"/);
  // The create form lives in a popup, opened by the Add application button.
  assert.match(mountStub.innerHTML, /class="open-create-application"/);
  assert.doesNotMatch(mountStub.innerHTML, /<form class="create-application">/);
  await click({ closest: (sel) => (sel === '.open-create-application' ? {} : null) });
  assert.match(mountStub.innerHTML, /<form class="create-application">/);
  await click({ closest: (sel) => (sel === '.cancel-application-dialog' ? {} : null) });
  assert.doesNotMatch(mountStub.innerHTML, /<form class="create-application">/);
});

test('Scenario (failure): Delete refused by the API shows the error code in the banner', async () => {
  window.location.hash = '#/applications';
  await appModule.show();
  server.deleteStatus = 404;
  server.deleteError = 'not_found';

  await click({ closest: (sel) => (sel === '.delete-application' ? { dataset: { applicationId: 'app-1' } } : null) });

  assert.match(banner() ?? '', /not_found/);
  server.deleteStatus = 204;
});

// ============================================================================
// AC21: the upload flow (presigned PUT straight to S3)
// ============================================================================

test('Scenario: Upload flow end to end in the console', async () => {
  window.location.hash = '#/applications';
  await appModule.show();
  server.posts.length = 0;
  server.puts.length = 0;

  const file = {
    name: '7z.msi',
    size: 1000,
    arrayBuffer: async () => new TextEncoder().encode('fake-installer-bytes').buffer,
  };
  const form = createApplicationForm({
    source: textField('upload'),
    name: textField('7-Zip'),
    description: textField(''),
    url: textField(''),
    installerType: textField(''),
    sha256: textField(''),
    installArgs: textField(''),
    file: fileField(file),
  });

  await submit(form);

  // fetch was called with U, method PUT, content-type application/octet-stream
  // and no authorization header
  assert.strictEqual(server.puts.length, 1);
  assert.strictEqual(server.puts[0].url, 'https://bucket.s3.example/put');
  assert.strictEqual(server.puts[0].headers['content-type'], 'application/octet-stream');
  assert.strictEqual(server.puts[0].headers.authorization, undefined, 'no authorization header should be sent to S3');

  // POST /admin/api/v1/applications was sent with source "upload", uploadKey K
  // and the file's hex SHA-256
  const registerCall = server.posts.find((p) => p.url === '/admin/api/v1/applications');
  assert.ok(registerCall);
  assert.strictEqual(registerCall.body.source, 'upload');
  assert.strictEqual(registerCall.body.uploadKey, 'applications/aaaa/x.msi');
  assert.match(registerCall.body.sha256, /^[0-9a-f]{64}$/);
});

test('Scenario (failure): S3 upload fails shows upload_failed and sends no register POST', async () => {
  window.location.hash = '#/applications';
  await appModule.show();
  server.posts.length = 0;
  server.puts.length = 0;
  server.putStatus = 403;

  const file = {
    name: '7z.msi',
    size: 1000,
    arrayBuffer: async () => new TextEncoder().encode('fake-installer-bytes').buffer,
  };
  const form = createApplicationForm({
    source: textField('upload'),
    name: textField('7-Zip'),
    description: textField(''),
    url: textField(''),
    installerType: textField(''),
    sha256: textField(''),
    installArgs: textField(''),
    file: fileField(file),
  });

  await submit(form);

  // The failure is shown inside the popup, which stays open, not as the banner.
  assert.strictEqual(banner(), null);
  assert.match(mountStub.innerHTML, /<p class="error application-dialog-error">upload_failed<\/p>/);
  assert.ok(!server.posts.some((p) => p.url === '/admin/api/v1/applications'), 'no register POST should be sent');
  server.putStatus = 200;
});

// ============================================================================
// AC22: the device page's install-application panel
// ============================================================================

test('Scenario: Install from the device page sends the install request and reloads', async () => {
  window.location.hash = '#/devices/dev-1';
  server.gets.length = 0;
  await appModule.show();

  assert.ok(server.gets.some((url) => url.startsWith('/admin/api/v1/applications?platform=windows')));
  assert.match(mountStub.innerHTML, /form class="install-application"/);

  server.posts.length = 0;
  const form = installApplicationForm({ deviceId: textField('dev-1'), applicationId: textField('app-1') });
  await submit(form);

  const installCall = server.posts.find((p) => p.url === '/admin/api/v1/devices/dev-1/applications');
  assert.ok(installCall);
  assert.deepStrictEqual(installCall.body, { applicationId: 'app-1' });
});

// ============================================================================
// Editing an application in the popup
// ============================================================================

function editApplicationForm(fields) {
  return {
    classList: { contains: (cls) => cls === 'edit-application-form' },
    elements: { namedItem: (name) => fields[name] ?? null },
  };
}

/** The open popup's markup, or `null` when it is closed. */
function dialogHtml() {
  const match = /<div class="modal" id="application-dialog"[\s\S]*?<\/form>/.exec(mountStub.innerHTML);
  return match === null ? null : match[0];
}

const editButton = {
  closest: (sel) => (sel === '.edit-application' ? { dataset: { applicationId: 'app-1' } } : null),
  classList: { contains: () => false },
};

test('Scenario: Edit opens the popup pre-filled, and Save sends a PATCH and closes it', async () => {
  window.location.hash = '#/applications';
  await appModule.show();
  server.patches.length = 0;
  server.patchResponse = { status: 200, body: { applicationId: 'app-1' } };

  await click(editButton);

  const dialog = dialogHtml();
  assert.ok(dialog, 'the popup is open');
  assert.match(dialog, /<form class="edit-application-form">/);
  assert.match(dialog, /name="applicationId" value="app-1"/);
  assert.match(dialog, /id="application-name" name="name" maxlength="100" value="7-Zip"/);
  // An upload app offers no file, no url, no installer type and no source.
  assert.doesNotMatch(dialog, /name="file"|name="url"|name="installerType"|name="source"/);

  await submit(
    editApplicationForm({
      applicationId: textField('app-1'),
      name: textField('7-Zip x64'),
      description: textField(''),
      installArgs: textField(''),
    }),
  );

  assert.deepStrictEqual(server.patches, [
    { url: '/admin/api/v1/applications/app-1', body: { name: '7-Zip x64', description: null, installArgs: null } },
  ]);
  assert.strictEqual(dialogHtml(), null, 'a successful save closes the popup');
  assert.strictEqual(banner(), null);
});

test('Scenario (failure): A refused edit keeps the popup open with the error inside it; Escape closes it', async () => {
  window.location.hash = '#/applications';
  await appModule.show();
  server.patchResponse = { status: 400, body: { error: 'invalid_request', fields: ['name'] } };

  await click(editButton);
  await submit(editApplicationForm({ applicationId: textField('app-1'), name: textField('x') }));

  assert.match(mountStub.innerHTML, /<p class="error application-dialog-error">invalid_request<\/p>/);
  assert.ok(dialogHtml(), 'the popup stays open');
  assert.strictEqual(banner(), null);

  const before = server.patches.length;
  listeners.keydown({ key: 'Escape', target: {}, preventDefault: () => {} });
  await flush();
  assert.strictEqual(dialogHtml(), null);
  assert.strictEqual(server.patches.length, before);
  server.patchResponse = { status: 200, body: { applicationId: 'app-1' } };
});

test('Scenario: A click on the dimmed backdrop closes the popup', async () => {
  window.location.hash = '#/applications';
  await appModule.show();
  await click({ closest: (sel) => (sel === '.open-create-application' ? {} : null) });
  assert.ok(dialogHtml());

  await click({
    closest: (sel) => (sel === '.modal-backdrop' ? {} : null),
    classList: { contains: (cls) => cls === 'application-dialog-backdrop' },
  });
  assert.strictEqual(dialogHtml(), null);
});
