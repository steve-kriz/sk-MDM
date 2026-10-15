/**
 * E2E tests for TASK-045's console wiring in backend/src/ui/public/app.js:
 *
 *   - U1: the Commands nav entry sits between Policies and Audit, and
 *     navigating to it loads the library and renders commands.js
 *   - U6: the device detail Run-a-command panel loads only the device's
 *     platform library, and its Queue button is wired through onInput/onSubmit
 *   - U12: an API refusal from a new console action shows the error code in
 *     the banner after the reload
 *
 * app.js guards its self-start, so the real exported `start()` is driven with
 * stub `window`/`document`/form objects. `fetch` is stubbed in-process: no
 * database is touched and nothing opens a socket. app.js keeps its state at
 * module level, so the scenarios below run in order against one module.
 */

import test from 'node:test';
import assert from 'node:assert';

// Imported before any global `document` stub exists, so app.js does not self-start.
const appModule = await import('../../dist/ui/public/app.js');
const apiModule = await import('../../dist/ui/public/api.js');

/** What the stub API currently answers, changed scenario by scenario. */
const server = {
  libraryScripts: [{ scriptId: 'scr-1', name: 'Flush DNS', interpreter: 'cmd', platform: 'windows' }],
  deviceProfile: { deviceId: 'dev-1', hostname: 'PC-1', platform: 'windows' },
  queueResponse: { status: 202, body: { commandId: 'cmd-1', seq: 1 } },
  gets: [],
  posts: [],
  // TASK-053: the AI generate route, plus the create/update routes the UI must
  // never call on its own (AC22-AC26).
  generateResponse: { status: 200, body: { script: 'Get-ChildItem' } },
  generateDeferred: false,
  generatePosts: [],
  createPosts: [],
  updatePuts: [],
};

let deferredGenerateResolve = null;

function json(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

globalThis.fetch = async (url, init = {}) => {
  if (url === '/admin/config.json') {
    return json(200, { tenantId: 't', clientId: 'c', redirectUri: 'https://example.invalid/cb', scope: 'openid' });
  }
  const method = init.method ?? 'GET';
  server.gets.push(url);
  if (method === 'POST' && url === '/admin/api/v1/scripts/generate') {
    server.generatePosts.push(JSON.parse(init.body));
    if (server.generateDeferred) {
      return new Promise((resolve) => {
        deferredGenerateResolve = resolve;
      });
    }
    return json(server.generateResponse.status, server.generateResponse.body);
  }
  if (method === 'POST' && url === '/admin/api/v1/scripts') {
    const body = JSON.parse(init.body);
    server.createPosts.push(body);
    return json(201, { scriptId: 'scr-new', ...body });
  }
  if (method === 'PUT' && url.startsWith('/admin/api/v1/scripts/')) {
    const body = JSON.parse(init.body);
    server.updatePuts.push({ url, body });
    return json(200, { scriptId: url.split('/').pop(), ...body });
  }
  if (method === 'GET' && url.startsWith('/admin/api/v1/scripts')) {
    const platform = new URL(url, 'http://placeholder.invalid').searchParams.get('platform');
    const items = platform ? server.libraryScripts.filter((s) => s.platform === platform) : server.libraryScripts;
    return json(200, { items });
  }
  if (method === 'GET' && url.startsWith('/admin/api/v1/devices/dev-1') && !url.includes('/scripts')) {
    return json(200, { profile: server.deviceProfile, commands: [] });
  }
  if (method === 'POST' && url === '/admin/api/v1/devices/dev-1/scripts') {
    server.posts.push(JSON.parse(init.body));
    return json(server.queueResponse.status, server.queueResponse.body);
  }
  if (method === 'GET' && url.startsWith('/admin/api/v1/groups')) {
    return json(200, { items: [] });
  }
  if (method === 'GET' && url.startsWith('/admin/api/v1/settings/commands')) {
    return json(200, { onFailure: 'continue' });
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
  location: { hash: '#/commands', search: '', origin: 'https://example.invalid' },
  addEventListener: () => {},
  history: { replaceState: () => {} },
};
apiModule.setToken('test-access-token');

function flush() {
  return new Promise((resolve) => setImmediate(resolve));
}

function banner() {
  const match = /<p class="error">([^<]*)<\/p>/.exec(mountStub.innerHTML);
  return match === null ? null : match[1];
}

function textField(value) {
  return { type: 'text', value };
}

/**
 * Poll `predicate` up to `attempts` times, yielding one real macrotask between
 * each try. Deterministic: it returns the moment the condition holds rather
 * than assuming any fixed number of microtask ticks, and throws rather than
 * hanging forever when the condition never holds.
 */
async function waitUntil(predicate, attempts = 50) {
  for (let i = 0; i < attempts; i += 1) {
    if (predicate()) {
      return;
    }
    await new Promise((resolve) => setImmediate(resolve));
  }
  throw new Error('condition not met before timeout');
}

/** The substring of the rendered HTML inside `<form class="<cls>">...</form>`. */
function formSection(cls) {
  const start = mountStub.innerHTML.indexOf(`<form class="${cls}">`);
  if (start === -1) {
    return '';
  }
  return mountStub.innerHTML.slice(start, mountStub.innerHTML.indexOf('</form>', start));
}

/** A stub `<form class="create-script">` or `<form class="edit-script">` holding the given fields. */
function scriptForm(fields, cls = 'create-script') {
  return {
    classList: { contains: (c) => c === cls },
    elements: { namedItem: (name) => fields[name] ?? null },
  };
}

/** A stub Generate `<button>` that `.closest('form')` resolves back to `form`. */
function generateButtonFor(form) {
  return {
    disabled: false,
    closest: (selector) => (selector === 'form' ? form : null),
  };
}

/** A click event whose target resolves `.closest('.generate-script')` to `button` and nothing else. */
function generateClickEvent(button) {
  return { target: { closest: (selector) => (selector === '.generate-script' ? button : null) } };
}

async function click(event) {
  listeners.click(event);
}

/** A stub `<form class="queue-script">` holding the given fields, with a Queue button. */
function queueScriptForm(fields, button = { disabled: false }) {
  return {
    classList: { contains: (cls) => cls === 'queue-script' },
    elements: { namedItem: (name) => fields[name] ?? null },
    querySelector: (selector) => (selector === 'button.queue' ? button : null),
  };
}

async function submit(form) {
  listeners.submit({ target: form, preventDefault: () => {} });
  await flush();
}

await appModule.start();

test('Scenario: U1 Commands appears between Policies and Audit', async () => {
  const labels = appModule.SCREENS.map((s) => s.label);
  const policiesIndex = labels.indexOf('Policies');
  const commandsIndex = labels.indexOf('Commands');
  const auditIndex = labels.indexOf('Audit');
  assert.strictEqual(commandsIndex, policiesIndex + 1, 'Commands must come right after Policies');
  assert.strictEqual(auditIndex, commandsIndex + 1, 'Audit must come right after Commands');
  assert.strictEqual(appModule.SCREENS[commandsIndex].hash, '#/commands');
});

test('Scenario: U1 Navigating to #/commands loads the library and renders commands.js', async () => {
  window.location.hash = '#/commands';
  server.gets.length = 0;

  await appModule.show();

  assert.ok(server.gets.includes('/admin/api/v1/scripts'), 'GET /scripts');
  assert.match(mountStub.innerHTML, /id="screen-commands"/);
  assert.match(mountStub.innerHTML, /Flush DNS/);
});

test('Scenario: U6 Run a command panel loads only the device platform library', async () => {
  window.location.hash = '#/devices/dev-1';
  server.gets.length = 0;
  server.libraryScripts = [
    { scriptId: 'scr-1', name: 'Flush DNS', interpreter: 'cmd', platform: 'windows' },
    { scriptId: 'scr-2', name: 'Mac only', interpreter: 'bash', platform: 'darwin' },
  ];

  await appModule.show();

  assert.ok(server.gets.some((url) => url.startsWith('/admin/api/v1/scripts?platform=windows')), 'GET /scripts?platform=windows');
  assert.match(mountStub.innerHTML, /id="detail-run-command"/);
  assert.match(mountStub.innerHTML, /<option value="scr-1">Flush DNS<\/option>/);
  assert.doesNotMatch(mountStub.innerHTML, /Mac only/);
  // The Queue button starts disabled: no script chosen and no hostname typed.
  const panel = mountStub.innerHTML.slice(mountStub.innerHTML.indexOf('id="detail-run-command"'));
  assert.match(panel.slice(0, panel.indexOf('</section>')), /class="queue" disabled>Queue<\/button>/);
});

test('Scenario: U6 Queue is enabled once a script is chosen and the hostname typed, and submits the queue request', async () => {
  const button = { disabled: true };
  const form = queueScriptForm(
    { deviceId: textField('dev-1'), scriptId: textField('scr-1'), typedHostname: textField('PC-1') },
    button,
  );
  const field = { name: 'typedHostname', closest: (selector) => (selector === 'form.queue-script' ? form : null) };

  listeners.input({ type: 'input', target: field });
  assert.strictEqual(button.disabled, false);

  // With the wrong case it must stay disabled (exact match required).
  const lowerForm = queueScriptForm(
    { deviceId: textField('dev-1'), scriptId: textField('scr-1'), typedHostname: textField('pc-1') },
    button,
  );
  const lowerField = { name: 'typedHostname', closest: (selector) => (selector === 'form.queue-script' ? lowerForm : null) };
  listeners.input({ type: 'input', target: lowerField });
  assert.strictEqual(button.disabled, true);

  server.posts.length = 0;
  server.queueResponse = { status: 202, body: { commandId: 'cmd-2', seq: 1 } };
  await submit(form);

  assert.strictEqual(server.posts.length, 1);
  assert.deepStrictEqual(server.posts[0], { scriptId: 'scr-1', confirm: true });
});

test('Scenario: U12 An API refusal from the queue form shows the error in the banner after the reload', async () => {
  server.queueResponse = { status: 409, body: { error: 'platform_mismatch' } };
  const form = queueScriptForm({ deviceId: textField('dev-1'), scriptId: textField('scr-1'), typedHostname: textField('PC-1') });

  await submit(form);

  assert.match(banner() ?? '', /platform_mismatch/);
});

// ============================================================================
// TASK-053: AI-generate a command (AC22-AC26)
// ============================================================================

/** The `<table class="grid scripts">...</table>` section of the rendered library. */
function listSnapshot() {
  const start = mountStub.innerHTML.indexOf('<table class="grid scripts">');
  if (start === -1) {
    return mountStub.innerHTML.includes('<p class="empty">') ? 'EMPTY' : '';
  }
  return mountStub.innerHTML.slice(start, mountStub.innerHTML.indexOf('</table>', start) + '</table>'.length);
}

/** Back to a known #/commands state with one library script and a clean generate server. */
async function resetToCommandsScreen() {
  window.location.hash = '#/commands';
  server.libraryScripts = [{ scriptId: 'scr-1', name: 'Flush DNS', interpreter: 'cmd', platform: 'windows' }];
  server.generateDeferred = false;
  server.generateResponse = { status: 200, body: { script: 'Get-ChildItem' } };
  server.generatePosts.length = 0;
  server.createPosts.length = 0;
  server.updatePuts.length = 0;
  server.posts.length = 0;
  deferredGenerateResolve = null;
  await appModule.show();
}

// AC22
test('Scenario: Button disabled while generating', async () => {
  await resetToCommandsScreen();
  server.generateDeferred = true;

  const fields = {
    name: textField('Big files'),
    interpreter: textField('powershell'),
    timeoutSeconds: textField('120'),
    description: textField('d'),
    script: textField('list files'),
  };
  const form = scriptForm(fields, 'create-script');
  const button = generateButtonFor(form);

  // When I type "list files" in the New command script box and click Generate
  await click(generateClickEvent(button));

  // Then exactly one POST to /admin/api/v1/scripts/generate was sent
  assert.strictEqual(server.generatePosts.length, 1);
  // And form.create-script's .generate-script is disabled and reads "Generating..."
  assert.match(
    formSection('create-script'),
    /<button type="button" class="generate-script" disabled>Generating\.\.\.<\/button>/,
  );

  // When I click Generate again before the response arrives
  await click(generateClickEvent(button));
  // Then still exactly one generate POST was sent
  assert.strictEqual(server.generatePosts.length, 1);

  // Let the pending call settle so later tests start from a clean slate.
  assert.ok(typeof deferredGenerateResolve === 'function');
  deferredGenerateResolve(json(200, { script: 'Get-ChildItem' }));
  await waitUntil(() => !mountStub.innerHTML.includes('Generating...'));
});

// AC23
test('Scenario: Successful generate fills the textarea and keeps other fields', async () => {
  await resetToCommandsScreen();

  const fields = {
    name: textField('Big files'),
    interpreter: textField('powershell'),
    timeoutSeconds: textField('120'),
    description: textField('d'),
    script: textField('list big files'),
  };
  const form = scriptForm(fields, 'create-script');
  const button = generateButtonFor(form);

  // When I click Generate and the API answers 200 {"script":"Get-ChildItem"}
  await click(generateClickEvent(button));
  await waitUntil(() => !mountStub.innerHTML.includes('Generating...'));

  // Then the New command script textarea contains "Get-ChildItem"
  const section = formSection('create-script');
  assert.match(section, /<textarea id="script-script" name="script"[^>]*>Get-ChildItem<\/textarea>/);
  // And name, shell, timeout and description still read "Big files", "powershell", 120 and "d"
  assert.match(section, /<input id="script-name" name="name"[^>]*value="Big files">/);
  assert.match(section, /<option value="powershell" selected>/);
  assert.match(section, /<input id="script-timeout" name="timeoutSeconds"[^>]*value="120">/);
  assert.match(section, /<input id="script-description" name="description"[^>]*value="d">/);
  // And the banner is empty and the button reads "Generate" and is enabled
  assert.strictEqual(banner(), null);
  assert.match(section, /<button type="button" class="generate-script">Generate<\/button>/);
});

// AC23
test('Scenario: Generate in the edit form keeps the panel open', async () => {
  await resetToCommandsScreen();
  // Given the edit panel is open for script "scr-1" (as a row click would open it)
  await click({ target: { closest: (sel) => (sel === 'tr.script' ? { dataset: { scriptId: 'scr-1' } } : null) } });
  assert.match(mountStub.innerHTML, /<div class="edit-panel" data-script-id="scr-1">/);

  server.generateResponse = { status: 200, body: { script: 'echo hi' } };
  const fields = {
    name: textField('Flush DNS'),
    interpreter: textField('cmd'),
    timeoutSeconds: textField(''),
    description: textField(''),
    script: textField('flush the dns cache'),
  };
  const form = scriptForm(fields, 'edit-script');
  const button = generateButtonFor(form);

  // When I click its Generate button and the API answers 200 {"script":"echo hi"}
  await click(generateClickEvent(button));
  await waitUntil(() => !mountStub.innerHTML.includes('Generating...'));

  // Then the edit panel for "scr-1" is open and its script textarea contains "echo hi"
  assert.match(mountStub.innerHTML, /<div class="edit-panel" data-script-id="scr-1">/);
  const section = formSection('edit-script');
  assert.match(section, /<textarea id="edit-script-script" name="script"[^>]*>echo hi<\/textarea>/);
});

// AC24
test('Scenario: Generated script is not saved or queued automatically', async () => {
  await resetToCommandsScreen();
  const beforeList = listSnapshot();

  const fields = {
    name: textField('Big files'),
    interpreter: textField('powershell'),
    timeoutSeconds: textField('120'),
    description: textField('d'),
    script: textField('list big files'),
  };
  const form = scriptForm(fields, 'create-script');
  const button = generateButtonFor(form);

  // When I click Generate and the API answers 200
  await click(generateClickEvent(button));
  await waitUntil(() => !mountStub.innerHTML.includes('Generating...'));

  // Then no POST /admin/api/v1/scripts, no PUT /admin/api/v1/scripts/{id} and no queue request was sent
  assert.strictEqual(server.createPosts.length, 0);
  assert.strictEqual(server.updatePuts.length, 0);
  assert.strictEqual(server.posts.length, 0);
  // And the library list is unchanged
  assert.strictEqual(listSnapshot(), beforeList);

  // When I then click "Save command"
  const saveForm = scriptForm(
    {
      name: textField('Big files'),
      interpreter: textField('powershell'),
      timeoutSeconds: textField('120'),
      description: textField('d'),
      script: textField('Get-ChildItem'),
    },
    'create-script',
  );
  await submit(saveForm);

  // Then one POST /admin/api/v1/scripts is sent with script equal to the generated text
  assert.strictEqual(server.createPosts.length, 1);
  assert.strictEqual(server.createPosts[0].script, 'Get-ChildItem');
});

// AC25
test('Scenario: Failed generate keeps the request text', async () => {
  await resetToCommandsScreen();
  server.generateResponse = { status: 502, body: { error: 'ai_failed' } };

  const fields = {
    name: textField(''),
    interpreter: textField('cmd'),
    timeoutSeconds: textField(''),
    description: textField(''),
    script: textField('list big files'),
  };
  const form = scriptForm(fields, 'create-script');
  const button = generateButtonFor(form);

  // When I click Generate and the API answers 502 {"error":"ai_failed"}
  await click(generateClickEvent(button));
  await waitUntil(() => !mountStub.innerHTML.includes('Generating...'));

  // Then the banner shows "ai_failed"
  assert.match(banner() ?? '', /ai_failed/);
  // And the script textarea still contains "list big files"
  const section = formSection('create-script');
  assert.match(section, /<textarea id="script-script" name="script"[^>]*>list big files<\/textarea>/);
  // And the button reads "Generate" and is enabled
  assert.match(section, /<button type="button" class="generate-script">Generate<\/button>/);
});

// AC26
test('Scenario: Empty script box sends nothing', async () => {
  await resetToCommandsScreen();

  const fields = {
    name: textField(''),
    interpreter: textField('cmd'),
    timeoutSeconds: textField(''),
    description: textField(''),
    script: textField(''),
  };
  const form = scriptForm(fields, 'create-script');
  const button = generateButtonFor(form);

  // Given the New command script textarea is empty
  // When I click Generate
  await click(generateClickEvent(button));

  // Then no request is sent
  assert.strictEqual(server.generatePosts.length, 0);
  // And the banner reads "Command not generated: prompt"
  assert.strictEqual(banner(), 'Command not generated: prompt');
});

// AC26
test('Scenario: Invalid timeout is refused client-side', async () => {
  await resetToCommandsScreen();

  const fields = {
    name: textField(''),
    interpreter: textField('cmd'),
    timeoutSeconds: textField('0'),
    description: textField(''),
    script: textField('list files'),
  };
  const form = scriptForm(fields, 'create-script');
  const button = generateButtonFor(form);

  // Given "list files" in the script box and timeout "0"
  // When I click Generate
  await click(generateClickEvent(button));

  // Then no request is sent and the banner reads "Command not generated: timeoutSeconds"
  assert.strictEqual(server.generatePosts.length, 0);
  assert.strictEqual(banner(), 'Command not generated: timeoutSeconds');
});
