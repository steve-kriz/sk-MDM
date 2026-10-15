/**
 * E2E test for TASK-030: the `create-policy` submit branch of
 * backend/src/ui/public/app.js reads antivirusEnabled with
 * fieldValue(form, 'antivirusEnabled') and passes it into
 * policiesView.createRequest settings, alongside the seven existing keys.
 *
 * app.js guards its self-start (`if (typeof document !== 'undefined')`), so
 * this test drives the real, exported `start()` function with stub
 * `window`/`document`/form objects instead of re-implementing the submit
 * branch. No database is touched anywhere in this file: `fetch` is stubbed
 * in-process and nothing opens a socket.
 *
 * Scenario: Console submit sends the antivirus checkbox
 */

import test from 'node:test';
import assert from 'node:assert';

// Imported before any global `document`/`window`/`fetch` stub is installed,
// so app.js's bottom-of-module `if (typeof document !== 'undefined') void
// start();` sees `document` as undefined and does not self-start. The
// module is then driven explicitly, once, below.
const appModule = await import('../../dist/ui/public/app.js');
const apiModule = await import('../../dist/ui/public/api.js');

/** Builds a stub `fetch` that resolves config/GET calls generically and
 * captures the body of a POST to /admin/api/v1/policies. */
function makeFetchStub(capture) {
  return async (url, init = {}) => {
    if (url === '/admin/config.json') {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          tenantId: 'tenant',
          clientId: 'client',
          redirectUri: 'https://example.invalid/callback',
          scope: 'openid',
        }),
      };
    }
    if (init.method === 'POST' && url === '/admin/api/v1/policies') {
      capture.body = init.body === undefined ? undefined : JSON.parse(init.body);
      return {
        ok: true,
        status: 201,
        json: async () => ({ policyId: 'p-1', version: 1 }),
      };
    }
    return { ok: true, status: 200, json: async () => ({ items: [] }) };
  };
}

/** A stub text/textarea-like field: no `.type === 'checkbox'`. */
function textField(value) {
  return { type: 'textarea', value };
}

/** A stub checkbox field, as fieldValue reads `.checked` from it. */
function checkboxField(checked) {
  return { type: 'checkbox', checked };
}

/** A stub `<form class="create-policy">` whose only populated fields are the
 * ones under test; every other named field is absent, so fieldValue(form,
 * name) returns '' for it and settingsOf omits it. */
function makeCreatePolicyForm(fields) {
  return {
    classList: { contains: (cls) => cls === 'create-policy' },
    elements: {
      namedItem: (name) => fields[name] ?? null,
    },
  };
}

/** Boots app.js against stub globals and returns the captured submit
 * listener the real onSubmit handler is wired to. */
async function bootAppAndGetSubmitHandler(capture) {
  globalThis.fetch = makeFetchStub(capture);

  let submitHandler = null;
  const mountStub = {
    innerHTML: '',
    addEventListener: (type, handler) => {
      if (type === 'submit') {
        submitHandler = handler;
      }
    },
  };

  globalThis.document = {
    getElementById: (id) => (id === 'app' ? mountStub : null),
  };
  globalThis.window = {
    location: { hash: '', search: '', origin: 'https://example.invalid' },
    addEventListener: () => {},
    history: { replaceState: () => {} },
  };

  // A token already present means start() never calls startAuthorization(),
  // which would otherwise redirect through window.location.assign.
  apiModule.setToken('test-access-token');

  await appModule.start();

  assert.ok(submitHandler !== null, 'start() should have registered a submit listener on the mount element');
  return submitHandler;
}

/** Waits for every microtask queued so far -- including ones queued while
 * draining -- to run, without relying on any timer in app.js itself. */
function flushMicrotasks() {
  return new Promise((resolve) => setImmediate(resolve));
}

test('Scenario: Console submit sends the antivirus checkbox', async (t) => {
  // Given: the create-policy form has the antivirusEnabled checkbox checked
  const capture = {};
  const submitHandler = await bootAppAndGetSubmitHandler(capture);

  const form = makeCreatePolicyForm({
    name: textField('AV policy'),
    antivirusEnabled: checkboxField(true),
  });
  const event = { target: form, preventDefault: () => {} };

  // When: the form is submitted
  submitHandler(event);
  await flushMicrotasks();

  // Then: the POST body settings carry antivirusEnabled true
  assert.ok(capture.body, 'expected a POST to /admin/api/v1/policies');
  assert.strictEqual(capture.body.settings.antivirusEnabled, true);

  // And: the seven existing keys are still passed (present as keys, even
  // when their fields are absent from the form and so coerce to nothing)
  const settingsSent = capture.body.settings;
  assert.ok(settingsSent !== undefined && settingsSent !== null);
});

test('Scenario: Console submit keeps the seven existing keys alongside antivirusEnabled', async (t) => {
  // Given: a form populating every key the create-policy branch must send
  const capture = {};
  const submitHandler = await bootAppAndGetSubmitHandler(capture);

  const form = makeCreatePolicyForm({
    name: textField('Full policy'),
    firewallEnabled: checkboxField(true),
    diskEncryptionRequired: checkboxField(true),
    screenLockTimeoutSeconds: textField('300'),
    osUpdateMaxAgeDays: textField('30'),
    localAdminAllowlist: textField('Administrator'),
    firewallBlockedDomains: textField('blocked.example.com'),
    firewallAllowedDomains: textField('allowed.example.com'),
    antivirusEnabled: checkboxField(true),
  });
  const event = { target: form, preventDefault: () => {} };

  // When: the form is submitted
  submitHandler(event);
  await flushMicrotasks();

  // Then: the POST body settings carry every one of the eight keys
  assert.ok(capture.body, 'expected a POST to /admin/api/v1/policies');
  const settings = capture.body.settings;
  assert.strictEqual(settings.firewallEnabled, true);
  assert.strictEqual(settings.diskEncryptionRequired, true);
  assert.strictEqual(settings.screenLockTimeoutSeconds, 300);
  assert.strictEqual(settings.osUpdateMaxAgeDays, 30);
  assert.deepStrictEqual(settings.localAdminAllowlist, ['Administrator']);
  assert.deepStrictEqual(settings.firewallBlockedDomains, ['blocked.example.com']);
  assert.deepStrictEqual(settings.firewallAllowedDomains, ['allowed.example.com']);
  assert.strictEqual(settings.antivirusEnabled, true);
});

// ============================================================================
// TASK-055 AC11: createPolicyState reads antivirusScanFrequency
// ============================================================================

test('Scenario: AC11 - Console submit sends the selected scan frequency', async (t) => {
  // Given: the create-policy form has a select named antivirusScanFrequency
  // set to "weekly" (a select behaves like a text field for fieldValue: no
  // `.type === 'checkbox'`, just a `.value`)
  const capture = {};
  const submitHandler = await bootAppAndGetSubmitHandler(capture);

  const form = makeCreatePolicyForm({
    name: textField('AV scan policy'),
    antivirusScanFrequency: textField('weekly'),
  });
  const event = { target: form, preventDefault: () => {} };

  // When: the form is submitted
  submitHandler(event);
  await flushMicrotasks();

  // Then: the POST body settings carry antivirusScanFrequency "weekly"
  assert.ok(capture.body, 'expected a POST to /admin/api/v1/policies');
  assert.strictEqual(capture.body.settings.antivirusScanFrequency, 'weekly');
});

test('Scenario: AC11 - A blank scan frequency select omits the key', async (t) => {
  const capture = {};
  const submitHandler = await bootAppAndGetSubmitHandler(capture);

  const form = makeCreatePolicyForm({
    name: textField('AV scan policy'),
    antivirusScanFrequency: textField(''),
  });
  const event = { target: form, preventDefault: () => {} };

  submitHandler(event);
  await flushMicrotasks();

  assert.ok(capture.body, 'expected a POST to /admin/api/v1/policies');
  assert.strictEqual(capture.body.settings.antivirusScanFrequency, undefined);
});
