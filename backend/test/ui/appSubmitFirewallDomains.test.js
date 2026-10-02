/**
 * E2E test for TASK-029 AC6: the `create-policy` submit branch of
 * backend/src/ui/public/app.js reads firewallBlockedDomains and
 * firewallAllowedDomains with fieldValue(form, ...) and passes them into
 * policiesView.createRequest settings, alongside the five existing keys.
 *
 * app.js guards its self-start (`if (typeof document !== 'undefined')`), so
 * this test drives the real, exported `start()` function with stub
 * `window`/`document`/form objects instead of re-implementing the submit
 * branch. No database is touched anywhere in this file: `fetch` is stubbed
 * in-process and nothing opens a socket.
 *
 * Scenario: Console submit sends the domain lists
 * Scenario: An invalid domain is never sent (failure/edge path)
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

/** A stub form field: a text/textarea-like field has no `.type === 'checkbox'`. */
function textField(value) {
  return { type: 'textarea', value };
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

test('Scenario: Console submit sends the domain lists', async (t) => {
  // Given: the create-policy form has firewallBlockedDomains "a.com" and firewallAllowedDomains "b.com"
  const capture = {};
  const submitHandler = await bootAppAndGetSubmitHandler(capture);

  const form = makeCreatePolicyForm({
    name: textField('Firewall policy'),
    firewallBlockedDomains: textField('a.com'),
    firewallAllowedDomains: textField('b.com'),
  });
  const event = { target: form, preventDefault: () => {} };

  // When: the form is submitted
  submitHandler(event);
  await flushMicrotasks();

  // Then: the POST body settings carry firewallBlockedDomains ["a.com"] and firewallAllowedDomains ["b.com"]
  assert.ok(capture.body, 'expected a POST to /admin/api/v1/policies');
  assert.deepStrictEqual(capture.body.settings.firewallBlockedDomains, ['a.com']);
  assert.deepStrictEqual(capture.body.settings.firewallAllowedDomains, ['b.com']);
});

test('Scenario: An invalid domain in the submitted form is never sent (edge path)', async (t) => {
  // Given: the create-policy form has an invalid firewallBlockedDomains entry
  const capture = {};
  const submitHandler = await bootAppAndGetSubmitHandler(capture);

  const form = makeCreatePolicyForm({
    name: textField('Firewall policy'),
    firewallBlockedDomains: textField('http://x.com'),
  });
  const event = { target: form, preventDefault: () => {} };

  // When: the form is submitted
  submitHandler(event);
  await flushMicrotasks();

  // Then: createRequest returned null (fieldErrors flagged the entry) and no POST was sent
  assert.strictEqual(capture.body, undefined, 'an invalid domain must never reach the API');
});
