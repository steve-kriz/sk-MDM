/**
 * E2E test for TASK-056: the `create-policy` submit branch of
 * backend/src/ui/public/app.js reads locationTracking with
 * fieldValue(form, 'locationTracking') and passes it into
 * policiesView.createRequest settings.
 *
 * Follows the same pattern as appSubmitAntivirus.test.js (TASK-030/TASK-055):
 * app.js guards its self-start, so this drives the real, exported `start()`
 * with stub window/document/form objects. No database is touched: `fetch` is
 * stubbed in-process and nothing opens a socket.
 */

import test from 'node:test';
import assert from 'node:assert';

const appModule = await import('../../dist/ui/public/app.js');
const apiModule = await import('../../dist/ui/public/api.js');

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
      return { ok: true, status: 201, json: async () => ({ policyId: 'p-1', version: 1 }) };
    }
    return { ok: true, status: 200, json: async () => ({ items: [] }) };
  };
}

function checkboxField(checked) {
  return { type: 'checkbox', checked };
}

function textField(value) {
  return { type: 'textarea', value };
}

function makeCreatePolicyForm(fields) {
  return {
    classList: { contains: (cls) => cls === 'create-policy' },
    elements: { namedItem: (name) => fields[name] ?? null },
  };
}

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

  globalThis.document = { getElementById: (id) => (id === 'app' ? mountStub : null) };
  globalThis.window = {
    location: { hash: '', search: '', origin: 'https://example.invalid' },
    addEventListener: () => {},
    history: { replaceState: () => {} },
  };

  apiModule.setToken('test-access-token');
  await appModule.start();

  assert.ok(submitHandler !== null, 'start() should have registered a submit listener on the mount element');
  return submitHandler;
}

function flushMicrotasks() {
  return new Promise((resolve) => setImmediate(resolve));
}

// ============================================================================
// Scenario: createPolicyState submits locationTracking from the form
// ============================================================================

test('Scenario: Console submit sends the locationTracking checkbox (checked)', async () => {
  const capture = {};
  const submitHandler = await bootAppAndGetSubmitHandler(capture);

  const form = makeCreatePolicyForm({
    name: textField('Tracking policy'),
    locationTracking: checkboxField(true),
  });
  const event = { target: form, preventDefault: () => {} };

  submitHandler(event);
  await flushMicrotasks();

  assert.ok(capture.body, 'expected a POST to /admin/api/v1/policies');
  assert.strictEqual(capture.body.settings.locationTracking, true);
});

test('Scenario: Console submit sends the locationTracking checkbox (unchecked)', async () => {
  const capture = {};
  const submitHandler = await bootAppAndGetSubmitHandler(capture);

  const form = makeCreatePolicyForm({
    name: textField('Tracking policy'),
    locationTracking: checkboxField(false),
  });
  const event = { target: form, preventDefault: () => {} };

  submitHandler(event);
  await flushMicrotasks();

  assert.ok(capture.body, 'expected a POST to /admin/api/v1/policies');
  assert.strictEqual(capture.body.settings.locationTracking, false);
});
