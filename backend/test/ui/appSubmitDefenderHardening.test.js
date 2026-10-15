/**
 * E2E test for TASK-060 AC5/AC6: the `create-policy` submit branch of
 * backend/src/ui/public/app.js reads all six Defender keys via
 * createPolicyState, and policiesView.settingsOf/fieldErrors/createRequest
 * reject an invalid defenderRansomwareProtection value. Modelled on
 * backend/test/ui/appSubmitAntivirus.test.js. No database is touched: fetch is
 * stubbed in-process.
 */

import test from 'node:test';
import assert from 'node:assert';

const appModule = await import('../../dist/ui/public/app.js');
const apiModule = await import('../../dist/ui/public/api.js');
const policiesView = await import('../../dist/ui/views/policies.js');

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

function textField(value) {
  return { type: 'textarea', value };
}
function checkboxField(checked) {
  return { type: 'checkbox', checked };
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
      if (type === 'submit') submitHandler = handler;
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

test('Scenario: Form state becomes settings -- createPolicyState collects all six fields', async (t) => {
  // Given the create form has defenderCloudProtection checked,
  // defenderPuaProtection (n/a, not a real field) absent, defenderRealTimeProtection
  // unchecked and the ransomware select blank
  const capture = {};
  const submitHandler = await bootAppAndGetSubmitHandler(capture);

  const form = makeCreatePolicyForm({
    name: textField('Defender policy'),
    defenderCloudProtection: checkboxField(true),
    defenderRealTimeProtection: checkboxField(false),
    defenderRansomwareProtection: textField(''),
  });
  const event = { target: form, preventDefault: () => {} };

  // When createPolicyState and settingsOf are applied (via the real submit path)
  submitHandler(event);
  await flushMicrotasks();

  // Then settings.defenderCloudProtection is true and
  // settings.defenderRealTimeProtection is false
  assert.ok(capture.body, 'expected a POST to /admin/api/v1/policies');
  assert.strictEqual(capture.body.settings.defenderCloudProtection, true);
  assert.strictEqual(capture.body.settings.defenderRealTimeProtection, false);
  // And settings has no defenderRansomwareProtection key
  assert.ok(!('defenderRansomwareProtection' in capture.body.settings));
});

test('Scenario: createPolicyState collects all six Defender fields and sends true/string values', async (t) => {
  const capture = {};
  const submitHandler = await bootAppAndGetSubmitHandler(capture);

  const form = makeCreatePolicyForm({
    name: textField('Full Defender policy'),
    defenderRealTimeProtection: checkboxField(true),
    defenderCloudProtection: checkboxField(true),
    defenderNetworkProtection: checkboxField(true),
    defenderReputationProtection: checkboxField(true),
    defenderDailySignatureUpdate: checkboxField(true),
    defenderRansomwareProtection: textField('block'),
  });
  const event = { target: form, preventDefault: () => {} };

  submitHandler(event);
  await flushMicrotasks();

  assert.ok(capture.body, 'expected a POST to /admin/api/v1/policies');
  const settings = capture.body.settings;
  assert.strictEqual(settings.defenderRealTimeProtection, true);
  assert.strictEqual(settings.defenderCloudProtection, true);
  assert.strictEqual(settings.defenderNetworkProtection, true);
  assert.strictEqual(settings.defenderReputationProtection, true);
  assert.strictEqual(settings.defenderDailySignatureUpdate, true);
  assert.strictEqual(settings.defenderRansomwareProtection, 'block');
});

test('Scenario: Invalid ransomware value blocks the create request', async (t) => {
  // Given form state with defenderRansomwareProtection "maybe"
  const state = { name: 'Bad Policy', settings: { defenderRansomwareProtection: 'maybe' } };

  // Then fieldErrors contains "defenderRansomwareProtection"
  assert.ok(policiesView.fieldErrors(state).includes('defenderRansomwareProtection'));
  // And createRequest returns null
  assert.strictEqual(policiesView.createRequest(state), null);
});

test('Scenario (edge): No submit is sent for an invalid ransomware value typed into the form', async (t) => {
  // The console submit handler itself must also refuse to send a request when
  // the typed ransomware value is invalid, not just the pure helper above.
  const capture = {};
  const submitHandler = await bootAppAndGetSubmitHandler(capture);

  const form = makeCreatePolicyForm({
    name: textField('Bad Defender Policy'),
    defenderRansomwareProtection: textField('maybe'),
  });
  const event = { target: form, preventDefault: () => {} };

  submitHandler(event);
  await flushMicrotasks();

  assert.strictEqual(capture.body, undefined, 'no POST should have been sent for an invalid ransomware value');
});
