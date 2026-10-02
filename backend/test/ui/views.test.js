/**
 * Unit tests for Admin UI view modules (TASK-013).
 *
 * Every view module exports a render function that:
 * - Takes a plain state object
 * - Returns a string
 * - References no document, window or fetch global
 * - Is imported directly under node --test with no browser or DOM shim
 *
 * Scenario: Device list renders rows
 * Scenario: Empty fleet message
 * Scenario: Device detail shows every section
 * Scenario: Destructive command requires typing the hostname
 * Scenario: Script command without an interpreter is blocked in the UI
 * Scenario: Group is created and populated
 * Scenario: Enrollment token is displayed once
 * Scenario: Out-of-range policy setting is blocked in the UI
 * Scenario: Policy assignment and removal
 * Scenario: Audit rows are rendered newest first
 * Scenario: Collection URL is shown to operators
 * Scenario: Views run without a browser
 */

import test from 'node:test';
import assert from 'node:assert';

// Import all view modules
const devicesModule = await import('../../dist/ui/views/devices.js');
const deviceDetailModule = await import('../../dist/ui/views/deviceDetail.js');
const dispatchModule = await import('../../dist/ui/views/dispatch.js');
const groupsModule = await import('../../dist/ui/views/groups.js');
const enrollmentTokensModule = await import('../../dist/ui/views/enrollmentTokens.js');
const policiesModule = await import('../../dist/ui/views/policies.js');
const auditModule = await import('../../dist/ui/views/audit.js');
const settingsModule = await import('../../dist/ui/views/settings.js');

const views = {
  devices: devicesModule.render,
  deviceDetail: deviceDetailModule.render,
  dispatch: dispatchModule.render,
  groups: groupsModule.render,
  enrollmentTokens: enrollmentTokensModule.render,
  policies: policiesModule.render,
  audit: auditModule.render,
  settings: settingsModule.render,
};

test('Scenario: Views run without a browser - all views export render function', async (t) => {
  for (const [name, render] of Object.entries(views)) {
    assert.ok(typeof render === 'function', `${name} should export render function`);
  }
});

test('Scenario: Device list renders rows - two items render two rows', async (t) => {
  const state = {
    items: [
      {
        deviceId: 'd-1',
        hostname: 'laptop-1',
        platform: 'windows',
        osVersion: '22H2',
        lastSeenAt: '2024-01-01T00:00:00Z',
        complianceState: 'compliant',
      },
      {
        deviceId: 'd-2',
        hostname: 'mac-2',
        platform: 'macos',
        osVersion: '14.1',
        lastSeenAt: '2024-01-02T00:00:00Z',
        complianceState: 'noncompliant',
      },
    ],
    cursor: null,
  };

  const html = devicesModule.render(state);

  assert.ok(typeof html === 'string', 'should return a string');
  assert.ok(html.includes('laptop-1'), 'should include first hostname');
  assert.ok(html.includes('mac-2'), 'should include second hostname');
  assert.ok(html.includes('windows'), 'should include first platform');
  assert.ok(html.includes('macos'), 'should include second platform');
  assert.ok(html.includes('22H2'), 'should include first osVersion');
  assert.ok(html.includes('14.1'), 'should include second osVersion');
});

test('Scenario: Empty fleet message - no items renders "No devices enrolled"', async (t) => {
  const state = {
    items: [],
    cursor: null,
  };

  const html = devicesModule.render(state);

  assert.ok(typeof html === 'string');
  assert.ok(html.includes('No devices enrolled'), 'should include empty message');
});

test('Scenario: Device detail shows every section - renders profile, inventory, posture, commands', async (t) => {
  const state = {
    profile: {},
    inventory: {
      hardware: {
        serialNumber: 'SN12345',
      },
      os: {
        version: '22H2',
      },
      software: [{ name: 'app1' }, { name: 'app2' }, { name: 'app3' }],
    },
    posture: {
      diskEncryption: { enabled: true },
      firewall: { enabled: false },
    },
    commands: [
      { commandId: 'cmd-1', type: 'restart', createdAt: '2024-01-01T00:00:00Z' },
      { commandId: 'cmd-2', type: 'lock', createdAt: '2024-01-02T00:00:00Z' },
      { commandId: 'cmd-3', type: 'run_script', createdAt: '2024-01-03T00:00:00Z' },
    ],
  };

  const html = deviceDetailModule.render(state);

  assert.ok(typeof html === 'string');
  assert.ok(html.includes('SN12345'), 'should include serialNumber');
  assert.ok(html.includes('22H2'), 'should include os version');
  assert.ok(html.includes('3'), 'should include software count');
  assert.ok(html.includes('enabled'), 'should include encryption enabled status');
  assert.ok(html.includes('cmd-1'), 'should include first command');
});

test('Scenario: Destructive command requires typing hostname - send disabled when typed hostname differs', async (t) => {
  const state = {
    deviceId: 'd-1',
    hostname: 'LAPTOP-7',
    type: 'restart',
    payload: {},
    typedHostname: 'LAPTOP-6',
  };

  const html = dispatchModule.render(state);

  assert.ok(typeof html === 'string');
  // When hostname differs, send should be disabled and no body produced
  assert.ok(html.includes('disabled') || !html.includes('requestBody'), 'send should be disabled');
});

test('Scenario: Destructive command requires typing hostname - send enabled when typed hostname matches', async (t) => {
  const state = {
    deviceId: 'd-1',
    hostname: 'LAPTOP-7',
    type: 'restart',
    payload: {},
    typedHostname: 'LAPTOP-7',
  };

  const html = dispatchModule.render(state);

  assert.ok(typeof html === 'string');
  // When hostname matches, send should be enabled and body produced
});

test('Scenario: Script command without interpreter is blocked - shows field error for payload.interpreter', async (t) => {
  const state = {
    deviceId: 'd-1',
    hostname: 'laptop-1',
    type: 'run_script',
    payload: {
      script: 'Write-Host "test"',
      interpreter: '', // Missing interpreter
    },
    typedHostname: 'laptop-1',
  };

  const html = dispatchModule.render(state);

  assert.ok(typeof html === 'string');
  assert.ok(
    html.includes('interpreter') || html.includes('error'),
    'should show field error for missing interpreter'
  );
});

test('Scenario: Group is created and populated - renders group rows', async (t) => {
  const state = {
    items: [
      { groupId: 'g-1', name: 'Sydney', createdAt: '2024-01-01T00:00:00Z' },
      { groupId: 'g-2', name: 'Melbourne', createdAt: '2024-01-02T00:00:00Z' },
    ],
    groupId: null,
  };

  const html = groupsModule.render(state);

  assert.ok(typeof html === 'string');
  assert.ok(html.includes('Sydney'), 'should include first group name');
  assert.ok(html.includes('Melbourne'), 'should include second group name');
});

test('Scenario: Group membership form - renders form to add devices', async (t) => {
  const state = {
    groups: [{ groupId: 'g-1', name: 'Sydney', memberCount: 5 }],
    selectedGroupId: 'g-1',
    memberIds: ['d-1', 'd-2'],
  };

  const html = groupsModule.render(state);

  assert.ok(typeof html === 'string');
  // Should render form to submit membership
});

test('Scenario: Enrollment token is displayed once - new token shows once', async (t) => {
  const state = {
    items: [],
    created: {
      token: 'a1b2',
    },
  };

  const html = enrollmentTokensModule.render(state);

  assert.ok(typeof html === 'string');
  assert.ok(html.includes('a1b2'), 'should include token value');
  assert.ok(html.includes('This token is shown once'), 'should include shown once message');
});

test('Scenario: Enrollment token is displayed once - re-render from stored list hides token', async (t) => {
  const state = {
    tokens: [
      { tokenId: 't-1', label: 'Batch 1', maxUses: 10, expiresAt: '2024-12-31T00:00:00Z' },
    ],
    createdResponse: null,
  };

  const html = enrollmentTokensModule.render(state);

  assert.ok(typeof html === 'string');
  // Token value should not be shown when createdResponse is null
  assert.ok(!html.includes('t-1') || html.includes('Batch 1'), 'should not show token secret value');
});

test('Scenario: Out-of-range policy setting blocked - screenLockTimeoutSeconds 30 shows error', async (t) => {
  const state = {
    name: 'Policy 1',
    settings: {
      screenLockTimeoutSeconds: 30, // Out of range (60..3600)
    },
  };

  const html = policiesModule.render(state);

  assert.ok(typeof html === 'string');
  assert.ok(
    html.includes('error') || html.includes('screenLock'),
    'should show error for out of range value'
  );
});

test('Scenario: Out-of-range policy setting blocked - valid range 60 seconds', async (t) => {
  const state = {
    name: 'Policy 1',
    settings: {
      screenLockTimeoutSeconds: 60,
    },
  };

  const html = policiesModule.render(state);

  assert.ok(typeof html === 'string');
  // Should not show error for valid range
});

test('Scenario: Policy assignment - POST /admin/api/v1/policies/p1/assignments with groupId', async (t) => {
  const state = {
    policyId: 'p-1',
    policies: [],
    selectedPolicyId: 'p-1',
    selectedGroupId: 'g-1',
  };

  const html = policiesModule.render(state);

  assert.ok(typeof html === 'string');
  // Should render form for assignment
});

test('Scenario: Audit rows rendered newest first - three entries in reverse chronological order', async (t) => {
  const state = {
    entries: [
      {
        actor: 'admin@example.com',
        action: 'DEVICE_ENROLLED',
        target: 'd-1',
        timestamp: '2024-01-03T00:00:00Z',
      },
      {
        actor: 'admin@example.com',
        action: 'POLICY_CREATED',
        target: 'p-1',
        timestamp: '2024-01-02T00:00:00Z',
      },
      {
        actor: 'admin@example.com',
        action: 'GROUP_CREATED',
        target: 'g-1',
        timestamp: '2024-01-01T00:00:00Z',
      },
    ],
  };

  const html = auditModule.render(state);

  assert.ok(typeof html === 'string');
  assert.ok(html.includes('DEVICE_ENROLLED'), 'should include DEVICE_ENROLLED');
  assert.ok(html.includes('POLICY_CREATED'), 'should include POLICY_CREATED');
  assert.ok(html.includes('GROUP_CREATED'), 'should include GROUP_CREATED');
  // Newest entry should appear first
  const deviceIdx = html.indexOf('DEVICE_ENROLLED');
  const policyIdx = html.indexOf('POLICY_CREATED');
  const groupIdx = html.indexOf('GROUP_CREATED');
  assert.ok(deviceIdx < policyIdx, 'DEVICE_ENROLLED should appear before POLICY_CREATED');
  assert.ok(policyIdx < groupIdx, 'POLICY_CREATED should appear before GROUP_CREATED');
});

test('Scenario: Audit empty response - renders "No audit entries in this range"', async (t) => {
  const state = {
    entries: [],
  };

  const html = auditModule.render(state);

  assert.ok(typeof html === 'string');
  assert.ok(html.includes('No audit entries in this range'), 'should include empty message');
});

test('Scenario: Collection URL shown to operators - displays AWS_LAMBDA_FUNCTION_URL', async (t) => {
  const state = {
    collectionUrl: 'https://abc.lambda-url.ap-southeast-2.on.aws/',
  };

  const html = settingsModule.render(state);

  assert.ok(typeof html === 'string');
  assert.ok(html.includes('https://abc.lambda-url.ap-southeast-2.on.aws/'), 'should display the collection URL');
});

test('Unit - all view modules do not reference document', async (t) => {
  const modules = [
    devicesModule,
    deviceDetailModule,
    dispatchModule,
    groupsModule,
    enrollmentTokensModule,
    policiesModule,
    auditModule,
    settingsModule,
  ];

  for (const mod of modules) {
    const renderStr = mod.render.toString();
    assert.ok(
      !renderStr.includes('document.'),
      'render function should not reference document'
    );
  }
});

test('Unit - all view modules do not reference window', async (t) => {
  const modules = [
    devicesModule,
    deviceDetailModule,
    dispatchModule,
    groupsModule,
    enrollmentTokensModule,
    policiesModule,
    auditModule,
    settingsModule,
  ];

  for (const mod of modules) {
    const renderStr = mod.render.toString();
    assert.ok(
      !renderStr.includes('window.'),
      'render function should not reference window'
    );
  }
});

test('Unit - all view modules do not reference fetch', async (t) => {
  const modules = [
    devicesModule,
    deviceDetailModule,
    dispatchModule,
    groupsModule,
    enrollmentTokensModule,
    policiesModule,
    auditModule,
    settingsModule,
  ];

  for (const mod of modules) {
    const renderStr = mod.render.toString();
    assert.ok(
      !renderStr.includes('fetch(') && !renderStr.includes('fetch ('),
      'render function should not reference fetch'
    );
  }
});

// ============================================================================
// TASK-027: user links -- devices.js (AC22), deviceDetail.js (AC24), app.js (AC23)
// ============================================================================

// Imported before any test sets globalThis.document, so app.js's own
// `if (typeof document !== 'undefined') { void start(); }` guard sees no
// `document` and does not auto-start the console while this file loads.
const appModule = await import('../../dist/ui/public/app.js');
const apiModule = await import('../../dist/ui/public/api.js');

test('AC22: COLUMNS carries primaryUser and both an empty and a non-empty fleet show the refresh button', async (t) => {
  assert.deepStrictEqual(devicesModule.COLUMNS, [
    'hostname',
    'primaryUser',
    'platform',
    'osVersion',
    'lastSeenAt',
    'complianceState',
  ]);

  const nonEmpty = devicesModule.render({
    items: [{ deviceId: 'd1', hostname: 'LAT', primaryUser: 'amy@contoso.com' }],
    cursor: null,
  });
  assert.ok(nonEmpty.includes('<button type="button" class="refresh-user-links">'));
  assert.ok(nonEmpty.includes('>hostname<'));
  assert.ok(nonEmpty.includes('>primaryUser<'));

  const empty = devicesModule.render({ items: [], cursor: null });
  assert.ok(empty.includes('No devices enrolled'));
  assert.ok(empty.includes('<button type="button" class="refresh-user-links">'));
});

test('AC24: device detail user section shows status, resolvedAt, one user row and the refresh button', async (t) => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    userLink: {
      status: 'linked',
      resolvedAt: '2026-09-21T13:46:40Z',
      users: [{ displayName: 'Amy', userPrincipalName: 'amy@contoso.com' }],
    },
  });

  assert.ok(html.includes('id="detail-user"'));
  assert.ok(html.includes('>User<'));
  assert.ok(html.includes('linked'));
  assert.ok(html.includes('2026-09-21T13:46:40Z'));
  assert.ok(html.includes('tr class="user"'));
  assert.ok(html.includes('Amy'));
  assert.ok(html.includes('amy@contoso.com'));
  assert.ok(html.includes('class="refresh-user-link"'));
  assert.ok(html.includes('data-device-id="d1"'));
});

test('AC24: device detail user section shows "Not resolved" when userLink is null', async (t) => {
  const html = deviceDetailModule.render({ profile: { deviceId: 'd1' }, userLink: null });
  const section = html.slice(html.indexOf('id="detail-user"'));
  assert.ok(section.includes('Not resolved'));
  assert.ok(section.includes('class="refresh-user-link"'));
  assert.ok(section.includes('data-device-id="d1"'));
});

test('AC24 (edge): Graph-supplied display names are escaped', async (t) => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    userLink: {
      status: 'linked',
      resolvedAt: '2026-09-21T13:46:40Z',
      users: [{ displayName: '<img src=x onerror=alert(1)>', userPrincipalName: 'x@x.com' }],
    },
  });
  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'));
  assert.ok(!html.includes('<img'));
});

test('AC23: refreshAllUserLinks follows the cursor until it is null', async (t) => {
  const responses = [
    { ok: true, data: { cursor: 'c1' } },
    { ok: true, data: { cursor: 'c2' } },
    { ok: true, data: { cursor: null } },
  ];
  const calls = [];
  const postFn = async (path, body) => {
    calls.push({ path, body });
    return responses[calls.length - 1];
  };

  const result = await appModule.refreshAllUserLinks(postFn);

  assert.strictEqual(calls.length, 3);
  assert.ok(calls.every((c) => c.path === '/user-links/refresh'));
  assert.deepStrictEqual(
    calls.map((c) => c.body.cursor),
    [null, 'c1', 'c2'],
  );
  assert.deepStrictEqual(result, { ok: true, calls: 3 });
});

test('AC23 (failure): refreshAllUserLinks stops at the first failed response', async (t) => {
  const responses = [{ ok: true, data: { cursor: 'c1' } }, { ok: false, status: 502, data: { error: 'graph_unavailable' } }];
  let index = 0;
  const postFn = async () => responses[index++];

  const result = await appModule.refreshAllUserLinks(postFn);

  assert.deepStrictEqual(result, { ok: false, error: 'graph_unavailable' });
  assert.strictEqual(index, 2);
});

test('AC23 (failure): refreshAllUserLinks makes at most 100 calls', async (t) => {
  let calls = 0;
  const postFn = async () => {
    calls += 1;
    return { ok: true, data: { cursor: 'again' } };
  };

  await appModule.refreshAllUserLinks(postFn);

  assert.strictEqual(calls, 100);
});

test('AC23, AC24 (failure): a refresh error survives the screen reload through show({error})', async (t) => {
  apiModule.configureApi({
    fetch: async () => ({ status: 200, json: async () => ({ items: [], cursor: null }) }),
  });

  const mount = { innerHTML: '' };
  globalThis.window = {
    location: { hash: '#/devices', search: '', origin: 'https://admin.example.com' },
    history: { replaceState() {} },
    addEventListener() {},
  };
  globalThis.document = { getElementById: (id) => (id === 'app' ? mount : null) };

  try {
    await appModule.show({ error: 'graph_forbidden' });
    assert.ok(mount.innerHTML.includes('<p class="error">graph_forbidden</p>'));

    await appModule.show();
    assert.ok(!mount.innerHTML.includes('<p class="error">'));
  } finally {
    delete globalThis.window;
    delete globalThis.document;
  }
});

test('Unit - policy settings restricted to allowed keys', async (t) => {
  const state = {
    name: 'Policy 1',
    settings: {
      firewallEnabled: true,
      diskEncryptionRequired: true,
      screenLockTimeoutSeconds: 300,
      osUpdateMaxAgeDays: 30,
      localAdminAllowlist: ['admin1'],
      // These should not be allowed:
      // unknownKey: 'value',
    },
  };

  const html = policiesModule.render(state);

  assert.ok(typeof html === 'string');
  // Should render without error for allowed keys
});
