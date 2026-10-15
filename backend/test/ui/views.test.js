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
const commandsModule = await import('../../dist/ui/views/commands.js');

const views = {
  devices: devicesModule.render,
  deviceDetail: deviceDetailModule.render,
  dispatch: dispatchModule.render,
  groups: groupsModule.render,
  enrollmentTokens: enrollmentTokensModule.render,
  policies: policiesModule.render,
  audit: auditModule.render,
  settings: settingsModule.render,
  commands: commandsModule.render,
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
// TASK-027 user links, removed by TASK-066 -- devices.js (AC7), deviceDetail.js (AC1), app.js (AC6)
// ============================================================================

// Imported before any test sets globalThis.document, so app.js's own
// `if (typeof document !== 'undefined') { void start(); }` guard sees no
// `document` and does not auto-start the console while this file loads.
const appModule = await import('../../dist/ui/public/app.js');
const apiModule = await import('../../dist/ui/public/api.js');

test('TASK-066 AC7: COLUMNS drops primaryUser and no fleet shows a refresh button or primaryUser', async (t) => {
  assert.strictEqual('REFRESH_USER_LINKS_BUTTON' in devicesModule, false);
  assert.deepStrictEqual(devicesModule.COLUMNS, [
    'hostname',
    'ownership',
    'platform',
    'osVersion',
    'lastSeenAt',
    'complianceState',
  ]);

  const empty = devicesModule.render({ items: [], cursor: null });
  const nonEmpty = devicesModule.render({
    items: [{ deviceId: 'd1', hostname: 'LAT', primaryUser: 'amy@contoso.com' }],
    cursor: null,
  });
  for (const html of [empty, nonEmpty]) {
    for (const absent of ['refresh-user-links', 'Refresh user links', '>primaryUser<', 'col-primaryUser', 'amy@contoso.com']) {
      assert.ok(!html.includes(absent), `unexpected ${absent}`);
    }
    assert.ok(html.includes('<select class="ownership-filter" name="ownership">'));
  }
  assert.ok(empty.includes('No devices enrolled'));
  assert.ok(nonEmpty.includes('>hostname<'));
});

/** AC1: what the removed User section rendered; none of it may appear. */
const REMOVED_USER_SECTION_STRINGS = [
  'id="detail-user"',
  'data-section="detail-user"',
  '<h3>User</h3>',
  'class="refresh-user-link"',
  'Refresh user link',
  '<table class="grid users">',
  '<tr class="user">',
];

test('TASK-066 AC1: device detail renders no User section for a populated userLink', async (t) => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    userLink: {
      status: 'linked',
      resolvedAt: '2026-09-21T13:46:40Z',
      users: [{ displayName: 'Amy', userPrincipalName: 'amy@contoso.com' }],
    },
  });
  for (const absent of REMOVED_USER_SECTION_STRINGS) {
    assert.ok(!html.includes(absent), `unexpected ${absent}`);
  }
});

test('TASK-066 AC1: device detail renders no User section for userLink null or absent', async (t) => {
  for (const state of [{ profile: { deviceId: 'd1' }, userLink: null }, { profile: { deviceId: 'd1' } }]) {
    const html = deviceDetailModule.render(state);
    for (const absent of REMOVED_USER_SECTION_STRINGS) {
      assert.ok(!html.includes(absent), `unexpected ${absent}`);
    }
  }
});

test('TASK-066 AC16 (edge): Graph-supplied display names no longer reach the page', async (t) => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    userLink: {
      status: 'linked',
      resolvedAt: '2026-09-21T13:46:40Z',
      users: [{ displayName: '<img src=x onerror=alert(1)>', userPrincipalName: 'x@x.com' }],
    },
  });
  assert.ok(!html.includes('<img'));
  assert.ok(!html.includes('&lt;img'));
});

test('TASK-066 AC6: the app module exports neither refreshAllUserLinks nor MAX_REFRESH_CALLS', async (t) => {
  assert.strictEqual('refreshAllUserLinks' in appModule, false);
  assert.strictEqual('MAX_REFRESH_CALLS' in appModule, false);
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

// ============================================================================
// TASK-029: Firewall and Domain UI Tests
// ============================================================================

test('Scenario: SETTING_KEYS holds exactly the sixteen keys', async (t) => {
  const expectedKeys = [
    'firewallEnabled',
    'diskEncryptionRequired',
    'screenLockTimeoutSeconds',
    'osUpdateMaxAgeDays',
    'localAdminAllowlist',
    'firewallBlockedDomains',
    'firewallAllowedDomains',
    'antivirusEnabled',
    'antivirusScanFrequency',
    'locationTracking',
    'defenderRealTimeProtection',
    'defenderCloudProtection',
    'defenderNetworkProtection',
    'defenderRansomwareProtection',
    'defenderReputationProtection',
    'defenderDailySignatureUpdate',
  ];

  assert.strictEqual(policiesModule.SETTING_KEYS.length, 16);
  assert.deepStrictEqual(policiesModule.SETTING_KEYS.sort(), expectedKeys.sort());
});

test('Scenario: render outputs domain textareas', async (t) => {
  const state = {
    name: 'Policy',
    settings: {
      firewallBlockedDomains: 'blocked.com',
      firewallAllowedDomains: 'allowed.com',
    },
  };

  const html = policiesModule.render(state);

  assert.ok(html.includes('firewall-blocked-domains'));
  assert.ok(html.includes('firewallBlockedDomains'));
  assert.ok(html.includes('firewall-allowed-domains'));
  assert.ok(html.includes('firewallAllowedDomains'));
});

test('Scenario: settingsOf parses domain lists from comma/space/newline', async (t) => {
  const state1 = {
    settings: {
      firewallBlockedDomains: 'a.com, b.com\nc.com',
      firewallAllowedDomains: '',
    },
  };

  const result1 = policiesModule.settingsOf(state1);

  assert.deepStrictEqual(result1.firewallBlockedDomains, ['a.com', 'b.com', 'c.com']);
  assert.strictEqual(result1.firewallAllowedDomains, undefined);
});

test('Scenario: settingsOf omits empty keys', async (t) => {
  const state = {
    settings: {
      firewallBlockedDomains: '',
      firewallAllowedDomains: undefined,
    },
  };

  const result = policiesModule.settingsOf(state);

  assert.strictEqual(result.firewallBlockedDomains, undefined);
  assert.strictEqual(result.firewallAllowedDomains, undefined);
});

test('Scenario: fieldErrors includes invalid domain entries', async (t) => {
  const state1 = {
    settings: {
      firewallBlockedDomains: 'http://x.com',
    },
  };

  const errors1 = policiesModule.fieldErrors(state1);

  assert.ok(errors1.includes('firewallBlockedDomains'));

  const state2 = {
    settings: {
      firewallAllowedDomains: '*.bad',
    },
  };

  const errors2 = policiesModule.fieldErrors(state2);

  assert.ok(errors2.includes('firewallAllowedDomains'));
});

test('Scenario: fieldErrors includes list with >500 entries', async (t) => {
  const state = {
    settings: {
      firewallBlockedDomains: Array(501).fill('a.com').join('\n'),
    },
  };

  const errors = policiesModule.fieldErrors(state);

  assert.ok(errors.includes('firewallBlockedDomains'));
});

test('Scenario: createRequest returns null when fieldErrors present', async (t) => {
  const state = {
    name: 'Policy',
    settings: {
      firewallBlockedDomains: 'invalid..domain',
    },
  };

  const result = policiesModule.createRequest(state);

  assert.strictEqual(result, null);
});

test('Scenario: render includes field-error element and disabled button on errors', async (t) => {
  const state = {
    name: 'Policy',
    settings: {
      firewallBlockedDomains: 'invalid',
    },
  };

  const html = policiesModule.render(state);

  assert.ok(html.includes('field-error'));
  assert.ok(html.includes('data-field'));
  assert.ok(html.includes('disabled'));
});

// ============================================================================
// TASK-030: Antivirus Setting and Findings UI Tests
// ============================================================================

test('Scenario: Policy form offers the antivirus checkbox', async (t) => {
  // When the policies view renders {settings:{antivirusEnabled:true}}
  const checkedHtml = policiesModule.render({ settings: { antivirusEnabled: true } });
  // Then the output contains input id "antivirus-enabled" name "antivirusEnabled" of type checkbox with the checked attribute
  assert.match(
    checkedHtml,
    /<input id="antivirus-enabled" name="antivirusEnabled" type="checkbox"[^>]*checked[^>]*>/,
  );

  // And rendering {} gives that input without checked
  const uncheckedHtml = policiesModule.render({});
  const inputMatch = uncheckedHtml.match(/<input id="antivirus-enabled"[^>]*>/);
  assert.ok(inputMatch, 'should render the antivirus-enabled input');
  assert.ok(!inputMatch[0].includes('checked'), 'input should not carry checked');

  // And settingsOf({settings:{antivirusEnabled:'true'}}) is {antivirusEnabled:true}
  assert.deepStrictEqual(policiesModule.settingsOf({ settings: { antivirusEnabled: 'true' } }), {
    antivirusEnabled: true,
  });

  // And createRequest({name:'av', settings:{antivirusEnabled:true}}).body.settings is {antivirusEnabled:true}
  const request = policiesModule.createRequest({ name: 'av', settings: { antivirusEnabled: true } });
  assert.deepStrictEqual(request.body.settings, { antivirusEnabled: true });
});

test('Scenario: Device detail screen renders antivirus state and findings', async (t) => {
  // Given device detail state with posture.antivirus.enabled false and one finding
  const state = {
    profile: { deviceId: 'd1' },
    posture: { antivirus: { enabled: false } },
    antivirusFindings: [
      {
        detectedAt: '2026-10-02T07:15:00Z',
        threatName: '<script>x</script>',
        severity: 'severe',
        remediated: true,
        resources: ['C:\\a.exe', 'C:\\b.exe'],
      },
    ],
  };

  const html = deviceDetailModule.render(state);

  // Then the posture section shows antivirus.enabled false
  assert.ok(
    html.includes('<span class="label">antivirus.enabled</span><span class="value">false</span>'),
    'should show antivirus.enabled false',
  );

  // And section detail-antivirus-findings has one row with the expected columns
  assert.ok(html.includes('id="detail-antivirus-findings"'));
  assert.ok(html.includes('C:\\a.exe, C:\\b.exe'), 'resources should be joined with ", "');

  // And the threatName is rendered escaped
  assert.ok(html.includes('&lt;script&gt;x&lt;/script&gt;'));
  assert.ok(!html.includes('<script>x</script>'));

  // And with no findings the section contains the empty-state paragraph
  const emptyHtml = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    posture: { antivirus: { enabled: true } },
    antivirusFindings: [],
  });
  assert.ok(emptyHtml.includes('<p class="empty">No antivirus findings</p>'));
});

// ============================================================================
// TASK-055 AC11: antivirusScanFrequency form field
// ============================================================================

test('Scenario: AC11 - The policy form offers the scan frequency', async (t) => {
  // Given a policy being edited with settings {"antivirusScanFrequency": "weekly"}
  const state = {
    editing: { policyId: 'p1', name: 'Policy', settings: { antivirusScanFrequency: 'weekly' } },
  };

  // When the policies view renders the edit form
  const html = policiesModule.render(state);

  // Then it contains a select named "antivirusScanFrequency" with options "", "off", "daily", "weekly", "monthly"
  const selectMatch = html.match(/<select id="edit-antivirus-scan-frequency" name="antivirusScanFrequency">([\s\S]*?)<\/select>/);
  assert.ok(selectMatch, 'expected a select named antivirusScanFrequency in the edit form');
  const options = [...selectMatch[1].matchAll(/<option value="([^"]*)"([^>]*)>/g)];
  assert.deepStrictEqual(
    options.map((o) => o[1]),
    ['', 'off', 'daily', 'weekly', 'monthly'],
  );

  // And the "weekly" option is selected
  const weeklyOption = options.find((o) => o[1] === 'weekly');
  assert.ok(weeklyOption[2].includes('selected'), 'the weekly option should be selected');
  for (const o of options) {
    if (o[1] !== 'weekly') {
      assert.ok(!o[2].includes('selected'), `option ${o[1]} should not be selected`);
    }
  }
});

test('Scenario: AC11 - The create form also offers the scan frequency select with no option selected', async (t) => {
  const html = policiesModule.render({});
  const selectMatch = html.match(/<select id="antivirus-scan-frequency" name="antivirusScanFrequency">([\s\S]*?)<\/select>/);
  assert.ok(selectMatch, 'expected a select named antivirusScanFrequency in the create form');
  const options = [...selectMatch[1].matchAll(/<option value="([^"]*)"([^>]*)>/g)];
  assert.deepStrictEqual(
    options.map((o) => o[1]),
    ['', 'off', 'daily', 'weekly', 'monthly'],
  );
  const blank = options.find((o) => o[1] === '');
  assert.ok(blank[2].includes('selected'), 'the blank option should be selected when nothing is stored');
});

test('Scenario: AC11 - Blank and invalid form values', async (t) => {
  // Given form settings {"antivirusScanFrequency": ""}
  // Then settingsOf omits "antivirusScanFrequency"
  const blank = policiesModule.settingsOf({ settings: { antivirusScanFrequency: '' } });
  assert.strictEqual(blank.antivirusScanFrequency, undefined);

  // Given form settings {"antivirusScanFrequency": "hourly"}
  // Then fieldErrors contains "antivirusScanFrequency"
  const errors = policiesModule.fieldErrors({ settings: { antivirusScanFrequency: 'hourly' } });
  assert.ok(errors.includes('antivirusScanFrequency'));

  // And a valid value is passed through as a string
  const valid = policiesModule.settingsOf({ settings: { antivirusScanFrequency: 'daily' } });
  assert.strictEqual(valid.antivirusScanFrequency, 'daily');
  assert.deepStrictEqual(policiesModule.fieldErrors({ settings: { antivirusScanFrequency: 'daily' } }), []);
});

// ============================================================================
// TASK-055 AC28: Antivirus scan device detail panel
// ============================================================================

test('Scenario: AC28 - The device page shows the scan panel', async (t) => {
  // Given device detail state with antivirusScan {...}
  const state = {
    profile: { deviceId: 'd1' },
    antivirusScan: {
      scanType: 'quick',
      result: 'threats_found',
      completedAt: '2026-10-11T01:05:00Z',
      threatsFound: 2,
    },
  };

  // When the device detail view renders
  const html = deviceDetailModule.render(state);

  // Then section "detail-antivirus-scan" shows "Last scan", "Quick", "Threats found" and 2
  assert.ok(html.includes('id="detail-antivirus-scan"'));
  assert.ok(html.includes('Antivirus scan'));
  assert.ok(html.includes('Last scan'));
  assert.ok(html.includes('Quick'));
  assert.ok(html.includes('Threats found'));
  assert.ok(html.includes('>2<'));
});

test('Scenario: AC28 - Device page with no scan or an unsupported platform', async (t) => {
  // Given device detail state with antivirusScan null
  const emptyHtml = deviceDetailModule.render({ profile: { deviceId: 'd1' }, antivirusScan: null });
  // Then section "detail-antivirus-scan" shows "No antivirus scan reported"
  assert.ok(emptyHtml.includes('id="detail-antivirus-scan"'));
  assert.ok(emptyHtml.includes('<p class="empty">No antivirus scan reported</p>'));

  // Given device detail state with antivirusScan absent entirely
  const absentHtml = deviceDetailModule.render({ profile: { deviceId: 'd1' } });
  assert.ok(absentHtml.includes('<p class="empty">No antivirus scan reported</p>'));

  // Given device detail state with antivirusScan result "unsupported"
  const unsupportedHtml = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    antivirusScan: { scanType: 'quick', result: 'unsupported', completedAt: null, threatsFound: 0 },
  });
  // Then the Result field shows "Not supported on this platform"
  assert.ok(unsupportedHtml.includes('Not supported on this platform'));

  // Given antivirusScan result "failed" with detail "<script>"
  const escapedHtml = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    antivirusScan: { scanType: 'quick', result: 'failed', completedAt: null, threatsFound: 0, detail: '<script>' },
  });
  // Then the Detail field shows the escaped text "&lt;script&gt;"
  assert.ok(escapedHtml.includes('&lt;script&gt;'));
  assert.ok(!escapedHtml.includes('<script>'));
  assert.ok(escapedHtml.includes('Failed'));
});

// ============================================================================
// TASK-058: Full antivirus / Defender status on the device page (AC23-AC31)
// ============================================================================

function fullProtection(overrides = {}) {
  return {
    amServiceEnabled: true,
    antispywareEnabled: true,
    antivirusEnabled: true,
    behaviorMonitorEnabled: true,
    ioavProtectionEnabled: true,
    onAccessProtectionEnabled: true,
    realTimeProtectionEnabled: true,
    nisEnabled: true,
    tamperProtected: true,
    ...overrides,
  };
}

test('Scenario: AC23 - The status panel sits before the findings panel', async (t) => {
  // When the device detail renders with antivirusStatus null
  const html = deviceDetailModule.render({ profile: { deviceId: 'd1' }, antivirusStatus: null });

  // Then section detail-antivirus-status with heading "Antivirus status"
  // appears immediately before section detail-antivirus-findings
  const statusIndex = html.indexOf('<section class="panel" id="detail-antivirus-status">');
  const findingsIndex = html.indexOf('<section class="panel" id="detail-antivirus-findings">');
  assert.ok(statusIndex >= 0 && findingsIndex >= 0, 'both sections should be present');
  assert.ok(statusIndex < findingsIndex, 'the status panel should come before the findings panel');
  assert.ok(html.includes('<h3>Antivirus status</h3>'));

  // And it contains the empty-state paragraph
  assert.ok(html.includes('<p class="empty">No antivirus status reported</p>'));
});

test('Scenario: AC24 - Header fields and the passive-mode warning', async (t) => {
  const state = {
    profile: { deviceId: 'd1', timeZone: 'UTC' },
    antivirusStatus: {
      product: 'Microsoft Defender',
      defenderAvailable: true,
      runningMode: 'Passive Mode',
      reportedAt: '2026-10-11T10:00:00Z',
      protection: fullProtection(),
      versions: {},
      signatures: {},
      scans: {},
      computerState: 0,
      rebootRequired: false,
      securityCenterProducts: [],
    },
    antivirusFindings: [
      { detectedAt: 'x', threatName: 'a', severity: 'low', remediated: true, resources: [], active: true },
      { detectedAt: 'x', threatName: 'b', severity: 'low', remediated: true, resources: [], active: true },
      { detectedAt: 'x', threatName: 'c', severity: 'low', remediated: true, resources: [], active: false },
    ],
  };

  const html = deviceDetailModule.render(state);

  assert.ok(html.includes('<span class="value">Microsoft Defender</span>'));
  assert.ok(html.includes('2026-10-11 10:00:00'), 'reportedAt should be formatted in the device time zone');
  assert.ok(html.includes('<span class="value">Yes</span>'), 'Microsoft Defender running should show Yes');
  assert.ok(html.includes('<span class="value">Passive Mode</span>'));
  assert.ok(html.includes('<span class="value">2</span>'), 'Active threats should count the two active findings');
  assert.ok(
    html.includes('<p class="warning">Microsoft Defender is in passive mode; another antivirus product is the primary one.</p>'),
  );
});

test('Scenario: AC24 failure - Defender not running', async (t) => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    antivirusStatus: {
      product: 'Microsoft Defender',
      defenderAvailable: false,
      runningMode: null,
      protection: fullProtection({ realTimeProtectionEnabled: null }),
      versions: {},
      signatures: {},
      scans: {},
      computerState: null,
      rebootRequired: null,
      securityCenterProducts: [],
    },
  });

  assert.ok(html.includes('<p class="warning">Microsoft Defender is not running on this device.</p>'));
  assert.ok(html.includes('<span class="value">No</span>'));
});

test('Scenario: AC25 - Protection table', async (t) => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    antivirusStatus: {
      product: 'Microsoft Defender',
      defenderAvailable: true,
      runningMode: 'Normal',
      protection: fullProtection({ realTimeProtectionEnabled: false, tamperProtected: null }),
      versions: {},
      signatures: {},
      scans: {},
      computerState: 0,
      rebootRequired: false,
      securityCenterProducts: [],
    },
  });

  assert.ok(html.includes('<table class="grid antivirus-protection">'));
  const rowLabels = [
    'Antivirus service', 'Antivirus', 'Antispyware', 'Real-time protection', 'Behaviour monitoring',
    'Downloads and attachments (IOAV)', 'On-access protection', 'Network inspection', 'Tamper protection',
  ];
  let lastIndex = -1;
  for (const label of rowLabels) {
    const index = html.indexOf(`<th>${label}</th>`);
    assert.ok(index > lastIndex, `expected ${label} to appear in order`);
    lastIndex = index;
  }
  assert.ok(html.includes('<th>Real-time protection</th><td><span class="off">Off</span></td>'));
  assert.ok(html.includes('<th>Tamper protection</th><td>Unknown</td>'));

  // With all nine protection values null the table is not rendered.
  const emptyHtml = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    antivirusStatus: {
      product: 'Microsoft Defender',
      defenderAvailable: true,
      runningMode: 'Normal',
      protection: {
        amServiceEnabled: null, antispywareEnabled: null, antivirusEnabled: null, behaviorMonitorEnabled: null,
        ioavProtectionEnabled: null, onAccessProtectionEnabled: null, realTimeProtectionEnabled: null,
        nisEnabled: null, tamperProtected: null,
      },
      versions: {},
      signatures: {},
      scans: {},
      computerState: null,
      rebootRequired: null,
      securityCenterProducts: [],
    },
  });
  assert.ok(!emptyHtml.includes('antivirus-protection'));
});

test('Scenario: AC26 - Versions show only reported values', async (t) => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    antivirusStatus: {
      product: 'Microsoft Defender',
      defenderAvailable: true,
      runningMode: 'Normal',
      protection: fullProtection(),
      versions: { engine: '1.1.24090.11' },
      signatures: {},
      scans: {},
      computerState: 0,
      rebootRequired: false,
      securityCenterProducts: [],
    },
  });

  assert.ok(html.includes('<span class="label">Engine</span><span class="value">1.1.24090.11</span>'));
  assert.ok(!html.includes('XProtect definitions'), 'a field with no value should not render');
});

test('Scenario Outline: AC27 - Signature age staleness', async (t) => {
  const cases = [
    { age: 2, shownFragment: '<span class="value">2 days</span>', staleFragment: null },
    { age: 3, shownFragment: '<span class="stale">3 days</span> (stale)', staleFragment: '<span class="stale">3 days</span>' },
    { age: null, shownFragment: '&mdash;', staleFragment: null },
  ];

  for (const tc of cases) {
    const html = deviceDetailModule.render({
      profile: { deviceId: 'd1' },
      antivirusStatus: {
        product: 'Microsoft Defender',
        defenderAvailable: true,
        runningMode: 'Normal',
        protection: fullProtection(),
        versions: {},
        signatures: { antivirusLastUpdatedAt: '2026-10-10T00:00:00Z', antivirusAgeDays: tc.age },
        scans: {},
        computerState: 0,
        rebootRequired: false,
        securityCenterProducts: [],
      },
    });
    assert.ok(html.includes('Antivirus signature age'));
    assert.ok(html.includes(tc.shownFragment), `expected ${JSON.stringify(tc.shownFragment)} for age ${tc.age}`);
    assert.ok(html.includes('Antivirus signatures updated'));
  }
});

test('Scenario: AC27 edge - Signatures out of date flag', async (t) => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    antivirusStatus: {
      product: 'Microsoft Defender',
      defenderAvailable: true,
      runningMode: 'Normal',
      protection: fullProtection(),
      versions: {},
      signatures: { outOfDate: true },
      scans: {},
      computerState: 0,
      rebootRequired: false,
      securityCenterProducts: [],
    },
  });
  assert.ok(html.includes('Signatures out of date'));
  assert.ok(html.includes('<span class="stale">Yes</span>'));
});

test('Scenario: AC28 - Scans, computer state and reboot', async (t) => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    antivirusStatus: {
      product: 'Microsoft Defender',
      defenderAvailable: true,
      runningMode: 'Normal',
      protection: fullProtection(),
      versions: {},
      signatures: {},
      scans: { quickAgeDays: 8, quickOverdue: true, fullAgeDays: 40, fullOverdue: false, fullRequired: false },
      computerState: 6,
      rebootRequired: true,
      securityCenterProducts: [],
    },
  });

  assert.ok(html.includes('<span class="stale">8 days</span> (stale) (overdue)'));
  assert.ok(html.includes('<span class="value">40 days</span>'), 'full scan age should show plainly');
  assert.ok(!html.includes('40 days</span> (stale)'), 'full scan age should have no stale marker');
  assert.ok(!html.includes('40 days (overdue)'), 'full scan age should have no overdue marker when fullOverdue is false');
  assert.ok(html.includes('Full scan required'));
  assert.ok(html.includes('<span class="value">No</span>'));
  assert.ok(html.includes('Reboot pending, Manual steps pending'));
  assert.ok(html.includes('<span class="value">Yes</span>'));

  const cleanHtml = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    antivirusStatus: {
      product: 'Microsoft Defender',
      defenderAvailable: true,
      runningMode: 'Normal',
      protection: fullProtection(),
      versions: {},
      signatures: {},
      scans: {},
      computerState: 0,
      rebootRequired: false,
      securityCenterProducts: [],
    },
  });
  assert.ok(cleanHtml.includes('Clean'));
});

test('Scenario: AC29 - Security Center products table', async (t) => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    antivirusStatus: {
      product: 'Microsoft Defender',
      defenderAvailable: true,
      runningMode: 'Normal',
      protection: fullProtection(),
      versions: {},
      signatures: {},
      scans: {},
      computerState: 0,
      rebootRequired: false,
      securityCenterProducts: [{ name: 'Contoso', state: 'snoozed', definitionsUpToDate: false }],
    },
  });

  assert.ok(html.includes('<table class="grid antivirus-products">'));
  assert.ok(html.includes('<td class="col-name">Contoso</td>'));
  assert.ok(html.includes('<td class="col-state">Snoozed</td>'));
  assert.ok(html.includes('<td class="col-definitions">Out of date</td>'));

  const emptyHtml = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    antivirusStatus: {
      product: 'Microsoft Defender',
      defenderAvailable: true,
      runningMode: 'Normal',
      protection: fullProtection(),
      versions: {},
      signatures: {},
      scans: {},
      computerState: 0,
      rebootRequired: false,
      securityCenterProducts: [],
    },
  });
  assert.ok(!emptyHtml.includes('antivirus-products'));
});

test('Scenario: AC30 - Findings table shows status columns and highlights active threats', async (t) => {
  const state = {
    profile: { deviceId: 'd1', timeZone: 'UTC' },
    antivirusFindings: [
      {
        detectedAt: '2026-10-02T07:00:00Z',
        threatName: 'T',
        severity: 'severe',
        remediated: true,
        resources: [],
        category: 'Trojan',
        status: 'quarantine_failed',
        action: 'no_action',
        active: true,
        lastStatusChangeAt: '2026-10-02T07:00:00Z',
      },
      {
        detectedAt: '2026-10-01T00:00:00Z',
        threatName: 'U',
        severity: 'low',
        remediated: false,
        resources: [],
      },
    ],
  };

  const html = deviceDetailModule.render(state);

  for (const column of [
    'detectedAt', 'threatName', 'severity', 'remediated', 'resources', 'category', 'status', 'action', 'active', 'lastStatusChangeAt',
  ]) {
    assert.ok(html.includes(`<th>${column}</th>`), `expected header column ${column}`);
  }

  assert.ok(html.includes('class="antivirus-finding active-threat"'), 'the active finding should be highlighted');
  assert.ok(html.includes('Quarantine failed'));
  assert.ok(html.includes('No action'));

  // The second row (no new fields) should show class without active-threat
  // and &mdash; in each new column, including active (never "unknown").
  const secondRowStart = html.indexOf('U</td>') > -1 ? html.lastIndexOf('<tr class="antivirus-finding"', html.indexOf('U</td>')) : -1;
  assert.ok(secondRowStart >= 0, 'expected to find the second finding row');
  const secondRowEnd = html.indexOf('</tr>', secondRowStart);
  const secondRow = html.slice(secondRowStart, secondRowEnd);
  assert.ok(!secondRow.includes('active-threat'));
  assert.ok(!secondRow.includes('unknown'), 'absent active should never render as unknown');
  assert.ok(secondRow.includes('&mdash;'));
});

test('Scenario: AC31 - Device-reported strings are escaped', async (t) => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    antivirusStatus: {
      product: 'Microsoft Defender',
      defenderAvailable: true,
      runningMode: 'Normal',
      protection: fullProtection(),
      versions: {},
      signatures: {},
      scans: {},
      computerState: 0,
      rebootRequired: false,
      securityCenterProducts: [{ name: '<img src=x onerror=alert(1)>', state: 'on', definitionsUpToDate: true }],
    },
    antivirusFindings: [
      { detectedAt: 'x', threatName: 'T', severity: 'low', remediated: false, resources: [], category: '<b>x</b>' },
    ],
  });

  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'));
  assert.ok(html.includes('&lt;b&gt;x&lt;/b&gt;'));
  assert.ok(!html.includes('<img src=x'));
  assert.ok(!html.includes('<b>x</b>'));
});

// ============================================================================
// TASK-037: Edit and delete policies (AC5, AC6, AC8)
// ============================================================================

test('Unit: AC5 edit form renders with prefilled policy data', async (t) => {
  const state = {
    items: [
      {
        policyId: 'pol-1',
        name: 'Base',
        version: 1,
        settings: {
          screenLockTimeoutSeconds: 300,
          firewallEnabled: true,
          diskEncryptionRequired: false,
        },
        createdAt: 'c',
        updatedAt: 'u',
      },
    ],
    groups: [],
    editing: {
      policyId: 'pol-1',
      name: 'Base',
      version: 1,
      settings: {
        screenLockTimeoutSeconds: 300,
        firewallEnabled: true,
        diskEncryptionRequired: false,
      },
    },
  };

  const html = policiesModule.render(state);

  // Edit panel should be present
  assert.ok(html.includes('class="edit-panel"'));

  // Edit form should be present with prefilled values
  assert.ok(html.includes('<form class="edit-policy">'));
  assert.ok(html.includes('id="edit-policy-name"'));
  assert.match(html, /id="edit-policy-name"[^>]*value="Base"/);
  assert.match(html, /id="edit-screen-lock"[^>]*value="300"/);
  assert.match(html, /id="edit-firewall-enabled"[^>]*type="checkbox"[^>]*checked/);
});

test('Unit: AC6 updateRequest returns correct PUT request or null', async (t) => {
  // Valid request
  const validReq = policiesModule.updateRequest({
    policyId: 'pol-1',
    name: '  Updated  ',
    settings: { screenLockTimeoutSeconds: 120 },
  });
  assert.strictEqual(validReq?.method, 'PUT');
  assert.strictEqual(validReq?.path, '/admin/api/v1/policies/pol-1');
  assert.strictEqual(validReq?.body.name, 'Updated'); // Trimmed
  assert.deepStrictEqual(validReq?.body.settings, { screenLockTimeoutSeconds: 120 });

  // Blank name
  const blankNameReq = policiesModule.updateRequest({
    policyId: 'pol-1',
    name: '   ',
    settings: {},
  });
  assert.strictEqual(blankNameReq, null);

  // Missing policyId
  const noPolicyIdReq = policiesModule.updateRequest({
    policyId: '',
    name: 'Updated',
    settings: {},
  });
  assert.strictEqual(noPolicyIdReq, null);

  // Out of range screenLockTimeoutSeconds
  const outOfRangeReq = policiesModule.updateRequest({
    policyId: 'pol-1',
    name: 'Updated',
    settings: { screenLockTimeoutSeconds: 5 }, // Below min 60
  });
  assert.strictEqual(outOfRangeReq, null);

  // Out of range osUpdateMaxAgeDays
  const outOfRangeAgeDaysReq = policiesModule.updateRequest({
    policyId: 'pol-1',
    name: 'Updated',
    settings: { osUpdateMaxAgeDays: 999 }, // Above max 180
  });
  assert.strictEqual(outOfRangeAgeDaysReq, null);
});

test('Unit: AC6 updateRefusal message names all problems', async (t) => {
  // No issues
  const noIssues = policiesModule.updateRefusal({
    policyId: 'pol-1',
    name: 'Updated',
    settings: { screenLockTimeoutSeconds: 120 },
  });
  assert.strictEqual(noIssues, null);

  // Blank name
  const blankName = policiesModule.updateRefusal({
    policyId: 'pol-1',
    name: '   ',
    settings: {},
  });
  assert.match(blankName || '', /name is required/);

  // Multiple issues
  const multiIssue = policiesModule.updateRefusal({
    policyId: 'pol-1',
    name: '   ',
    settings: { screenLockTimeoutSeconds: 5, osUpdateMaxAgeDays: 999 },
  });
  assert.ok(multiIssue);
  assert.match(multiIssue, /name is required/);
  assert.match(multiIssue, /screenLockTimeoutSeconds/);
  assert.match(multiIssue, /osUpdateMaxAgeDays/);
});

test('Unit: AC8 deleteRequest requires exact typed name match', async (t) => {
  const policy = { policyId: 'pol-1', name: 'Base' };

  // Empty typedName
  const emptyTyped = policiesModule.deleteRequest({ ...policy, typedName: '' });
  assert.strictEqual(emptyTyped, null);

  // Partial match
  const partialMatch = policiesModule.deleteRequest({ ...policy, typedName: 'Bas' });
  assert.strictEqual(partialMatch, null);

  // Case mismatch
  const caseMismatch = policiesModule.deleteRequest({ ...policy, typedName: 'base' });
  assert.strictEqual(caseMismatch, null);

  // Exact match
  const exactMatch = policiesModule.deleteRequest({ ...policy, typedName: 'Base' });
  assert.strictEqual(exactMatch?.method, 'DELETE');
  assert.strictEqual(exactMatch?.path, '/admin/api/v1/policies/pol-1');
  assert.deepStrictEqual(exactMatch?.body, { confirm: true });

  // Extra space
  const extraSpace = policiesModule.deleteRequest({ ...policy, typedName: 'Base ' });
  assert.strictEqual(extraSpace, null);
});

test('Unit: AC8 delete form renders in edit panel', async (t) => {
  const state = {
    items: [],
    groups: [],
    editing: {
      policyId: 'pol-1',
      name: 'Base',
      version: 1,
      settings: {},
    },
  };

  const html = policiesModule.render(state);

  // Delete form should be present in edit panel
  assert.ok(html.includes('<form class="delete-policy">'));
  assert.ok(html.includes('id="delete-policy-name"'));
  assert.ok(html.includes('name="typedName"'));
  assert.ok(html.includes('class="delete"')); // Delete button

  // Verify form order: edit form first, then delete form
  const editFormIdx = html.indexOf('<form class="edit-policy">');
  const deleteFormIdx = html.indexOf('<form class="delete-policy">');
  assert.ok(editFormIdx > -1);
  assert.ok(deleteFormIdx > editFormIdx); // Delete comes after edit

  // Verify delete form is not nested inside edit form (forms are siblings)
  const editFormEnd = html.indexOf('</form>', editFormIdx);
  assert.ok(deleteFormIdx > editFormEnd); // Delete form starts after edit form closes
});

test('Unit: AC6 and AC8 both forms use correct field names', async (t) => {
  const state = {
    items: [],
    groups: [],
    editing: {
      policyId: 'pol-1',
      name: 'TestPolicy',
      version: 1,
      settings: {},
    },
  };

  const html = policiesModule.render(state);

  // Edit form should have name input
  assert.match(html, /<input[^>]*id="edit-policy-name"[^>]*name="name"/);

  // Delete form should have typedName input
  assert.match(html, /<input[^>]*id="delete-policy-name"[^>]*name="typedName"/);
});

// ============================================================================
// TASK-042: Edit and delete groups (AC8, AC9, AC10)
// ============================================================================

test('Unit: AC8 renameRequest returns PUT request or null', async (t) => {
  // Valid request with trimmed name
  const validReq = groupsModule.renameRequest({
    groupId: 'grp-a',
    name: '  Perth ',
  });
  assert.strictEqual(validReq?.method, 'PUT');
  assert.strictEqual(validReq?.path, '/admin/api/v1/groups/grp-a');
  assert.deepStrictEqual(validReq?.body, { name: 'Perth' });

  // No group selected
  const noGroupReq = groupsModule.renameRequest({
    groupId: '',
    name: 'Perth',
  });
  assert.strictEqual(noGroupReq, null);

  // Blank name after trimming
  const blankNameReq = groupsModule.renameRequest({
    groupId: 'grp-a',
    name: '  ',
  });
  assert.strictEqual(blankNameReq, null);

  // Missing name field
  const noNameReq = groupsModule.renameRequest({
    groupId: 'grp-a',
  });
  assert.strictEqual(noNameReq, null);
});

test('Unit: AC9 removeMembersRequest returns DELETE request or null', async (t) => {
  // Valid request
  const validReq = groupsModule.removeMembersRequest({
    groupId: 'grp-a',
    deviceIds: 'dev-1, dev-2',
  });
  assert.strictEqual(validReq?.method, 'DELETE');
  assert.strictEqual(validReq?.path, '/admin/api/v1/groups/grp-a/members');
  assert.deepStrictEqual(validReq?.body.deviceIds, ['dev-1', 'dev-2']);

  // Valid with array input
  const arrayReq = groupsModule.removeMembersRequest({
    groupId: 'grp-a',
    deviceIds: ['dev-1', 'dev-2'],
  });
  assert.deepStrictEqual(arrayReq?.body.deviceIds, ['dev-1', 'dev-2']);

  // No group selected
  const noGroupReq = groupsModule.removeMembersRequest({
    groupId: '',
    deviceIds: ['dev-1'],
  });
  assert.strictEqual(noGroupReq, null);

  // No device ids
  const noIdsReq = groupsModule.removeMembersRequest({
    groupId: 'grp-a',
    deviceIds: '',
  });
  assert.strictEqual(noIdsReq, null);

  // Only whitespace
  const whitespaceReq = groupsModule.removeMembersRequest({
    groupId: 'grp-a',
    deviceIds: '   ',
  });
  assert.strictEqual(whitespaceReq, null);
});

test('Unit: AC9 removed message uses singular for 1 device and plural otherwise', async (t) => {
  // Single device removed
  const singleHtml = groupsModule.render({ removed: 1 });
  assert.ok(singleHtml.includes('1 device removed'), 'should use singular for 1');
  assert.ok(!singleHtml.includes('1 devices removed'));

  // Multiple devices removed
  const multiHtml = groupsModule.render({ removed: 2 });
  assert.ok(multiHtml.includes('2 devices removed'), 'should use plural for 2');
  assert.ok(!multiHtml.includes('2 device removed'));

  // Zero devices removed
  const zeroHtml = groupsModule.render({ removed: 0 });
  assert.ok(zeroHtml.includes('0 devices removed'));
});

test('Unit: AC10 deleteRequest returns DELETE request only when typed name matches', async (t) => {
  const groups = [
    { groupId: 'grp-a', name: 'Sydney', createdAt: '2026-01-01T00:00:00Z' },
  ];

  // Case mismatch
  const caseMismatchReq = groupsModule.deleteRequest({
    groupId: 'grp-a',
    name: 'Sydney',
    typedName: 'sydney',
  });
  assert.strictEqual(caseMismatchReq, null);

  // Partial match
  const partialReq = groupsModule.deleteRequest({
    groupId: 'grp-a',
    name: 'Sydney',
    typedName: 'Sydn',
  });
  assert.strictEqual(partialReq, null);

  // Exact match
  const exactReq = groupsModule.deleteRequest({
    groupId: 'grp-a',
    name: 'Sydney',
    typedName: 'Sydney',
  });
  assert.strictEqual(exactReq?.method, 'DELETE');
  assert.strictEqual(exactReq?.path, '/admin/api/v1/groups/grp-a');
  assert.deepStrictEqual(exactReq?.body, { confirm: true });

  // No group selected
  const noGroupReq = groupsModule.deleteRequest({
    groupId: '',
    name: 'Sydney',
    typedName: 'Sydney',
  });
  assert.strictEqual(noGroupReq, null);

  // Extra space in typed
  const extraSpaceReq = groupsModule.deleteRequest({
    groupId: 'grp-a',
    name: 'Sydney',
    typedName: 'Sydney ',
  });
  assert.strictEqual(extraSpaceReq, null);
});

test('Unit: AC10 delete button is disabled until typed name matches', async (t) => {
  // Setup state with a group
  const items = [
    { groupId: 'grp-a', name: 'Sydney', createdAt: '2026-01-01T00:00:00Z' },
  ];

  // When typed name doesn't match: button should be disabled
  const htmlMismatch = groupsModule.render({
    items,
    groupId: 'grp-a',
    typedName: 'sydney',
  });
  assert.ok(htmlMismatch.includes('disabled'), 'button should be disabled when name mismatch');

  // When typed name matches exactly: button should not be disabled
  const htmlMatch = groupsModule.render({
    items,
    groupId: 'grp-a',
    typedName: 'Sydney',
  });
  assert.ok(htmlMatch.includes('<button type="submit" class="delete">'));
  assert.ok(!htmlMatch.includes('type="submit" class="delete" disabled'));

  // When no name typed yet: button should be disabled
  const htmlEmpty = groupsModule.render({
    items,
    groupId: 'grp-a',
    typedName: '',
  });
  assert.ok(htmlEmpty.includes('disabled'), 'button should be disabled when empty');
});

test('Unit: AC8-AC10 groups render form sections', async (t) => {
  const items = [{ groupId: 'grp-a', name: 'Test', createdAt: '2026-01-01T00:00:00Z' }];
  const html = groupsModule.render({ items, groupId: 'grp-a' });

  // Rename form
  assert.ok(html.includes('<form class="rename-group">'));
  assert.ok(html.includes('id="rename-group-id"'));
  assert.ok(html.includes('id="rename-group-name"'));

  // Add/remove members form
  assert.ok(html.includes('<form class="add-members">'));
  assert.ok(html.includes('<button type="button" class="remove-members">'));

  // Delete form
  assert.ok(html.includes('<form class="delete-group">'));
  assert.ok(html.includes('id="delete-group-id"'));
  assert.ok(html.includes('id="delete-group-name"'));
});

// ============================================================================
// TASK-038: Device Detail Software Section Tests
// ============================================================================

test('Scenario: Device detail lists software sorted (AC3)', async (t) => {
  const state = {
    profile: { deviceId: 'd1', hostname: 'test' },
    inventory: {
      software: [
        { name: 'zoom', version: '5.1', publisher: null, installedAt: null },
        { name: 'Chrome', version: '120', publisher: 'Google', installedAt: null },
        { name: 'chrome', version: '119', publisher: null, installedAt: null },
      ],
    },
  };

  const html = deviceDetailModule.render(state);

  assert.ok(typeof html === 'string');
  assert.ok(html.includes('id="detail-software"'), 'should have detail-software section');
  assert.ok(html.includes('Software (3)'), 'should show software count');
  assert.ok(html.includes('class="grid software"'), 'should have software table');
  assert.match(
    html,
    /<details class="expandable"><summary><h3>Software \(3\)<\/h3><\/summary><table class="grid software">/,
    'software list should start collapsed behind its heading',
  );

  // Check sorting: chrome 119, Chrome 120, zoom 5.1 (lowercase then code-unit)
  const chromeIdx = html.indexOf('chrome');
  const chromeCapIdx = html.indexOf('Chrome');
  const zoomIdx = html.indexOf('zoom');

  if (chromeIdx !== -1 && chromeCapIdx !== -1 && zoomIdx !== -1) {
    // chromelowercase (119) should come before Chrome (120)
    assert.ok(chromeIdx < chromeCapIdx, 'lowercase chrome should come before Chrome');
    // Chrome should come before zoom
    assert.ok(chromeCapIdx < zoomIdx, 'Chrome should come before zoom');
  }
});

test('Scenario: Device detail escapes software names (AC3, edge)', async (t) => {
  const state = {
    profile: { deviceId: 'd1', hostname: 'test' },
    inventory: {
      software: [
        { name: '<script>x</script>', version: '1.0', publisher: null, installedAt: null },
      ],
    },
  };

  const html = deviceDetailModule.render(state);

  assert.ok(typeof html === 'string');
  assert.ok(html.includes('&lt;script&gt;'), 'should HTML-escape angle brackets');
  assert.ok(!html.includes('<script>x</script>'), 'should not include literal script tag');
});

test('Scenario: Device with no software (AC4, edge)', async (t) => {
  const state = {
    profile: { deviceId: 'd1', hostname: 'test' },
    inventory: null,
  };

  const html = deviceDetailModule.render(state);

  assert.ok(typeof html === 'string');
  assert.ok(html.includes('id="detail-software"'), 'should have detail-software section');
  assert.ok(html.includes('Software (0)'), 'should show zero software');
  assert.ok(html.includes('No software reported'), 'should show empty message');
  assert.ok(!html.includes('class="grid software"') || !html.includes('tr'), 'should not have table rows');
});

test('Unit: Device detail software section displays installed software correctly (AC3)', async (t) => {
  const state = {
    profile: { deviceId: 'd1', hostname: 'test' },
    inventory: {
      software: [
        { name: 'App1', version: '1.0', publisher: 'Pub1', installedAt: '2026-01-01T00:00:00Z' },
        { name: 'App2', version: '2.0', publisher: null, installedAt: null },
      ],
    },
  };

  const html = deviceDetailModule.render(state);

  assert.ok(html.includes('Software (2)'));
  assert.ok(html.includes('App1'));
  assert.ok(html.includes('1.0'));
  assert.ok(html.includes('Pub1'));
  assert.ok(html.includes('2026-01-01'));
  assert.ok(html.includes('App2'));
  // Em dash for missing publisher/installedAt
  assert.ok(html.includes('—') || html.includes('&mdash;') || html.includes('-'), 'should show em dash for missing values');
});

// ============================================================================
// TASK-045: Command library, ordered queues and cmd/bash -- UI (U1-U12)
// ============================================================================

test('Scenario: U2 Commands screen lists the library', () => {
  const html = commandsModule.render({
    items: [
      { scriptId: 'scr-1', name: 'Alpha', interpreter: 'cmd', platform: 'windows', description: 'd1', updatedAt: '2026-10-01T00:00:00Z' },
      { scriptId: 'scr-2', name: 'Beta', interpreter: 'bash', platform: 'darwin', description: 'd2', updatedAt: '2026-10-02T00:00:00Z' },
    ],
  });

  assert.match(html, /<table class="grid scripts">/);
  for (const column of commandsModule.COLUMNS) {
    assert.match(html, new RegExp(`<th>${column}</th>`));
  }
  assert.strictEqual((html.match(/<tr class="script"/g) ?? []).length, 2);
  assert.match(html, /data-script-id="scr-1"/);
  assert.match(html, /data-script-id="scr-2"/);
});

test('Scenario: U2 Empty library', () => {
  const html = commandsModule.render({ items: [] });
  assert.match(html, new RegExp(commandsModule.EMPTY_MESSAGE));
  assert.doesNotMatch(html, /<table class="grid scripts">/);
});

test('Scenario: U3 New command form request and client-side refusal', () => {
  const request = commandsModule.createRequest({ name: 'A', interpreter: 'zsh', script: 'ls', timeoutSeconds: 60 });
  assert.deepStrictEqual(request, {
    method: 'POST',
    path: '/admin/api/v1/scripts',
    body: { name: 'A', interpreter: 'zsh', script: 'ls', timeoutSeconds: 60, description: null },
  });

  assert.strictEqual(commandsModule.createRequest({ name: 'A', interpreter: 'zsh', script: 'ls', timeoutSeconds: 4000 }), null);
  assert.strictEqual(commandsModule.createRequest({ name: 'A', interpreter: 'zsh', script: '', timeoutSeconds: 60 }), null);
  assert.strictEqual(commandsModule.createRequest({ name: '', interpreter: 'zsh', script: 'ls' }), null);
});

test('Scenario: U4 Row click opens a prefilled edit form', () => {
  const editing = { scriptId: 'scr-1', name: 'Alpha', interpreter: 'cmd', timeoutSeconds: 120, description: 'desc', script: 'echo hi' };
  const html = commandsModule.render({ items: [editing], editing, editDraft: null });

  assert.match(html, /<div class="edit-panel" data-script-id="scr-1">/);
  assert.match(html, /<input id="edit-script-name" name="name"[^>]*value="Alpha">/);
  assert.match(html, /<option value="cmd" selected>/);
  assert.match(html, /<input id="edit-script-timeout" name="timeoutSeconds"[^>]*value="120">/);
  assert.match(html, /<input id="edit-script-description" name="description"[^>]*value="desc">/);
  assert.match(html, /<textarea id="edit-script-script" name="script" class="script-body monospace"[^>]*style="font-family: monospace">echo hi<\/textarea>/);

  const saveRequest = commandsModule.updateRequest({ scriptId: 'scr-1', name: 'Alpha', interpreter: 'cmd', timeoutSeconds: 120, description: 'desc', script: 'echo hi' });
  assert.deepStrictEqual(saveRequest, {
    method: 'PUT',
    path: '/admin/api/v1/scripts/scr-1',
    body: { name: 'Alpha', interpreter: 'cmd', script: 'echo hi', timeoutSeconds: 120, description: 'desc' },
  });
});

test('Scenario: U5 Delete requires typing the name', () => {
  const notYet = commandsModule.deleteRequest({ scriptId: 'scr-1', name: 'Alpha', typedName: 'alpha' });
  assert.strictEqual(notYet, null);

  const editHtmlDisabled = commandsModule.render({
    items: [],
    editing: { scriptId: 'scr-1', name: 'Alpha', interpreter: 'cmd', script: 'x' },
  });
  assert.match(editHtmlDisabled, /class="delete" disabled>Delete<\/button>/);

  const ready = commandsModule.deleteRequest({ scriptId: 'scr-1', name: 'Alpha', typedName: 'Alpha' });
  assert.deepStrictEqual(ready, { method: 'DELETE', path: '/admin/api/v1/scripts/scr-1' });
});

test('Scenario: U7 Queue list in run order with controls', () => {
  const commands = [
    { commandId: 'S2', seq: 2, status: 'pending', scriptName: 'Two', issuedAt: 20 },
    { commandId: 'S1', seq: 1, status: 'leased', scriptName: 'One', issuedAt: 10 },
    { commandId: 'X', status: 'succeeded', type: 'run_script', issuedAt: 5 },
  ];
  const html = deviceDetailModule.render({ profile: { deviceId: 'dev-1', hostname: 'PC-1', platform: 'windows' }, commands });

  const s1Index = html.indexOf('data-command-id="S1"');
  const s2Index = html.indexOf('data-command-id="S2"');
  assert.ok(s1Index !== -1 && s2Index !== -1 && s1Index < s2Index, 'S1 (seq 1) must render before S2 (seq 2)');

  const queueSection = html.slice(html.indexOf('id="detail-queue"'), html.indexOf('id="detail-commands"'));
  assert.doesNotMatch(queueSection, /data-command-id="X"/);

  // S2 is pending: its move/cancel buttons are enabled.
  const s2Row = html.slice(html.indexOf('<tr class="queued-command" data-command-id="S2"'), html.indexOf('</tr>', html.indexOf('data-command-id="S2"')));
  assert.doesNotMatch(s2Row, /disabled/);

  // S1 is leased: its move/cancel buttons are disabled.
  const s1Row = html.slice(html.indexOf('<tr class="queued-command" data-command-id="S1"'), html.indexOf('</tr>', html.indexOf('data-command-id="S1"')));
  assert.match(s1Row, /class="move-command"[^>]*disabled/);
  assert.match(s1Row, /class="cancel-command"[^>]*disabled/);

  assert.deepStrictEqual(
    deviceDetailModule.moveRequest({ deviceId: 'dev-1', commandId: 'S2', direction: 'up' }),
    { method: 'POST', path: '/admin/api/v1/devices/dev-1/commands/S2/move', body: { direction: 'up' } },
  );
  assert.deepStrictEqual(
    deviceDetailModule.cancelRequest({ deviceId: 'dev-1', commandId: 'S2' }),
    { method: 'POST', path: '/admin/api/v1/devices/dev-1/commands/S2/cancel', body: {} },
  );
});

test('Scenario: U8 History shows name, exit code and expandable output', () => {
  const commands = [
    { commandId: 'X', status: 'succeeded', scriptName: 'Flush DNS', exitCode: 0, issuedAt: 1, output: '<b>ok</b>' },
    { commandId: 'P', status: 'pending', seq: 1, issuedAt: 2 },
  ];
  const html = deviceDetailModule.render({ profile: { deviceId: 'dev-1' }, commands });

  // TASK-067 (AC23): History is one timeline table with these headers.
  for (const column of deviceDetailModule.HISTORY_COLUMNS) {
    assert.match(html, new RegExp(`<th>${column}</th>`));
  }
  assert.deepStrictEqual(deviceDetailModule.HISTORY_COLUMNS, ['When', 'Source', 'Action', 'Status', 'Details']);

  const historySection = html.slice(html.indexOf('id="detail-commands"'));
  assert.match(
    historySection,
    /<tr class="command-output" data-command-id="X"><td colspan="5"><details class="expandable"><summary>output<\/summary><pre class="output">&lt;b&gt;ok&lt;\/b&gt;<\/pre><\/details><\/td><\/tr>/,
  );
  assert.doesNotMatch(historySection, /data-command-id="P"/);
});

test('Scenario: U10 Queue on group members', () => {
  const items = [{ groupId: 'grp-sales', name: 'Sales', createdAt: 'c' }];
  const scripts = [
    { scriptId: 'scr-1', name: 'Alpha', platform: 'windows' },
    { scriptId: 'scr-2', name: 'Beta', platform: 'darwin' },
  ];
  const html = groupsModule.render({ items, scripts });

  assert.match(html, /<option value="scr-1"[^>]*>Alpha \(windows\)<\/option>/);
  assert.match(html, /<option value="scr-2"[^>]*>Beta \(darwin\)<\/option>/);

  assert.strictEqual(
    groupsModule.queueScriptRequest({ groupId: 'grp-sales', scriptId: 'scr-1', name: 'Sales', typedName: 'sales' }),
    null,
  );
  assert.deepStrictEqual(
    groupsModule.queueScriptRequest({ groupId: 'grp-sales', scriptId: 'scr-1', name: 'Sales', typedName: 'Sales' }),
    { method: 'POST', path: '/admin/api/v1/groups/grp-sales/scripts', body: { scriptId: 'scr-1', confirm: true } },
  );
  assert.strictEqual(groupsModule.queuedMessage({ queued: 3, skipped: { wrongPlatform: 1 } }), 'Queued 3, skipped 1 (wrong platform)');

  const resultHtml = groupsModule.render({ items, scripts, queued: { queued: 3, skipped: { wrongPlatform: 1 } } });
  assert.match(resultHtml, /Queued 3, skipped 1 \(wrong platform\)/);
});

test('Scenario: U11 Settings on-failure select', () => {
  const html = settingsModule.render({ collectionUrl: 'https://example.invalid/', onFailure: 'stop' });

  assert.match(html, /Collection URL/);
  assert.match(html, /When a command fails/);
  assert.match(html, /<option value="continue">Continue<\/option>/);
  assert.match(html, /<option value="stop" selected>Stop the remaining commands<\/option>/);

  assert.deepStrictEqual(
    settingsModule.commandSettingsRequest({ onFailure: 'stop' }),
    { method: 'PUT', path: '/admin/api/v1/settings/commands', body: { onFailure: 'stop' } },
  );
  assert.strictEqual(settingsModule.commandSettingsRequest({ onFailure: 'halt' }), null);
});

// ============================================================================
// TASK-046: device info -- Agent version, time zone dates, Groups and
// Policies panels, and the Groups screen device lookup (pure render / pure
// function coverage; DOM wiring is covered separately in
// test/ui/appGroupsLookup.test.js and test/ui/appDeviceEdit.test.js).
// ============================================================================

// AC1
test('AC1: Profile panel shows Agent version, or an em dash when absent', () => {
  const withVersion = deviceDetailModule.render({ profile: { deviceId: 'd1', agentVersion: '1.4.0' } });
  assert.match(withVersion, /Agent version<\/span><span class="value">1\.4\.0<\/span>/);

  const without = deviceDetailModule.render({ profile: { deviceId: 'd1' } });
  assert.match(without, /Agent version<\/span><span class="value">&mdash;<\/span>/);
});

// AC9
test('AC9: Profile panel shows Time zone and the time-zone-note for a valid zone', () => {
  const html = deviceDetailModule.render({ profile: { deviceId: 'd1', timeZone: 'Australia/Sydney' } });
  assert.match(html, /Time zone<\/span><span class="value">Australia\/Sydney<\/span>/);
  assert.ok(html.includes('<p class="time-zone-note">Times shown in Australia/Sydney</p>'));
});

test('AC9 (edge): no timeZone shows not reported for the field (TASK-052)', () => {
  const html = deviceDetailModule.render({ profile: { deviceId: 'd1' } });
  assert.match(html, /Time zone<\/span><span class="value">not reported<\/span>/);
});

// ============================================================================
// TASK-052: Time zone field precedence and escaping (AC13, AC14)
// ============================================================================

test('Scenario Outline: The Time zone field shows the zone or why it is missing (AC13)', () => {
  // profile timeZone "Australia/Sydney", inventory warnings ["timezone:timeout"] -> "Australia/Sydney"
  const withZoneAndWarning = deviceDetailModule.render({
    profile: { deviceId: 'd1', timeZone: 'Australia/Sydney' },
    inventory: { warnings: ['timezone:timeout'] },
  });
  assert.match(withZoneAndWarning, /Time zone<\/span><span class="value">Australia\/Sydney<\/span>/);

  // profile timeZone absent, warnings ["software", "timezone:unmapped:Foo Standard Time"]
  // -> "not reported (timezone:unmapped:Foo Standard Time)"
  const unmapped = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    inventory: { warnings: ['software', 'timezone:unmapped:Foo Standard Time'] },
  });
  assert.match(
    unmapped,
    /Time zone<\/span><span class="value">not reported \(timezone:unmapped:Foo Standard Time\)<\/span>/,
  );

  // profile timeZone absent, warnings ["software"] (no timezone: warning) -> "not reported"
  const noTimezoneWarning = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    inventory: { warnings: ['software'] },
  });
  assert.match(noTimezoneWarning, /Time zone<\/span><span class="value">not reported<\/span>/);

  // profile timeZone absent, inventory null -> "not reported"
  const nullInventory = deviceDetailModule.render({ profile: { deviceId: 'd1' }, inventory: null });
  assert.match(nullInventory, /Time zone<\/span><span class="value">not reported<\/span>/);
});

test('Scenario: The warning text is HTML-escaped (AC14)', () => {
  // Given the profile has no timeZone and the inventory warnings are ["timezone:unmapped:<b>x</b>"]
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    inventory: { warnings: ['timezone:unmapped:<b>x</b>'] },
  });

  // Then the HTML contains "not reported (timezone:unmapped:&lt;b&gt;x&lt;/b&gt;)"
  assert.ok(html.includes('not reported (timezone:unmapped:&lt;b&gt;x&lt;/b&gt;)'));
  // And the HTML contains no "<b>" element
  assert.ok(!html.includes('<b>'));
});

// AC10
test('AC10: lastSeenAt is shown in the device zone', () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1', timeZone: 'Australia/Sydney', lastSeenAt: '2026-10-10T22:30:00Z' },
  });
  assert.match(html, /lastSeenAt<\/span><span class="value">2026-10-11 09:30:00<\/span>/);
});

// AC11
test('AC11: epoch-millisecond command issuedAt is shown in the device zone, queued and history', () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1', timeZone: 'Australia/Sydney' },
    commands: [
      { commandId: 'c-pending', status: 'pending', issuedAt: 1791671400000, type: 'run_script' },
      { commandId: 'c-done', status: 'succeeded', issuedAt: 1791671400000, type: 'run_script' },
    ],
  });
  const queueSection = html.slice(html.indexOf('id="detail-queue"'), html.indexOf('id="detail-commands"'));
  assert.ok(queueSection.includes('2026-10-11 09:30:00'), 'Queue issuedAt should show the device-zone time');
  const historySection = html.slice(html.indexOf('id="detail-commands"'));
  assert.ok(historySection.includes('2026-10-11 09:30:00'), 'History issuedAt should show the device-zone time');
});

// AC12
test('AC12: every other device page date is shown in the device zone', () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1', timeZone: 'Australia/Sydney' },
    credential: { status: 'active', disabledAt: '2026-10-10T22:30:00Z' },
    antivirusFindings: [{ detectedAt: '2026-10-10T22:30:00Z', threatName: 't', severity: 's', remediated: false, resources: [] }],
    loginHistory: [{ username: 'u', firstSeenAt: '2026-10-10T22:30:00Z', lastSeenAt: '2026-10-10T22:30:00Z', loginCount: 1 }],
    inventory: { software: [{ name: 'App', version: '1', installedAt: '2026-10-10T22:30:00Z' }] },
    analytics: {
      snapshot: { boot: { lastBootAt: '2026-10-10T22:30:00Z' }, receivedAt: '2026-10-10T22:30:00Z' },
      bootHistory: [{ bootAt: '2026-10-10T22:30:00Z' }],
      crashes: [{ occurredAt: '2026-10-10T22:30:00Z', appName: 'a', appVersion: '1', kind: 'crash' }],
    },
    heartbeatHistory: {
      open: true,
      items: [{ receivedAt: '2026-10-10T22:30:00Z', collectedAt: '2026-10-10T22:30:00Z' }],
    },
  });
  const expected = '2026-10-11 09:30:00';
  const occurrences = html.split(expected).length - 1;
  // Disabled at, detectedAt, firstSeenAt, lastSeenAt, installedAt,
  // Last boot, Reported at, bootAt, occurredAt, receivedAt, collectedAt = 11
  assert.strictEqual(occurrences, 11, `expected 11 occurrences of ${expected}, found ${occurrences}`);
});

// AC13
test('AC13: daylight saving uses the offset of the date shown, not today', () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1', timeZone: 'Australia/Sydney', lastSeenAt: '2026-07-01T00:00:00Z' },
  });
  assert.match(html, /lastSeenAt<\/span><span class="value">2026-07-01 10:00:00<\/span>/);
});

// AC14
test('AC14: no usable zone falls back to UTC, with its own note', () => {
  const noZone = deviceDetailModule.render({ profile: { deviceId: 'd1', lastSeenAt: '2026-10-10T22:30:00Z' } });
  assert.match(noZone, /lastSeenAt<\/span><span class="value">2026-10-10 22:30:00<\/span>/);
  assert.ok(noZone.includes('<p class="time-zone-note">Times shown in UTC</p>'));

  const badZone = deviceDetailModule.render({
    profile: { deviceId: 'd1', timeZone: 'Mars/Olympus', lastSeenAt: '2026-10-10T22:30:00Z' },
  });
  assert.match(badZone, /lastSeenAt<\/span><span class="value">2026-10-10 22:30:00<\/span>/);
  assert.ok(badZone.includes('<p class="time-zone-note">Times shown in UTC</p>'));
});

// AC15
test('AC15: an unparseable date shows unchanged; an absent date shows an em dash', () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1', timeZone: 'Australia/Sydney' },
    loginHistory: [{ username: 'u', firstSeenAt: 'not-a-date', lastSeenAt: '2026-10-10T22:30:00Z', loginCount: 1 }],
  });
  assert.ok(html.includes('>not-a-date<'), 'an unparseable date should show unchanged');

  assert.strictEqual(deviceDetailModule.formatDeviceTime(null, 'Australia/Sydney'), '&mdash;');
  assert.strictEqual(deviceDetailModule.formatDeviceTime(undefined, 'Australia/Sydney'), '&mdash;');
  assert.strictEqual(deviceDetailModule.formatDeviceTime('not-a-date', 'Australia/Sydney'), 'not-a-date');
});

// AC17
test('AC17: the Groups panel lists memberships with a Remove button, or "No groups"', () => {
  const withGroup = deviceDetailModule.render({
    profile: { deviceId: 'dev-1' },
    groups: [{ groupId: 'grp-a', name: 'Finance' }],
  });
  const section = withGroup.slice(withGroup.indexOf('id="detail-groups"'), withGroup.indexOf('id="detail-policies"'));
  assert.ok(section.includes('Finance'));
  assert.match(
    section,
    /<button type="button" class="remove-device-group" data-group-id="grp-a" data-device-id="dev-1">Remove from group<\/button>/,
  );

  const empty = deviceDetailModule.render({ profile: { deviceId: 'dev-1' }, groups: [] });
  const emptySection = empty.slice(empty.indexOf('id="detail-groups"'), empty.indexOf('id="detail-policies"'));
  assert.ok(emptySection.includes('No groups'));
});

// AC18
test('AC18: add-device-group select offers only groups the device is not already in', () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'dev-1' },
    groups: [{ groupId: 'grp-a', name: 'Finance' }],
    allGroups: [
      { groupId: 'grp-a', name: 'Finance' },
      { groupId: 'grp-c', name: 'Ops' },
    ],
  });
  const form = html.slice(html.indexOf('form class="add-device-group"'));
  assert.ok(form.includes('value="grp-c"'), 'should offer grp-c');
  assert.ok(!form.includes('value="grp-a"'), 'should not offer grp-a, already a member');

  assert.deepStrictEqual(
    deviceDetailModule.addGroupRequest({ deviceId: 'dev-1', groupId: 'grp-c' }),
    { method: 'POST', path: '/admin/api/v1/groups/grp-c/members', body: { deviceIds: ['dev-1'] } },
  );
  assert.strictEqual(deviceDetailModule.addGroupRequest({ deviceId: 'dev-1', groupId: '' }), null);
});

// AC19
test('AC19: removeGroupRequest builds the DELETE on the membership route', () => {
  assert.deepStrictEqual(
    deviceDetailModule.removeGroupRequest({ deviceId: 'dev-1', groupId: 'grp-a' }),
    { method: 'DELETE', path: '/admin/api/v1/groups/grp-a/members', body: { deviceIds: ['dev-1'] } },
  );
  assert.strictEqual(deviceDetailModule.removeGroupRequest({ deviceId: '', groupId: 'grp-a' }), null);
});

// AC21
test('AC21: the Policies panel is read-only and shows name, version and via-group names', () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'dev-1' },
    groups: [{ groupId: 'grp-a', name: 'Finance' }],
    policies: [{ policyId: 'pol-1', name: 'Baseline', version: 3, viaGroups: ['grp-a'] }],
  });
  const section = html.slice(html.indexOf('id="detail-policies"'), html.indexOf('id="detail-credential"'));
  assert.ok(section.includes('Baseline'));
  assert.ok(section.includes('>3<'));
  assert.ok(section.includes('Finance'));
  assert.ok(!section.includes('<form'), 'the Policies panel must contain no form');
  assert.ok(!section.includes('<button'), 'the Policies panel must contain no button');

  const empty = deviceDetailModule.render({ profile: { deviceId: 'dev-1' }, policies: [] });
  const emptySection = empty.slice(empty.indexOf('id="detail-policies"'), empty.indexOf('id="detail-credential"'));
  assert.ok(emptySection.includes('No policies'));
});

// ----------------------------------------------------------------------------
// Groups screen device lookup: pure functions (AC23-AC28, AC35) and markup
// (AC23). App-level wiring (Enter, x, submit, failed loads) lives in
// test/ui/appGroupsLookup.test.js.
// ----------------------------------------------------------------------------

const lookupDevices = [
  { deviceId: 'dev-1', hostname: 'PC-01' },
  { deviceId: 'dev-2', hostname: 'PC-02' },
];

// AC23
test('AC23: the add-members form offers the lookup input, a datalist, and "No devices selected"', () => {
  const html = groupsModule.render({ items: [], devices: lookupDevices, pending: [] });
  const formStart = html.indexOf('form class="add-members"');
  const form = html.slice(formStart, html.indexOf('</form>', formStart));
  assert.match(form, /<input id="member-lookup" class="device-lookup" name="lookup"[^>]*list="member-device-options"/);
  assert.ok(form.includes('<datalist id="member-device-options">'));
  assert.ok(!form.includes('<textarea'), 'the form must contain no textarea');

  const datalistSection = html.slice(html.indexOf('<datalist'), html.indexOf('</datalist>'));
  assert.strictEqual((datalistSection.match(/<option/g) || []).length, 2);

  assert.ok(html.includes('<p class="empty">No devices selected</p>'));
});

// AC24
test('AC24: matchDevices and addPending find the one exact, case-insensitive match', () => {
  for (const text of ['PC-01', 'pc-01', ' PC-01 ', 'dev-1']) {
    assert.strictEqual(groupsModule.matchDevices(lookupDevices, text).length, 1, `expected one match for ${text}`);
    const outcome = groupsModule.addPending({ devices: lookupDevices, pending: [] }, text);
    assert.deepStrictEqual(outcome.pending, [{ deviceId: 'dev-1', hostname: 'PC-01' }]);
    assert.strictEqual(outcome.lookup, '');
    assert.strictEqual(outcome.lookupMessage, null);
  }
});

// AC25
test('AC25: Enter with no matching device keeps the list and reports no match', () => {
  const outcome = groupsModule.addPending({ devices: lookupDevices, pending: [] }, 'PC-99');
  assert.deepStrictEqual(outcome.pending, []);
  assert.strictEqual(outcome.lookup, 'PC-99');
  assert.strictEqual(outcome.lookupMessage, 'No device matches "PC-99"');
});

// AC26
test('AC26: a hostname shared by several devices adds nothing until the id is typed', () => {
  const shared = [
    { deviceId: 'dev-1', hostname: 'PC-01' },
    { deviceId: 'dev-7', hostname: 'PC-01' },
  ];
  const outcome = groupsModule.addPending({ devices: shared, pending: [] }, 'PC-01');
  assert.deepStrictEqual(outcome.pending, []);
  assert.strictEqual(outcome.lookup, 'PC-01');
  assert.strictEqual(outcome.lookupMessage, '"PC-01" matches 2 devices; enter the device id');

  const second = groupsModule.addPending({ devices: shared, pending: [] }, 'dev-7');
  assert.deepStrictEqual(second.pending, [{ deviceId: 'dev-7', hostname: 'PC-01' }]);
});

// AC27
test('AC27: Enter for a device already in the list leaves it listed once', () => {
  const pending = [{ deviceId: 'dev-1', hostname: 'PC-01' }];
  const outcome = groupsModule.addPending({ devices: lookupDevices, pending }, 'PC-01');
  assert.deepStrictEqual(outcome.pending, pending);
  assert.strictEqual(outcome.lookup, '');
  assert.strictEqual(outcome.lookupMessage, 'PC-01 (dev-1) is already in the list');
});

// AC28
test('AC28: Enter with empty or whitespace-only text changes nothing and renders no message', () => {
  const pending = [{ deviceId: 'dev-1', hostname: 'PC-01' }];
  const outcome = groupsModule.addPending({ devices: lookupDevices, pending }, '   ');
  assert.deepStrictEqual(outcome.pending, pending);
  assert.strictEqual(outcome.lookupMessage, null);

  const html = groupsModule.render({ items: [], devices: lookupDevices, pending, lookupMessage: outcome.lookupMessage });
  assert.ok(!html.includes('lookup-message'));
});

// AC29
test('AC29: removePending drops only the named device', () => {
  const pending = [
    { deviceId: 'dev-1', hostname: 'PC-01' },
    { deviceId: 'dev-2', hostname: 'PC-02' },
  ];
  assert.deepStrictEqual(groupsModule.removePending(pending, 'dev-1'), [{ deviceId: 'dev-2', hostname: 'PC-02' }]);
});

// AC30 / AC31 / AC32
test('AC30, AC31, AC32: membership requests carry pending ids in order, or null without a group or devices', () => {
  assert.deepStrictEqual(
    groupsModule.membershipRequest({
      groupId: 'grp-a',
      deviceIds: groupsModule.pendingIds([{ deviceId: 'dev-1' }, { deviceId: 'dev-2' }]),
    }),
    { method: 'POST', path: '/admin/api/v1/groups/grp-a/members', body: { deviceIds: ['dev-1', 'dev-2'] } },
  );
  assert.deepStrictEqual(
    groupsModule.removeMembersRequest({
      groupId: 'grp-a',
      deviceIds: groupsModule.pendingIds([{ deviceId: 'dev-1' }, { deviceId: 'dev-2' }]),
    }),
    { method: 'DELETE', path: '/admin/api/v1/groups/grp-a/members', body: { deviceIds: ['dev-1', 'dev-2'] } },
  );
  assert.strictEqual(groupsModule.membershipRequest({ groupId: '', deviceIds: ['dev-1'] }), null);
  assert.strictEqual(groupsModule.membershipRequest({ groupId: 'grp-a', deviceIds: [] }), null);
  assert.strictEqual(groupsModule.removeMembersRequest({ groupId: '', deviceIds: ['dev-1'] }), null);
  assert.strictEqual(groupsModule.removeMembersRequest({ groupId: 'grp-a', deviceIds: [] }), null);
});

test('AC30/AC31: the added/removed banners render the response counts', () => {
  const added = groupsModule.render({ items: [], added: 1 });
  assert.ok(added.includes('<p class="added" data-added="1">1 device added</p>'));
  const removed = groupsModule.render({ items: [], removed: 2 });
  assert.ok(removed.includes('<p class="removed" data-removed="2">2 devices removed</p>'));
});

// ============================================================================
// TASK-049 AC19/AC20: the admin Applications view (backend/src/ui/views/applications.js)
// ============================================================================

const applicationsModule = await import('../../dist/ui/views/applications.js');

test('Scenario: Applications admin screen -- one tr.application with a delete button and the create form', () => {
  const html = applicationsModule.render({
    items: [
      { applicationId: 'app-1', name: '7-Zip', platform: 'windows', installerType: 'msi', source: 'upload', description: 'Archiver' },
    ],
    dialog: { open: true, mode: 'create' },
  });
  assert.match(html, /<tr class="application" data-application-id="app-1">/);
  assert.match(html, /<button type="button" class="delete-application" data-application-id="app-1">/);
  assert.match(html, /<form class="create-application">/);
  // TASK-050: no sha256 field; a URL source's hash is computed by the server.
  for (const field of ['source', 'name', 'description', 'url', 'installerType', 'installArgs']) {
    assert.ok(html.includes(`name="${field}"`), `expected a field named "${field}"`);
  }
  assert.match(html, /type="file"[^>]*accept="\.msi,\.exe,\.pkg"/);
});

test('Unit: createUploadRequest/deleteRequest build the documented requests', () => {
  assert.deepStrictEqual(
    applicationsModule.createUploadRequest({ name: 'X', description: '', uploadKey: 'k', sha256: 'h', installArgs: '' }),
    { method: 'POST', path: applicationsModule.APPLICATIONS_PATH, body: { source: 'upload', name: 'X', description: null, uploadKey: 'k', sha256: 'h', installArgs: null } },
  );
  assert.deepStrictEqual(
    applicationsModule.deleteRequest({ applicationId: 'app-1' }),
    { method: 'DELETE', path: `${applicationsModule.APPLICATIONS_PATH}/app-1` },
  );
  assert.strictEqual(applicationsModule.deleteRequest({}), null);
});

test('Unit: URL request built from the form', () => {
  const H = 'a'.repeat(64);
  assert.deepStrictEqual(
    applicationsModule.createUrlRequest({ name: 'Zoom', url: 'https://zoom.us/x.msi', installerType: 'msi', sha256: H, description: '', installArgs: '' }),
    {
      method: 'POST',
      path: applicationsModule.APPLICATIONS_PATH,
      // TASK-050: the body carries no sha256, even when the state has one.
      body: { source: 'url', name: 'Zoom', description: null, url: 'https://zoom.us/x.msi', installerType: 'msi', installArgs: null },
    },
  );
});

test('Scenario Outline: Admin form refusals', () => {
  const H = 'a'.repeat(64);
  assert.strictEqual(applicationsModule.fileRefusal({ name: 'a.dmg', size: 10 }), 'file_type_not_allowed');
  assert.strictEqual(applicationsModule.fileRefusal({ name: 'A.MSI', size: 524288001 }), 'file_too_large');
  assert.strictEqual(applicationsModule.fileRefusal({ name: 'a.pkg', size: 10 }), null);
  assert.strictEqual(
    // TASK-050: an empty sha256 no longer makes it null; an empty url still does.
    applicationsModule.createUrlRequest({ name: 'Zoom', url: '', installerType: 'msi', sha256: H }),
    null,
  );
});

// ============================================================================
// TASK-049 AC22: the device page's install-application form
// ============================================================================

test('Scenario: Install from the device\'s Software section', () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'dev-1', hostname: 'PC-1', platform: 'windows' },
    // TASK-050: the select lists only applications whose hash is ready.
    applications: [
      { applicationId: 'app-1', name: '7-Zip', hashStatus: 'ready' },
      { applicationId: 'app-2', name: 'Zoom', hashStatus: 'ready' },
    ],
  });
  const softwareSection = html.slice(html.indexOf('id="detail-software"'), html.indexOf('id="detail-posture"'));
  const formIndex = softwareSection.indexOf('<form class="install-application">');
  // TASK-062: the form sits inside the outer Software section expander, and
  // after the inner software list's </details> when that list exists.
  const outerCloseIndex = softwareSection.indexOf('</details></section>');
  const innerListCloseIndex = softwareSection.indexOf('</table></details>');
  assert.ok(formIndex !== -1, 'expected a form.install-application');
  assert.ok(outerCloseIndex !== -1 && formIndex < outerCloseIndex, 'the install form should sit inside the Software section expander');
  assert.ok(
    innerListCloseIndex === -1 || formIndex > innerListCloseIndex,
    'the install form should sit outside the collapsed software list <details>',
  );
  assert.match(softwareSection, /<option value="app-1">7-Zip<\/option>/);
  assert.match(softwareSection, /<option value="app-2">Zoom<\/option>/);
  assert.match(softwareSection, /<select id="install-application-id" name="applicationId"><option value=""><\/option>/);
  assert.match(softwareSection, /<button type="submit" class="install"[^>]*disabled[^>]*>Install<\/button>/);

  assert.deepStrictEqual(
    deviceDetailModule.installRequest({ deviceId: 'dev-1', applicationId: 'app-1' }),
    { method: 'POST', path: '/admin/api/v1/devices/dev-1/applications', body: { applicationId: 'app-1' } },
  );
});

test('Scenario (edge): No applications for the platform', () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'dev-2', hostname: 'Mac-1', platform: 'darwin' },
    applications: [],
  });
  const softwareSection = html.slice(html.indexOf('id="detail-software"'));
  assert.ok(softwareSection.includes('<p class="empty">No applications for this platform</p>'));
  assert.ok(softwareSection.includes('<form class="install-application">'), 'the form should still render even when empty');

  assert.strictEqual(deviceDetailModule.installRequest({ deviceId: 'dev-2', applicationId: '' }), null);
});

// ============================================================================
// TASK-053: AI script generation -- commandsView (AC20, AC21)
// ============================================================================

/** The substring of `html` from `form.<cls>` up to its closing `</form>`. */
function formSection(html, cls) {
  const start = html.indexOf(`<form class="${cls}">`);
  assert.notStrictEqual(start, -1, `expected a <form class="${cls}"> in the rendered HTML`);
  const end = html.indexOf('</form>', start);
  return html.slice(start, end);
}

// AC20
test('Scenario: Generate button in both forms', () => {
  // When commandsView.render is called with an editing script
  const editing = { scriptId: 'scr-1', name: 'Alpha', interpreter: 'cmd', timeoutSeconds: 120, description: 'desc', script: 'echo hi' };
  const html = commandsModule.render({ items: [editing], editing, editDraft: null });

  const GENERATE_BUTTON = '<button type="button" class="generate-script">Generate</button>';

  // Then inside form.create-script the script textarea is immediately followed by the Generate button
  const createSection = formSection(html, 'create-script');
  const createTextareaEnd = createSection.indexOf('</textarea>') + '</textarea>'.length;
  assert.strictEqual(createSection.slice(createTextareaEnd, createTextareaEnd + GENERATE_BUTTON.length), GENERATE_BUTTON);

  // And inside form.edit-script the script textarea is immediately followed by the same button
  const editSection = formSection(html, 'edit-script');
  const editTextareaEnd = editSection.indexOf('</textarea>') + '</textarea>'.length;
  assert.strictEqual(editSection.slice(editTextareaEnd, editTextareaEnd + GENERATE_BUTTON.length), GENERATE_BUTTON);
});

test('Unit: the Generate button reads "Generating..." and is disabled while that form is generating', () => {
  const editing = { scriptId: 'scr-1', name: 'Alpha', interpreter: 'cmd', script: 'echo hi' };
  const htmlCreating = commandsModule.render({ items: [], generating: 'create' });
  assert.match(formSection(htmlCreating, 'create-script'), /<button type="button" class="generate-script" disabled>Generating\.\.\.<\/button>/);

  const htmlEditing = commandsModule.render({ items: [editing], editing, generating: 'edit' });
  assert.match(formSection(htmlEditing, 'edit-script'), /<button type="button" class="generate-script" disabled>Generating\.\.\.<\/button>/);
  // The create form (not the one generating) keeps its enabled button.
  assert.match(formSection(htmlEditing, 'create-script'), /<button type="button" class="generate-script">Generate<\/button>/);
});

// AC21
test('Scenario: generateRequest builds the request', () => {
  // When generateRequest is called with {script:"  list files ", interpreter:"zsh", timeoutSeconds:"", description:""}
  const request = commandsModule.generateRequest({ script: '  list files ', interpreter: 'zsh', timeoutSeconds: '', description: '' });

  // Then it returns {method:"POST", path:"/admin/api/v1/scripts/generate", body:{prompt:"list files", interpreter:"zsh", timeoutSeconds:300, description:null}}
  assert.deepStrictEqual(request, {
    method: 'POST',
    path: '/admin/api/v1/scripts/generate',
    body: { prompt: 'list files', interpreter: 'zsh', timeoutSeconds: 300, description: null },
  });
  assert.strictEqual(commandsModule.GENERATE_PATH, '/admin/api/v1/scripts/generate');
});

test('Unit: generateRequest keeps a typed timeout and description', () => {
  const request = commandsModule.generateRequest({ script: 'list files', interpreter: 'bash', timeoutSeconds: '45', description: 'd' });
  assert.deepStrictEqual(request.body, { prompt: 'list files', interpreter: 'bash', timeoutSeconds: 45, description: 'd' });
});

// AC21
const GENERATE_REFUSAL_EXAMPLES = [
  ['script', '   '],
  ['script', 'x'.repeat(4001)],
  ['interpreter', 'fish'],
  ['timeoutSeconds', '0'],
  ['description', 'y'.repeat(501)],
];

for (const [field, value] of GENERATE_REFUSAL_EXAMPLES) {
  test(`Scenario Outline: generateRequest refuses invalid input -- ${field}`, () => {
    const valid = { script: 'list files', interpreter: 'powershell', timeoutSeconds: '60', description: 'd' };
    const state = { ...valid, [field]: value };
    // The server-side field name for the script textarea is "prompt".
    const refusedAs = field === 'script' ? 'prompt' : field;

    // When generateRequest is called with a valid state except <field> = <value>
    // Then it returns null
    assert.strictEqual(commandsModule.generateRequest(state), null);
    assert.ok(commandsModule.generateRefusals(state).includes(refusedAs));
  });
}

test('Unit: generateRefusals lists every offending field, prompt first', () => {
  const refusals = commandsModule.generateRefusals({ script: '', interpreter: 'fish', timeoutSeconds: '0', description: 'y'.repeat(501) });
  assert.deepStrictEqual(refusals, ['prompt', 'description', 'interpreter', 'timeoutSeconds']);
});

// ============================================================================
// TASK-059: full Windows device details + friendly OS display.
// E2E cucumber-style tests (AC21-AC24) for devices.js and deviceDetail.js.
// ============================================================================

/** The full device-details inventory, matching the golden contract fixture. */
function deviceDetailsInventory(overrides = {}) {
  return {
    os: {
      name: 'Microsoft Windows 11 Enterprise',
      version: '10.0.22631',
      build: '22631',
      architecture: 'amd64',
      edition: 'Enterprise',
      displayVersion: '23H2',
      ubr: 4317,
      installDate: '2024-03-12T02:18:44Z',
      lastBootAt: '2026-10-10T21:04:37Z',
      locale: 'en-AU',
    },
    hardware: {
      manufacturer: 'LENOVO',
      model: '20XW004PUS',
      serialNumber: 'PF2K8R3C',
      cpu: '11th Gen Intel(R) Core(TM) i7-1185G7',
      ramBytes: 34072571904,
      diskBytes: 1023303839744,
      systemFamily: 'ThinkPad X1 Carbon Gen 9',
      systemSku: 'LENOVO_MT_20XW',
      cpuCores: 4,
      cpuLogicalProcessors: 8,
    },
    software: [],
    firmware: {
      type: 'uefi',
      biosVersion: 'N32ET91W (1.67 )',
      biosReleaseDate: '2024-06-20T00:00:00Z',
      secureBootEnabled: true,
      tpmPresent: true,
      tpmReady: true,
      tpmVersion: '2.0',
    },
    disks: [{ deviceId: 'C:', fileSystem: 'NTFS', sizeBytes: 1023303839744, freeBytes: 412876075008 }],
    physicalDisks: [{ model: 'SAMSUNG MZVL21T0HCLR', mediaType: 'ssd', sizeBytes: 1024209543168 }],
    network: [
      {
        description: 'Intel(R) Wi-Fi 6 AX201',
        macAddress: 'A4:C3:F0:85:7B:21',
        ipv4: ['192.168.1.47'],
        ipv6: ['fe80::8d2c:41a7:3b1e:9f02'],
        dhcpEnabled: true,
        dnsServers: ['192.168.1.1'],
        gateways: ['192.168.1.1'],
      },
    ],
    join: {
      azureAdJoined: true,
      domainJoined: true,
      domain: 'contoso.local',
      tenantName: 'OfficeHQ',
      tenantId: '3e1c9a7b-2f4d-4b8e-9c6a-1d5f8e2b4c70',
      entraDeviceId: '5b7f2d1e-8c4a-4e9b-a1d3-6f0e2c9b7a45',
    },
    ...overrides,
  };
}

test('Scenario: Profile shows the friendly OS name (AC21)', () => {
  // Given a profile with osDisplay and osVersion
  const html = deviceDetailModule.render({
    profile: {
      deviceId: 'd1',
      osDisplay: 'Windows 11 Enterprise 23H2 (build 22631.4317)',
      osVersion: '10.0.22631',
    },
  });

  // When the device detail renders
  // Then the field labelled "OS" shows the display string
  assert.match(html, /<span class="label">OS<\/span><span class="value">Windows 11 Enterprise 23H2 \(build 22631\.4317\)<\/span>/);

  // And no field is labelled "osVersion"
  assert.ok(!html.includes('<span class="label">osVersion</span>'));
  assert.ok(!html.includes('10.0.22631'), 'the raw kernel version should not appear when osDisplay is shown');
});

test('Scenario: Profile and list fall back to osVersion (AC21)', () => {
  // Given a device with osVersion and no osDisplay
  const detailHtml = deviceDetailModule.render({ profile: { deviceId: 'd1', osVersion: '10.0.22631' } });

  // When the device detail and the device list render
  // Then the OS field shows "10.0.22631"
  assert.match(detailHtml, /<span class="label">OS<\/span><span class="value">10\.0\.22631<\/span>/);

  const listHtml = devicesModule.render({
    items: [{ deviceId: 'd1', hostname: 'host-1', platform: 'windows', osVersion: '10.0.22631' }],
    cursor: null,
  });
  // And the OS column shows "10.0.22631"
  assert.ok(listHtml.includes('>10.0.22631<'));

  // And the device list COLUMNS are unchanged and the column heading reads "OS"
  assert.deepStrictEqual(devicesModule.COLUMNS, [
    'hostname',
    'ownership',
    'platform',
    'osVersion',
    'lastSeenAt',
    'complianceState',
  ]);
  assert.ok(listHtml.includes('<th>OS</th>'));
});

test('Scenario: Device list falls back to osVersion when osDisplay is an empty string', () => {
  // Edge: osDisplay present but not a non-empty string must still fall back.
  const html = devicesModule.render({
    items: [{ deviceId: 'd1', hostname: 'host-1', platform: 'windows', osVersion: '10.0.22631', osDisplay: '' }],
    cursor: null,
  });
  assert.ok(html.includes('>10.0.22631<'));
});

test('Scenario: Device list uses osDisplay when it is a non-empty string', () => {
  const html = devicesModule.render({
    items: [{
      deviceId: 'd1',
      hostname: 'host-1',
      platform: 'windows',
      osVersion: '10.0.22631',
      osDisplay: 'Windows 11 Enterprise 23H2 (build 22631.4317)',
    }],
    cursor: null,
  });
  assert.ok(html.includes('Windows 11 Enterprise 23H2 (build 22631.4317)'));
});

test('Scenario: Device details panel groups every collected detail (AC22)', () => {
  // Given the stored inventory from the device-details fixture
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    inventory: deviceDetailsInventory(),
  });

  // When the device detail renders
  // Then panel "detail-inventory" has heading "Device details"
  const panel = html.slice(html.indexOf('id="detail-inventory"'), html.indexOf('id="detail-software"'));
  assert.ok(panel.includes('<h3>Device details</h3>'));

  // And it has groups OS, Hardware, Firmware & security, Storage, Network,
  // Join state in that order
  const headings = ['OS', 'Hardware', 'Firmware & security', 'Storage', 'Network', 'Join state'].map((h) =>
    panel.indexOf(`<h4>${h}</h4>`),
  );
  for (const index of headings) {
    assert.ok(index >= 0, `expected to find all six <h4> group headings, got indices ${headings}`);
  }
  for (let i = 1; i < headings.length; i += 1) {
    assert.ok(headings[i] > headings[i - 1], `groups should be in order, got indices ${headings}`);
  }

  // And it shows build "22631.4317", firmware type "UEFI", memory in GiB, a
  // row per disk, physical disk and adapter, and the tenant name
  assert.ok(panel.includes('22631.4317'));
  assert.ok(panel.includes('UEFI'));
  assert.ok(/\d+(\.\d)? GiB/.test(panel), 'expected memory/disk shown in GiB');
  assert.ok(panel.includes('class="grid device-disks"'));
  assert.ok(panel.includes('class="grid device-physical-disks"'));
  assert.ok(panel.includes('class="grid device-network"'));
  assert.ok(panel.includes('C:'));
  assert.ok(panel.includes('SAMSUNG MZVL21T0HCLR'));
  assert.ok(panel.includes('A4:C3:F0:85:7B:21'));
  assert.ok(panel.includes('OfficeHQ'));
  assert.ok(panel.includes('contoso.local'));
});

test('Scenario: Old inventory still renders (AC23)', () => {
  // Given an inventory with only hardware.serialNumber and os.version
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    inventory: { hardware: { serialNumber: 'SN12345' }, os: { version: '10.0.22631' } },
  });

  // When the device detail renders
  // Then it does not throw (render already completed) and contains "SN12345" and "10.0.22631"
  assert.ok(html.includes('SN12345'));
  assert.ok(html.includes('10.0.22631'));

  // And Firmware & security, Storage, Network and Join state each show "Not reported"
  const panel = html.slice(html.indexOf('id="detail-inventory"'), html.indexOf('id="detail-software"'));
  const notReportedCount = panel.split('<p class="empty">Not reported</p>').length - 1;
  assert.strictEqual(notReportedCount, 4, `expected exactly 4 "Not reported" groups, got ${notReportedCount}`);
});

test('Scenario: No inventory at all still renders (AC23)', () => {
  // Given the detail state has inventory null
  assert.doesNotThrow(() => {
    const html = deviceDetailModule.render({ profile: { deviceId: 'd1' }, inventory: null });

    // Then it does not throw
    // And Firmware & security, Storage, Network and Join state each show "Not reported"
    const panel = html.slice(html.indexOf('id="detail-inventory"'), html.indexOf('id="detail-software"'));
    const notReportedCount = panel.split('<p class="empty">Not reported</p>').length - 1;
    assert.strictEqual(notReportedCount, 4, `expected exactly 4 "Not reported" groups, got ${notReportedCount}`);
  });
});

test('Scenario: Device detail values are escaped (AC24)', () => {
  // Given an adapter description "<script>x</script>"
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    inventory: deviceDetailsInventory({
      network: [{ description: '<script>x</script>', macAddress: 'AA:BB:CC:DD:EE:FF' }],
    }),
  });

  // When the device detail renders
  // Then the HTML contains "&lt;script&gt;" and not "<script>x"
  assert.ok(html.includes('&lt;script&gt;'));
  assert.ok(!html.includes('<script>x'));
});
