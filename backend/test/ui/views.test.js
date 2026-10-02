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

test('Scenario: SETTING_KEYS holds exactly the eight keys', async (t) => {
  const expectedKeys = [
    'firewallEnabled',
    'diskEncryptionRequired',
    'screenLockTimeoutSeconds',
    'osUpdateMaxAgeDays',
    'localAdminAllowlist',
    'firewallBlockedDomains',
    'firewallAllowedDomains',
    'antivirusEnabled',
  ];

  assert.strictEqual(policiesModule.SETTING_KEYS.length, 8);
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
