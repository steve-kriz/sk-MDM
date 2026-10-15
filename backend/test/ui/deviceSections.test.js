/**
 * Unit tests for TASK-062: the device detail page's section expanders
 * (render-level, AC1-AC8). Pure render-function tests: no DOM, no fetch, no
 * database. Implements the ticket's Gherkin scenarios (Given/When/Then) by
 * calling the real exported `render()` from
 * backend/src/ui/views/deviceDetail.js with plain state objects.
 */

import test from 'node:test';
import assert from 'node:assert';

const deviceDetailModule = await import('../../dist/ui/views/deviceDetail.js');
const { render } = deviceDetailModule;

/** The 17 section ids named in the ticket, in page order. */
const ALL_SECTION_IDS = [
  'detail-manage',
  'detail-groups',
  'detail-policies',
  'detail-credential',
  'detail-inventory',
  'detail-software',
  'detail-posture',
  'detail-run-command',
  'detail-queue',
  'detail-commands',
  'detail-antivirus-status',
  'detail-defender-hardening',
  'detail-antivirus-findings',
  'detail-antivirus-scan',
  'detail-location',
  'detail-login-history',
  'detail-analytics',
];

/** AC1's Examples table (Software is covered separately by AC6). */
const AC1_EXAMPLES = [
  ['detail-manage', 'Manage'],
  ['detail-groups', 'Groups'],
  ['detail-policies', 'Policies'],
  ['detail-credential', 'Device credential'],
  ['detail-inventory', 'Device details'],
  ['detail-posture', 'Posture'],
  ['detail-run-command', 'Run a command'],
  ['detail-queue', 'Queue'],
  ['detail-commands', 'History'],
  ['detail-antivirus-status', 'Antivirus status'],
  ['detail-defender-hardening', 'Defender protection policy'],
  ['detail-antivirus-findings', 'Antivirus findings'],
  ['detail-antivirus-scan', 'Antivirus scan'],
  ['detail-location', 'Location'],
  ['detail-login-history', 'Login history'],
  ['detail-analytics', 'Analytics'],
];

/** A state with every section rendered: "a device with hostname PC-1" (ticket Background). */
function fullFixture(overrides = {}) {
  return {
    profile: { deviceId: 'dev-1', hostname: 'PC-1', platform: 'other', timeZone: 'UTC' },
    inventory: { software: [{ name: 'App A', version: '1.0' }, { name: 'App B', version: '2.0' }] },
    posture: {},
    commands: [],
    antivirusFindings: [],
    loginHistory: [],
    groups: [],
    allGroups: [],
    policies: [],
    scripts: [],
    applications: [],
    runCommand: {},
    credential: {},
    antivirusStatus: {},
    // A hardening block so "detail-defender-hardening" is rendered.
    defenderHardening: { reportedAt: '2026-10-11T10:00:00Z', items: [{ item: 'puaProtection', state: 'applied' }] },
    antivirusScan: {},
    location: null,
    locationTracking: false,
    heartbeat: {},
    heartbeatHistory: null,
    analyticsCollection: {},
    analytics: {},
    deleteDialog: null,
    ...overrides,
  };
}

/** The slice of `html` for the `<section class="panel" id="ID">` named, up to the next panel section. */
function sectionHtml(html, id) {
  const start = html.indexOf(`<section class="panel" id="${id}">`);
  if (start === -1) {
    return null;
  }
  const next = html.indexOf('<section class="panel" id="', start + 1);
  return html.slice(start, next === -1 ? html.length : next);
}

/** The `<details`/`</details>` balance before `index`: 0 means "outside every details element". */
function detailsDepthAt(html, index) {
  const before = html.slice(0, index);
  const opens = (before.match(/<details\b/g) ?? []).length;
  const closes = (before.match(/<\/details>/g) ?? []).length;
  return opens - closes;
}

/** Every `device-section` expander tag that carries ` open`. */
function deviceSectionTagsOpen(html) {
  const matches = html.match(/<details class="expandable device-section" data-section="[^"]*"( open)?>/g) ?? [];
  return matches.filter((tag) => tag.includes(' open>'));
}

// ============================================================================
// AC1
// ============================================================================

test('Scenario Outline: Each section is an expander with its title in the summary (AC1)', () => {
  // When the device detail page is rendered with every section's data
  const html = render(fullFixture());
  for (const [id, title] of AC1_EXAMPLES) {
    const expectedOpen = `<section class="panel" id="${id}"><details class="expandable device-section" data-section="${id}"><summary><h3>${title}</h3></summary>`;
    // Then the HTML contains the exact opening sequence
    const openIndex = html.indexOf(expectedOpen);
    assert.ok(openIndex !== -1, `expected opening sequence for "${id}": ${expectedOpen}`);
    // And the section's "</details></section>" closes after all of its content
    const closeIndex = html.indexOf('</details></section>', openIndex);
    assert.ok(closeIndex > openIndex, `expected a closing </details></section> after "${id}"`);
  }
});

// ============================================================================
// AC2
// ============================================================================

test('Scenario Outline: Every section starts collapsed (AC2)', () => {
  const examples = { absent: Symbol('absent'), null: null, '"x"': 'x', '{a: 1}': { a: 1 } };
  for (const [label, value] of Object.entries(examples)) {
    const state = fullFixture();
    if (value !== examples.absent) {
      state.openSections = value;
    }
    // When the page is rendered with openSections <value>
    const html = render(state);
    // Then no details tag with class "device-section" has an open attribute
    assert.strictEqual(deviceSectionTagsOpen(html).length, 0, `openSections ${label} should leave every section collapsed`);
  }
});

// ============================================================================
// AC3
// ============================================================================

test('Scenario: Named sections render open (AC3)', () => {
  // When the page is rendered with openSections ["detail-software", "detail-analytics"]
  const html = render(fullFixture({ openSections: ['detail-software', 'detail-analytics'] }));
  // Then the Software and Analytics expanders carry " open"
  assert.ok(html.includes('<details class="expandable device-section" data-section="detail-software" open>'));
  assert.ok(html.includes('<details class="expandable device-section" data-section="detail-analytics" open>'));
  // And every other device-section expander does not
  const openTags = deviceSectionTagsOpen(html);
  assert.strictEqual(openTags.length, 2, `expected exactly two open device-section expanders, got: ${openTags.join(', ')}`);
});

// ============================================================================
// AC4 (edge)
// ============================================================================

test('Scenario: Junk entries in openSections are ignored (AC4)', () => {
  // Given the device reported no Defender hardening block
  const state = fullFixture({ defenderHardening: null });
  state.openSections = [42, null, 'detail-defender-hardening', 'detail-profile', 'nope', 'detail-groups', 'detail-groups'];
  // When the page is rendered with that openSections
  let html;
  assert.doesNotThrow(() => {
    html = render(state);
  });
  // Then rendering does not throw, and only the Groups expander carries " open"
  const openTags = deviceSectionTagsOpen(html);
  assert.strictEqual(openTags.length, 1, `expected exactly one open expander, got: ${openTags.join(', ')}`);
  assert.ok(openTags[0].includes('data-section="detail-groups"'));
  // And there is no data-section="detail-defender-hardening" in the HTML
  assert.ok(!html.includes('data-section="detail-defender-hardening"'));
});

// ============================================================================
// AC5
// ============================================================================

test('Scenario: Heading, Profile and the delete popup stay outside the expanders (AC5)', () => {
  // Given the delete popup is open
  const state = fullFixture({ deleteDialog: { open: true, typedHostname: '', error: null } });
  // When the page is rendered
  const html = render(state);

  // Then the h2 and the detail-profile section are inside no details element
  const h2Index = html.indexOf('<h2>');
  assert.ok(h2Index !== -1);
  assert.strictEqual(detailsDepthAt(html, h2Index), 0, 'the <h2> should be outside every <details>');

  const profileStart = html.indexOf('<section class="panel" id="detail-profile">');
  assert.ok(profileStart !== -1);
  assert.strictEqual(detailsDepthAt(html, profileStart), 0, 'detail-profile should be outside every <details>');
  const profileEnd = html.indexOf('</section>', profileStart) + '</section>'.length;
  const profileHtml = html.slice(profileStart, profileEnd);

  // And the detail-profile section contains no "<details"
  assert.ok(!profileHtml.includes('<details'));
  // And it contains the Refresh and Delete device buttons
  assert.ok(profileHtml.includes('class="refresh-device"'));
  assert.ok(profileHtml.includes('class="open-delete-device"'));

  // And the modal-backdrop is inside no details element
  const modalIndex = html.indexOf('<div class="modal-backdrop">');
  assert.ok(modalIndex !== -1);
  assert.strictEqual(detailsDepthAt(html, modalIndex), 0, 'the delete popup should be outside every <details>');
});

// ============================================================================
// AC6
// ============================================================================

test('Scenario: Software section wraps the unchanged list expander and the install form (AC6)', () => {
  // Given the device reports 3 software entries
  const state = fullFixture({
    inventory: { software: [{ name: 'A', version: '1' }, { name: 'B', version: '2' }, { name: 'C', version: '3' }] },
    // An application is supplied so the install-form ordering assertion below
    // is about the form itself, not the "no applications" helper message.
    applications: [{ applicationId: 'app-1', name: 'App 1', hashStatus: 'ready' }],
  });
  // When the page is rendered
  const html = render(state);
  const section = sectionHtml(html, 'detail-software');
  assert.ok(section !== null);

  // Then the Software section contains exactly two "<details"
  const detailsCount = (section.match(/<details\b/g) ?? []).length;
  assert.strictEqual(detailsCount, 2, `expected exactly two <details elements, got ${detailsCount}`);

  // And it starts with the exact opening sequence
  assert.ok(
    section.startsWith(
      '<section class="panel" id="detail-software"><details class="expandable device-section" data-section="detail-software"><summary><h3>Software (3)</h3></summary><details class="expandable"><summary><h3>Software (3)</h3></summary><table class="grid software">',
    ),
  );

  // And form.install-application comes after the inner list's "</details>" and before the outer "</details></section>"
  const innerCloseIndex = section.indexOf('</table></details>');
  const outerCloseIndex = section.lastIndexOf('</details></section>');
  const formIndex = section.indexOf('<form class="install-application">');
  assert.ok(innerCloseIndex !== -1 && formIndex !== -1 && outerCloseIndex !== -1);
  assert.ok(formIndex > innerCloseIndex, "the install form should come after the inner list's </details>");
  assert.ok(formIndex < outerCloseIndex, 'the install form should come before the outer </details></section>');
});

test('Scenario: A device with no software shows a Software (0) expander with no inner list (AC6 edge)', () => {
  // Given the device reports no software
  const state = fullFixture({ inventory: { software: [] } });
  // When the page is rendered
  const html = render(state);
  const section = sectionHtml(html, 'detail-software');
  assert.ok(section !== null);

  // Then the Software section contains exactly one "<details"
  const detailsCount = (section.match(/<details\b/g) ?? []).length;
  assert.strictEqual(detailsCount, 1, `expected exactly one <details element, got ${detailsCount}`);

  // And the outer summary is followed by the empty message and then form.install-application
  assert.ok(section.includes('<summary><h3>Software (0)</h3></summary><p class="empty">No software reported</p>'));
  const emptyIndex = section.indexOf('<p class="empty">No software reported</p>');
  const formIndex = section.indexOf('<form class="install-application">');
  assert.ok(emptyIndex !== -1 && formIndex !== -1 && formIndex > emptyIndex);
  assert.ok(!section.includes('<h3>Software (0)</h3>', formIndex), 'no <h3> should appear outside the summary');

  // And the section ends with "</details></section>"
  assert.ok(section.endsWith('</details></section>'));
});

// ============================================================================
// AC7
// ============================================================================

test('Scenario: Collapsed sections still carry their content (AC7)', () => {
  // Given the device reports 2 software entries and no antivirus findings
  const state = fullFixture({
    inventory: { software: [{ name: 'A', version: '1' }, { name: 'B', version: '2' }] },
    antivirusFindings: [],
  });
  // When the page is rendered with no openSections
  const html = render(state);

  // Then the Software expander contains 2 rows of class "software"
  const softwareSection = sectionHtml(html, 'detail-software');
  assert.ok(softwareSection.includes('<table class="grid software">'));
  const rowCount = (softwareSection.match(/<tr class="software">/g) ?? []).length;
  assert.strictEqual(rowCount, 2);

  // And the Antivirus findings expander contains '<p class="empty">No antivirus findings</p>'
  const findingsSection = sectionHtml(html, 'detail-antivirus-findings');
  assert.ok(findingsSection.includes('<p class="empty">No antivirus findings</p>'));
});

// ============================================================================
// AC8
// ============================================================================

test('Scenario: Nested expanders keep their own open state (AC8)', () => {
  // Given heartbeatHistory is {open: true, items: []}
  // And a finished command with output "ok"
  const state = fullFixture({
    heartbeatHistory: { open: true, items: [] },
    commands: [
      {
        commandId: 'c1',
        scriptName: 'Script 1',
        type: 'script',
        status: 'succeeded',
        exitCode: 0,
        issuedAt: '2026-10-01T00:00:00Z',
        output: 'ok',
      },
    ],
  });
  // When the page is rendered with no openSections
  const html = render(state);

  // Then the Analytics expander has no open attribute
  const analyticsSection = sectionHtml(html, 'detail-analytics');
  assert.ok(!analyticsSection.includes('data-section="detail-analytics" open>'));

  // And the heartbeat-history details inside it has the open attribute
  assert.ok(/<details class="expandable heartbeat-history" data-device-id="[^"]*" open>/.test(analyticsSection));

  // And the command output details has no device-section class and no open attribute
  assert.ok(html.includes('<details class="expandable"><summary>output</summary><pre class="output">ok</pre></details>'));
});

test('Scenario: The inner Software list never opens from openSections (AC8 edge)', () => {
  // Given the device reports 2 software entries
  const state = fullFixture({
    inventory: { software: [{ name: 'A', version: '1' }, { name: 'B', version: '2' }] },
    openSections: ['detail-software'],
  });
  // When the page is rendered with openSections ["detail-software"]
  const html = render(state);

  // Then the Software device-section expander carries " open"
  assert.ok(html.includes('<details class="expandable device-section" data-section="detail-software" open>'));

  // And the inner software list renders as '<details class="expandable"><summary><h3>Software (2)</h3></summary>' with no open attribute
  assert.ok(html.includes('<details class="expandable"><summary><h3>Software (2)</h3></summary>'));
  assert.ok(!html.includes('<details class="expandable" open><summary><h3>Software (2)</h3></summary>'));
});

// ============================================================================
// TASK-066 AC3: the 17 TASK-062 sections render once each, in order
// ============================================================================

test('Scenario: The 17 TASK-062 sections render once each, in order (TASK-066 AC3)', () => {
  // When the device detail page is rendered with the fullFixture state
  const html = render(fullFixture());

  // Then each of the 17 ids appears exactly once, as <section class="panel" id="ID">
  const indices = ALL_SECTION_IDS.map((id) => {
    const occurrences = html.split(`<section class="panel" id="${id}">`).length - 1;
    assert.strictEqual(occurrences, 1, `expected "${id}" to render exactly once, got ${occurrences}`);
    return html.indexOf(`<section class="panel" id="${id}">`);
  });

  // And they appear in the stated relative order
  for (let i = 1; i < indices.length; i += 1) {
    assert.ok(
      indices[i - 1] < indices[i],
      `expected "${ALL_SECTION_IDS[i - 1]}" to come before "${ALL_SECTION_IDS[i]}"`,
    );
  }

  // And the data-section immediately after "detail-credential" is "detail-inventory"
  const dataSections = [...html.matchAll(/data-section="([^"]*)"/g)].map((m) => m[1]);
  const credentialIndex = dataSections.indexOf('detail-credential');
  assert.ok(credentialIndex !== -1, 'expected a data-section="detail-credential"');
  assert.strictEqual(dataSections[credentialIndex + 1], 'detail-inventory');
});

// ============================================================================
// TASK-066 AC4 (edge): a remembered "detail-user" open entry is ignored
// ============================================================================

test('Scenario: A remembered "detail-user" open entry is ignored (TASK-066 AC4)', () => {
  // When the page is rendered with openSections ["detail-user"]
  let html;
  assert.doesNotThrow(() => {
    html = render(fullFixture({ openSections: ['detail-user'] }));
  });
  // Then rendering does not throw, and no device-section expander carries " open"
  assert.strictEqual(deviceSectionTagsOpen(html).length, 0);
});

test('Scenario: "detail-user" alongside a real section opens only the real one (TASK-066 AC4)', () => {
  // When the page is rendered with openSections ["detail-user", "detail-groups"]
  const html = render(fullFixture({ openSections: ['detail-user', 'detail-groups'] }));
  // Then exactly one device-section expander carries " open", and it is detail-groups
  const openTags = deviceSectionTagsOpen(html);
  assert.strictEqual(openTags.length, 1, `expected exactly one open expander, got: ${openTags.join(', ')}`);
  assert.ok(openTags[0].includes('data-section="detail-groups"'));
});

// ============================================================================
// Regression guard: every section id is still unique and still renders
// ============================================================================

test('Unit: every section id named in the ticket renders exactly once', () => {
  const html = render(fullFixture());
  for (const id of ALL_SECTION_IDS) {
    const occurrences = html.split(`<section class="panel" id="${id}">`).length - 1;
    assert.strictEqual(occurrences, 1, `expected "${id}" to render exactly once, got ${occurrences}`);
  }
});
