/**
 * E2E cucumber-style tests for TASK-067 (History view): the device detail
 * page's History section (`backend/src/ui/views/deviceDetail.js`). Pure view
 * rendering, no database involved -- tests implement the ticket's Gherkin
 * scenarios for AC20-AC26 in Given/When/Then style using node:test.
 */
import { strict as assert } from 'node:assert';
import { test } from 'node:test';

const deviceDetailModule = await import('../../dist/ui/views/deviceDetail.js');

function historySectionOf(html) {
  const match = html.match(/<section class="panel" id="detail-commands">[\s\S]*?<\/section>/);
  assert.ok(match, 'expected a #detail-commands (History) section');
  return match[0];
}

function baseState(overrides = {}) {
  return { profile: { deviceId: 'dev-1', timeZone: 'Australia/Sydney' }, deviceEvents: [], commands: [], ...overrides };
}

// ============================================================================
// Scenario: History is one timeline table (AC20)
// ============================================================================

test('Scenario: History is one timeline table (AC20)', () => {
  // Given device detail state with 2 deviceEvents and commands one "succeeded"
  // and one "pending"
  const deviceEvents = [
    { eventId: 'e1', source: 'admin', type: 'device.disabled', summary: 'Device disabled', details: {}, actor: 'alice@x', occurredAt: '2026-10-12T01:00:00Z' },
    { eventId: 'e2', source: 'agent', type: 'device.enrolled', summary: 'Device enrolled', details: {}, actor: null, occurredAt: '2026-10-11T01:00:00Z' },
  ];
  const commands = [
    { commandId: 'c1', status: 'succeeded', scriptName: 'Flush DNS', issuedAt: 1000 },
    { commandId: 'c2', status: 'pending', seq: 1, issuedAt: 2000 },
  ];
  const html = deviceDetailModule.render(baseState({ deviceEvents, commands }));

  // Then section "detail-commands" titled "History" contains a table with
  // class "grid history" and headers When, Source, Action, Status, Details
  const section = historySectionOf(html);
  assert.ok(section.includes('<h3>History</h3>'));
  assert.ok(section.includes('<table class="grid history">'));
  const headerMatch = section.match(/<thead><tr>([\s\S]*?)<\/tr><\/thead>/);
  assert.ok(headerMatch);
  const headers = [...headerMatch[1].matchAll(/<th>(.*?)<\/th>/g)].map((m) => m[1]);
  assert.deepStrictEqual(headers, ['When', 'Source', 'Action', 'Status', 'Details']);

  // And it has 2 "device-event" rows and 1 "command" row, and no row for the
  // pending command
  assert.strictEqual((section.match(/class="device-event"/g) ?? []).length, 2);
  assert.strictEqual((section.match(/class="command"/g) ?? []).length, 1);
  assert.ok(!section.includes('data-command-id="c2"'));
  // The section sits after Queue, and is collapsed by default.
  const queueIndex = html.indexOf('id="detail-queue"');
  const historyIndex = html.indexOf('id="detail-commands"');
  assert.ok(queueIndex !== -1 && queueIndex < historyIndex);
  assert.ok(section.includes('<details class="expandable device-section" data-section="detail-commands">'));
});

// ============================================================================
// Scenario: Rows are merged newest first (AC21)
// ============================================================================

test('Scenario: Rows are merged newest first (AC21)', () => {
  // Given an event at 2026-10-12T03:00:00Z, a command issued at
  // 2026-10-12T02:00:00Z (epoch ms), an event at 2026-10-12T01:00:00Z and a
  // command with no issuedAt
  const deviceEvents = [
    { eventId: 'e-late', source: 'admin', type: 'x', summary: 'Latest event', details: {}, actor: null, occurredAt: '2026-10-12T03:00:00Z' },
    { eventId: 'e-early', source: 'admin', type: 'x', summary: 'Earlier event', details: {}, actor: null, occurredAt: '2026-10-12T01:00:00Z' },
  ];
  const commands = [
    { commandId: 'c-mid', status: 'succeeded', type: 'run_script', issuedAt: Date.parse('2026-10-12T02:00:00Z') },
    { commandId: 'c-none', status: 'succeeded', type: 'run_script' },
  ];
  const html = deviceDetailModule.render(baseState({ deviceEvents, commands }));
  const section = historySectionOf(html);

  // Then the History rows appear in that order: latest event, mid command,
  // earlier event, then the command with no parseable time last.
  const order = [...section.matchAll(/data-(?:event|command)-id="([^"]+)"/g)].map((m) => m[1]);
  assert.deepStrictEqual(order, ['e-late', 'c-mid', 'e-early', 'c-none']);
});

// ============================================================================
// Scenario: An event row shows its parts (AC22)
// ============================================================================

test('Scenario: An event row shows its parts (AC22)', () => {
  // Given an event summary "Device disabled", source "admin", actor
  // "alice@x", details {reason: "lost"}, occurredAt 2026-10-10T22:30:00Z and
  // time zone "Australia/Sydney"
  const deviceEvents = [
    {
      eventId: 'e1',
      source: 'admin',
      type: 'device.disabled',
      summary: 'Device disabled',
      details: { reason: 'lost' },
      actor: 'alice@x',
      occurredAt: '2026-10-10T22:30:00Z',
    },
  ];
  const html = deviceDetailModule.render(
    baseState({ profile: { deviceId: 'dev-1', timeZone: 'Australia/Sydney' }, deviceEvents }),
  );
  const section = historySectionOf(html);
  const rowMatch = section.match(/<tr class="device-event" data-event-id="e1">([\s\S]*?)<\/tr>/);
  assert.ok(rowMatch, 'expected the event row');
  const row = rowMatch[1];

  // Then its row reads When "2026-10-11 09:30:00" (Sydney is UTC+11 in
  // October), Source "admin", Action "Device disabled", Status "&mdash;",
  // Details "by=alice@x; reason=lost"
  assert.ok(row.includes('2026-10-11 09:30:00'), row);
  assert.ok(row.includes('<td class="col-source">admin</td>'));
  assert.ok(row.includes('<td class="col-action">Device disabled</td>'));
  assert.ok(row.includes('<td class="col-status">&mdash;</td>'));
  assert.ok(row.includes('<td class="col-details">by=alice@x; reason=lost</td>'));
});

test('Unit: an event with no actor and no details renders an empty Details cell', () => {
  const deviceEvents = [
    { eventId: 'e2', source: 'system', type: 'agent.version_changed', summary: 'x', details: {}, actor: null, occurredAt: '2026-10-10T22:30:00Z' },
  ];
  const html = deviceDetailModule.render(baseState({ deviceEvents }));
  const section = historySectionOf(html);
  assert.ok(section.includes('<td class="col-details"></td>'));
});

// ============================================================================
// Scenario: A command row keeps its expandable output (AC23)
// ============================================================================

test('Scenario: A command row keeps its expandable output (AC23)', () => {
  // Given a command "X" with scriptName "Flush DNS", type "run_script",
  // status "succeeded", exitCode 0, issuedBy "alice@x" and output "<b>ok</b>"
  const commands = [
    {
      commandId: 'X',
      scriptName: 'Flush DNS',
      type: 'run_script',
      status: 'succeeded',
      exitCode: 0,
      issuedBy: 'alice@x',
      issuedAt: 1000,
      output: '<b>ok</b>',
    },
  ];
  const html = deviceDetailModule.render(baseState({ commands }));
  const section = historySectionOf(html);

  // Then its row reads Action "Flush DNS", Status "succeeded", Details
  // "type=run_script; exitCode=0; by=alice@x"
  const rowMatch = section.match(/<tr class="command" data-command-id="X">([\s\S]*?)<\/tr>/);
  assert.ok(rowMatch);
  const row = rowMatch[1];
  assert.ok(row.includes('<td class="col-action">Flush DNS</td>'));
  assert.ok(row.includes('<td class="col-status">succeeded</td>'));
  assert.ok(row.includes('<td class="col-details">type=run_script; exitCode=0; by=alice@x</td>'));

  // And the next row is a "command-output" row with colspan 5 holding
  // "&lt;b&gt;ok&lt;/b&gt;" in pre.output inside details.expandable
  assert.match(
    section,
    /<tr class="command-output" data-command-id="X"><td colspan="5"><details class="expandable"><summary>output<\/summary><pre class="output">&lt;b&gt;ok&lt;\/b&gt;<\/pre><\/details><\/td><\/tr>/,
  );
});

// ============================================================================
// Scenario: An empty history shows the empty message (AC24)
// ============================================================================

test('Scenario: An empty history shows the empty message (AC24)', () => {
  // Given deviceEvents "not-an-array" and only pending commands
  const commands = [{ commandId: 'p1', status: 'pending', seq: 1, issuedAt: 1 }];
  const html = deviceDetailModule.render(baseState({ deviceEvents: 'not-an-array', commands }));
  const section = historySectionOf(html);

  // Then the History section contains "No actions recorded"
  assert.ok(section.includes('<p class="empty">No actions recorded</p>'));
});

test('Unit: a non-array commands value also counts as empty', () => {
  const html = deviceDetailModule.render(baseState({ deviceEvents: [], commands: 'nope' }));
  const section = historySectionOf(html);
  assert.ok(section.includes('<p class="empty">No actions recorded</p>'));
});

// ============================================================================
// Scenario: Event text is escaped (AC25)
// ============================================================================

test('Scenario: Event text is escaped (AC25)', () => {
  // Given an event with summary "<img src=x onerror=alert(1)>" and details
  // key "<k>" value "<v>"
  const deviceEvents = [
    {
      eventId: 'e<1>',
      source: '<admin>',
      type: 'x',
      summary: '<img src=x onerror=alert(1)>',
      details: { '<k>': '<v>' },
      actor: '<alice>',
      occurredAt: '2026-10-10T22:30:00Z',
    },
  ];
  const html = deviceDetailModule.render(baseState({ deviceEvents }));
  const section = historySectionOf(html);

  // Then the HTML contains the escaped summary and the escaped key=value pair
  assert.ok(section.includes('&lt;img src=x onerror=alert(1)&gt;'));
  assert.ok(section.includes('&lt;k&gt;=&lt;v&gt;'));
  // And no "<img" element is created
  assert.ok(!section.includes('<img'));
  assert.ok(!section.includes('<admin>'));
  assert.ok(!section.includes('<alice>'));
});

test('Unit: command strings are escaped (AC25)', () => {
  const commands = [
    {
      commandId: 'c<1>',
      scriptName: '<script>',
      status: '<bad>',
      issuedBy: '<admin>',
      type: '<type>',
      exitCode: '<1>',
      issuedAt: 1,
      output: '<pre>',
    },
  ];
  const html = deviceDetailModule.render(baseState({ commands }));
  const section = historySectionOf(html);
  assert.ok(!section.includes('<script>'));
  assert.ok(!section.includes('<bad>'));
  assert.ok(!section.includes('<admin>'));
  assert.ok(section.includes('&lt;script&gt;'));
  assert.ok(section.includes('type=&lt;type&gt;'));
  assert.ok(section.includes('exitCode=&lt;1&gt;'));
  assert.ok(section.includes('by=&lt;admin&gt;'));
});

// ============================================================================
// Scenario: An opened History section survives a refresh (AC26)
// ============================================================================

test('Scenario: An opened History section survives a refresh (AC26)', () => {
  // Given the admin opened the History section
  // When the view renders again with openSections ["detail-commands"]
  const html = deviceDetailModule.render(baseState({ openSections: ['detail-commands'] }));
  // Then the History details element has the open attribute
  assert.ok(html.includes('<details class="expandable device-section" data-section="detail-commands" open>'));

  // When the hash changes to another device (simulated: render afresh with no
  // openSections, as TASK-062's hashchange handler resets it)
  const htmlAfterNavigation = deviceDetailModule.render(baseState({ openSections: [] }));
  // Then the History details element renders without the open attribute
  assert.ok(
    htmlAfterNavigation.includes('<details class="expandable device-section" data-section="detail-commands">'),
  );
  assert.ok(!htmlAfterNavigation.includes('data-section="detail-commands" open'));
});
