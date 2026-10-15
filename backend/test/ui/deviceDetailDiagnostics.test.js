/**
 * E2E cucumber-style tests and unit tests for TASK-054's device detail
 * diagnostics (`backend/src/ui/views/deviceDetail.js`): the heartbeat status
 * paragraph (AC6-AC8), the analytics diagnostic (AC9-AC11) and the
 * collection-warnings field (AC12).
 *
 * New file per TASK-054 instructions: backend/test/ui/heartbeatView.test.js
 * and backend/test/ui/views.test.js (AC16) must pass unchanged. This is a
 * pure view module: no database or network call of any kind is involved.
 */

import test from 'node:test';
import assert from 'node:assert';

const deviceDetailModule = await import('../../dist/ui/views/deviceDetail.js');
const { render, formatDeviceTime, deviceTimeZone } = deviceDetailModule;

function analyticsSectionOf(html) {
  const start = html.indexOf('id="detail-analytics"');
  assert.ok(start > -1, 'detail-analytics section should be present');
  return html.slice(start);
}

// ============================================================================
// Scenario: Heartbeat off tells the admin how to start it (AC6)
// ============================================================================

test('Scenario: Heartbeat off tells the admin how to start it', () => {
  // When the device detail renders with heartbeat {enabled: false, intervalSeconds: 300}
  const html = render({
    profile: { deviceId: 'd1' },
    heartbeat: { enabled: false, intervalSeconds: 300 },
  });
  const section = analyticsSectionOf(html);

  // Then detail-analytics has field "Heartbeat" with value "Off"
  assert.match(section, /Heartbeat<\/[^>]*>\s*<[^>]*>Off/);

  // And detail-analytics contains the off status paragraph
  assert.ok(
    section.includes('<p class="heartbeat-status">Off: turn the heartbeat on to start receiving samples.</p>'),
  );
});

test('Scenario: Heartbeat absent behaves the same as off', () => {
  const html = render({ profile: { deviceId: 'd1' } });
  const section = analyticsSectionOf(html);
  assert.match(section, /Heartbeat<\/[^>]*>\s*<[^>]*>Off/);
  assert.ok(
    section.includes('<p class="heartbeat-status">Off: turn the heartbeat on to start receiving samples.</p>'),
  );
});

// ============================================================================
// Scenario: Heartbeat on with a received heartbeat shows when (AC7)
// ============================================================================

test('Scenario: Heartbeat on with a received heartbeat shows when', () => {
  // Given the profile has lastHeartbeatAt "2026-10-11T11:58:00Z" and timeZone "Australia/Sydney"
  const profile = { deviceId: 'd1', lastHeartbeatAt: '2026-10-11T11:58:00Z', timeZone: 'Australia/Sydney' };

  // When the device detail renders with heartbeat {enabled: true, intervalSeconds: 60}
  const html = render({ profile, heartbeat: { enabled: true, intervalSeconds: 60 } });
  const section = analyticsSectionOf(html);

  // Then detail-analytics has field "Heartbeat" with value "On"
  assert.match(section, /Heartbeat<\/[^>]*>\s*<[^>]*>On/);

  // And detail-analytics contains a p.heartbeat-status reading "On: last heartbeat " followed by
  // formatDeviceTime("2026-10-11T11:58:00Z", "Australia/Sydney")
  const zone = deviceTimeZone(profile.timeZone);
  const expectedTime = formatDeviceTime('2026-10-11T11:58:00Z', zone);
  assert.ok(section.includes(`<p class="heartbeat-status">On: last heartbeat ${expectedTime}</p>`));
});

// ============================================================================
// Scenario Outline: Heartbeat on but nothing received yet (AC8, edge)
// ============================================================================

test('Scenario Outline: Heartbeat on but nothing received yet - with a last check-in', () => {
  const profile = { deviceId: 'd1', lastCheckInAt: '2026-10-11T11:50:00Z' };
  const html = render({ profile, heartbeat: { enabled: true, intervalSeconds: 300 } });
  const section = analyticsSectionOf(html);

  const zone = deviceTimeZone(profile.timeZone);
  const expectedTime = formatDeviceTime('2026-10-11T11:50:00Z', zone);
  assert.ok(
    section.includes(
      `<p class="heartbeat-status">On: no heartbeat received yet. The device picks up this setting at its next check-in (last check-in: ${expectedTime}).</p>`,
    ),
  );
});

test('Scenario Outline: Heartbeat on but nothing received yet - never checked in', () => {
  const profile = { deviceId: 'd1' };
  const html = render({ profile, heartbeat: { enabled: true, intervalSeconds: 300 } });
  const section = analyticsSectionOf(html);

  assert.ok(
    section.includes(
      '<p class="heartbeat-status">On: no heartbeat received yet. The device picks up this setting at its next check-in (last check-in: never).</p>',
    ),
  );
});

// ============================================================================
// Scenario: A check-in without analytics is called out with the agent
// version (AC9)
// ============================================================================

test('Scenario: A check-in without analytics is called out with the agent version', () => {
  // Given the profile has lastCheckInAt "2026-10-11T11:50:00Z" and agentVersion "<b>1.0.0</b>"
  const profile = { deviceId: 'd1', lastCheckInAt: '2026-10-11T11:50:00Z', agentVersion: '<b>1.0.0</b>' };

  // And analytics collection is on and the analytics snapshot is null
  const html = render({
    profile,
    analytics: { snapshot: null },
    analyticsCollection: { enabled: true },
  });
  const section = analyticsSectionOf(html);

  const zone = deviceTimeZone(profile.timeZone);
  const expectedTime = formatDeviceTime('2026-10-11T11:50:00Z', zone);
  assert.ok(
    section.includes(
      `<p class="analytics-diagnostic">The last check-in (${expectedTime}) carried no analytics. Agent version: &lt;b&gt;1.0.0&lt;/b&gt;.</p>`,
    ),
  );
});

test('Scenario: Missing agent version reads "not reported" (AC9, edge)', () => {
  const profile = { deviceId: 'd1', lastCheckInAt: '2026-10-11T11:50:00Z' };
  const html = render({
    profile,
    analytics: { snapshot: null },
    analyticsCollection: { enabled: true },
  });
  const section = analyticsSectionOf(html);
  const diagnosticMatch = /<p class="analytics-diagnostic">(.*?)<\/p>/.exec(section);
  assert.ok(diagnosticMatch);
  assert.ok(diagnosticMatch[1].endsWith('Agent version: not reported.'));
});

// ============================================================================
// Scenario Outline: A stale analytics snapshot versus the last check-in
// (AC10)
// ============================================================================

test('Scenario Outline: A stale analytics snapshot versus the last check-in - present', () => {
  const profile = { deviceId: 'd1', lastCheckInAt: '2026-10-11T11:50:00Z' };
  const html = render({
    profile,
    analytics: { snapshot: { receivedAt: '2026-10-10T09:00:00Z' } },
    analyticsCollection: { enabled: true },
  });
  const section = analyticsSectionOf(html);
  assert.ok(section.includes('class="analytics-diagnostic"'));
});

test('Scenario Outline: A stale analytics snapshot versus the last check-in - absent when equal', () => {
  const profile = { deviceId: 'd1', lastCheckInAt: '2026-10-11T11:50:00Z' };
  const html = render({
    profile,
    analytics: { snapshot: { receivedAt: '2026-10-11T11:50:00Z' } },
    analyticsCollection: { enabled: true },
  });
  const section = analyticsSectionOf(html);
  assert.ok(!section.includes('class="analytics-diagnostic"'));
});

// ============================================================================
// Scenario: No check-in ever received (AC11)
// ============================================================================

test('Scenario: No check-in has ever been received', () => {
  const html = render({
    profile: { deviceId: 'd1' },
    analytics: { snapshot: null },
    analyticsCollection: { enabled: true },
  });
  const section = analyticsSectionOf(html);
  assert.ok(section.includes('<p class="analytics-diagnostic">No check-in has been received from this device yet.</p>'));
});

// ============================================================================
// Scenario: Collection off shows no analytics diagnostic (AC11, edge)
// ============================================================================

test('Scenario: Collection off shows no analytics diagnostic', () => {
  const html = render({
    profile: { deviceId: 'd1', lastCheckInAt: '2026-10-11T11:50:00Z' },
    analytics: { snapshot: null },
    analyticsCollection: { enabled: false },
  });
  const section = analyticsSectionOf(html);
  assert.ok(!section.includes('class="analytics-diagnostic"'));
  // And the existing "Analytics collection is off" warning is shown.
  assert.ok(section.includes('Analytics collection is off'));
});

// ============================================================================
// Scenario Outline: Collection warnings are shown (AC12)
// ============================================================================

test('Scenario Outline: Collection warnings are shown - multiple entries', () => {
  const html = render({
    profile: { deviceId: 'd1' },
    analytics: { snapshot: { warnings: ['performance:timeout', 'boot:unparseable'] } },
  });
  const section = analyticsSectionOf(html);
  assert.ok(section.includes('Collection warnings'));
  assert.ok(section.includes('performance:timeout, boot:unparseable'));
});

test('Scenario Outline: Collection warnings are shown - HTML escaped', () => {
  const html = render({
    profile: { deviceId: 'd1' },
    analytics: { snapshot: { warnings: ['<x>'] } },
  });
  const section = analyticsSectionOf(html);
  assert.ok(section.includes('&lt;x&gt;'));
  assert.ok(!section.includes('<x>'));
});

test('Scenario Outline: Collection warnings are shown - absent when empty', () => {
  const html = render({
    profile: { deviceId: 'd1' },
    analytics: { snapshot: { warnings: [] } },
  });
  const section = analyticsSectionOf(html);
  assert.ok(!section.includes('Collection warnings'));
});

test('Scenario Outline: Collection warnings are shown - absent when the key is absent', () => {
  const html = render({
    profile: { deviceId: 'd1' },
    analytics: { snapshot: {} },
  });
  const section = analyticsSectionOf(html);
  assert.ok(!section.includes('Collection warnings'));
});

test('Edge: collection warnings not an array produces no field', () => {
  const html = render({
    profile: { deviceId: 'd1' },
    analytics: { snapshot: { warnings: 'not-an-array' } },
  });
  const section = analyticsSectionOf(html);
  assert.ok(!section.includes('Collection warnings'));
});

// ============================================================================
// Edge: snapshot present but receivedAt not a string -> no diagnostic
// ============================================================================

test('Edge: snapshot present but receivedAt not a string produces no diagnostic', () => {
  const html = render({
    profile: { deviceId: 'd1', lastCheckInAt: '2026-10-11T11:50:00Z' },
    analytics: { snapshot: { receivedAt: 12345 } },
    analyticsCollection: { enabled: true },
  });
  const section = analyticsSectionOf(html);
  assert.ok(!section.includes('class="analytics-diagnostic"'));
});
