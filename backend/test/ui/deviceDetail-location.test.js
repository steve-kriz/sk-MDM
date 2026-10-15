/**
 * E2E cucumber-style tests for TASK-056: the `#detail-location` panel on the
 * device detail page (`backend/src/ui/views/deviceDetail.js`). Pure view
 * rendering, no database involved.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

const deviceDetailModule = await import('../../dist/ui/views/deviceDetail.js');

function locationPanelOf(html) {
  const match = html.match(/<section class="panel" id="detail-location">[\s\S]*?<\/section>/);
  assert.ok(match, 'expected a #detail-location panel');
  return match[0];
}

// ============================================================================
// Scenario: Device page shows the location panel and map link
// ============================================================================

test('Scenario: Device page shows the location panel and map link', () => {
  const state = {
    profile: { deviceId: 'd1', timeZone: 'Australia/Sydney' },
    location: {
      latest: {
        latitude: -33.8688,
        longitude: 151.2093,
        city: 'Sydney',
        region: 'New South Wales',
        country: 'AU',
        source: 'ip',
        accuracyMeters: null,
        capturedAt: '2026-10-11T00:00:00Z',
      },
      history: [],
    },
    locationTracking: true,
  };

  const html = deviceDetailModule.render(state);
  const panel = locationPanelOf(html);

  assert.ok(panel.includes('-33.8688'));
  assert.ok(panel.includes('151.2093'));
  assert.ok(panel.includes('Sydney'));
  assert.ok(panel.includes('IP-based (approximate)'));
  assert.ok(panel.includes('Approximate'));

  // The captured time is formatted with formatDeviceTime in Australia/Sydney.
  const expectedTime = deviceDetailModule.formatDeviceTime('2026-10-11T00:00:00Z', 'Australia/Sydney');
  assert.ok(panel.includes(expectedTime));

  // The OpenStreetMap link, target and rel.
  const expectedHref = 'https://www.openstreetmap.org/?mlat=-33.8688&mlon=151.2093#map=12/-33.8688/151.2093';
  assert.ok(panel.includes(`href="${expectedHref}"`));
  assert.ok(panel.includes('target="_blank"'));
  assert.ok(panel.includes('rel="noopener noreferrer"'));

  // No embedded map, iframe or script (CSP).
  assert.ok(!panel.includes('<iframe'));
  assert.ok(!panel.includes('<script'));
});

test('Scenario: Device page shows one history row per stored entry', () => {
  const state = {
    profile: { deviceId: 'd1' },
    location: {
      latest: {
        latitude: 1,
        longitude: 2,
        city: 'A',
        region: null,
        country: null,
        source: 'ip',
        accuracyMeters: null,
        capturedAt: '2026-10-11T00:00:00Z',
      },
      history: [
        { latitude: 1, longitude: 2, city: 'A', region: null, country: null, source: 'ip', accuracyMeters: null, capturedAt: '2026-10-11T00:00:00Z' },
        { latitude: 3, longitude: 4, city: 'B', region: null, country: null, source: 'ip', accuracyMeters: null, capturedAt: '2026-10-10T00:00:00Z' },
      ],
    },
    locationTracking: true,
  };

  const html = deviceDetailModule.render(state);
  const panel = locationPanelOf(html);
  assert.ok(panel.includes('class="grid location-history"'));
  const rowMatches = panel.match(/<tr class="location">/g) ?? [];
  assert.strictEqual(rowMatches.length, 2);
});

// ============================================================================
// Scenario Outline: Device page empty states
// ============================================================================

test('Scenario Outline: Device page empty states - tracking true shows "No location captured"', () => {
  const state = { profile: { deviceId: 'd1' }, location: { latest: null, history: [] }, locationTracking: true };
  const html = deviceDetailModule.render(state);
  const panel = locationPanelOf(html);
  assert.ok(panel.includes('No location captured'));
  assert.ok(!panel.includes('openstreetmap.org'));
});

test('Scenario Outline: Device page empty states - tracking false shows "Location tracking is not enabled by any policy"', () => {
  const state = { profile: { deviceId: 'd1' }, location: { latest: null, history: [] }, locationTracking: false };
  const html = deviceDetailModule.render(state);
  const panel = locationPanelOf(html);
  assert.ok(panel.includes('Location tracking is not enabled by any policy'));
  assert.ok(!panel.includes('openstreetmap.org'));
});

test('Scenario Outline: Device page empty states - location absent entirely behaves like latest null', () => {
  const html = deviceDetailModule.render({ profile: { deviceId: 'd1' }, locationTracking: false });
  const panel = locationPanelOf(html);
  assert.ok(panel.includes('Location tracking is not enabled by any policy'));
});

// ============================================================================
// Scenario: Stored location shown after tracking is turned off
// ============================================================================

test('Scenario: Stored location shown after tracking is turned off', () => {
  const state = {
    profile: { deviceId: 'd1' },
    location: {
      latest: {
        latitude: 1,
        longitude: 2,
        city: 'Somewhere',
        region: null,
        country: null,
        source: 'ip',
        accuracyMeters: null,
        capturedAt: '2026-10-11T00:00:00Z',
      },
      history: [],
    },
    locationTracking: false,
  };

  const html = deviceDetailModule.render(state);
  const panel = locationPanelOf(html);
  assert.ok(panel.includes('Somewhere'));
  assert.ok(panel.includes('Location tracking is off; showing the last captured location'));
  // Still shows the map link, since a location is present.
  assert.ok(panel.includes('openstreetmap.org'));
});

// ============================================================================
// Scenario: City text is escaped
// ============================================================================

test('Scenario: City text is escaped', () => {
  const state = {
    profile: { deviceId: 'd1' },
    location: {
      latest: {
        latitude: 1,
        longitude: 2,
        city: '<script>alert(1)</script>',
        region: null,
        country: null,
        source: 'ip',
        accuracyMeters: null,
        capturedAt: '2026-10-11T00:00:00Z',
      },
      history: [],
    },
    locationTracking: true,
  };

  const html = deviceDetailModule.render(state);
  const panel = locationPanelOf(html);
  assert.ok(panel.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.ok(!panel.includes('<script>alert(1)</script>'));
});

// ============================================================================
// Edge: accuracyMeters present shows "<n> m"
// ============================================================================

test('Edge: a numeric accuracyMeters is shown as "<n> m" rather than "Approximate"', () => {
  const state = {
    profile: { deviceId: 'd1' },
    location: {
      latest: {
        latitude: 1,
        longitude: 2,
        city: null,
        region: null,
        country: null,
        source: 'ip',
        accuracyMeters: 50,
        capturedAt: '2026-10-11T00:00:00Z',
      },
      history: [],
    },
    locationTracking: true,
  };

  const html = deviceDetailModule.render(state);
  const panel = locationPanelOf(html);
  assert.ok(panel.includes('50 m'));
});
